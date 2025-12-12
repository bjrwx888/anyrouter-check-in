#!/usr/bin/env python3
"""
AnyRouter.top / AgentRouter.org 自动签到脚本（中文钉钉通知版本）
支持：
✅ AnyRouter（原逻辑）
✅ AgentRouter（兼容余额解析或提示“余额信息暂不可用”）
"""

import asyncio
import hashlib
import json
import os
import sys
import requests
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


# ============================= 基础工具函数 =============================
def load_balance_hash():
    """加载余额hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_balance_hash(balance_hash):
    """保存余额hash"""
    try:
        with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
            f.write(balance_hash)
    except Exception as e:
        print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
    """生成余额数据的hash"""
    simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
    """解析 cookies 数据"""
    if isinstance(cookies_data, dict):
        return cookies_data
    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


# ============================= Playwright 处理 =============================
async def get_waf_cookies_with_playwright(account_name: str, login_url: str):
    """使用 Playwright 获取 WAF cookies"""
    print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')
    async with async_playwright() as p:
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=temp_dir,
                headless=False,
                ignorg_https_errors=true,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--no-sandbox',
                    '--ignore-certificate-errors', 
                ],
            )
            page = await context.new_page()
            try:
                print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')
                await page.goto(login_url, wait_until='networkidle')
                try:
                    await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                except Exception:
                    await page.wait_for_timeout(3000)

                cookies = await page.context.cookies()
                waf_cookies = {}
                for cookie in cookies:
                    name, value = cookie.get('name'), cookie.get('value')
                    if name in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'] and value:
                        waf_cookies[name] = value

                print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')
                required = ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']
                missing = [c for c in required if c not in waf_cookies]
                if missing:
                    print(f'[FAILED] {account_name}: Missing WAF cookies: {missing}')
                    await context.close()
                    return None

                print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')
                await context.close()
                return waf_cookies
            except Exception as e:
                print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
                await context.close()
                return None


# ============================= 用户信息与签到 =============================
def get_user_info(client, headers, user_info_url: str):
    """获取用户信息，兼容 AnyRouter 与 AgentRouter"""
    try:
        response = client.get(user_info_url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()

            # ✅ AnyRouter 格式
            if data.get('success'):
                user_data = data.get('data', {})
                quota = round(user_data.get('quota', 0) / 500000, 2)
                used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
                return {
                    'success': True,
                    'quota': quota,
                    'used_quota': used_quota,
                    'display': f'💰 当前余额: ${quota}，已使用: ${used_quota}',
                }

            # ✅ AgentRouter 格式（部分接口返回 status/credit/usage）
            elif data.get('status') in ('ok', 'success') or data.get('code') == 0:
                quota = round(data.get('credit', 0) / 500000, 2)
                used_quota = round(data.get('usage', 0) / 500000, 2)
                msg = (
                    f'💰 当前余额: ${quota}，已使用: ${used_quota}'
                    if quota or used_quota
                    else '💰 当前余额信息暂不可用'
                )
                return {
                    'success': True,
                    'quota': quota,
                    'used_quota': used_quota,
                    'display': msg,
                }

        return {'success': False, 'error': f'获取用户信息失败: HTTP {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': f'获取用户信息异常: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
    """准备 cookies"""
    waf_cookies = {}
    if provider_config.needs_waf_cookies():
        login_url = f'{provider_config.domain}{provider_config.login_path}'
        waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url)
        if not waf_cookies:
            print(f'[FAILED] {account_name}: Unable to get WAF cookies')
            return None
    else:
        print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')
    return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
    """执行签到请求"""
    print(f'[NETWORK] {account_name}: Executing check-in')
    checkin_headers = headers.copy()
    checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
    response = client.post(sign_in_url, headers=checkin_headers, timeout=30)
    print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
                print(f'[SUCCESS] {account_name}: 签到成功！')
                return True
            else:
                print(f'[FAILED] {account_name}: 签到失败 - {result.get("msg", "Unknown error")}')
                return False
        except json.JSONDecodeError:
            if 'success' in response.text.lower():
                print(f'[SUCCESS] {account_name}: 签到成功！')
                return True
            else:
                print(f'[FAILED] {account_name}: 签到失败 - 返回格式无效')
                return False
    print(f'[FAILED] {account_name}: 签到失败 - HTTP {response.status_code}')
    return False


# ============================= 主流程 =============================
async def check_in_account(account: AccountConfig, idx: int, app_config: AppConfig):
    """为单个账号执行签到"""
    name = account.get_display_name(idx)
    print(f'\n[PROCESSING] 开始处理 {name}')
    provider = app_config.get_provider(account.provider)
    if not provider:
        print(f'[FAILED] {name}: 未找到 provider 配置 {account.provider}')
        return False, None

    print(f'[INFO] {name}: Using provider "{account.provider}" ({provider.domain})')
    cookies = parse_cookies(account.cookies)
    if not cookies:
        print(f'[FAILED] {name}: cookies 配置无效')
        return False, None

    all_cookies = await prepare_cookies(name, provider, cookies)
    if not all_cookies:
        return False, None

    client = httpx.Client(http2=True, timeout=30.0)
    try:
        client.cookies.update(all_cookies)
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json, text/plain, */*',
            provider.api_user_key: account.api_user,
        }
        info_url = f'{provider.domain}{provider.user_info_path}'
        info = get_user_info(client, headers, info_url)

        if info and info.get('success'):
            print(info['display'])
        else:
            print(f'[INFO] {name}: 未能获取余额信息')

        if provider.needs_manual_check_in():
            success = execute_check_in(client, name, provider, headers)
            return success, info
        else:
            print(f'[INFO] {name}: 自动签到完成')
            return True, info
    except Exception as e:
        print(f'[FAILED] {name}: 签到过程异常 - {e}')
        return False, None
    finally:
        client.close()


# ============================= 中文钉钉推送 =============================
def send_dingtalk_message(accounts_info, success, fail, total):
    webhook = os.getenv("DINGDING_WEBHOOK")
    if not webhook:
        print("***DingTalk***: 未配置 DINGDING_WEBHOOK，跳过推送")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg_lines = [
        "📢 AnyRouter / AgentRouter 自动签到通知",
        f"🕒 执行时间：{now}",
        "",
        "💰【账户余额信息】"
    ]
    for acc in accounts_info:
        msg_lines.append(f"🔹 {acc['name']}：当前余额 ${acc['balance']}，已使用 ${acc['used']}")
    msg_lines.append("")
    msg_lines.append("📊【统计结果】")
    msg_lines.append(f"✅ 成功：{success}/{total}")
    msg_lines.append(f"❌ 失败：{fail}/{total}")
    msg_lines.append("🎉 所有账户签到成功！" if fail == 0 else "⚠️ 部分账户签到失败，请检查日志。")

    payload = {"msgtype": "text", "text": {"content": "\n".join(msg_lines)}}
    try:
        r = requests.post(webhook, json=payload, timeout=10)
        print("***DingTalk***: ✅ 推送成功" if r.status_code == 200 else f"***DingTalk***: ❌ 推送失败 {r.status_code}")
    except Exception as e:
        print(f"***DingTalk***: ❌ 推送异常: {e}")


# ============================= 主入口 =============================
async def main():
    print('[SYSTEM] AnyRouter.top 多账号自动签到脚本启动')
    print(f'[TIME] 当前执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    app_config = AppConfig.load_from_env()
    accounts = load_accounts_config()
    if not accounts:
        print('[FAILED] 无法加载账户配置，程序退出')
        sys.exit(1)

    success, total = 0, len(accounts)
    balances = []

    for i, account in enumerate(accounts):
        ok, info = await check_in_account(account, i, app_config)
        if ok:
            success += 1
        if info and info.get('success'):
            balances.append({
                "name": account.get_display_name(i),
                "balance": info['quota'],
                "used": info['used_quota']
            })

    fail = total - success
    send_dingtalk_message(balances, success, fail, total)
    sys.exit(0 if success > 0 else 1)


def run_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[WARNING] 用户中断程序')
        sys.exit(1)
    except Exception as e:
        print(f'\n[FAILED] 执行出错: {e}')
        sys.exit(1)


if __name__ == '__main__':
    run_main()
