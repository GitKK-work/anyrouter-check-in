#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
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
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
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


async def open_browser_session(
	account_name: str,
	domain: str,
	user_cookies: dict,
	waf_cookie_names: list[str],
	probe_path: str = '/login',
):
	"""Open a browser context pre-loaded with user cookies and a solved WAF session.

	All subsequent API calls for this account should be made via `page.evaluate(fetch(...))`
	inside the returned page so the browser automatically attaches WAF + session cookies.
	"""
	import tempfile

	print(f'[PROCESSING] {account_name}: Starting browser session...')

	parsed = urlparse(domain)
	cookie_domain = parsed.hostname or domain

	# Use mkdtemp + manual cleanup so the profile dir survives past the
	# open_browser_session call (we hand the context back to the caller,
	# which is responsible for closing it; close_browser_session will then
	# delete the dir).
	profile_dir = tempfile.mkdtemp(prefix=f'pw-{account_name.replace(" ", "_")}-')
	playwright_cm = async_playwright()
	p = await playwright_cm.__aenter__()
	try:
		context = await p.chromium.launch_persistent_context(
			user_data_dir=profile_dir,
			headless=False,
			user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			viewport={'width': 1920, 'height': 1080},
			args=[
				'--disable-blink-features=AutomationControlled',
				'--disable-dev-shm-usage',
				'--no-sandbox',
			],
		)

		# Stash the playwright + profile dir on the context so close_browser_session
		# can shut them down deterministically.
		context._pw_cm = playwright_cm  # type: ignore[attr-defined]
		context._pw_p = p  # type: ignore[attr-defined]
		context._profile_dir = profile_dir  # type: ignore[attr-defined]

		# Inject the user-provided session cookies before any navigation so
		# they are sent on the very first request and accepted by the API.
		if user_cookies:
			inject = []
			for name, value in user_cookies.items():
				inject.append({
					'name': name,
					'value': value,
					'domain': cookie_domain,
					'path': '/',
				})
			try:
				await context.add_cookies(inject)
			except Exception as e:
				print(f'[WARNING] {account_name}: Failed to inject user cookies: {e}')

		page = await context.new_page()

		# Probe a page that may trigger the WAF JS challenge. The WAF
		# challenge HTML sets acw_sc__v2 via document.cookie after the
		# obfuscated script computes it. We wait specifically for that
		# cookie to appear (with a generous timeout) so we don't race
		# against the JS.
		probe_url = f'{domain.rstrip("/")}{probe_path}'
		print(f'[PROCESSING] {account_name}: Probing {probe_url} to settle WAF session...')
		try:
			await page.goto(probe_url, wait_until='domcontentloaded', timeout=30000)
		except Exception as e:
			print(f'[WARNING] {account_name}: Initial navigation warning: {e}')

		if waf_cookie_names:
			# Wait up to 20s for the required WAF cookies to appear.
			cookie_predicate = (
				'(['
				+ ','.join(f"'{c}'" for c in waf_cookie_names)
				+ '] || []).every(c => document.cookie.split("; ").some(k => k.startsWith(c + "=")))'
			)
			try:
				await page.wait_for_function(cookie_predicate, timeout=20000)
			except Exception:
				pass

			# Reload once more so the freshly-set WAF cookies are sent on
			# the request that actually fetches the protected content.
			try:
				await page.reload(wait_until='domcontentloaded', timeout=30000)
				await page.wait_for_function(cookie_predicate, timeout=20000)
			except Exception:
				pass

			# Diagnostic: what cookies does the browser actually hold now?
			try:
				final_cookies = await context.cookies()
				names = sorted({c.get('name') for c in final_cookies if c.get('name')})
				doc_cookie = await page.evaluate('document.cookie')
				print(f'[DIAGNOSTIC] {account_name}: browser cookies after probe: {names}')
				print(f'[DIAGNOSTIC] {account_name}: document.cookie = {doc_cookie!r}')
			except Exception as de:
				print(f'[WARNING] {account_name}: cookie diagnostic failed: {de}')

		return context, page
	except Exception:
		# Clean up on the failure path: stop the playwright instance and remove the dir.
		try:
			await playwright_cm.__aexit__(None, None, None)
		except Exception:
			pass
		import shutil
		shutil.rmtree(profile_dir, ignore_errors=True)
		raise


async def close_browser_session(context, page):
	"""Close the browser context, stop Playwright, and remove the temp profile dir."""
	import shutil

	profile_dir = getattr(context, '_profile_dir', None)
	pw_cm = getattr(context, '_pw_cm', None)
	try:
		if page is not None:
			try:
				await page.close()
			except Exception:
				pass
		await context.close()
	finally:
		if pw_cm is not None:
			try:
				await pw_cm.__aexit__(None, None, None)
			except Exception:
				pass
		if profile_dir:
			shutil.rmtree(profile_dir, ignore_errors=True)


async def browser_fetch(page, method: str, url: str, headers: dict, body: str | None = None) -> dict:
	"""Issue an HTTP request from inside the browser context and return its result.

	Returning {status, headers, text} mirrors what an httpx response would give
	us, so the existing response-parsing code in get_user_info / execute_check_in
	can be reused almost as-is.
	"""
	js = """
		async ({method, url, headers, body}) => {
			const init = {method, headers, credentials: 'include'};
			if (body !== null && body !== undefined) init.body = body;
			const r = await fetch(url, init);
			const respHeaders = {};
			r.headers.forEach((v, k) => { respHeaders[k] = v; });
			const text = await r.text();
			return {status: r.status, headers: respHeaders, text};
		}
	"""
	return await page.evaluate(js, {'method': method, 'url': url, 'headers': headers, 'body': body})


def parse_user_info_response(account_name: str, response: dict) -> dict:
	"""Parse a user_info response (httpx or browser_fetch shape) into the result dict."""
	status = response.get('status')
	if status != 200:
		return {'success': False, 'error': f'Failed to get user info: HTTP {status}'}

	text = response.get('text', '') or ''
	try:
		data = json.loads(text)
	except Exception as je:
		ct = response.get('headers', {}).get('content-type', '')
		preview = text[:200].replace('\n', ' ')
		print(
			f'[DIAGNOSTIC] user_info 200 but JSON parse failed: {je}\n'
			f'  content-type={ct!r}\n'
			f'  resp len={len(text)}\n'
			f'  resp text[:200]={preview!r}'
		)
		return {'success': False, 'error': 'Failed to get user info: non-JSON response'}

	if data.get('success'):
		user_data = data.get('data', {}) or {}
		quota = round(user_data.get('quota', 0) / 500000, 2)
		used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
		return {
			'success': True,
			'quota': quota,
			'used_quota': used_quota,
			'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
		}
	return {'success': False, 'error': 'Failed to get user info: success=false'}


def parse_check_in_response(account_name: str, response: dict) -> bool:
	"""Parse a sign_in response (httpx or browser_fetch shape) into success bool."""
	status = response.get('status')
	text = response.get('text', '') or ''
	if status != 200:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {status}')
		return False
	try:
		result = json.loads(text)
	except Exception:
		if 'success' in text.lower():
			print(f'[SUCCESS] {account_name}: Check-in successful!')
			return True
		print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
		return False

	if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
		print(f'[SUCCESS] {account_name}: Check-in successful!')
		return True
	error_msg = result.get('msg', result.get('message', 'Unknown error'))
	already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
	if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
		print(f'[SUCCESS] {account_name}: Already checked in today')
		return True
	print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
	return False


async def get_user_info(page, account_name: str, provider_config, headers: dict, api_user: str) -> dict:
	"""Fetch user info via the browser context (auto-attaches WAF + session cookies)."""
	user_info_url = f'{provider_config.domain.rstrip("/")}{provider_config.user_info_path}'
	req_headers = {**headers, provider_config.api_user_key: api_user}
	try:
		response = await browser_fetch(page, 'GET', user_info_url, req_headers)
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}
	return parse_user_info_response(account_name, response)


async def execute_check_in(page, account_name: str, provider_config, headers: dict, api_user: str) -> bool:
	"""Execute the sign-in request via the browser context."""
	sign_in_url = f'{provider_config.domain.rstrip("/")}{provider_config.sign_in_path}'
	req_headers = {
		**headers,
		'Content-Type': 'application/json',
		'X-Requested-With': 'XMLHttpRequest',
		provider_config.api_user_key: api_user,
	}
	print(f'[NETWORK] {account_name}: Executing check-in')
	try:
		response = await browser_fetch(page, 'POST', sign_in_url, req_headers, body='null')
	except Exception as e:
		print(f'[FAILED] {account_name}: Check-in failed - {str(e)[:50]}...')
		return False
	print(f'[RESPONSE] {account_name}: Response status code {response.get("status")}')
	return parse_check_in_response(account_name, response)


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息

	Args:
		detail: 包含签到详情的字典

	Returns:
		格式化后的通知消息
	"""
	lines = [
		f'[CHECK-IN] {detail["name"]}',
		'  ━━━━━━━━━━━━━━━━━━━━',
		'  📍 签到前',
		f'     💵 余额: ${detail["before_quota"]:.2f}  |  📊 累计消耗: ${detail["before_used"]:.2f}',
		'  📍 签到后',
		f'     💵 余额: ${detail["after_quota"]:.2f}  |  📊 累计消耗: ${detail["after_used"]:.2f}',
	]

	# 判断是否有变化
	has_reward = detail['check_in_reward'] != 0
	has_usage = detail['usage_increase'] != 0

	if has_reward or has_usage:
		lines.append('  ━━━━━━━━━━━━━━━━━━━━')

		# 已签到但期间有使用
		if not has_reward and has_usage:
			lines.append('  ℹ️  今日已签到（期间有使用）')

		# 签到获得
		if has_reward:
			lines.append(f'  🎁 签到获得: +${detail["check_in_reward"]:.2f}')

		# 期间消耗
		if has_usage:
			lines.append(f'  📉 期间消耗: ${detail["usage_increase"]:.2f}')

		# 余额变化
		if detail['balance_change'] != 0:
			change_symbol = '+' if detail['balance_change'] > 0 else ''
			change_emoji = '📈' if detail['balance_change'] > 0 else '📉'
			lines.append(f'  {change_emoji} 余额变化: {change_symbol}${detail["balance_change"]:.2f}')
	else:
		# 无任何变化
		lines.extend(['  ━━━━━━━━━━━━━━━━━━━━', '  ℹ️  今日已签到，无变化'])

	return '\n'.join(lines)


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None, None

	context = None
	page = None
	try:
		# Open one browser per account. All API calls for this account go
		# through page.evaluate(fetch) so the browser auto-attaches both the
		# user session cookies and the WAF acw_sc__v2 cookie.
		waf_cookie_names = provider_config.waf_cookie_names if provider_config.needs_waf_cookies() else []
		probe_path = provider_config.waf_challenge_path or provider_config.login_path or '/login'
		context, page = await open_browser_session(
			account_name,
			provider_config.domain,
			user_cookies,
			waf_cookie_names,
			probe_path=probe_path,
		)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
		}

		user_info_before = await get_user_info(page, account_name, provider_config, headers, account.api_user)
		if user_info_before.get('success'):
			print(user_info_before['display'])
		else:
			print(user_info_before.get('error', 'Unknown error'))

		if provider_config.needs_manual_check_in():
			success = await execute_check_in(page, account_name, provider_config, headers, account.api_user)
			user_info_after = await get_user_info(page, account_name, provider_config, headers, account.api_user)
			return success, user_info_before, user_info_after
		else:
			print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
			user_info_after = await get_user_info(page, account_name, provider_config, headers, account.api_user)
			return True, user_info_before, user_info_after

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None, None
	finally:
		if context is not None:
			await close_browser_session(context, page)


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	account_check_in_details = {}  # 存储每个账号的签到详情
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			# 存储签到前后的余额信息
			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

				# 计算签到收益
				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']
					after_quota = user_info_after['quota']
					after_used = user_info_after['used_quota']

					# 计算总额度（余额 + 历史消耗）
					total_before = before_quota + before_used
					total_after = after_quota + after_used

					# 签到获得的额度 = 总额度增加量
					check_in_reward = total_after - total_before

					# 本次消耗 = 历史消耗增加量
					usage_increase = after_used - before_used

					# 余额变化
					balance_change = after_quota - before_quota

					account_check_in_details[account_key] = {
						'name': account.get_display_name(i),
						'before_quota': before_quota,
						'before_used': before_used,
						'after_quota': after_quota,
						'after_used': after_used,
						'check_in_reward': check_in_reward,  # 签到获得
						'usage_increase': usage_increase,  # 本次消耗
						'balance_change': balance_change,  # 余额变化
						'success': success,
					}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {account_name}'
				if user_info_after and user_info_after.get('success'):
					account_result += f'\n{user_info_after["display"]}'
				elif user_info_after:
					account_result += f'\n{user_info_after.get("error", "Unknown error")}'
				notification_content.append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True  # 异常也需要通知
			notification_content.append(f'[FAIL] {account_name} exception: {str(e)[:50]}...')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				detail = account_check_in_details[account_key]
				account_name = detail['name']

				# 使用格式化函数生成通知消息
				account_result = format_check_in_notification(detail)

				# 检查是否已经在通知内容中（避免重复）
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		summary = [
			'[STATS] Check-in result statistics:',
			f'[SUCCESS] Success: {success_count}/{total_count}',
			f'[FAIL] Failed: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('[SUCCESS] All accounts check-in successful!')
		elif success_count > 0:
			summary.append('[WARN] Some accounts check-in successful')
		else:
			summary.append('[ERROR] All accounts check-in failed')

		time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		print(notify_content)
		notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
