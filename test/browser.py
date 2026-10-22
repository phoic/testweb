"""Real Chromium/HTTP checks. Requires Python Playwright and local Chromium."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='sqli-browser-') as directory:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    environment = {**os.environ, 'PORT': str(port), 'LAB_DB_PATH': f'{directory}/lab.db'}
    process = subprocess.Popen(['node', 'server.js'], cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        base = f'http://127.0.0.1:{port}'
        for attempt in range(100):
            try:
                with urlopen(base, timeout=1) as response:
                    assert response.status == 200
                break
            except OSError:
                if process.poll() is not None:
                    raise AssertionError(process.stdout.read().decode())
                time.sleep(0.1)
        else:
            raise AssertionError('Server did not become ready')
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True, args=['--no-sandbox'])
            page = browser.new_page(viewport={'width': 1440, 'height': 1100}, accept_downloads=True)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            requests = []
            page.on('request', lambda request: requests.append(json.loads(request.post_data)) if request.url.endswith('/api/sqli/compare') else None)
            page.goto(base)
            page.get_by_role('button', name='정상 계정', exact=True).click()
            assert not requests, 'Example buttons must only fill values'
            assert page.locator('#username').input_value() == 'alice'
            assert page.locator('#password').input_value() == 'password123'
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 1")
            assert page.locator('#vulnerable-result .status').inner_text() == '인증 성공'
            assert page.locator('#safe-result .status').inner_text() == '인증 성공'
            assert '인증 우회 관찰' not in page.locator('#analysis-result').inner_text()
            first_record = page.locator('#history-body tr').first.inner_text()
            page.locator('#username').fill('changed after run')
            page.locator('#password').fill('changed password')
            assert page.locator('#history-body tr').first.inner_text() == first_record
            page.get_by_role('button', name='잘못된 비밀번호', exact=True).click()
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 2")
            assert page.locator('#vulnerable-result .status').inner_text() == '인증 실패'
            assert page.locator('#safe-result .status').inner_text() == '인증 실패'
            page.get_by_role('button', name='인증 우회 입력', exact=True).click()
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 3")
            assert page.locator('#vulnerable-result .status').inner_text() == '인증 성공'
            assert page.locator('#safe-result .status').inner_text() == '인증 실패'
            assert '인증 우회 관찰' in page.locator('#analysis-result').inner_text()
            page.locator('#show-values').check()
            assert page.locator('#password').get_attribute('type') == 'text'
            assert "' OR '1'='1' -- " in page.locator('#safe-result .bindings').inner_text()
            with page.expect_download() as info:
                page.get_by_role('button', name='기록 JSON 다운로드', exact=True).click()
            records = json.loads(Path(info.value.path()).read_text())['records']
            assert len(records) == 3
            assert records[0]['input'] == {'username': 'alice', 'password': 'password123'}
            for record in records:
                assert record['vulnerable']['input'] == record['safe']['input'] == record['input']
            page.locator('#show-values').uncheck()
            assert page.locator('#password').get_attribute('type') == 'password'
            assert not page.locator('#vulnerable-result .query').is_visible()
            page.locator('#show-values').check()
            first_record_visible = page.locator('#history-body tr').first.inner_text()
            page.screenshot(path='/tmp/testweb-comparison.png', full_page=True)
            page.get_by_role('button', name='구문 오류 입력', exact=True).click()
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 4")
            assert page.locator('#vulnerable-result .status').inner_text() == 'DB 오류'
            assert page.locator('#safe-result .status').inner_text() == '인증 실패'
            # Delayed response: input edits and a second submit cannot change this run.
            def delay(route):
                response = route.fetch()
                page.locator('#username').fill('edited during request')
                assert page.locator('#run').is_disabled()
                page.locator('#compare-form').evaluate('(form) => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))')
                route.fulfill(response=response)
            page.route('**/api/sqli/compare', delay)
            page.get_by_role('button', name='정상 계정', exact=True).click()
            previous = len(requests)
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 5")
            assert len(requests) == previous + 1
            assert requests[-1]['username'] == 'alice'
            assert page.locator('#vulnerable-result .input').inner_text().find('alice') >= 0
            assert page.locator('#history-body tr').first.inner_text() == first_record_visible
            page.unroute('**/api/sqli/compare', delay)
            # History selection reads frozen prior responses, not the current form.
            page.locator('#history-body tr').first.get_by_role('button').click()
            assert page.locator('#vulnerable-result .status').inner_text() == '인증 성공'
            assert 'password123' in page.locator('#safe-result .bindings').inner_text()
            assert page.locator('#username').input_value() == 'edited during request'
            # Long user content is rendered as text and wraps inside the result panels.
            text_input = '<img src=x onerror="throw new Error(1)">' + 'x' * 300
            page.locator('#username').fill(text_input)
            page.locator('#password').fill('test')
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("document.querySelectorAll('#history-body tr').length === 6")
            assert page.locator('#vulnerable-result img').count() == 0
            assert text_input in page.locator('#vulnerable-result .query').inner_text()
            for selector in ['#vulnerable-result .query', '#safe-result .bindings']:
                assert page.locator(selector).evaluate('(element) => element.scrollWidth <= element.clientWidth')
            # Connection failure must be visible and cannot masquerade as a DB result.
            page.route('**/api/sqli/compare', lambda route: route.abort())
            page.get_by_role('button', name='두 방식 비교 실행', exact=True).click()
            page.wait_for_function("!document.querySelector('#run').disabled")
            assert page.locator('#request-error').inner_text()
            assert page.locator('#history-body tr').count() == 6
            assert not errors, errors
            page.set_viewport_size({'width': 390, 'height': 844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            browser.close()
            print('PASS: examples, normal/wrong/bypass/quote, shared captured input, duplicate-submit guard, immutable records, JSON download, visibility, network failure, history selection, literal HTML input, long SQL wrapping, mobile layout; no JS errors')
    finally:
        process.terminate()
        process.wait(timeout=10)
