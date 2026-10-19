"""Session rotation, CSRF and private remote browser access."""
import http.client
import base64
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import io
import threading
import unittest
from unittest.mock import Mock, patch

import requests
from canvas_access.auth import AuthRequired, checked_json
from canvas_access.session import SessionStore
from canvas_access.session_login import handler

BASE = 'https://school.instructure.com'
COOKIE = {'name': 'canvas_session', 'value': 'test-session', 'domain': 'school.instructure.com',
          'path': '/', 'expires': -1, 'secure': True, 'httpOnly': True, 'sameSite': 'Lax'}
CSRF = COOKIE | {'name': '_csrf_token', 'value': 'test%2Bcsrf', 'httpOnly': False}

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.transport = requests.Session()
        self.store = SessionStore(self.tmp.name, BASE, session=self.transport)
        with self.store.locked():
            self.store.save([COOKIE, CSRF, COOKIE | {'domain': 'sso.school.edu', 'value': 'sso-test'}])

    def test_rotation_is_saved_and_sso_is_not_sent(self):
        def request(method, url, **kw):
            self.assertEqual(url, BASE + '/api/v1/users/self')
            self.assertFalse(kw['allow_redirects'])
            self.assertNotIn('Authorization', kw['headers'])
            self.assertEqual(len(self.transport.cookies), 2)
            self.transport.cookies.set('canvas_session', 'rotated', domain=COOKIE['domain'], path='/', secure=True)
            return Mock(status_code=200, headers={'Content-Type': 'application/json'})
        with patch.object(self.transport, 'request', side_effect=request):
            self.store.request('GET', '/api/v1/users/self')
        record = self.store.read()
        self.assertTrue(any(c['value'] == 'rotated' for c in record['cookies']))
        self.assertTrue(any(c['value'] == 'sso-test' for c in record['cookies']))
        self.assertEqual(Path(self.tmp.name, 'session.json').stat().st_mode & 0o777, 0o600)

    def test_write_decodes_csrf_and_is_never_replayed(self):
        with patch.object(self.transport, 'request', return_value=Mock(status_code=401, headers={})) as call:
            with self.assertRaises(AuthRequired):
                self.store.request('POST', '/api/v1/conversations', json={'body': 'test'})
        call.assert_called_once()
        self.assertEqual(call.call_args.kwargs['headers']['X-CSRF-Token'], 'test+csrf')

    def test_missing_csrf_blocks_write_before_request(self):
        with self.store.locked():
            self.store.save([COOKIE])
        with patch.object(self.transport, 'request') as call, self.assertRaises(AuthRequired):
            self.store.request('POST', '/api/v1/conversations', json={})
        call.assert_not_called()

    def test_login_redirect_never_receives_api_payload(self):
        with patch.object(self.transport, 'request', return_value=Mock(status_code=302, headers={})) as call:
            with self.assertRaises(AuthRequired):
                self.store.request('GET', '/api/v1/users/self')
        self.assertFalse(call.call_args.kwargs['allow_redirects'])

    def test_cookie_json_guard_is_parsed(self):
        response = Mock(status_code=200, text='while(1);{"id":12}')
        response.json.side_effect = ValueError
        self.assertEqual(checked_json(response), {'id': 12})

    def test_keepalive_recovers_with_sso_and_notifies_only_if_recovery_fails(self):
        from canvas_access.browser import keepalive
        store = Mock()
        store.request.side_effect = AuthRequired('expired')
        with patch('canvas_access.browser.SessionStore', return_value=store), patch('canvas_access.browser.login') as login, \
             patch('herald.db.session') as session:
            session.return_value.__enter__.return_value.execute.return_value.fetchone.return_value = None
            self.assertEqual(keepalive(), {'connected': True})
            login.assert_called_once_with(store, lifetime=45)

    def test_failed_sso_requests_login_instead_of_discarding_facts(self):
        from canvas_access.browser import keepalive
        store = Mock()
        store.request.side_effect = AuthRequired('expired')
        with patch('canvas_access.browser.SessionStore', return_value=store), \
             patch('canvas_access.browser.login', side_effect=AuthRequired('login needed')), \
             patch('herald.db.session') as session, \
             patch('canvas_access.sync.require_login', return_value={'login_required':1}) as required:
            self.assertEqual(keepalive(), {'login_required':1})
            required.assert_called_once_with(session.return_value.__enter__.return_value)

class PrivateViewTests(unittest.TestCase):
    def test_browser_can_decode_image_rectangles_under_the_actual_policy(self):
        from PIL import Image
        from playwright.sync_api import sync_playwright
        with tempfile.TemporaryDirectory() as tmp:
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler(
                root=tmp, websocket_port=1, stop=threading.Event()))
            origin = f'http://127.0.0.1:{server.server_port}'
            settings = {'canvas.login_url': origin, 'canvas.login_users': ['test-user']}
            with patch('canvas_access.session_login.config.get', side_effect=lambda k,d=None:settings.get(k,d)):
                server.RequestHandlerClass = handler(root=tmp, websocket_port=1, stop=threading.Event())
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with sync_playwright() as p:
                        if not Path(p.chromium.executable_path).exists():
                            self.skipTest('Chromium is not installed')
                        browser = p.chromium.launch()
                        try:
                            page = browser.new_page(extra_http_headers={'Tailscale-User-Login':'test-user'})
                            page.route('**/viewer.js', lambda route:route.fulfill(body='',content_type='text/javascript'))
                            page.goto(origin)
                            pixels = io.BytesIO()
                            Image.new('RGB', (2, 2), (240, 20, 20)).save(pixels, format='JPEG')
                            value = 'data:image/jpeg;base64,' + base64.b64encode(pixels.getvalue()).decode()
                            result = page.evaluate('''src => new Promise((resolve,reject) => {
                                const image = new Image();
                                image.onload = () => {
                                    const canvas = document.createElement('canvas');
                                    canvas.width=2; canvas.height=2;
                                    const ctx=canvas.getContext('2d'); ctx.drawImage(image,0,0);
                                    resolve([...ctx.getImageData(0,0,1,1).data]);
                                };
                                image.onerror=()=>reject(new Error('VNC image frame blocked'));
                                image.src=src;
                            })''', value)
                            self.assertGreater(result[0], 200)
                            self.assertLess(result[1], 50)
                            self.assertEqual(result[3], 255)
                        finally:
                            browser.close()
                finally:
                    server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_every_route_checks_identity_and_websocket_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'core').mkdir()
            (root / 'core/rfb.js').write_text('export default class RFB {}')
            settings = {'canvas.login_url': 'https://private.ts.net:8447', 'canvas.login_users': ['test-user']}
            stop = threading.Event()
            now = [0]
            with patch('canvas_access.session_login.config.get', side_effect=lambda k,d=None: settings.get(k,d)):
                server = ThreadingHTTPServer(('127.0.0.1', 0), handler(root=root, websocket_port=1, stop=stop, clock=lambda:now[0]))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                def get(path, extra=None):
                    con = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                    try:
                        headers = {'Host':'private.ts.net:8447', **(extra or {})}
                        con.request('GET', path, headers=headers)
                        res = con.getresponse()
                        return res.status, res.read()
                    finally:
                        con.close()
                try:
                    for path in ('/', '/viewer.js', '/core/rfb.js', '/websockify'):
                        self.assertEqual(get(path)[0], 403)
                    identity = {'Tailscale-User-Login': 'test-user'}
                    self.assertEqual(get('/', identity)[0], 200)
                    self.assertEqual(get('/core/rfb.js', identity)[0], 200)
                    self.assertEqual(get('/core/../../session.json', identity)[0], 404)
                    self.assertEqual(get('/websockify', identity | {'Origin':'https://evil.example','Upgrade':'websocket'})[0], 403)
                    self.assertEqual(get('/', identity | {'Host':'evil.example'})[0], 403)
                    now[0] = 901
                    self.assertEqual(get('/', identity)[0], 403)
                finally:
                    server.shutdown(); server.server_close(); thread.join(timeout=3)

if __name__ == '__main__':
    unittest.main()
