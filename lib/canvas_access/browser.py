"""User-driven browser login and bounded, headless SSO recovery."""
import os
import json
import time
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, Error as BrowserError
from herald import config
from .auth import AuthRequired, CanvasError
from .session import SessionStore


def login(store=None, *, display=None, lifetime=900, ready=None, stop=None):
    store = store or SessionStore()
    with store.locked('browser', blocking=False):
        profile = store.directory / 'browser'
        profile.mkdir(mode=0o700, exist_ok=True)
        profile.chmod(0o700)
        with sync_playwright() as playwright:
            env = dict(os.environ)
            if display:
                env['DISPLAY'] = display
            context = playwright.chromium.launch_persistent_context(
                str(profile), headless=display is None, env=env,
                viewport={'width': 430, 'height': 760}, args=['--window-size=430,860'])
            try:
                try:
                    context.add_cookies(store.read()['cookies'])
                except AuthRequired:
                    pass
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(store.base + '/login', wait_until='domcontentloaded', timeout=60000)
                if ready:
                    ready()
                deadline = time.monotonic() + lifetime
                while time.monotonic() < deadline and not (stop and stop.is_set()):
                    # No page contents, screenshots, passwords or local storage
                    # enter the ledger or a model. Only authenticated API status.
                    if urlsplit(page.url).hostname == urlsplit(store.base).hostname:
                        response = context.request.get(store.base + '/api/v1/users/self/profile',
                                                       headers={'Accept': 'application/json'},
                                                       max_redirects=0, timeout=10000)
                        try:
                            text = response.text()
                            if text.startswith('while(1);'):
                                text = text[len('while(1);'):]
                            try:
                                user = json.loads(text) if response.status == 200 else {}
                            except ValueError:
                                user = {}
                            if isinstance(user, dict) and isinstance(user.get('id'), int):
                                with store.locked():
                                    store.save(context.cookies())
                                return True
                        finally:
                            response.dispose()
                    page.wait_for_timeout(1500)
                if display is None:
                    raise AuthRequired('Canvas needs you to log in again')
                return False
            except BrowserError:
                raise AuthRequired('Canvas login did not complete; reopen the private login page') from None
            finally:
                context.close()


def keepalive():
    from herald import db
    from .sync import require_login
    store = SessionStore()
    try:
        try:
            response = store.request('GET', '/api/v1/users/self/profile')
            if response.status_code != 200:
                raise CanvasError('Canvas keepalive failed')
        except AuthRequired:
            login(store, lifetime=45)
        # Recovery means a later expiry can notify once again.
        with db.session() as con:
            import json
            row = con.execute("SELECT data FROM facts WHERE source='canvas' AND kind='status' AND external_id='api'").fetchone()
            if row:
                state = json.loads(row[0])
                state.update(connected=True, login_required=False, login_notified=False)
                from .sync import status
                status(con, **state)
        return {'connected': True}
    except AuthRequired:
        with db.session() as con:
            return require_login(con)
