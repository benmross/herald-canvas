"""Cookie transport. Persist rotations without exposing cookies to callers."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import unquote, urlsplit

import requests
from herald import config
from .auth import AuthRequired, CanvasError, http, origin


class SessionStore:
    def __init__(self, directory=None, base_url=None, session=None):
        self.directory = Path(directory or config.get('canvas.auth_dir') or config.HOME / 'canvas')
        self.base = origin(base_url or config.get('canvas.base_url'))
        self.session = session or requests.Session()

    @contextmanager
    def locked(self, name='session', blocking=True):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        fd = os.open(self.directory / (name + '.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise CanvasError('Your Canvas login browser is already open') from None
            yield
        finally:
            os.close(fd)

    def read(self):
        try:
            record = json.loads((self.directory / 'session.json').read_text())
        except (OSError, ValueError):
            raise AuthRequired('Canvas is not connected; open the private login page') from None
        if record.get('base_url') != self.base:
            raise AuthRequired('Canvas session belongs to a different institution')
        return record

    def save(self, cookies):
        fd, tmp = tempfile.mkstemp(prefix='session-', dir=self.directory)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump({'base_url': self.base, 'cookies': cookies, 'updated_at': time.time()}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.directory / 'session.json')
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def request(self, method, path, **kwargs):
        if not path.startswith('/api/v1/') or '?' in path or '#' in path:
            raise PermissionError('Use a Canvas API path and separate parameters')
        with self.locked():
            record = self.read()
            host = urlsplit(self.base).hostname
            jar = requests.cookies.RequestsCookieJar()
            # Preserve SSO cookies on disk, but never send them to Canvas.
            original = record.get('cookies', [])
            canvas = [c for c in original if c['domain'].lstrip('.') == host or
                      host.endswith('.' + c['domain'].lstrip('.'))]
            for c in canvas:
                expires = c.get('expires', -1)
                jar.set(c['name'], c['value'], domain=c['domain'], path=c.get('path', '/'),
                        secure=c.get('secure', True), expires=int(expires) if expires > 0 else None,
                        rest={'HttpOnly': c.get('httpOnly', False), 'SameSite': c.get('sameSite', 'Lax')})
            self.session.cookies = jar
            csrf = next((unquote(c.value) for c in jar if c.name == '_csrf_token'), None)
            headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
            if method.upper() not in ('GET', 'HEAD'):
                if not csrf:
                    raise AuthRequired('Canvas session has no CSRF token; reconnect Canvas')
                headers.update({'X-CSRF-Token': csrf, 'Origin': self.base, 'Referer': self.base + '/'})
            response = http(self.session, method, self.base + path, headers=headers, **kwargs)
            # Requests has applied Set-Cookie, including session-cookie rotation.
            kept = [c for c in original if c not in canvas]
            for c in self.session.cookies:
                kept.append({'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path,
                             'expires': c.expires or -1, 'secure': c.secure,
                             'httpOnly': c.has_nonstandard_attr('HttpOnly') and c._rest.get('HttpOnly') is not False,
                             'sameSite': {'strict': 'Strict', 'none': 'None'}.get(
                                 str(c._rest.get('SameSite', 'Lax')).lower(), 'Lax')})
            self.save(kept)
            if response.status_code in (401, 302, 303) or 'text/html' in response.headers.get('Content-Type', ''):
                raise AuthRequired('Canvas session expired; reconnect Canvas')
            return response
