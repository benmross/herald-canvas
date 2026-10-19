"""Short-lived noVNC view, gated by tailnet identity on every HTTP/WS request."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

from herald import collector, config
from .auth import CanvasError
from .browser import login
from .session import SessionStore

PAGE = '''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Canvas login</title><link rel="stylesheet" href="/viewer.css"></head>
<body><p id="status">Log in to Canvas in the browser below. Complete Duo if asked. This view closes after 15 minutes.</p><div id="screen"></div><script type="module" src="/viewer.js"></script></body></html>'''
JS = '''import RFB from '/core/rfb.js';
const rfb = new RFB(document.getElementById('screen'), `wss://${location.host}/websockify`);
rfb.scaleViewport = true; rfb.resizeSession = false;
rfb.addEventListener('disconnect', () => {document.getElementById('status').textContent = 'The login view has closed. Check Herald for your connection status.';});
'''
CSS = 'body{margin:0;background:#202b36;color:white;font:16px system-ui}p{padding:8px;margin:0}#screen{height:calc(100dvh - 80px);width:100%}'


def handler(*, root, websocket_port, stop, clock=time.monotonic, lifetime=900):
    started = clock()
    login_url = config.get('canvas.login_url', '').rstrip('/')
    host = urlsplit(login_url).netloc
    users = set(config.get('canvas.login_users', []))
    root = Path(root).resolve()

    class Handler(BaseHTTPRequestHandler):
        timeout = 10
        def log_message(self, *args):
            pass

        def permitted(self):
            return (not stop.is_set() and clock() - started < lifetime and bool(users) and
                    self.headers.get('Host') == host and self.headers.get('Tailscale-User-Login') in users)

        def reply(self, code, payload, content_type='text/plain; charset=utf-8'):
            if isinstance(payload, str):
                payload = payload.encode()
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            # noVNC decodes JPEG rectangles with Image(data:...). Blocking
            # those images leaves a connected, sized canvas entirely blank.
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if not self.permitted():
                self.reply(403, 'This private login view is unavailable or has expired.')
                return
            if self.path == '/websockify':
                if self.headers.get('Origin') != login_url or self.headers.get('Upgrade', '').lower() != 'websocket':
                    self.reply(403, 'Open the private Canvas login page.')
                    return
                self.proxy_websocket()
                return
            files = {'/': (PAGE, 'text/html; charset=utf-8'), '/viewer.js': (JS, 'text/javascript'), '/viewer.css': (CSS, 'text/css')}
            if self.path in files:
                self.reply(200, *files[self.path])
                return
            # noVNC modules only. Resolve before reading, including symlinks.
            if self.path.startswith(('/core/', '/vendor/')) and '?' not in self.path and '%' not in self.path:
                path = (root / self.path.lstrip('/')).resolve()
                if path.is_relative_to(root) and path.is_file() and path.suffix == '.js':
                    self.reply(200, path.read_bytes(), 'text/javascript')
                    return
            self.reply(404, 'Not found')

        def proxy_websocket(self):
            try:
                with socket.create_connection(('127.0.0.1', websocket_port), timeout=5) as upstream:
                    # Tailnet identity and browser cookies never reach websockify.
                    names = ('Upgrade', 'Connection', 'Sec-WebSocket-Key', 'Sec-WebSocket-Version', 'Sec-WebSocket-Protocol')
                    lines = ['GET /websockify HTTP/1.1', f'Host: 127.0.0.1:{websocket_port}']
                    lines += [f'{n}: {self.headers[n]}' for n in names if self.headers.get(n)]
                    upstream.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
                    upstream.settimeout(5)
                    self.connection.settimeout(5)
                    while self.permitted():
                        readable, _, _ = select.select([upstream, self.connection], [], [], .5)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            target = self.connection if source is upstream else upstream
                            target.sendall(data)
            except OSError:
                pass
            finally:
                self.close_connection = True

    return Handler


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def novnc_root(store):
    """noVNC's static files: the configured directory, a copy in the auth
    directory, or the distribution package (Debian and Ubuntu: `novnc`)."""
    candidates = [config.get('canvas.novnc_dir')] if config.get('canvas.novnc_dir') else []
    candidates += [str(store.directory / 'novnc'), '/usr/share/novnc']
    for candidate in candidates:
        if (Path(candidate) / 'core/rfb.js').is_file():
            return Path(candidate)
    raise CanvasError('Install noVNC before opening the Canvas login view: '
                      '`sudo apt install novnc`, or clone https://github.com/novnc/noVNC '
                      f'to {store.directory / "novnc"}')


def tailnet_route(on):
    """Publish the login view on the tailnet at `canvas.login_url`, or take it down.

    `tailscale serve` only ever proxies to the loopback listener, and only to
    devices on the user's own tailnet; the handler then checks the Tailscale
    identity header against `canvas.login_users`. Needs `tailscale set
    --operator=$USER` once, so a user service may change serve config.
    """
    url = config.get('canvas.login_url', '')
    if not url:
        return
    port = urlsplit(url).port or 443
    args = (['--bg', f'--https={port}', f"http://127.0.0.1:{int(config.get('canvas.login_port', 8793))}"]
            if on else [f'--https={port}', 'off'])
    result = subprocess.run(['tailscale', 'serve', *args], capture_output=True, text=True)
    if on and result.returncode != 0:
        raise CanvasError(f'tailscale serve failed: {(result.stderr or result.stdout).strip()[:200]}')


def serve():
    import os
    import signal
    store = SessionStore()
    root = novnc_root(store)
    # systemd stops the unit with SIGTERM at RuntimeMaxSec; turn that into an
    # exception so the finally below still takes the tailnet route down.
    def _stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _stop)
    display = config.get('canvas.login_display', ':77')
    vnc_port, ws_port = free_port(), free_port()
    processes = []
    stop = threading.Event()
    server = None
    thread = None
    try:
        # All backend listeners are loopback-only. The proxy is the sole
        # tailnet route and checks both identity and WebSocket origin.
        # Chromium's minimum outer width is 500px. Leave room for its
        # decorations so the phone view does not crop the login form.
        processes.append(subprocess.Popen(['Xtigervnc', display, '-geometry', '520x920', '-depth', '24',
                    '-SecurityTypes', 'None', '-localhost', 'yes', '-rfbport', str(vnc_port), '-nolisten', 'tcp', '-ac'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 10
        while not Path('/tmp/.X11-unix/X' + display.lstrip(':')).exists():
            if processes[0].poll() is not None or time.monotonic() > deadline:
                raise CanvasError('Canvas login display could not start')
            time.sleep(.1)
        if processes[0].poll() is not None:
            raise CanvasError('Canvas login display is already in use')
        processes.append(subprocess.Popen(['websockify', f'127.0.0.1:{ws_port}', f'127.0.0.1:{vnc_port}'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        server = ThreadingHTTPServer(('127.0.0.1', int(config.get('canvas.login_port', 8793))),
                    handler(root=root, websocket_port=ws_port, stop=stop))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tailnet_route(True)
        if login(store, display=display, stop=stop):
            stop.set()
            server.shutdown()
            from .sync import collect_api, collect_news
            collector.run('canvas_api', collect_api)
            collector.run('canvas_news', collect_news)
    finally:
        stop.set()
        tailnet_route(False)
        if server:
            server.shutdown()
            server.server_close()
        if thread:
            thread.join(timeout=3)
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
