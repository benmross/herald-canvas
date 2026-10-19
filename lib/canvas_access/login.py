"""Short-lived, tailnet-only QR authorization page. No credentials in logs."""
from __future__ import annotations

import ctypes
import ctypes.util
from email import policy
from email.parser import BytesParser
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import secrets
import time
from urllib.parse import urlsplit

from PIL import Image
from herald import config, collector
from .auth import CanvasError, AuthRequired, TokenStore


def decode_qr(payload):
    library = ctypes.util.find_library("zbar")
    if not library:
        raise ValueError("QR decoding is unavailable; paste the decoded QR link instead")
    Image.MAX_IMAGE_PIXELS = 24_000_000
    try:
        image = Image.open(io.BytesIO(payload))
        image.load()
        if image.width * image.height > Image.MAX_IMAGE_PIXELS:
            raise ValueError
        image = image.convert("L")
    except Exception:
        raise ValueError("Choose a PNG or JPEG screenshot containing the Canvas QR") from None
    lib = ctypes.CDLL(library)
    signatures = {
        "zbar_image_scanner_create": (ctypes.c_void_p, []),
        "zbar_image_create": (ctypes.c_void_p, []),
        "zbar_image_scanner_set_config": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]),
        "zbar_image_set_format": (None, [ctypes.c_void_p, ctypes.c_ulong]),
        "zbar_image_set_size": (None, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]),
        "zbar_image_set_data": (None, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]),
        "zbar_scan_image": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p]),
        "zbar_image_first_symbol": (ctypes.c_void_p, [ctypes.c_void_p]),
        "zbar_symbol_get_type": (ctypes.c_int, [ctypes.c_void_p]),
        "zbar_symbol_get_data": (ctypes.c_char_p, [ctypes.c_void_p]),
        "zbar_symbol_next": (ctypes.c_void_p, [ctypes.c_void_p]),
        "zbar_image_destroy": (None, [ctypes.c_void_p]),
        "zbar_image_scanner_destroy": (None, [ctypes.c_void_p]),
    }
    for name, (result, args) in signatures.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    scanner, frame = lib.zbar_image_scanner_create(), lib.zbar_image_create()
    try:
        lib.zbar_image_scanner_set_config(scanner, 0, 0, 0)
        lib.zbar_image_scanner_set_config(scanner, 64, 0, 1)  # QR only
        lib.zbar_image_set_format(frame, int.from_bytes(b"Y800", "little"))
        lib.zbar_image_set_size(frame, image.width, image.height)
        data = ctypes.create_string_buffer(image.tobytes())
        lib.zbar_image_set_data(frame, data, image.width * image.height, None)
        lib.zbar_scan_image(scanner, frame)
        symbol = lib.zbar_image_first_symbol(frame)
        found = []
        while symbol:
            if lib.zbar_symbol_get_type(symbol) == 64:
                found.append(lib.zbar_symbol_get_data(symbol).decode("utf-8"))
            symbol = lib.zbar_symbol_next(symbol)
        if len(found) != 1:
            raise ValueError("Choose a screenshot with exactly one Canvas QR")
        return found[0]
    finally:
        lib.zbar_image_destroy(frame)
        lib.zbar_image_scanner_destroy(scanner)


def handler(store, *, clock=time.monotonic, lifetime=900, connected=None):
    started = clock()
    csrf = secrets.token_urlsafe(32)
    allowed_users = set(config.get("canvas.login_users", []))
    allowed_host = urlsplit(config.get("canvas.login_url", "")).netloc

    class Handler(BaseHTTPRequestHandler):
        timeout = 15

        def log_message(self, *args):
            pass

        def permitted(self):
            return (clock() - started < lifetime and bool(allowed_users) and
                    self.headers.get("Tailscale-User-Login") in allowed_users and
                    self.headers.get("Host") == allowed_host)

        def reply(self, code, text):
            payload = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            # Native form POSTs send Origin: null under no-referrer.
            # Keep the origin for our own form, without referring other sites.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if not self.permitted():
                self.reply(403, "This private login page is unavailable or has expired.")
                return
            if self.path != "/":
                self.reply(404, "Not found")
                return
            self.reply(200, f'''<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Canvas</title><style>body{{font:18px system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}input,button{{font:inherit;margin:.5rem 0;max-width:100%}}button{{padding:.6rem 1rem}}input[type=url]{{width:95%}}</style>
<h1>Connect Canvas</h1><p>In Canvas, open Account, then QR for Mobile Login. Take a screenshot of the QR and choose it here within 10 minutes.</p>
<p>You authorize Herald to use the Canvas Student OAuth flow for your account. This page closes after you connect or after 15 minutes.</p>
<form method="post" action="/connect" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{csrf}">
<label>QR screenshot<br><input type="file" name="image" accept="image/png,image/jpeg"></label>
<p>Or paste the decoded QR link:</p><input type="url" name="qr_url" autocomplete="off">
<br><button type="submit">Connect Canvas</button></form></html>''')

        def do_POST(self):
            if not self.permitted() or self.path != "/connect":
                self.reply(403, "This private login page is unavailable or has expired.")
                return
            if self.headers.get("Origin") != config.get("canvas.login_url", "").rstrip("/"):
                self.reply(403, "Open this form from your private Canvas login page.")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                content_type = self.headers.get("Content-Type", "")
                if not 0 < length <= 8_000_000 or not content_type.startswith("multipart/form-data;"):
                    raise ValueError("Choose a QR screenshot smaller than 8 MB")
                message = BytesParser(policy=policy.default).parsebytes(
                    ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + self.rfile.read(length))
                fields = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True)
                          for p in message.iter_parts()}
                if not hmac.compare_digest(fields.get("csrf", b"").decode(), csrf):
                    raise ValueError("This form expired; reload the private page")
                link = fields.get("qr_url", b"").decode().strip()
                if not link:
                    link = decode_qr(fields.get("image", b""))
                store.connect(link)
            except (ValueError, CanvasError, AuthRequired) as exc:
                from html import escape
                self.reply(400, escape(str(exc)) + '<p><a href="/">Try a fresh QR</a></p>')
                return
            self.server.connected = True
            self.reply(200, "<p>Canvas is connected. You can close this page. Herald will collect your courses and grades now.</p>")
            if connected:
                connected()

    return Handler


def serve():
    from .sync import collect_api, collect_news
    def connected():
        collector.run("canvas_api", collect_api)
        collector.run("canvas_news", collect_news)
    server = HTTPServer(("127.0.0.1", int(config.get("canvas.login_port", 8793))), handler(TokenStore(), connected=connected))
    server.timeout = 1
    server.connected = False
    deadline = time.monotonic() + 900
    try:
        while time.monotonic() < deadline and not server.connected:
            server.handle_request()
    finally:
        server.server_close()
