"""OAuth grants and refreshes, isolated from ordinary Canvas writes."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

import requests
from herald import config


class AuthRequired(RuntimeError):
    pass


class CanvasError(RuntimeError):
    pass


def origin(value):
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.port:
        raise ValueError("Canvas requires an HTTPS origin without credentials or a port")
    if p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError("Canvas base URL must contain only the HTTPS origin")
    return f"https://{p.hostname.lower()}"


def checked_json(response, *, auth=False):
    # Neither a response body nor a requests exception is safe to log here.
    if response.status_code in (400, 401) and auth:
        raise AuthRequired("Canvas authorization expired or was revoked; reconnect Canvas")
    if not 200 <= response.status_code < 300:
        raise CanvasError(f"Canvas returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError:
        # Cookie-authenticated API responses carry Canvas's JSON guard.
        try:
            text = response.text
            if not text.startswith("while(1);"):
                raise ValueError
            return json.loads(text[len("while(1);"):])
        except (ValueError, TypeError):
            raise CanvasError("Canvas returned an invalid JSON response") from None


def http(session, method, url, **kwargs):
    try:
        return session.request(method, url, timeout=30, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise CanvasError("Canvas network request failed") from None


class TokenStore:
    def __init__(self, directory=None, base_url=None, session=None, clock=time.time):
        self.directory = Path(directory or config.get("canvas.auth_dir") or config.HOME / "canvas")
        self.base = origin(base_url or config.get("canvas.base_url"))
        self.session = session or requests.Session()
        self.clock = clock

    @contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        fd = os.open(self.directory / "oauth.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def read(self):
        try:
            record = json.loads((self.directory / "oauth.json").read_text())
        except (OSError, ValueError):
            raise AuthRequired("Canvas is not connected; open the private login page") from None
        if record.get("base_url") != self.base:
            raise AuthRequired("Canvas authorization belongs to a different institution")
        return record

    def save(self, record):
        fd, tmp = tempfile.mkstemp(prefix="oauth-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(record, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.directory / "oauth.json")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def grant(self, record, fields):
        response = http(self.session, "POST", self.base + "/login/oauth2/token", data={
            "client_id": record["client_id"], "client_secret": record["client_secret"],
            **fields,
            **({"redirect_uri": record["redirect_uri"]} if record.get("redirect_uri") else {}),
        })
        result = checked_json(response, auth=True)
        if not result.get("access_token") or result.get("token_type", "bearer").lower() != "bearer":
            raise CanvasError("Canvas did not issue a bearer token")
        record.update(access_token=result["access_token"],
                      expires_at=self.clock() + float(result.get("expires_in", 3600)),
                      refresh_token=result.get("refresh_token", record.get("refresh_token")),
                      user=result.get("user", record.get("user", {})))
        if not record.get("refresh_token"):
            raise CanvasError("Canvas did not issue a refresh token")
        return record

    def connect(self, qr_url):
        # Accept the app's QR deep link; never trust its domain as a destination.
        parsed = urlsplit(qr_url.strip())
        query = parse_qs(parsed.query)
        code = (query.get("code") or [None])[0]
        domain = (query.get("domain") or [parsed.hostname])[0]
        if (parsed.scheme != "https" or parsed.hostname != "sso.canvaslms.com" or
                parsed.path != "/canvas/login" or parsed.username or parsed.password or parsed.port or
                not code or not domain or len(query.get("code", [])) != 1 or len(query.get("domain", [])) != 1):
            raise ValueError("Choose the QR for Mobile Login from your Canvas account")
        if domain.lower().rstrip("/") != urlsplit(self.base).hostname:
            raise ValueError("The QR belongs to a different Canvas institution")
        if len(code) > 4096:
            raise ValueError("Invalid Canvas login code")
        with self.locked():
            response = http(self.session, "GET", "https://sso.canvaslms.com/api/v1/mobile_verify.json",
                            params={"domain": urlsplit(self.base).hostname},
                            headers={"Accept": "application/json", "User-Agent": "Herald Canvas integration"})
            mobile = checked_json(response)
            if not mobile.get("authorized") or not mobile.get("client_id") or not mobile.get("client_secret"):
                raise AuthRequired("Canvas mobile authorization is unavailable for this institution")
            if origin(mobile.get("base_url", self.base)) != self.base:
                raise CanvasError("Canvas mobile discovery returned a different institution")
            record = {"base_url": self.base, "client_id": mobile["client_id"],
                      "client_secret": mobile["client_secret"]}
            self.save(self.grant(record, {"grant_type": "authorization_code", "code": code}))
        return {"connected": True}

    def access_token(self, rejected=None):
        with self.locked():
            record = self.read()
            # A different process may already have refreshed the rejected token.
            refresh = (self.clock() >= record.get("expires_at", 0) - 90 or
                       rejected is not None and rejected == record.get("access_token"))
            if refresh:
                record = self.grant(record, {"grant_type": "refresh_token", "refresh_token": record["refresh_token"]})
                self.save(record)
            return record["access_token"]
