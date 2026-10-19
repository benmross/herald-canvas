"""Submit the exact approved file bytes; never forward a bearer token to storage."""
from __future__ import annotations

import hashlib
import pathlib
from urllib.parse import urlsplit
from herald import config, red, safety
from .auth import CanvasError, checked_json, http
from .session import SessionStore


def file_bytes(path):
    path = pathlib.Path(path).expanduser().resolve()
    settings = safety.load(str(config.ROOT), str(config.HOME))
    if safety.under(str(path), settings.secret_paths) or safety.under(str(path), settings.protected_paths):
        raise PermissionError("This file is protected and cannot be submitted through Canvas")
    roots = [pathlib.Path(p).expanduser().resolve() for p in config.get("canvas.upload_roots", [str(config.RAW)])]
    if not any(path.is_relative_to(root) for root in roots):
        raise PermissionError("Choose an attachment from your approved Canvas upload directory")
    if not path.is_file() or path.stat().st_size > 30_000_000:
        raise ValueError("Canvas attachments must be regular files under 30 MB")
    return path.read_bytes()


def prepare_file(path):
    content = file_bytes(path)
    return {"path": str(pathlib.Path(path).expanduser().resolve()),
            "name": pathlib.Path(path).name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


def validate_submission(p, client):
    if set(p) - {"course_id", "assignment_id", "files", "text", "url"}:
        raise ValueError("Unknown Canvas submission fields")
    if sum(bool(p.get(key)) for key in ("files", "text", "url")) != 1:
        raise ValueError("Choose files, text, or a URL for this submission")
    cid, aid = str(p["course_id"]), str(p["assignment_id"])
    if not cid.isdigit() or not aid.isdigit():
        raise ValueError("Use numeric Canvas course and assignment IDs")
    path = f"/api/v1/courses/{cid}/assignments/{aid}/submissions"
    client.gate("POST", path)
    assignment = client.get(f"/api/v1/courses/{cid}/assignments/{aid}")
    submission_type = "online_upload" if p.get("files") else "online_text_entry" if p.get("text") else "online_url"
    if submission_type not in assignment.get("submission_types", []):
        raise ValueError("This assignment does not accept the selected submission type")
    return path, assignment, submission_type


def upload(client, cid, aid, file, content):
    if red.acting() is None:
        raise PermissionError("Canvas uploads require a granted red.py approval")
    value, _ = client._request("POST", f"/api/v1/courses/{cid}/assignments/{aid}/submissions/self/files",
                              data={"name": file["name"], "size": len(content), "on_duplicate": "rename"})
    url = value.get("upload_url", "")
    parsed = urlsplit(url)
    allowed = set(config.get("canvas.upload_hosts", [])) | {urlsplit(client.base).hostname}
    if parsed.scheme != "https" or parsed.hostname not in allowed or parsed.username or parsed.password:
        raise CanvasError("Canvas selected a storage host that is not enabled for uploads")
    # No Authorization header and no redirects on the storage request.
    response = http(client.session, "POST", url, data=value["upload_params"],
                    files={"file": (file["name"], content)})
    if response.status_code in (301, 302, 303):
        target = response.headers.get("Location", "")
        p = urlsplit(target)
        if p.scheme != "https" or p.netloc != urlsplit(client.base).netloc or not p.path.startswith("/api/v1/files/"):
            raise CanvasError("Canvas upload completion pointed outside your institution")
        if isinstance(client.tokens, SessionStore):
            if p.query or p.fragment or p.username or p.password:
                raise CanvasError("Canvas upload completion returned an invalid API URL")
            response = client.tokens.request("GET", p.path)
        else:
            response = http(client.session, "GET", target,
                            headers={"Authorization": "Bearer " + client.tokens.access_token()})
    result = checked_json(response)
    if not isinstance(result.get("id"), int):
        raise CanvasError("Canvas did not confirm the uploaded file")
    return result["id"]


def submit(p, client):
    if red.acting() is None:
        raise PermissionError("Canvas submissions require a granted red.py approval")
    path, assignment, kind = validate_submission(p, client)
    submission = {"submission_type": kind}
    if kind == "online_upload":
        # Read and verify ALL files before the first outward write.
        files = []
        for item in p["files"]:
            content = file_bytes(item["path"])
            if hashlib.sha256(content).hexdigest() != item["sha256"] or len(content) != item["size"]:
                raise PermissionError("An attachment changed after approval; request a new approval")
            files.append((item, content))
        submission["file_ids"] = [upload(client, p["course_id"], p["assignment_id"], item, content) for item, content in files]
    elif kind == "online_text_entry":
        submission["body"] = p["text"]
    else:
        submission["url"] = p["url"]
    client.write("POST", path, {"submission": submission})
    return (f"You submitted {assignment['name']} in {client.course(p['course_id'])['name']}", client.base + path)
