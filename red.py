"""The same exact-payload tap for Canvas actions that Herald uses for mail."""
import json
from canvas_access.client import Client


def validate(p, client):
    if set(p) != {"method", "path", "data"} or not isinstance(p["data"], dict):
        raise ValueError("Canvas actions need exactly method, path and data")
    method = p["method"].upper()
    if method == "GET":
        raise ValueError("GET is a read, not an action")
    client.gate(method, p["path"])
    return method


def render(p):
    client = Client()
    method = validate(p, client)
    lines = ["Carry out this Canvas action?", "", method + " " + client.base + p["path"]]
    import re
    match = re.match(r"/api/v1/courses/(\d+)", p["path"])
    if match:
        lines += ["Course: " + client.course(match[1])["name"]]
    lines += ["", json.dumps(p["data"], indent=2, ensure_ascii=False)]
    text = "\n".join(lines)
    # Telegram's limit must never silently truncate an approval's exact body.
    if len(text.encode("utf-16-le")) // 2 > 3500:
        raise ValueError("This payload exceeds a complete Telegram approval; shorten it")
    return text


def perform(p):
    client = Client()
    method = validate(p, client)
    client.write(method, p["path"], p["data"])
    return ("You approved " + method + " " + p["path"], client.base + p["path"])


KINDS = {"canvas.request": (render, perform)}


def render_submit(p):
    from canvas_access.files import validate_submission
    client = Client()
    path, assignment, kind = validate_submission(p, client)
    lines = ["Submit this work to Canvas?", "", "Course: " + client.course(p["course_id"])["name"],
             "Assignment: " + assignment["name"], "Destination: " + client.base + path, ""]
    if kind == "online_upload":
        for item in p["files"]:
            lines += [item["name"] + f" ({item['size']} bytes)", "SHA256: " + item["sha256"]]
    else:
        lines.append(p.get("text") or p["url"])
    text = "\n".join(lines)
    if len(text.encode("utf-16-le")) // 2 > 3500:
        raise ValueError("This submission exceeds a complete Telegram approval; shorten it")
    return text


def perform_submit(p):
    from canvas_access.files import submit
    return submit(p, Client())


KINDS["canvas.submit"] = (render_submit, perform_submit)
