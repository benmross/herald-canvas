"""Deterministic Canvas collection. The calendar feed owns assignment facts."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from herald import collector, db, notify
from .auth import AuthRequired
from .client import Client, SUBMISSION_FIELDS, pick, restricted


def status(con, **fields):
    db.put_fact(con, "canvas", "status", external_id="api", ts=db.now(),
                title="Canvas connection", data=fields)


def require_login(con):
    row = con.execute("SELECT data FROM facts WHERE source='canvas' AND kind='status' AND external_id='api'").fetchone()
    prior = json.loads(row[0]) if row else {}
    told = prior.get("login_notified", False)
    if not told:
        told = notify.tell("Canvas needs you to reconnect", "Your Canvas authorization expired or was revoked. Ask for the private Canvas login page.")
    status(con, connected=False, login_required=True, login_notified=bool(told))
    return {"login_required": 1}


def collect_api(con, client=None):
    client = client or Client()
    try:
        courses = client.catalog()
        assignments = {}
        announcements = []
        until = datetime.now(timezone.utc).isoformat()
        for c in courses:
            cid = c["id"]
            assignments[str(cid)] = client.get(f"/api/v1/courses/{cid}/assignments", {"include[]": ["submission"]})
            if not restricted(c):
                # Course-scoped topics avoid a global context query bypass.
                topics = client.get(f"/api/v1/courses/{cid}/discussion_topics", {"only_announcements": True})
                announcements += [(c, t) for t in topics]
        conversations = client.get("/api/v1/conversations")
    except AuthRequired:
        return require_login(con)

    # Publish the complete snapshot only after all required requests succeeded.
    db.clear(con, "canvas", "course")
    db.clear(con, "canvas", "submission")
    db.clear(con, "canvas", "conversation")
    n = 0
    for c in courses:
        cid = c["id"]
        db.put_fact(con, "canvas", "course", external_id=str(cid), ts=db.now(),
                    title=c["name"], data={**c, "metadata_only": restricted(c)})
        for a in assignments[str(cid)]:
            submission = pick(a.get("submission") or {}, SUBMISSION_FIELDS)
            # No course text, attachments, submitted answers or rubrics, in any course.
            data = {"course_id": cid, "course_code": c.get("course_code"), "assignment_id": a["id"],
                    "due_at": a.get("due_at"), "points_possible": a.get("points_possible"),
                    "html_url": a.get("html_url"), "submission": submission}
            db.put_fact(con, "canvas", "submission", external_id=f"{cid}:{a['id']}",
                        ts=submission.get("graded_at") or submission.get("submitted_at") or db.now(),
                        title=a["name"], data=data)
            n += 1
    for c, topic in announcements:
        db.put_fact(con, "canvas", "announcement", external_id=f"{c['id']}:{topic['id']}",
                    ts=topic.get("posted_at") or db.now(), title=topic.get("title"), body=topic.get("message"),
                    data=pick(topic, ("id", "html_url", "posted_at", "last_reply_at")) | {"course_id": c["id"], "course_code": c.get("course_code")})
    for conversation in conversations:
        db.put_fact(con, "canvas", "conversation", external_id=str(conversation["id"]),
                    ts=conversation.get("last_message_at") or db.now(), title=conversation.get("subject"), data=conversation)
    status(con, connected=True, login_required=False, login_notified=False, last_sync=db.now())
    return {"courses": len(courses), "submissions": n, "announcements": len(announcements),
            "conversations": len(conversations), "_cursor": until}


def collect_news(con, client=None):
    client = client or Client()
    courses = [json.loads(r[0]) for r in con.execute("SELECT data FROM facts WHERE source='canvas' AND kind='course'")]
    changed = 0
    for course in courses:
        if not restricted(course):
            continue
        key = f"news:{course['id']}"
        row = con.execute("SELECT data FROM facts WHERE source='canvas' AND kind='status' AND external_id=?", (key,)).fetchone()
        old = json.loads(row[0]) if row else None
        try:
            signature = client.news_signature(course)
        except AuthRequired:
            return require_login(con)
        if old and old.get("hash") != signature["hash"]:
            label = course.get("course_code") or course.get("name") or "A restricted course"
            if not notify.tell(f"{label} News changed", f"Your {label} News page was updated.\n{signature['url']}"):
                continue  # Keep the old signature so the next run retries delivery.
            changed += 1
        db.put_fact(con, "canvas", "status", external_id=key, ts=db.now(),
                    title=f"{course.get('course_code') or course['id']} News fingerprint", data=signature)
    return {"news_changes": changed}
