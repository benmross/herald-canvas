"""API transport and the course boundary, shared by reads and approved writes."""
from __future__ import annotations

import copy
import re
import time
from urllib.parse import urlsplit

import requests
from herald import config, red
from .auth import AuthRequired, CanvasError, TokenStore, checked_json, http
from .session import SessionStore


COURSE_FIELDS = ("id", "name", "course_code", "workflow_state", "default_view", "enrollments", "html_url")
ASSIGNMENT_FIELDS = ("id", "name", "due_at", "unlock_at", "lock_at", "points_possible", "published",
                     "submission_types", "html_url", "quiz_id", "is_quiz_assignment", "updated_at")
SUBMISSION_FIELDS = ("id", "assignment_id", "user_id", "submitted_at", "graded_at", "score", "grade",
                     "workflow_state", "late", "missing", "attempt", "excused", "posted_at")


def pick(item, fields):
    return {k: item[k] for k in fields if k in item}


def course_metadata(course):
    data = pick(course, COURSE_FIELDS)
    data["enrollments"] = [pick(e, ("type", "enrollment_state", "computed_current_score",
                                   "computed_final_score", "computed_current_grade", "computed_final_grade"))
                           for e in course.get("enrollments", [])]
    return data


def code_pattern(code):
    """"CMSC132" also matches "CMSC 132", "CMSC-132" and "202608-CMSC132-0101"."""
    m = re.fullmatch(r"\s*([A-Za-z]+)\s*[-_ ]?\s*(\d+[A-Za-z]?)\s*", str(code))
    if not m:
        return re.compile(rf"\b{re.escape(str(code).strip())}\b", re.I)
    return re.compile(rf"\b{m[1]}\s*[-_]?\s*{m[2]}\b", re.I)


def restricted(course):
    """Whether a course is metadata only: names, dates, grades and submission
    state, and never its text, files, rubrics, answers or messages.

    Which courses are restricted is the user's own rule (usually a syllabus
    banning AI tools from course materials), so it is read from
    `canvas.metadata_only_courses` (course codes) and
    `canvas.metadata_only_course_ids`, never written here.
    """
    labels = " ".join(str(course.get(k, "")) for k in ("name", "course_code"))
    codes = config.get("canvas.metadata_only_courses", []) or []
    return any(code_pattern(c).search(labels) for c in codes) or str(course["id"]) in {
        str(i) for i in config.get("canvas.metadata_only_course_ids", []) or []}


def canonical(path):
    # Encoded slashes, query strings and dot segments cannot evade the gate.
    if not isinstance(path, str) or not path.startswith("/api/v1/") or any(c in path for c in ("?", "#", "\\", "%")):
        raise PermissionError("Use a plain Canvas /api/v1/ path and separate query parameters")
    if any(part in (".", "..", "") for part in path.split("/")[1:]):
        raise PermissionError("Invalid Canvas API path")
    return path.rstrip("/")


class Client:
    def __init__(self, tokens=None, session=None, sleep=time.sleep):
        self.tokens = tokens or SessionStore()
        self.base = self.tokens.base
        self.session = session or requests.Session()
        self.sleep = sleep
        self.courses = None

    def _request(self, method, path, *, params=None, data=None):
        if isinstance(self.tokens, SessionStore):
            try:
                response = self.tokens.request(method, path, params=params, json=data)
            except AuthRequired:
                if method != "GET":
                    raise  # Never replay an approved write automatically.
                from .browser import login
                login(self.tokens, lifetime=45)
                response = self.tokens.request(method, path, params=params)
            if method == "GET":
                for _ in range(2):
                    if response.status_code != 429:
                        break
                    try:
                        delay = min(max(float(response.headers.get("Retry-After", "2")), 1), 20)
                    except ValueError:
                        delay = 2
                    self.sleep(delay)
                    response = self.tokens.request(method, path, params=params)
            if response.status_code == 204:
                return None, response
            return checked_json(response), response
        token = self.tokens.access_token()
        url = self.base + path
        response = http(self.session, method, url, params=params, json=data,
                        headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        if response.status_code == 401:
            token = self.tokens.access_token(rejected=token)
            response = http(self.session, method, url, params=params, json=data,
                            headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        if method == "GET":
            for _ in range(2):
                if response.status_code != 429:
                    break
                try:
                    delay = min(max(float(response.headers.get("Retry-After", "2")), 1), 20)
                except ValueError:
                    delay = 2
                self.sleep(delay)
                response = http(self.session, method, url, params=params,
                                headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        if response.status_code == 401:
            raise AuthRequired("Canvas authorization was rejected; reconnect Canvas")
        if response.status_code == 204:
            return None, response
        return checked_json(response), response

    def _pages(self, path, params=None):
        params = {"per_page": 100, **(params or {})}
        rows = []
        seen = set()
        for _ in range(100):
            value, response = self._request("GET", path, params=params)
            if not isinstance(value, list):
                return value
            rows.extend(value)
            link = response.links.get("next", {}).get("url")
            if not link:
                return rows
            p = urlsplit(link)
            if p.scheme != "https" or p.netloc != urlsplit(self.base).netloc or p.username or p.password:
                raise CanvasError("Canvas pagination pointed outside your institution")
            if p.path != path or link in seen:
                raise CanvasError("Canvas pagination returned an unexpected or repeated path")
            seen.add(link)
            from urllib.parse import parse_qs
            params = parse_qs(p.query)
        raise CanvasError("Canvas pagination exceeded the page limit")

    def catalog(self):
        if self.courses is None:
            result = self._pages("/api/v1/courses", {"enrollment_type": "student", "enrollment_state": "active",
                                                    "include[]": ["total_scores"]})
            self.courses = {str(c["id"]): course_metadata(c) for c in result if "id" in c}
        return list(self.courses.values())

    def course(self, cid):
        self.catalog()
        if str(cid) not in self.courses:
            # Fail closed for courses outside the active student catalog.
            raise PermissionError("This course is outside your active student courses")
        return self.courses[str(cid)]

    def gate(self, method, path, params=None):
        path = canonical(path)
        if method not in ("GET", "POST", "PUT", "PATCH"):
            raise PermissionError("Canvas deletion is unavailable; archive instead")
        if re.search(r"quiz|assessment|question|bank|lti|external_tool", path, re.I):
            raise PermissionError("Canvas quiz attempts and external graded tools are blocked")
        if any(k in (params or {}) for k in ("as_user_id", "user_id")):
            raise PermissionError("Canvas impersonation is unavailable")
        match = re.match(r"/api/v1/courses/(\d+)(?:/|$)", path)
        if match:
            course = self.course(match[1])
            if restricted(course):
                suffix = path[match.end(1):]
                allowed = suffix == "" or bool(re.fullmatch(r"/assignments(?:/\d+(?:/submissions/self)?)?", suffix))
                if method != "GET" or not allowed:
                    raise PermissionError("This course is metadata only: no course materials or writes")
                if params and set(params) - {"per_page", "page", "include[]"}:
                    raise PermissionError("A metadata-only course accepts only pagination parameters")
                if params and params.get("include[]") not in (None, ["submission"]):
                    raise PermissionError("Content includes are blocked for a metadata-only course")
            if method != "GET" and re.search(r"/assignments/\d+/submissions", path):
                aid = re.search(r"/assignments/(\d+)", path)[1]
                item, _ = self._request("GET", f"/api/v1/courses/{course['id']}/assignments/{aid}")
                if item.get("quiz_id") or item.get("is_quiz_assignment") or "online_quiz" in item.get("submission_types", []):
                    raise PermissionError("Submitting a Canvas quiz is blocked")
            return path
        if path == "/api/v1/courses" and method == "GET":
            if params:
                raise PermissionError("Read the sanitized course catalog without custom includes")
            return path
        if re.fullmatch(r"/api/v1/users/self(?:/profile)?", path) and method == "GET":
            return path
        if re.fullmatch(r"/api/v1/conversations(?:/\d+(?:/add_message)?)?", path):
            return path
        # Global files, groups, GraphQL and search can contain restricted material.
        raise PermissionError("Use a course-scoped Canvas endpoint")

    def sanitize(self, path, result):
        course_match = re.match(r"/api/v1/courses/(\d+)(?:/|$)", path)
        if course_match and restricted(self.course(course_match[1])):
            if path == f"/api/v1/courses/{course_match[1]}":
                return course_metadata(result)
            def metadata(item):
                if "/submissions/" in path:
                    return pick(item, SUBMISSION_FIELDS)
                value = pick(item, ASSIGNMENT_FIELDS)
                if item.get("submission"):
                    value["submission"] = pick(item["submission"], SUBMISSION_FIELDS)
                return value
            return [metadata(i) for i in result] if isinstance(result, list) else metadata(result)
        if path.startswith("/api/v1/conversations"):
            def safe_conversation(item):
                # Only preserve headers. Inbox messages may quote a restricted course's
                # materials even when Canvas omits a course context.
                return pick(item, ("id", "subject", "workflow_state", "last_message_at", "last_authored_message_at",
                                   "message_count", "participants", "context_code"))
            return [safe_conversation(i) for i in result] if isinstance(result, list) else safe_conversation(result)
        return result

    def get(self, path, params=None):
        self.gate("GET", path, params)
        if path == "/api/v1/courses":
            return self.catalog()
        return self.sanitize(path, self._pages(path, params))

    def write(self, method, path, data):
        if red.acting() is None:
            raise PermissionError("Canvas writes require a granted red.py approval")
        method = method.upper()
        self.gate(method, path)
        if method == "GET":
            raise PermissionError("Use the read command for GET requests")
        def impersonates(value):
            if isinstance(value, dict):
                return any(k in ("as_user_id", "user_id") or k.startswith("as_user_id[") or impersonates(v)
                           for k, v in value.items())
            return isinstance(value, list) and any(impersonates(v) for v in value)
        if not isinstance(data, dict) or impersonates(data):
            raise PermissionError("Invalid Canvas write payload")
        if path.startswith("/api/v1/conversations"):
            context = data.get("context_code") or data.get("conversation", {}).get("context_code")
            if context and context.startswith("course_") and restricted(self.course(context[7:])):
                raise PermissionError("Messages from a metadata-only course are unavailable")
            match = re.match(r"/api/v1/conversations/(\d+)", path)
            if match:
                conversation, _ = self._request("GET", "/api/v1/conversations/" + match[1])
                context = conversation.get("context_code", "")
                if context.startswith("course_") and restricted(self.course(context[7:])):
                    raise PermissionError("Messages from a metadata-only course are unavailable")
        value, _ = self._request(method, path, data=copy.deepcopy(data))
        return self.sanitize(path, value) if value is not None else None

    def news_signature(self, course):
        # The only restricted-content read: hash in Python, discard immediately.
        # Neither the response body nor the syllabus enters any model or ledger.
        from hashlib import sha256
        cid = course["id"]
        view = course.get("default_view")
        if view == "wiki":
            page, _ = self._request("GET", f"/api/v1/courses/{cid}/front_page")
            body = page.get("body", "") + "\n" + page.get("title", "") + "\n" + str(page.get("updated_at", ""))
            timestamp = page.get("updated_at")
            url = page.get("html_url", f"{self.base}/courses/{cid}")
        elif view == "feed":
            topics = self._pages(f"/api/v1/courses/{cid}/discussion_topics", {"only_announcements": True})
            import json
            body = json.dumps([pick(t, ("id", "title", "message", "posted_at", "updated_at"))
                               for t in sorted(topics, key=lambda t: t["id"])], sort_keys=True)
            timestamp = max((t.get("updated_at") or t.get("posted_at") or "" for t in topics), default="")
            url = f"{self.base}/courses/{cid}/announcements"
        else:
            details, _ = self._request("GET", f"/api/v1/courses/{cid}", params={"include[]": "syllabus_body"})
            body = details.get("syllabus_body", "")
            timestamp = None
            url = f"{self.base}/courses/{cid}"
        return {"hash": sha256(body.encode()).hexdigest(), "updated_at": timestamp, "url": url}
