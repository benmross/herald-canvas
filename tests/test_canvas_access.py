"""Exercise authorization failures, cross-course leaks and the write boundary."""
import http.client
import json
import pathlib
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import requests
from herald import db
from canvas_access.auth import AuthRequired, CanvasError, TokenStore
from canvas_access.client import Client
from canvas_access.files import prepare_file, submit, upload
from canvas_access.login import decode_qr, handler
from canvas_access.sync import collect_api, collect_news, require_login

BASE = "https://school.instructure.com"
QR = "https://sso.canvaslms.com/canvas/login?domain=school.instructure.com&code=test-code"
RESTRICTED = {"id": 132, "name": "Object-Oriented Programming II", "course_code": "202608-CMSC132-0101", "default_view": "wiki"}
NORMAL = {"id": 120, "name": "FIRE120", "course_code": "FIRE120", "default_view": "syllabus"}
POISON = "CMSC132 COURSE CONTENT MUST NEVER BE STORED"


def response(data, status=200, links=None):
    value = Mock(status_code=status, headers={}, links=links or {})
    value.json.return_value = data
    return value


# Which courses are metadata only is the user's setting. These tests pin it,
# so they hold on an install whose config names no course at all.
_real_get = None
_pin = None


def setUpModule():
    global _real_get, _pin
    from herald import config as _config
    _real_get = _config.get
    _pin = patch.object(_config, "get", side_effect=lambda key, default=None:
                        ["CMSC132"] if key == "canvas.metadata_only_courses" else _real_get(key, default))
    _pin.start()


def tearDownModule():
    _pin.stop()


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.session = Mock()
        self.tokens = TokenStore(self.tmp.name, BASE, session=self.session, clock=lambda: 1000)

    def seed(self, **overrides):
        record = {"base_url": BASE, "client_id": "test-id", "client_secret": "test-client-secret",
                  "access_token": "test-access", "refresh_token": "test-refresh", "expires_at": 2000}
        self.tokens.save(record | overrides)

    def test_qr_connection_never_persists_one_time_code(self):
        self.session.request.side_effect = [response({"authorized": True, "client_id": "test-id", "client_secret": "test-client-secret", "base_url": BASE + "/"}),
                                             response({"access_token": "test-access", "refresh_token": "test-refresh", "expires_in": 3600})]
        self.assertEqual(self.tokens.connect(QR), {"connected": True})
        stored = pathlib.Path(self.tmp.name, "oauth.json")
        self.assertNotIn("test-code", stored.read_text())
        self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
        self.assertEqual(pathlib.Path(self.tmp.name).stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.tokens.read()["expires_at"], 4600)

    def test_refresh_preserves_refresh_token_when_server_omits_it(self):
        self.seed(expires_at=999)
        self.session.request.return_value = response({"access_token": "test-new", "expires_in": 3600})
        self.assertEqual(self.tokens.access_token(), "test-new")
        self.assertEqual(self.tokens.read()["refresh_token"], "test-refresh")
        self.assertEqual(self.session.request.call_args.kwargs["data"]["grant_type"], "refresh_token")

    def test_concurrent_refresh_already_completed_avoids_second_grant(self):
        self.seed(access_token="new-test-access")
        self.assertEqual(self.tokens.access_token(rejected="old-test-access"), "new-test-access")
        self.session.request.assert_not_called()

    def test_revocation_is_actionable_without_response_body(self):
        self.seed(expires_at=0)
        self.session.request.return_value = response({"secret": "sensitive-response"}, 400)
        with self.assertRaisesRegex(AuthRequired, "revoked"):
            self.tokens.access_token()

    def test_missing_and_wrong_institution(self):
        with self.assertRaises(AuthRequired):
            self.tokens.access_token()
        self.seed(base_url="https://different.instructure.com")
        with self.assertRaises(AuthRequired):
            self.tokens.access_token()

    def test_invalid_qr_never_contacts_discovery(self):
        for value in (QR.replace("school.instructure", "other.instructure"), QR.replace("sso.canvaslms.com", "evil.example"),
                      QR + "&code=duplicate", "https://sso.canvaslms.com/canvas/login?code=123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.tokens.connect(value)
        self.session.request.assert_not_called()

    def test_discovery_cannot_change_token_destination(self):
        self.session.request.return_value = response({"authorized": True, "client_id": "test-id", "client_secret": "test-secret", "base_url": "https://evil.example"})
        with self.assertRaises(CanvasError):
            self.tokens.connect(QR)
        self.assertEqual(self.session.request.call_count, 1)

    def test_network_error_does_not_expose_token_request(self):
        self.seed(expires_at=0)
        self.session.request.side_effect = requests.RequestException("test-refresh test-client-secret")
        with self.assertRaises(CanvasError) as caught:
            self.tokens.access_token()
        self.assertNotIn("test-refresh", str(caught.exception))


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.tokens = Mock(base=BASE)
        self.tokens.access_token.return_value = "test-access"
        self.session = Mock()
        self.client = Client(self.tokens, session=self.session, sleep=lambda _: None)
        self.client.courses = {"132": RESTRICTED, "120": NORMAL}

    def test_restricted_assignment_strips_all_content_and_submission_answers(self):
        self.session.request.return_value = response([{"id": 1, "name": "Project 4", "description": POISON,
            "rubric": POISON, "submission": {"score": 95, "body": POISON, "attachments": [POISON], "submission_comments": [POISON]}}])
        result = self.client.get("/api/v1/courses/132/assignments", {"include[]": ["submission"]})
        self.assertEqual(result[0]["submission"]["score"], 95)
        self.assertNotIn(POISON, json.dumps(result))

    def test_restricted_course_never_exposes_syllabus(self):
        self.session.request.return_value = response(RESTRICTED | {"syllabus_body": POISON})
        result = self.client.get("/api/v1/courses/132")
        self.assertNotIn(POISON, json.dumps(result))

    def test_all_restricted_content_routes_and_writes_block_before_request(self):
        for suffix in ("/files", "/pages/news", "/front_page", "/modules", "/discussion_topics", "/enrollments"):
            with self.subTest(suffix=suffix), self.assertRaises(PermissionError):
                self.client.get("/api/v1/courses/132" + suffix)
        with self.assertRaises(PermissionError):
            self.client.gate("POST", "/api/v1/courses/132/assignments/1/submissions")
        with self.assertRaises(PermissionError):
            self.client.get("/api/v1/courses/132", {"include[]": ["syllabus_body"]})
        self.session.request.assert_not_called()

    def test_global_and_encoded_bypasses_are_closed(self):
        for path in ("/api/v1/files/12", "/api/v1/groups/1/files", "/api/v1/courses/120/../132/files",
                     "/api/v1/courses/120/%2e%2e/132/files", "/api/v1/courses/132?include=syllabus_body",
                     "/api/v1/courses/120/quizzes/1/submissions", "/api/v1/courses/120/external_tools/1"):
            with self.subTest(path=path), self.assertRaises(PermissionError):
                self.client.get(path)
        self.session.request.assert_not_called()

    def test_unknown_courses_fail_closed(self):
        with self.assertRaises(PermissionError):
            self.client.get("/api/v1/courses/999/files")
        self.session.request.assert_not_called()

    def test_cannot_submit_quiz_through_assignment_endpoint(self):
        self.session.request.return_value = response({"id": 1, "submission_types": ["online_quiz"]})
        with self.assertRaisesRegex(PermissionError, "quiz"):
            self.client.gate("POST", "/api/v1/courses/120/assignments/1/submissions")
        self.assertEqual(self.session.request.call_count, 1)
        self.assertEqual(self.session.request.call_args.args[0], "GET")

    def test_direct_writes_without_approval_never_contact_canvas(self):
        with self.assertRaises(PermissionError):
            self.client.write("POST", "/api/v1/conversations", {"body": "hello"})
        self.session.request.assert_not_called()

    def test_pagination_consumes_every_page(self):
        next_url = BASE + "/api/v1/courses/120/assignments?page=2"
        self.session.request.side_effect = [response([{"id": 1}], links={"next": {"url": next_url}}), response([{"id": 2}])]
        self.assertEqual(self.client.get("/api/v1/courses/120/assignments"), [{"id": 1}, {"id": 2}])

    def test_off_origin_pagination_never_receives_bearer(self):
        self.session.request.return_value = response([], links={"next": {"url": "https://evil.example/api/v1/courses/120/assignments?page=2"}})
        with self.assertRaises(CanvasError):
            self.client.get("/api/v1/courses/120/assignments")
        self.assertEqual(self.session.request.call_count, 1)

    def test_401_refreshes_once_and_replays_get(self):
        self.session.request.side_effect = [response({}, 401), response({"id": 5})]
        self.tokens.access_token.side_effect = ["test-old", "test-new"]
        self.assertEqual(self.client.get("/api/v1/users/self"), {"id": 5})
        self.tokens.access_token.assert_called_with(rejected="test-old")

    def test_storage_redirect_is_never_followed(self):
        self.session.request.return_value = response({}, 302)
        with self.assertRaises(CanvasError):
            self.client.get("/api/v1/courses/120/files")
        self.assertFalse(self.session.request.call_args.kwargs["allow_redirects"])

    def test_inbox_never_stores_unscoped_course_content(self):
        self.session.request.return_value = response([{"id": 4, "subject": "Course update", "last_message": POISON, "messages": [{"body": POISON}]}])
        self.assertNotIn(POISON, json.dumps(self.client.get("/api/v1/conversations")))

    def test_news_content_is_only_hashed(self):
        self.session.request.return_value = response({"body": POISON, "title": "News", "updated_at": "2026-10-08", "html_url": BASE + "/courses/132"})
        result = self.client.news_signature(RESTRICTED)
        self.assertEqual(len(result["hash"]), 64)
        self.assertNotIn(POISON, json.dumps(result))


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(db.SCHEMA)
        self.addCleanup(self.con.close)
        db.put_fact(self.con, "canvas", "assignment", external_id="feed:existing", title="Feed deadline", data={})

    def test_sync_preserves_feed_and_never_stores_restricted_text(self):
        real = Client(Mock(base=BASE), session=Mock())
        real.courses = {"132": RESTRICTED, "120": NORMAL}
        def fetch(path, params=None):
            if path.endswith("assignments"):
                return [{"id": 5, "name": "Project", "description": POISON, "submission": {"score": 20, "body": POISON}}]
            if path.endswith("discussion_topics"):
                return [{"id": 9, "title": "Announcement", "message": "Allowed FIRE news", "posted_at": db.now()}]
            return [{"id": 3, "subject": "Inbox", "last_message": POISON}]
        real._pages = fetch
        counts = collect_api(self.con, real)
        self.assertEqual(counts["courses"], 2)
        self.assertEqual(self.con.execute("SELECT count(*) FROM facts WHERE kind='assignment'").fetchone()[0], 1)
        self.assertNotIn(POISON, "".join(str(tuple(r)) for r in self.con.execute("SELECT * FROM facts")))

    def test_news_first_run_is_baseline_later_change_notifies_once(self):
        db.put_fact(self.con, "canvas", "course", external_id="132", data=RESTRICTED)
        client = Mock()
        client.news_signature.return_value = {"hash": "first", "updated_at": "now", "url": BASE + "/courses/132"}
        with patch("canvas_access.sync.notify.tell", return_value=True) as tell:
            collect_news(self.con, client)
            tell.assert_not_called()
            client.news_signature.return_value["hash"] = "second"
            self.assertEqual(collect_news(self.con, client)["news_changes"], 1)
            self.assertEqual(collect_news(self.con, client)["news_changes"], 0)
            tell.assert_called_once()

    def test_news_failed_delivery_retries_next_run(self):
        db.put_fact(self.con, "canvas", "course", external_id="132", data=RESTRICTED)
        client = Mock()
        client.news_signature.return_value = {"hash": "a", "url": BASE}
        collect_news(self.con, client)
        client.news_signature.return_value = {"hash": "b", "url": BASE}
        with patch("canvas_access.sync.notify.tell", side_effect=[False, True]) as tell:
            self.assertEqual(collect_news(self.con, client)["news_changes"], 0)
            self.assertEqual(collect_news(self.con, client)["news_changes"], 1)
            self.assertEqual(tell.call_count, 2)

    def test_revoked_auth_notifies_once_without_deleting_existing_facts(self):
        client = Mock()
        client.catalog.side_effect = AuthRequired("revoked")
        with patch("canvas_access.sync.notify.tell", return_value=True) as tell:
            collect_api(self.con, client)
            collect_api(self.con, client)
            tell.assert_called_once()
        self.assertEqual(self.con.execute("SELECT count(*) FROM facts WHERE kind='assignment'").fetchone()[0], 1)


class FileTests(unittest.TestCase):
    def test_changed_file_is_rejected_before_any_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "essay.txt")
            path.write_text("original work")
            with patch("canvas_access.files.config.get", side_effect=lambda key, default=None: [tmp] if key == "canvas.upload_roots" else default):
                file = prepare_file(path)
                path.write_text("changed work")
                p = {"course_id": "120", "assignment_id": "3", "files": [file]}
                client = Mock()
                client.get.return_value = {"name": "Homework", "submission_types": ["online_upload"]}
                with patch("canvas_access.files.red.acting", return_value=1), self.assertRaisesRegex(PermissionError, "changed"):
                    submit(p, client)
                client._request.assert_not_called()
                client.write.assert_not_called()

    def test_invalid_image_has_safe_error(self):
        with self.assertRaises(ValueError):
            decode_qr(b"not an image")

    def test_storage_request_has_no_bearer_and_changed_origin_is_refused(self):
        client = Mock(base=BASE)
        client._request.return_value = ({"upload_url": BASE + "/upload", "upload_params": {"key": "test-upload-key"}}, None)
        client.session.request.return_value = response({"id": 42})
        file = {"name": "work.txt"}
        with patch("canvas_access.files.red.acting", return_value=1):
            self.assertEqual(upload(client, "120", "1", file, b"work"), 42)
        self.assertNotIn("headers", client.session.request.call_args.kwargs)
        self.assertFalse(client.session.request.call_args.kwargs["allow_redirects"])
        client._request.return_value = ({"upload_url": "https://evil.example/upload", "upload_params": {}}, None)
        client.session.request.reset_mock()
        with patch("canvas_access.files.red.acting", return_value=1), self.assertRaises(CanvasError):
            upload(client, "120", "1", file, b"work")
        client.session.request.assert_not_called()


class LoginPageTests(unittest.TestCase):
    def test_tailnet_identity_origin_and_csrf_then_exact_code_exchange(self):
        from http.server import HTTPServer
        store = Mock()
        settings = {"canvas.login_users": ["test-user"], "canvas.login_url": "https://private.ts.net:8447"}
        with patch("canvas_access.login.config.get", side_effect=lambda key, default=None: settings.get(key, default)):
            server = HTTPServer(("127.0.0.1", 0), handler(store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def call(method, path, headers, body=None):
                    con = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                    try:
                        con.request(method, path, body=body, headers=headers)
                        res = con.getresponse()
                        return res.status, res.read().decode()
                    finally:
                        con.close()
                headers = {"Host": "private.ts.net:8447", "Tailscale-User-Login": "test-user"}
                self.assertEqual(call("GET", "/", {"Host": "private.ts.net:8447"})[0], 403)
                self.assertEqual(call("POST", "/connect", headers, b"invalid")[0], 403)
                code, page = call("GET", "/", headers)
                self.assertEqual(code, 200)
                import re
                token = re.search(r'name="csrf" value="([^"]+)"', page)[1]
                def multipart(token):
                    return (f'--test-boundary\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n{token}\r\n'
                            f'--test-boundary\r\nContent-Disposition: form-data; name="qr_url"\r\n\r\n{QR}\r\n--test-boundary--\r\n').encode()
                post_headers = headers | {"Origin": "https://private.ts.net:8447", "Content-Type": "multipart/form-data; boundary=test-boundary"}
                for origin in ("null", "https://evil.example"):
                    self.assertEqual(call("POST", "/connect", post_headers | {"Origin": origin}, multipart(token))[0], 403)
                store.connect.assert_not_called()
                self.assertEqual(call("POST", "/connect", post_headers, multipart("incorrect"))[0], 400)
                store.connect.assert_not_called()
                self.assertEqual(call("POST", "/connect", post_headers, multipart(token))[0], 200)
                store.connect.assert_called_once_with(QR)
                self.assertTrue(server.connected)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
