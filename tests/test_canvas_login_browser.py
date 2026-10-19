"""Exercise native form navigation, which hand-written HTTP headers miss."""
from http.server import HTTPServer
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock, patch

from canvas_access.login import handler


class NativeFormTests(unittest.TestCase):
    def test_browser_supplies_origin_when_submitting_the_qr_form(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is not installed")
        with sync_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).exists():
                self.skipTest("Chromium is not installed")
            server = HTTPServer(("127.0.0.1", 0), handler(Mock()))
            origin = f"http://127.0.0.1:{server.server_port}"
            settings = {"canvas.login_url": origin, "canvas.login_users": ["test-user"]}
            store = Mock()
            with patch("canvas_access.login.config.get", side_effect=lambda key, default=None: settings.get(key, default)):
                server.RequestHandlerClass = handler(store)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                browser = playwright.chromium.launch()
                try:
                    page = browser.new_page(extra_http_headers={"Tailscale-User-Login": "test-user"})
                    page.goto(origin)
                    page.locator('[name="qr_url"]').fill("https://sso.canvaslms.com/canvas/login?domain=school.instructure.com&code=test-code")
                    with page.expect_navigation() as navigation:
                        page.get_by_role("button", name="Connect Canvas").click()
                    self.assertEqual(navigation.value.status, 200)
                    self.assertIn("Canvas is connected", page.locator("body").inner_text())
                    store.connect.assert_called_once()
                finally:
                    browser.close()
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
