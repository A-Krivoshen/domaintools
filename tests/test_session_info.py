import unittest
from unittest.mock import patch

import app as app_module


class SessionInfoTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def test_api_session_info_returns_payload(self):
        with patch.object(app_module, "_client_ip", return_value="8.8.8.8"):
            with patch.object(app_module, "_geo_from_ip_for_session", return_value={
                "city": "Moscow",
                "country": "Russia",
                "country_code": "RU",
            }):
                with patch.object(app_module, "_visitor_id", return_value="11111111-2222-4333-8444-555555555555"):
                    resp = self.client.get(
                        "/api/session/info",
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"},
                    )
        self.assertEqual(200, resp.status_code)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        self.assertEqual("8.8.8.8", data.get("ip"))
        self.assertIn("Moscow", data.get("location_en", ""))
        self.assertIn("Chrome 126", data.get("browser_en", ""))
        self.assertEqual("11111111…", data.get("session_id_short"))
        self.assertIn("no-store", resp.headers.get("Cache-Control", ""))

    def test_dns_page_has_collapsed_session_trigger(self):
        with patch.object(app_module.dns.resolver, "resolve", side_effect=Exception("no records")):
            with patch.object(app_module, "_evaluate_domain_availability", return_value=None):
                with patch.object(app_module, "_verify_form_recaptcha_if_needed", return_value=None):
                    with patch.object(app_module, "_tool_rate_limited", return_value=None):
                        with patch.object(app_module, "save_history", return_value=None):
                            html = self.client.get("/dns?q=example.com&types=A&lang=ru").get_data(as_text=True)
        self.assertIn("data-qa-session-info-toggle", html)
        self.assertIn("Информация о сессии", html)
        self.assertIn("data-qa-session-info-panel", html)
        self.assertIn("hidden", html)
        self.assertIn("Почему вы видите эти данные?", html)

    def test_short_user_agent_chrome_windows(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"
        ru, en = app_module._short_user_agent(ua)
        self.assertIn("Chrome 126", ru)
        self.assertIn("Windows", ru)
        self.assertIn("Chrome 126", en)


if __name__ == "__main__":
    unittest.main()