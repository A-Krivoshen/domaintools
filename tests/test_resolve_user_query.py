import unittest
from unittest import mock

import app as app_module


class ResolveUserQueryTests(unittest.TestCase):
    def setUp(self):
        self.ctx = app_module.app.test_request_context("/")
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_fqdn_routes_to_check_from_home(self):
        resolved = app_module.resolve_user_query("krivoshein.site", context="home")
        self.assertEqual(resolved.get("kind"), "fqdn")
        self.assertIn("/check/krivoshein.site", str(resolved.get("default_url")))

    def test_idn_fqdn_preserves_unicode_display(self):
        from urllib.parse import unquote

        resolved = app_module.resolve_user_query("агнкс.рф", context="home")
        self.assertEqual(resolved.get("kind"), "fqdn")
        self.assertEqual(resolved.get("display"), "агнкс.рф")
        self.assertIn("/check/", str(resolved.get("default_url")))
        self.assertIn("агнкс.рф", unquote(str(resolved.get("default_url"))))

    def test_label_routes_to_domains(self):
        resolved = app_module.resolve_user_query("mybrand", context="home")
        self.assertEqual(resolved.get("kind"), "label")
        self.assertIn("/domains", str(resolved.get("default_url")))

    def test_cyrillic_label_on_home_expands_to_rf_check(self):
        resolved = app_module.resolve_user_query("агнкс", context="home")
        self.assertEqual(resolved.get("kind"), "fqdn")
        self.assertEqual(resolved.get("display"), "агнкс.рф")
        self.assertIn("/check/", str(resolved.get("default_url")))

    def test_check_page_prefills_domain_in_search_field(self):
        from urllib.parse import quote

        with mock.patch.object(app_module, "_report_cache_get", return_value=None):
            with mock.patch.object(app_module, "_is_crawler_request", return_value=True):
                resp = app_module.app.test_client().get("/check/" + quote("агнкс.рф"))
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('value="агнкс.рф"', html)
        self.assertIn('data-prefill="агнкс.рф"', html)

    def test_ideas_routes_to_domains(self):
        resolved = app_module.resolve_user_query("coffee shop", context="home")
        self.assertEqual(resolved.get("kind"), "ideas")

    def test_ip_routes_to_geo(self):
        resolved = app_module.resolve_user_query("8.8.8.8", context="home")
        self.assertEqual(resolved.get("kind"), "ip")
        self.assertIn("/geo", str(resolved.get("default_url")))

    def test_email_extracts_domain(self):
        resolved = app_module.resolve_user_query("admin@агнкс.рф", context="home")
        self.assertEqual(resolved.get("kind"), "fqdn")
        self.assertEqual(resolved.get("display"), "агнкс.рф")

    def test_whois_context_for_fqdn(self):
        resolved = app_module.resolve_user_query("example.com", context="whois")
        self.assertIn("/whois", str(resolved.get("default_url")))

    def test_dns_context_for_fqdn(self):
        resolved = app_module.resolve_user_query("example.com", context="dns")
        self.assertIn("/dns", str(resolved.get("default_url")))

    def test_api_resolve_endpoint(self):
        resp = app_module.app.test_client().get("/api/resolve?q=mybrand&context=home")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("kind"), "label")
        self.assertIn("intent_label", data)

    def test_api_resolve_respects_lang_ru_on_domains_context(self):
        resp = app_module.app.test_client().get("/api/resolve?q=mybrand&context=domains&lang=ru")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("action_label"), "Проверить домены")
        self.assertIn("Проверка доступности", data.get("intent_label", ""))

    def test_api_resolve_respects_lang_en_on_domains_context(self):
        resp = app_module.app.test_client().get("/api/resolve?q=mybrand&context=domains&lang=en")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("action_label"), "Check domains")
        self.assertIn("Search availability", data.get("intent_label", ""))

    def test_smart_go_redirects_label(self):
        resp = app_module.app.test_client().get("/go?q=mybrand", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/domains", resp.headers.get("Location", ""))

    def test_check_query_redirects_fqdn(self):
        from urllib.parse import quote

        resp = app_module.app.test_client().get("/check?q=" + quote("агнкс.рф"), follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(quote("агнкс.рф"), resp.headers.get("Location", ""))

    def test_home_post_label_redirects_domains(self):
        with mock.patch.object(app_module, "_verify_form_recaptcha_if_needed", return_value=None):
            resp = app_module.app.test_client().post("/report", data={"q": "mybrand"}, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/domains", resp.headers.get("Location", ""))


if __name__ == "__main__":
    unittest.main()