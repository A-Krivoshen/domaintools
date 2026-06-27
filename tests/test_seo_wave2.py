import unittest

import app as app_module


class SeoWave2Tests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_developers_page_renders(self):
        html = self.client.get("/developers").get_data(as_text=True)
        self.assertIn("llms.txt", html)
        self.assertIn("openapi.json", html)
        self.assertIn("FAQPage", html)

    def test_about_page_renders(self):
        html = self.client.get("/about").get_data(as_text=True)
        self.assertIn("FAQPage", html)
        self.assertIn("krivoshein", html.lower())

    def test_public_openapi(self):
        resp = self.client.get("/openapi.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("openapi"), "3.1.0")
        self.assertTrue(any("domaintools.site" in s.get("url", "") for s in data.get("servers", [])))

    def test_ai_txt(self):
        resp = self.client.get("/ai.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"llms.txt", resp.data)

    def test_humans_txt(self):
        body = self.client.get("/humans.txt").get_data(as_text=True)
        self.assertIn("LLMs", body)

    def test_security_txt(self):
        body = self.client.get("/.well-known/security.txt").get_data(as_text=True)
        self.assertIn("security@domaintools.site", body)

    def test_home_has_faq_visible_and_schema(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("FAQPage", html)
        self.assertIn("accordion", html)

    def test_dns_landing_faq_visible(self):
        html = self.client.get("/lookup/dns/example.com").get_data(as_text=True)
        self.assertIn("FAQPage", html)
        self.assertIn("accordion", html)

    def test_hreflang_matches_canonical_base_on_dns_result(self):
        html = self.client.get("/dns?q=example.com").get_data(as_text=True)
        self.assertIn('hreflang="ru" href="https://domaintools.site/lookup/dns/example.com?lang=ru"', html)

    def test_site_checker_empty_has_jsonld(self):
        html = self.client.get("/site-checker").get_data(as_text=True)
        self.assertIn("WebApplication", html)
        self.assertIn("FAQPage", html)

    def test_site_checker_with_domain_is_noindex(self):
        html = self.client.get("/site-checker?domain=example.com").get_data(as_text=True)
        self.assertIn('name="robots" content="noindex, follow"', html)

    def test_robots_allows_agent_discovery(self):
        body = self.client.get("/robots.txt").get_data(as_text=True)
        self.assertIn("Allow: /openapi.json", body)
        self.assertIn("Allow: /developers", body)


if __name__ == "__main__":
    unittest.main()