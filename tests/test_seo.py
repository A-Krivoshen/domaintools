import unittest

import app as app_module


class SeoTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_og_image_exists(self):
        resp = self.client.get("/static/og.png")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue((resp.data or b"")[:4] == b"\x89PNG")

    def test_sitemap_excludes_history(self):
        xml = self.client.get("/sitemap.xml").get_data(as_text=True)
        self.assertNotIn("/history/", xml)
        self.assertNotIn("/history</loc>", xml)

    def test_sitemap_has_prioritized_home(self):
        xml = self.client.get("/sitemap.xml").get_data(as_text=True)
        self.assertIn("<priority>1.0</priority>", xml)

    def test_history_has_noindex(self):
        html = self.client.get("/history").get_data(as_text=True)
        self.assertIn('name="robots" content="noindex, follow"', html)

    def test_jsonld_uses_canonical_site_root(self):
        html = self.client.get("/", base_url="https://python.domaintools.site").get_data(as_text=True)
        self.assertIn("https://domaintools.site/", html)
        self.assertIn('rel="canonical" href="https://domaintools.site/', html)

    def test_dns_h1_is_keyword_rich(self):
        html = self.client.get("/dns").get_data(as_text=True)
        self.assertIn("DNS", html)
        self.assertTrue("lookup" in html.lower() or "запис" in html.lower() or "Проверка" in html)

    def test_lookup_whois_route_is_not_shadowed(self):
        resp = self.client.get("/lookup/whois/example.com")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("lookup-landing", html)
        self.assertIn("WHOIS for example.com", html)
        self.assertRegex(
            html,
            r'tool-page-header__title[^>]*>[\s\S]*?example\.com[\s\S]*?</h1>',
        )
        self.assertNotRegex(
            html,
            r'tool-page-header__title[^>]*>[\s\S]*?whois/example\.com[\s\S]*?</h1>',
        )

    def test_lookup_dns_landing_renders(self):
        resp = self.client.get("/lookup/dns/example.com")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("DNS", html)
        self.assertIn("lookup-landing", html)

    def test_zone_landing_renders_for_ru(self):
        resp = self.client.get("/zones/ru")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn(".ru", html)

    def test_sitemap_includes_zone_pages(self):
        xml = self.client.get("/sitemap.xml").get_data(as_text=True)
        self.assertIn("/zones/ru", xml)


if __name__ == "__main__":
    unittest.main()