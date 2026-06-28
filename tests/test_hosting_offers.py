import unittest

import app as app_module


class HostingOffersTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_hosting_offers_returns_featured_providers(self):
        offers = app_module._hosting_offers(featured_only=True)
        ids = [o["id"] for o in offers]
        self.assertEqual(ids, ["firstvds", "beget", "sweb"])
        self.assertIn("krivoshein.site/firstvds", offers[0]["url"])

    def test_hosting_all_offers_include_ultravds(self):
        offers = app_module._hosting_offers()
        ultravds = next((o for o in offers if o["id"] == "ultravds"), None)
        self.assertIsNotNone(ultravds)
        self.assertIn("ultravds", ultravds["url"])
        self.assertEqual(249, ultravds["price_rub"])
        self.assertIn("Windows VPS", ultravds["desc"])

    def test_yandex_cloud_offer_is_premium_enterprise(self):
        offers = app_module._hosting_offers()
        yc = next((o for o in offers if o["id"] == "yandexcloud"), None)
        self.assertIsNotNone(yc)
        self.assertEqual("enterprise", yc["badge"])
        self.assertEqual("Enterprise", yc["badge_text"])
        self.assertEqual("#ea580c", yc["accent"])

    def test_hosting_page_providers_grid_layout(self):
        html = self.client.get("/hosting?lang=ru").get_data(as_text=True)
        self.assertIn("hosting-offers-grid--providers", html)
        self.assertIn("hosting-offer-card--premium", html)
        self.assertIn("Windows VPS", html)

    def test_hosting_featured_offers_exclude_ultravds(self):
        offers = app_module._hosting_offers(featured_only=True)
        self.assertNotIn("ultravds", [o["id"] for o in offers])

    def test_dns_suggests_hosting_for_taken_domain_without_connect_records(self):
        records = {"NS": ["ns1.example.com."]}
        availability = {"status": "taken"}
        self.assertTrue(app_module._dns_suggests_hosting(records, availability))

    def test_dns_suggests_hosting_false_when_a_record_exists(self):
        records = {"A": ["93.184.216.34"]}
        availability = {"status": "taken"}
        self.assertFalse(app_module._dns_suggests_hosting(records, availability))

    def test_hosting_page_renders_launch_path_and_providers(self):
        resp = self.client.get("/hosting?lang=ru")
        self.assertEqual(200, resp.status_code)
        html = resp.get_data(as_text=True)
        self.assertIn("launch-path", html)
        self.assertIn("FirstVDS", html)
        self.assertIn("data-ref-track", html)
        self.assertIn("vps.krivoshein.site", html)

    def test_home_renders_hosting_funnel(self):
        html = self.client.get("/?lang=ru").get_data(as_text=True)
        self.assertIn("launch-path", html)
        self.assertIn("hosting-footer-strip", html)

    def test_sitemap_includes_hosting(self):
        xml = self.client.get("/sitemap.xml").get_data(as_text=True)
        self.assertIn("/hosting", xml)

    def test_sweb_verification_file_served_from_site_root(self):
        resp = self.client.get("/7508a901e87b92a2d6baedf07a004316.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.get_data(as_text=True).strip(),
            "7508a901e87b92a2d6baedf07a004316",
        )
        self.assertIn("text/plain", resp.content_type)

    def test_ref_click_tracking_accepts_hosting(self):
        resp = self.client.post(
            "/track/ref-click",
            json={"type": "hosting", "id": "firstvds", "placement": "test", "locale": "ru"},
        )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.get_json().get("ok"))