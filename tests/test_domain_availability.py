import unittest
from unittest.mock import patch

import app as app_module


class DomainAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_whois_result_indicates_taken_with_registrar(self):
        self.assertTrue(app_module._whois_result_indicates_taken({"registrar": "RU-CENTER"}))

    def test_whois_result_not_taken_when_empty(self):
        self.assertFalse(app_module._whois_result_indicates_taken({}))

    def test_dns_records_indicate_taken_with_ns(self):
        self.assertTrue(app_module._dns_records_indicate_taken({"NS": ["ns1.example.com"]}))

    def test_evaluate_available_from_sparse_whois(self):
        with self.app.test_request_context("/"):
            with patch.object(app_module, "_is_available_via_whois", return_value=True):
                result = app_module._evaluate_domain_availability(
                    "free-example-zz-12345.test",
                    whois_data={"domain_name": "free-example-zz-12345.test"},
                )
        self.assertIsNotNone(result)
        self.assertEqual(result.get("status"), "available")

    def test_evaluate_taken_from_whois_registrar(self):
        with self.app.test_request_context("/"):
            result = app_module._evaluate_domain_availability(
                "example.com",
                whois_data={"domain_name": "example.com", "registrar": "Test Registrar"},
            )
        self.assertEqual(result.get("status"), "taken")

    def test_evaluate_taken_from_dns_ns(self):
        with self.app.test_request_context("/"):
            result = app_module._evaluate_domain_availability(
                "example.com",
                dns_records={"NS": ["ns1.example.com"]},
            )
        self.assertEqual(result.get("status"), "taken")

    def test_available_domain_links_include_buy_url(self):
        items = [{"fqdn": "brand.shop", "available": True}]
        with self.app.test_request_context("/"):
            payload = app_module._domain_availability_from_search_items(items)
        self.assertEqual(len(payload.get("available_domain_links") or []), 1)
        self.assertIn("beget.com", (payload["available_domain_links"][0].get("buy_url") or ""))

    def test_generate_domain_name_ideas_from_seed(self):
        ideas = app_module._generate_domain_name_ideas("coffee shop")
        self.assertGreaterEqual(len(ideas), 3)
        self.assertTrue(any("coffee" in idea for idea in ideas))

    def test_domains_generator_renders_idea_chips(self):
        resp = self.client.get("/domains?idea=coffee+shop&generate=1")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("domain-name-generator", html)
        self.assertIn("coffee", html.lower())

    def test_domain_availability_from_search_items(self):
        items = [
            {"fqdn": "brand.ru", "available": False},
            {"fqdn": "brand.shop", "available": True},
            {"fqdn": "brand.site", "available": True},
        ]
        with self.app.test_request_context("/"):
            payload = app_module._domain_availability_from_search_items(items)
        self.assertEqual(payload.get("status"), "available")
        self.assertEqual(payload.get("available_count"), 2)
        self.assertEqual(payload.get("domain"), "brand.shop")

    def test_dns_page_renders_availability_banner_markers(self):
        availability = {
            "status": "available",
            "domain": "free.example",
            "display_domain": "free.example",
            "affiliate_domain": "free.example",
            "affiliate_buy_url": "https://beget.com/p754742/ru/domains/search/free.example",
            "affiliate_domain_search_url": "/domains?query=free",
            "zones_search_url": "/domains?query=free",
        }
        with patch.object(app_module, "_evaluate_domain_availability", return_value=availability):
            with patch.object(app_module.dns.resolver, "resolve", side_effect=Exception("no records")):
                with patch.object(app_module, "save_history", return_value=None):
                    with patch.object(app_module, "_track_domain_for_seo"):
                        resp = self.client.get("/dns?q=free.example&types=NS")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("domain-available-banner", html)
        self.assertIn("domain-sticky-cta", html)

    def test_availability_banner_renders_clickable_chip_links(self):
        availability = {
            "status": "available",
            "available_count": 2,
            "display_domain": "brand.shop",
            "affiliate_domain": "brand.shop",
            "affiliate_buy_url": "https://beget.com/p754742/ru/domains/search/brand.shop",
            "available_domain_links": [
                {"fqdn": "brand.shop", "display": "brand.shop", "buy_url": "https://beget.com/x/brand.shop"},
                {"fqdn": "brand.site", "display": "brand.site", "buy_url": "https://beget.com/x/brand.site"},
            ],
        }
        with self.app.test_request_context("/"):
            html = self.app.jinja_env.get_template("_domain_availability_banner.html").render(
                domain_availability=availability,
                tr=lambda ru, en: ru,
                get_locale=lambda: "ru",
            )
        self.assertIn('class="domain-available-banner__chip"', html)
        self.assertIn("https://beget.com/x/brand.site", html)


if __name__ == "__main__":
    unittest.main()