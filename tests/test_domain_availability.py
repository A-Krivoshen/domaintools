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

    def test_domains_unified_search_generates_ideas_for_description(self):
        resp = self.client.get("/domains?query=coffee+shop")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("domain-idea-suggestions", html)
        self.assertIn("coffee", html.lower())

    def test_default_tlds_ru_audience(self):
        with self.app.test_request_context("/domains", headers={"CF-IPCountry": "RU"}):
            groups, _ = app_module._build_tld_groups(
                ["ru", "рф", "com", "net", "io"],
                [],
            )
            tlds = app_module._default_tlds_for_audience(
                ["ru", "рф", "com", "net", "io"],
                groups,
            )
        self.assertIn("ru", tlds)
        self.assertIn("рф", tlds)
        self.assertNotIn("com", tlds)

    def test_default_tlds_global_audience(self):
        with self.app.test_request_context("/domains", headers={"CF-IPCountry": "US"}):
            groups, _ = app_module._build_tld_groups(
                ["ru", "рф", "com", "net", "io", "app"],
                [],
            )
            tlds = app_module._default_tlds_for_audience(
                ["ru", "рф", "com", "net", "io", "app"],
                groups,
            )
        self.assertIn("com", tlds)
        self.assertIn("io", tlds)
        self.assertNotIn("ru", tlds)
        self.assertNotIn("рф", tlds)

    def test_classify_domain_search_query(self):
        tlds = ["ru", "рф", "site", "com", "tatar"]
        self.assertEqual(
            app_module._classify_domain_search_query("coffee shop", tlds).get("mode"),
            "ideas",
        )
        self.assertEqual(
            app_module._classify_domain_search_query("mybrand", tlds).get("mode"),
            "label",
        )
        fqdn = app_module._classify_domain_search_query("krivoshein.site", tlds)
        self.assertEqual(fqdn.get("mode"), "fqdn")
        self.assertEqual(fqdn.get("tld"), "site")
        self.assertEqual(fqdn.get("label"), "krivoshein")
        idn = app_module._classify_domain_search_query("агнкс.рф", tlds)
        self.assertEqual(idn.get("mode"), "fqdn")
        self.assertEqual(idn.get("tld"), "рф")
        self.assertEqual(idn.get("label"), "агнкс")
        self.assertEqual(idn.get("display_fqdn"), "агнкс.рф")
        puny = app_module._classify_domain_search_query("xn--80agvlv.xn--p1ai", tlds)
        self.assertEqual(puny.get("mode"), "fqdn")
        self.assertEqual(puny.get("tld"), "рф")
        self.assertEqual(puny.get("label"), "агнкс")
        www = app_module._classify_domain_search_query("www.агнкс.рф", tlds)
        self.assertEqual(www.get("label"), "агнкс")
        self.assertEqual(www.get("tld"), "рф")

    def test_full_domain_search_checks_only_entered_zone(self):
        with patch.object(app_module, "_check_candidates") as check_mock:
            check_mock.return_value = [
                {"fqdn": "krivoshein.site", "puny": "krivoshein.site", "available": False, "error": None},
            ]
            resp = self.client.get("/domains?query=krivoshein.site")
        self.assertEqual(resp.status_code, 200)
        check_mock.assert_called_once()
        label, zones = check_mock.call_args[0]
        self.assertEqual(label, "krivoshein")
        self.assertEqual(zones, ["site"])
        self.assertNotIn("domain-idea-suggestions", resp.get_data(as_text=True))

    def test_check_page_refreshes_incomplete_cached_whois_for_idn_domain(self):
        from urllib.parse import quote

        ascii_domain = "xn--80agvlv.xn--p1ai"
        incomplete = {
            "input": "агнкс.рф",
            "domain": ascii_domain,
            "domain_display": "агнкс.рф",
            "whois": {
                "whois_server": "whois.tcinet.ru",
                "domain_name": ascii_domain,
                "domain_unicode": "агнкс.рф",
            },
            "dns": {"records": {"A": ["93.184.216.34"]}, "ips": ["93.184.216.34"], "has_records": True},
            "geo": {"ip": "93.184.216.34"},
            "reverse": {},
        }
        app_module.r.setex(
            f"cache:report:full:{ascii_domain}",
            60,
            app_module._json_dumps(incomplete),
        )
        resp = self.client.get("/check/" + quote("агнкс.рф") + "?lang=ru")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("REGRU-RF", html)
        self.assertNotRegex(html, r"Регистратор</span><span class=\"report-value\">—")

    def test_idn_full_domain_search_checks_only_entered_zone(self):
        from urllib.parse import quote

        with patch.object(app_module, "_check_candidates") as check_mock:
            check_mock.return_value = [
                {
                    "fqdn": "агнкс.рф",
                    "puny": "xn--80agvlv.xn--p1ai",
                    "available": False,
                    "error": None,
                },
            ]
            resp = self.client.get("/domains?query=" + quote("агнкс.рф"))
        self.assertEqual(resp.status_code, 200)
        check_mock.assert_called_once()
        label, zones = check_mock.call_args[0]
        self.assertEqual(label, "агнкс")
        self.assertEqual(zones, ["рф"])
        self.assertIn("агнкс.рф", resp.get_data(as_text=True))
        self.assertNotIn("domain-idea-suggestions", resp.get_data(as_text=True))

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

    def test_domain_availability_from_search_items_taken_fqdn(self):
        items = [{"fqdn": "taken.example", "available": False}]
        with self.app.test_request_context("/"):
            payload = app_module._domain_availability_from_search_items(items, fqdn_mode=True)
        self.assertEqual("taken", payload.get("status"))
        self.assertEqual("taken.example", payload.get("domain"))

    def test_domain_search_results_surface_primary_before_zone_settings(self):
        items = [{"fqdn": "free.test", "available": True, "puny": "free.test"}]
        with patch.object(app_module, "_check_candidates", return_value=items):
            with patch.object(app_module, "_verify_form_recaptcha_if_needed", return_value=None):
                with patch.object(app_module, "_tool_rate_limited", return_value=None):
                    with patch.object(app_module, "_track_domain_for_seo"):
                        resp = self.client.post(
                            "/domains",
                            data={"query": "free", "zone_preset": "defaults"},
                        )
        html = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn("data-domain-search-results", html)
        self.assertIn("data-domain-zone-settings", html)
        self.assertLess(html.index("data-domain-search-results"), html.index("data-domain-zone-settings"))
        self.assertIn("tool-form--compact", html)

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
                registrar_offers_featured=app_module._registrar_offers,
                registrar_buy_url=app_module._registrar_buy_url,
                url_for=app_module.url_for,
            )
        self.assertIn('class="domain-available-banner__chip"', html)
        self.assertIn("https://beget.com/x/brand.site", html)


if __name__ == "__main__":
    unittest.main()