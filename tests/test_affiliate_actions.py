import unittest
from unittest.mock import patch

import app as app_module


class AffiliateActionsTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_extract_affiliate_domain_from_whois_query(self):
        domain = app_module._extract_affiliate_domain("Example.COM", "whois")
        self.assertEqual(domain, "example.com")

    def test_extract_affiliate_domain_skips_ip(self):
        self.assertIsNone(app_module._extract_affiliate_domain("8.8.8.8", "geo"))

    def test_extract_affiliate_domain_from_security_host(self):
        domain = app_module._extract_affiliate_domain("ports:example.com:80", "security")
        self.assertEqual(domain, "example.com")

    def test_affiliate_buy_url_uses_beget_template(self):
        with self.app.test_request_context("/"):
            url = app_module._affiliate_buy_url("example.com")
        self.assertIn("example.com", url)
        self.assertIn("beget.com", url)

    def test_history_renders_register_button_for_domain_item(self):
        with patch.object(app_module, "load_history") as load_history:
            load_history.return_value = {
                "kind": "whois",
                "id": "abc",
                "query": "example.com",
                "result": {"domain_name": "example.com"},
                "ts": 1_700_000_000,
            }
            with patch.object(app_module.r, "zrevrange", return_value=["whois:abc"]):
                resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("data-buy-track", html)
        self.assertIn("example.com", html)
        self.assertIn("beget.com", html)


if __name__ == "__main__":
    unittest.main()