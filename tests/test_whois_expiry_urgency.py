import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import app as app_module


class WhoisExpiryUrgencyTests(unittest.TestCase):
    def test_parse_iso_date(self):
        dt = app_module._parse_whois_expiration_date("2026-06-27")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.date().isoformat(), "2026-06-27")

    def test_parse_ru_dot_date(self):
        dt = app_module._parse_whois_expiration_date("27.06.2026")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.day, 27)
        self.assertEqual(dt.month, 6)

    def test_parse_datetime_object(self):
        raw = datetime(2026, 6, 27, 12, 0, tzinfo=timezone.utc)
        dt = app_module._parse_whois_expiration_date(raw)
        self.assertEqual(dt, raw)

    def test_build_urgency_none_when_far_future(self):
        far = (datetime.now(timezone.utc) + timedelta(days=120)).strftime("%Y-%m-%d")
        with self.app.test_request_context("/"):
            payload = app_module._build_whois_expiry_urgency(
                {"expiration_date": far, "domain_name": "example.com"},
                domain="example.com",
            )
        self.assertIsNone(payload)

    def test_build_urgency_critical_within_seven_days(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d")
        with self.app.test_request_context("/"):
            payload = app_module._build_whois_expiry_urgency(
                {"expiration_date": soon, "domain_name": "example.com"},
                domain="example.com",
            )
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("urgency"), "critical")
        self.assertEqual(payload.get("days_left"), 3)

    def test_build_urgency_expired_recently(self):
        past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        with self.app.test_request_context("/"):
            payload = app_module._build_whois_expiry_urgency(
                {"paid_till": past, "domain_name": "example.ru"},
                domain="example.ru",
            )
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("urgency"), "expired")
        self.assertEqual(payload.get("days_left"), -5)

    def test_banner_renders_for_warning(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=20)).strftime("%Y-%m-%d")
        with self.app.test_request_context("/"):
            payload = app_module._build_whois_expiry_urgency(
                {"expiration_date": soon, "domain_name": "brand.io"},
                domain="brand.io",
            )
            html = self.app.jinja_env.get_template("_whois_expiry_urgency_banner.html").render(
                whois_expiry_urgency=payload,
                tr=lambda ru, en: en,
                get_locale=lambda: "en",
            )
        self.assertIn("whois-expiry-banner--warning", html)
        self.assertIn("20", html)
        self.assertIn("brand.io", html)

    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()


if __name__ == "__main__":
    unittest.main()