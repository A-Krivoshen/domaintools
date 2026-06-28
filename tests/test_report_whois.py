import os
import unittest
import unittest.mock
from datetime import datetime, timezone

import app as app_module


SAMPLE_COM_WHOIS = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, LLC
Creation Date: 2010-05-01T10:20:30Z
Registry Expiry Date: 2030-05-01T10:20:30Z
"""

SAMPLE_RU_WHOIS = """
domain:       BRAND.RU
registrar:    RU-CENTER-RU
created:      2015-03-10T12:00:00Z
paid-till:    2026-03-10T12:00:00Z
"""


class ReportWhoisTests(unittest.TestCase):
    def setUp(self):
        self.ctx = app_module.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_extract_core_fields_from_icann_style_text(self):
        parsed = app_module._extract_whois_core_fields_from_text(SAMPLE_COM_WHOIS)
        self.assertEqual(parsed.get("registrar"), "Example Registrar, LLC")
        self.assertEqual(parsed.get("creation_date"), "2010-05-01T10:20:30Z")
        self.assertEqual(parsed.get("expiration_date"), "2030-05-01T10:20:30Z")

    def test_finalize_formats_datetime_lists(self):
        payload = {
            "registrar": "MarkMonitor, Inc.",
            "creation_date": [
                datetime(1997, 9, 15, 4, 0, tzinfo=timezone.utc),
                datetime(1997, 9, 15, 7, 0, tzinfo=timezone.utc),
            ],
            "expiration_date": datetime(2028, 9, 14, 4, 0, tzinfo=timezone.utc),
        }
        out = app_module._finalize_whois_summary(payload, "example.com")
        self.assertEqual(out["creation_date"], "1997-09-15 04:00 UTC")
        self.assertEqual(out["expiration_date"], "2028-09-14 04:00 UTC")

    def test_report_whois_summary_has_no_empty_core_fields_for_sample_com(self):
        merged = app_module._finalize_whois_summary(
            app_module._extract_whois_core_fields_from_text(SAMPLE_COM_WHOIS),
            "example.com",
        )
        self.assertTrue(merged.get("registrar"))
        self.assertTrue(merged.get("creation_date"))
        self.assertTrue(merged.get("expiration_date"))

    def test_ru_whois_parser_still_fills_dates(self):
        parsed = app_module._parse_ru_whois_text(SAMPLE_RU_WHOIS)
        out = app_module._finalize_whois_summary(parsed, "brand.ru")
        self.assertEqual(out.get("registrar"), "RU-CENTER-RU")
        self.assertEqual(out.get("creation_date"), "2015-03-10T12:00:00Z")
        self.assertEqual(out.get("expiration_date"), "2026-03-10T12:00:00Z")

    def test_whois_executable_resolves_without_system_path(self):
        with unittest.mock.patch.dict("os.environ", {"PATH": "/var/www/python.domaintools.site/htdocs/.venv/bin"}, clear=True):
            exe = app_module._whois_executable()
        self.assertTrue(exe.endswith("whois"))
        self.assertTrue(os.path.isfile(exe))

    def test_cached_whois_summary_rejects_incomplete_cache(self):
        host = "xn--80agvlv.xn--p1ai"
        incomplete = {
            "whois_server": "whois.tcinet.ru",
            "domain_name": host,
            "domain_unicode": "агнкс.рф",
        }
        app_module.r.setex(
            f"cache:report:whois:{host}",
            60,
            app_module._json_dumps(incomplete),
        )
        summary = app_module._cached_whois_summary(host)
        self.assertTrue(app_module._whois_has_core_fields(summary))
        self.assertEqual(summary.get("registrar"), "REGRU-RF")


if __name__ == "__main__":
    unittest.main()