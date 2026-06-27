import unittest
from unittest.mock import patch

import app as app_module


class CheckCrawlerGuardTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_check_cold_cache_is_fast_for_crawler(self):
        with patch.object(app_module, "_report_cache_get", return_value=None):
            with patch.object(app_module, "_is_crawler_request", return_value=True):
                with patch.object(app_module, "_build_domain_report") as build_mock:
                    resp = self.client.get(
                        "/check/example.com",
                        headers={"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0)"},
                    )
        self.assertEqual(resp.status_code, 200)
        build_mock.assert_not_called()
        html = resp.get_data(as_text=True)
        self.assertIn("Run full check", html)

    def test_check_run_flag_invokes_report_cache(self):
        with patch.object(app_module, "_report_cache_get", return_value=None):
            with patch.object(app_module, "_is_crawler_request", return_value=False):
                with patch.object(app_module, "cache_json", return_value=None) as cache_mock:
                    with patch.object(app_module, "_endpoint_ip_rate_limited", return_value=False):
                        resp = self.client.get("/check/example.com?run=1")
        self.assertIn(resp.status_code, (200, 302))
        self.assertTrue(
            any("cache:report:full:example.com" in str(c) for c in cache_mock.call_args_list),
            cache_mock.call_args_list,
        )


if __name__ == "__main__":
    unittest.main()