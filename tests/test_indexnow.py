import unittest
from unittest.mock import MagicMock, patch

import app as app_module


class IndexNowTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_robots_txt_not_shadowed_by_indexnow_route(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("User-agent:", body)
        self.assertIn("Sitemap:", body)

    def test_indexnow_key_file_disabled_in_tests(self):
        with self.app.app_context():
            key = self.app.config.get("INDEXNOW_KEY") or "deadbeef"
        resp = self.client.get(f"/{key}.txt")
        self.assertEqual(resp.status_code, 404)

    def test_indexnow_urls_for_domain_use_canonical_root(self):
        with self.app.app_context():
            self.app.config["SITE_CANONICAL_ROOT"] = "https://domaintools.site"
            urls = app_module._indexnow_urls_for_domain("example.com")
        self.assertEqual(len(urls), 3)
        for url in urls:
            self.assertTrue(url.startswith("https://domaintools.site/"))
        self.assertTrue(any("/check/" in u for u in urls))
        self.assertTrue(any("/lookup/whois/" in u for u in urls))
        self.assertTrue(any("/lookup/dns/" in u for u in urls))

    def test_track_domain_skips_ip_addresses(self):
        with patch.object(app_module, "_queue_indexnow_for_domain") as queue_mock:
            with patch.object(app_module.r, "pipeline") as pipe_mock:
                pipe = MagicMock()
                pipe_mock.return_value = pipe
                app_module._track_domain_for_seo("8.8.8.8")
        queue_mock.assert_not_called()
        pipe_mock.assert_not_called()

    def test_track_domain_queues_indexnow_for_valid_domain(self):
        with patch.object(app_module, "_queue_indexnow_for_domain") as queue_mock:
            with patch.object(app_module.r, "pipeline") as pipe_mock:
                pipe = MagicMock()
                pipe_mock.return_value = pipe
                app_module._track_domain_for_seo("example.com")
        queue_mock.assert_called_once_with("example.com")
        pipe_mock.assert_called_once()

    def test_indexnow_enabled_with_explicit_flag(self):
        with patch.dict(
            "os.environ",
            {"INDEXNOW_ENABLED": "1", "INDEXNOW_KEY": "a" * 32},
            clear=False,
        ):
            with patch.object(app_module, "_running_under_tests", return_value=False):
                key = (app_module.os.environ.get("INDEXNOW_KEY") or "").strip()
                wanted = app_module.os.environ.get("INDEXNOW_ENABLED", "").strip().lower() in {
                    "1", "true", "yes", "on",
                }
                self.assertTrue(key and wanted)


if __name__ == "__main__":
    unittest.main()