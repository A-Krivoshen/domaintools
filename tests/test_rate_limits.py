import unittest
from unittest.mock import patch

import app as app_module


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self._cfg_snapshot = dict(self.app.config)
        self._buckets_snapshot = {
            k: dict(v) for k, v in app_module._ENDPOINT_RATE_BUCKETS.items()
        }
        app_module._ENDPOINT_RATE_BUCKETS.clear()
        self.app.config["TOOL_RATE_LIMIT_PER_MIN"] = 2
        self.app.config["AGENT_API_ENABLED"] = True
        self.app.config["AGENT_API_KEY"] = "rate-test-key"
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.config.clear()
        self.app.config.update(self._cfg_snapshot)
        app_module._ENDPOINT_RATE_BUCKETS.clear()
        app_module._ENDPOINT_RATE_BUCKETS.update(self._buckets_snapshot)

    def test_ip_rate_limited_uses_memory_fallback_when_redis_fails(self):
        with patch.object(app_module.r, "pipeline", side_effect=RuntimeError("redis down")):
            self.assertFalse(app_module._ip_rate_limited("test_bucket", "203.0.113.1", 2))
            self.assertFalse(app_module._ip_rate_limited("test_bucket", "203.0.113.1", 2))
            self.assertTrue(app_module._ip_rate_limited("test_bucket", "203.0.113.1", 2))

    def test_dns_web_tool_returns_rate_limit_error(self):
        with patch.object(app_module, "_verify_form_recaptcha_if_needed", return_value=None):
            with patch.object(app_module, "_endpoint_ip_rate_limited", return_value=True):
                resp = self.client.get("/dns?q=example.com")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Too many requests", resp.get_data(as_text=True))

    def test_agent_api_report_has_separate_rate_bucket(self):
        headers = {"X-API-Key": "rate-test-key"}
        with patch("agent_api.blueprint._rate_limited", return_value=True) as mocked:
            resp = self.client.get("/api/v1/report?domains=example.com", headers=headers)
        self.assertEqual(resp.status_code, 429)
        mocked.assert_called_once()
        args, kwargs = mocked.call_args
        self.assertEqual(args[0], "agent_api_report")
        self.assertEqual(args[1], "AGENT_API_REPORT_RATE_LIMIT_PER_MIN")


if __name__ == "__main__":
    unittest.main()