import unittest
from unittest.mock import patch

import app as app_module


class AgentApiTests(unittest.TestCase):
    API_KEY = "test-secret-key"

    def setUp(self):
        self.app = app_module.app
        self._cfg_snapshot = dict(self.app.config)
        self.app.config["AGENT_API_ENABLED"] = True
        self.app.config["AGENT_API_KEY"] = self.API_KEY
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.config.clear()
        self.app.config.update(self._cfg_snapshot)

    def _auth_headers(self, key: str | None = None) -> dict:
        return {"X-API-Key": key if key is not None else self.API_KEY}

    def test_api_disabled_by_default_config(self):
        self.app.config["AGENT_API_ENABLED"] = False
        resp = self.client.get("/api/v1/", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 403)
        self.assertIn("disabled", (resp.get_json() or {}).get("error", "").lower())

    def test_api_enabled_without_key_is_rejected(self):
        self.app.config["AGENT_API_KEY"] = ""
        resp = self.client.get("/api/v1/", headers=self._auth_headers("anything"))
        self.assertEqual(resp.status_code, 403)
        self.assertIn("not configured", (resp.get_json() or {}).get("error", "").lower())

    def test_api_index_returns_endpoints(self):
        resp = self.client.get("/api/v1/", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        self.assertIn("dns", data.get("endpoints", {}))
        self.assertIn("openapi", data)
        self.assertTrue(data.get("auth", {}).get("api_key_required"))

    def test_openapi_spec_available(self):
        resp = self.client.get("/api/v1/openapi.json", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        spec = resp.get_json()
        self.assertEqual(spec.get("openapi"), "3.1.0")
        self.assertIn("/dns", spec.get("paths", {}))

    def test_llms_txt_served(self):
        resp = self.client.get("/llms.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"llms-ru.txt", resp.data)
        self.assertIn(b"llms-en.txt", resp.data)

    def test_llms_txt_ru_served(self):
        resp = self.client.get("/llms-ru.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Agent API", resp.data)
        self.assertIn("русскоязычную".encode(), resp.data)

    def test_llms_txt_en_served(self):
        resp = self.client.get("/llms-en.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Agent API", resp.data)

    def test_api_key_required_in_header(self):
        resp = self.client.get("/api/v1/")
        self.assertEqual(resp.status_code, 403)
        resp_ok = self.client.get("/api/v1/", headers=self._auth_headers())
        self.assertEqual(resp_ok.status_code, 200)

    def test_bearer_token_accepted(self):
        resp = self.client.get(
            "/api/v1/",
            headers={"Authorization": f"Bearer {self.API_KEY}"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_query_string_api_key_rejected(self):
        resp = self.client.get(f"/api/v1/?api_key={self.API_KEY}")
        self.assertEqual(resp.status_code, 403)

    def test_dns_requires_domain(self):
        resp = self.client.get("/api/v1/dns", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))

    @patch("agent_api.services.lookup_dns")
    def test_dns_lookup_success(self, mock_lookup):
        mock_lookup.return_value = {"domain": "example.com", "records": {"A": ["93.184.216.34"]}}
        resp = self.client.get("/api/v1/dns?domain=example.com", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload["data"]["domain"], "example.com")


if __name__ == "__main__":
    unittest.main()