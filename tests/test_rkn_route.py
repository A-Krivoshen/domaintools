import unittest
from unittest.mock import patch

import app as app_module


class RknRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()
        app_module._RKN_CACHE.update({"data": None, "data_set": None, "ts": 0})

    def test_get_rkn_returns_200(self):
        resp = self.client.get("/rkn")
        self.assertEqual(resp.status_code, 200)

    def test_post_with_mocked_is_in_rkn_returns_blocked_status_in_html(self):
        with patch.object(app_module, "_verify_form_recaptcha_if_needed", return_value=None):
            with patch.object(app_module, "_get_rkn_cached", return_value={"blocked.example"}):
                with patch.object(app_module, "is_in_rkn", return_value=True):
                    resp = self.client.post("/rkn", data={"query": "blocked.example"})
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("In RKN registry", html)
        self.assertIn("blocked.example", html)


if __name__ == "__main__":
    unittest.main()