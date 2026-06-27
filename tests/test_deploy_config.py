import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import app as app_module


class DeployConfigTests(unittest.TestCase):
    def test_resolve_secret_key_prefers_explicit_env(self):
        with patch.dict(os.environ, {"SECRET_KEY": "prod-secret"}, clear=False):
            self.assertEqual(app_module._resolve_secret_key(), "prod-secret")

    def test_resolve_secret_key_allows_debug_fallback(self):
        with patch.object(app_module, "_running_under_tests", return_value=False):
            with patch.dict(os.environ, {"FLASK_DEBUG": "1"}, clear=True):
                self.assertEqual(app_module._resolve_secret_key(), "dev-secret")

    def test_app_has_secret_key_under_unittest(self):
        self.assertTrue(app_module.app.config.get("SECRET_KEY"))

    def test_wsgi_exits_when_secret_key_missing(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        python_bin = sys.executable
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in {"SECRET_KEY", "FLASK_DEBUG", "FLASK_TESTING"}
        }
        proc = subprocess.run(
            [python_bin, "-c", "import wsgi"],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SECRET_KEY", proc.stderr)


if __name__ == "__main__":
    unittest.main()