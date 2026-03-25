import unittest

import app as app_module


class UIToolPagesSmokeTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_key_tool_pages_render_successfully(self):
        pages = [
            '/dns',
            '/whois',
            '/domains',
            '/geo',
            '/reverse',
            '/security',
            '/site-checker',
            '/history',
        ]
        for path in pages:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)

    def test_unified_tool_pattern_markers_present(self):
        checks = {
            '/dns': ['tool-form', 'tool-intro'],
            '/whois': ['tool-form', 'tool-intro'],
            '/domains': ['tool-form', 'tool-intro'],
            '/geo': ['tool-form', 'tool-intro'],
            '/reverse': ['tool-form', 'tool-intro'],
            '/security': ['tool-form', 'tool-intro'],
            '/site-checker': ['tool-form', 'tool-intro'],
        }
        for path, markers in checks.items():
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                for marker in markers:
                    self.assertIn(marker, html)


if __name__ == '__main__':
    unittest.main()
