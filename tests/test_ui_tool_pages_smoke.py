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
            '/report',
            '/hosting',
            '/geo',
            '/reverse',
            '/security',
            '/site-checker',
            '/rkn',
            '/history',
        ]
        for path in pages:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)

    def test_security_forms_post_to_clean_security_endpoint(self):
        html = self.client.get('/security?scan=ports&host=&ports=').get_data(as_text=True)
        self.assertIn('action="/security"', html)

    def test_unified_tool_pattern_markers_present(self):
        checks = {
            '/dns': ['tool-form', 'tool-intro'],
            '/whois': ['tool-form', 'tool-intro'],
            '/domains': ['tool-form', 'tool-intro'],
            '/geo': ['tool-form', 'tool-intro'],
            '/reverse': ['tool-form', 'tool-intro'],
            '/security': ['tool-form', 'tool-intro'],
            '/site-checker': ['tool-form', 'tool-intro'],
            '/rkn': ['tool-form', 'tool-intro'],
        }
        for path, markers in checks.items():
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                for marker in markers:
                    self.assertIn(marker, html)

    def test_check_query_redirects_to_report_without_domain(self):
        resp = self.client.get('/check?q=', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/report', resp.headers.get('Location', ''))

    def test_command_palette_and_mobile_nav_present(self):
        html = self.client.get('/').get_data(as_text=True)
        for marker in (
            'commandPalette',
            'command-palette-data',
            'data-command-palette-open',
            'mobile-bottom-nav',
            'scrollToTop',
            'scroll-to-top',
        ):
            self.assertIn(marker, html)


if __name__ == '__main__':
    unittest.main()
