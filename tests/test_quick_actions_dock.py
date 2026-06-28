import unittest
from contextlib import contextmanager
from unittest.mock import patch

import app as app_module


class QuickActionsDockTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    @contextmanager
    def _tool_request_patches(self):
        with patch.object(app_module, '_verify_form_recaptcha_if_needed', return_value=None):
            with patch.object(app_module, '_tool_rate_limited', return_value=None):
                with patch.object(app_module, '_track_domain_for_seo'):
                    with patch.object(app_module, 'save_history', return_value='hist123'):
                        yield

    def test_dns_dock_renders_with_toggle_and_i18n(self):
        with patch.object(app_module.dns.resolver, 'resolve', side_effect=Exception('no records')):
            with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                with self._tool_request_patches():
                    html = self.client.get('/dns?q=example.com&types=A&lang=ru').get_data(as_text=True)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('data-quick-actions-dock', html)
        self.assertIn('data-qa-dock-toggle', html)
        self.assertIn('aria-expanded="false"', html)
        self.assertIn('Быстрые действия', html)
        self.assertIn('Поделиться результатом', html)
        self.assertIn('tool-page-layout--dock', html)

    def test_whois_dock_renders_on_result_with_secondary(self):
        whois_data = {'domain_name': 'example.com', 'registrar': 'Test'}
        with self._tool_request_patches():
            with patch.object(app_module, 'cache_json', return_value=whois_data):
                with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                    html = self.client.get('/whois?query=example.com&lang=en').get_data(as_text=True)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('Share result', html)
        self.assertIn('data-qa-action="share"', html)
        self.assertIn('More', html)
        self.assertIn('/export/whois/hist123.json', html)

    def test_geo_dock_renders_on_result(self):
        geo_data = {'ip': '8.8.8.8', 'asn': 'AS15169', 'country_code': 'US', 'country_name': 'United States'}
        with self._tool_request_patches():
            with patch.object(app_module, 'cache_json', return_value=geo_data):
                html = self.client.get('/geo?query=8.8.8.8&lang=ru').get_data(as_text=True)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('Поделиться результатом', html)
        self.assertIn('Быстрый переход', html)

    def test_reverse_dock_renders_on_result(self):
        reverse_data = {
            'input': '8.8.8.8',
            'type': 'ip',
            'rows': [{'ip': '8.8.8.8', 'ptr': ['dns.google'], 'fcrdns_ok': True, 'forward_of_ptr': {}}],
        }
        with self._tool_request_patches():
            with patch.object(app_module, 'cache_json', return_value=reverse_data):
                html = self.client.get('/reverse?query=8.8.8.8&lang=en').get_data(as_text=True)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('Share result', html)
        self.assertIn('data-qa-action="favorite"', html)


if __name__ == '__main__':
    unittest.main()