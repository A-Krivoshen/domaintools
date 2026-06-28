import unittest
from unittest.mock import patch

import app as app_module


class DnsQuickActionsDockTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def _dns_result_html(self, query='example.com'):
        with patch.object(app_module.dns.resolver, 'resolve', side_effect=Exception('no records')):
            with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                with patch.object(app_module, '_track_domain_for_seo'):
                    return self.client.get(f'/dns?q={query}&types=A&lang=ru')

    def test_dns_results_render_quick_actions_dock(self):
        resp = self._dns_result_html()
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('data-quick-actions-dock', html)
        self.assertIn('data-qa-dock-toggle', html)
        self.assertIn('Быстрые действия', html)
        self.assertIn('Поделиться результатом', html)
        self.assertIn('Скопировать все записи', html)
        self.assertIn('Экспорт JSON / CSV', html)
        self.assertIn('Открыть в WHOIS', html)
        self.assertIn('Сохранить в избранное', html)
        self.assertIn('tool-page-layout--dock', html)

    def test_dns_dock_keeps_main_form_unchanged(self):
        resp = self._dns_result_html()
        html = resp.get_data(as_text=True)
        self.assertIn('Проверка DNS записей домена', html)
        self.assertIn('data-smart-query-form', html)


if __name__ == '__main__':
    unittest.main()