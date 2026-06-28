import unittest
from contextlib import contextmanager
from unittest.mock import patch

import app as app_module


class ToolSidePanelTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    @contextmanager
    def _tool_request_patches(self):
        with patch.object(app_module, '_verify_form_recaptcha_if_needed', return_value=None):
            with patch.object(app_module, '_tool_rate_limited', return_value=None):
                with patch.object(app_module, '_track_domain_for_seo'):
                    with patch.object(app_module, 'save_history', return_value='hist123'):
                        yield

    def test_dns_error_state_keeps_side_panel(self):
        captcha_msg = 'Проверка captcha не пройдена.'
        with patch.object(app_module, '_verify_form_recaptcha_if_needed', return_value=captcha_msg):
            resp = self.client.get('/dns?q=example.com&types=A&lang=ru')
            html = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('tool-page-layout--dock', html)
        self.assertIn('quick-actions-dock', html)
        self.assertIn(captcha_msg, html)
        self.assertIn('tool-page-alert', html)
        self.assertNotIn('Скопировать все записи', html)
        self.assertIn('Поделиться результатом', html)

    def test_dns_result_dock_has_no_history_section(self):
        with patch.object(app_module.dns.resolver, 'resolve', side_effect=Exception('no records')):
            with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                with self._tool_request_patches():
                    html = self.client.get('/dns?q=example.com&types=A&lang=ru').get_data(as_text=True)
        self.assertNotIn('status-chips-dock', html)
        self.assertIn('data-qa-history-user', html)
        self.assertIn('data-qa-clear-history', html)
        self.assertIn('example.com', html)

    def test_panel_history_renders_up_to_eight_items(self):
        items = [
            {
                'query': f'site{i}.com',
                'kind': 'dns',
                'chip_kind_label': 'DNS',
                'domain_display': f'site{i}.com',
                'repeat_url': f'/dns?q=site{i}.com',
                'view_url': f'/history/dns/h{i}',
                'status_tone': 'ok',
                'time_ago_ru': '2 мин назад',
                'time_ago_en': '2 min ago',
            }
            for i in range(8)
        ]
        dock = {'items': items, 'total': 12, 'has_more': True, 'history_url': '/history'}
        with patch.object(app_module.dns.resolver, 'resolve', side_effect=Exception('no records')):
            with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                with self._tool_request_patches():
                    with patch.object(app_module, 'recent_history_user_dock', return_value=dock):
                        html = self.client.get('/dns?q=site0.com&types=A&lang=ru').get_data(as_text=True)
        self.assertGreaterEqual(html.count('quick-actions-dock__history-chip'), 8)
        self.assertIn('Мои запросы', html)
        self.assertIn('cookie', html.lower())

    def test_visitor_cookie_is_set_on_first_visit(self):
        resp = self.client.get('/?lang=ru')
        cookies = ' '.join(resp.headers.getlist('Set-Cookie'))
        self.assertIn(app_module.VISITOR_COOKIE, cookies)

    def test_save_history_tracks_visitor_zset(self):
        vid = '11111111-2222-4333-8444-555555555555'
        with app_module.app.test_request_context('/', headers={'Cookie': f'{app_module.VISITOR_COOKIE}={vid}'}):
            with patch.object(app_module.r, 'set', return_value=True):
                with patch.object(app_module.r, 'zadd') as zadd_mock:
                    with patch.object(app_module.r, 'zcard', return_value=1):
                        hid = app_module.save_history('whois', 'test.com', {'ok': True})
        self.assertTrue(hid)
        zset_keys = [call.args[0] for call in zadd_mock.call_args_list]
        self.assertIn(app_module.HIST_ZSET, zset_keys)
        self.assertIn(f'{app_module.HIST_USER_ZSET_PREFIX}{vid}', zset_keys)

    def test_api_history_dock_returns_user_payload(self):
        dock = {
            'items': [{
                'query': 'example.com',
                'kind': 'whois',
                'chip_kind_label': 'WHOIS',
                'domain_display': 'example.com',
                'repeat_url': '/whois?query=example.com',
                'view_url': '/history/whois/x',
                'status_tone': 'ok',
                'ts': 1710000000,
                'time_ago_ru': 'только что',
                'time_ago_en': 'just now',
            }],
            'total': 1,
            'has_more': False,
            'history_url': '/history',
        }
        with patch.object(app_module, 'recent_history_user_dock', return_value=dock):
            resp = self.client.get('/api/history/dock?lang=ru')
        self.assertEqual(200, resp.status_code)
        data = resp.get_json()
        self.assertIn('user', data)
        self.assertNotIn('global', data)
        self.assertEqual('example.com', data['user']['items'][0]['query'])

    def test_api_history_dock_global_opt_in(self):
        with patch.object(app_module, 'recent_history_global_dock', return_value={'items': [], 'total': 0, 'has_more': False, 'history_url': '/history'}):
            resp = self.client.get('/api/history/dock?global=1')
        self.assertIn('global', resp.get_json())

    def test_security_port_scan_requires_ownership_confirm(self):
        resp = self.client.post(
            '/security?lang=ru',
            data={'scan': 'ports', 'host': 'example.com', 'ports': '80'},
            follow_redirects=True,
        )
        html = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('подтверждаю', html.lower())
        self.assertIn('подтвердите', html.lower())
        self.assertNotIn('Сканирование запущено', html)
        self.assertNotIn('alert alert-primary mb-3" data-security-job', html)

    def test_recent_history_user_dock_uses_visitor_zset(self):
        vid = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        fake_keys = ['whois:w1', 'report:r1']

        def fake_zrevrange(zset_key, start, end):
            if zset_key == f'{app_module.HIST_USER_ZSET_PREFIX}{vid}':
                return fake_keys[start : end + 1]
            return []

        with app_module.app.test_request_context('/', headers={'Cookie': f'{app_module.VISITOR_COOKIE}={vid}'}):
            with patch.object(app_module.r, 'zrevrange', side_effect=fake_zrevrange):
                with patch.object(app_module, 'load_history', return_value={'query': 'x.com', 'ts': 1}):
                    data = app_module.recent_history_user_dock(limit=10)
        self.assertEqual(2, len(data['items']))

    def test_plaque_summary_from_report_history(self):
        doc = {
            'query': 'example.com',
            'result': {
                'domain': 'example.com',
                'domain_display': 'example.com',
                'dns': {'has_records': True, 'records': {'A': ['1.2.3.4']}},
                'whois': {'registrar': 'Test Registrar', 'domain': 'example.com'},
                'whois_expiry_urgency': None,
            },
        }
        with app_module.app.test_request_context('/'):
            summary = app_module._plaque_summary_from_history('report', doc)
        self.assertEqual('example.com', summary['domain_display'])
        self.assertEqual('Занят', summary['availability_label_ru'])
        self.assertEqual('DNS настроен', summary['dns_label_ru'])

    def test_history_chip_kind_label_localized(self):
        with app_module.app.test_request_context('/?lang=ru'):
            self.assertEqual('Проверка', app_module._history_chip_kind_label('report'))
        with app_module.app.test_request_context('/?lang=en'):
            self.assertEqual('Check', app_module._history_chip_kind_label('report'))

    def test_recent_history_for_kind_filters_by_kind(self):
        fake_keys = ['dns:h1', 'whois:w1', 'dns:h2', 'geo:g1']

        def fake_zrevrange(_zset, start, end):
            return fake_keys[start : end + 1]

        def fake_load(kind, hid):
            return {'query': f'{kind}-{hid}', 'ts': 1710000000}

        with app_module.app.test_request_context('/'):
            with patch.object(app_module.r, 'zrevrange', side_effect=fake_zrevrange):
                with patch.object(app_module, 'load_history', side_effect=fake_load):
                    data = app_module.recent_history_for_kind('dns', limit=10)
        self.assertEqual(2, data['total'])
        self.assertEqual(2, len(data['items']))
        self.assertEqual('dns-h1', data['items'][0]['query'])
        self.assertEqual('dns-h2', data['items'][1]['query'])

    def test_recent_history_has_more_flag(self):
        fake_keys = [f'dns:h{i}' for i in range(12)]

        with app_module.app.test_request_context('/'):
            with patch.object(app_module.r, 'zrevrange', return_value=fake_keys):
                with patch.object(app_module, 'load_history', return_value={'query': 'x.com', 'ts': 1}):
                    data = app_module.recent_history_for_kind('dns', limit=10)
        self.assertTrue(data['has_more'])
        self.assertEqual(10, len(data['items']))

    def test_domains_page_renders_side_panel(self):
        with patch.object(app_module, '_verify_form_recaptcha_if_needed', return_value=None):
            with patch.object(app_module, '_tool_rate_limited', return_value=None):
                with patch.object(app_module, '_check_candidates', return_value=[{'fqdn': 'test.ru', 'puny': 'test.ru', 'available': True}]):
                    with patch.object(app_module, '_track_domain_for_seo'):
                        resp = self.client.post('/domains?lang=ru', data={'query': 'test', 'zones': 'ru'}, follow_redirects=True)
        html = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('tool-page-layout--dock', html)
        self.assertIn('quick-actions-dock', html)
        self.assertIn('data-qa-action="copy"', html)
        self.assertIn('Скопировать список', html)

    def test_check_page_renders_side_panel(self):
        sample = {
            'domain': 'example.com',
            'domain_display': 'example.com',
            'dns': {'has_records': True, 'records': {'A': ['1.2.3.4']}},
            'whois': {'registrar': 'Test', 'expiration_date': '2030-01-01'},
            'whois_expiry_urgency': None,
        }
        with patch.object(app_module, 'cache_json', return_value=sample):
            with patch.object(app_module, 'save_history', return_value='hid1'):
                with patch.object(app_module, '_track_domain_for_seo'):
                    html = self.client.get('/check/example.com?run=1&lang=ru').get_data(as_text=True)
        self.assertIn('tool-page-layout--dock', html)
        self.assertIn('Поделиться результатом', html)

    def test_security_page_side_panel_includes_history_block(self):
        resp = self.client.get('/security?lang=ru')
        html = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('tool-page-layout--dock', html)
        self.assertIn('quick-actions-dock__history', html)
        self.assertIn('data-qa-history-user', html)
        self.assertIn('Мои запросы', html)
        self.assertIn('tool-faq-wrap', html)

    def test_home_and_domains_do_not_surface_ultravds_promo_cards(self):
        for path in ('/', '/domains', '/dns', '/security'):
            html = self.client.get(f'{path}?lang=ru').get_data(as_text=True)
            self.assertNotIn('UltraVDS', html, msg=path)
            self.assertNotIn('Полезные ссылки', html, msg=path)

    def test_hosting_page_includes_ultravds_as_regular_provider(self):
        html = self.client.get('/hosting?lang=ru').get_data(as_text=True)
        self.assertIn('UltraVDS', html)
        self.assertIn('data-ref-id="ultravds"', html)
        self.assertIn('hosting-offer-card', html)
        self.assertNotIn('Полезные ссылки', html)

    def test_faq_section_uses_site_wide_wrap_markup(self):
        html = self.client.get('/domains?lang=ru').get_data(as_text=True)
        self.assertIn('tool-faq-wrap', html)
        self.assertIn('tool-faq card-soft p-4', html)

    def test_navbar_contains_global_history_toggle(self):
        html = self.client.get('/?lang=ru').get_data(as_text=True)
        nav_end = html.split('</nav>', 1)[0]
        self.assertIn('data-qa-show-global-history-nav', nav_end)
        self.assertIn('Показать общую историю', nav_end)

    def test_dns_compact_faq_when_result_shown(self):
        with patch.object(app_module.dns.resolver, 'resolve', side_effect=Exception('no records')):
            with patch.object(app_module, '_evaluate_domain_availability', return_value=None):
                with self._tool_request_patches():
                    html = self.client.get('/dns?q=example.com&types=A&lang=ru').get_data(as_text=True)
        self.assertIn('tool-faq-wrap--compact', html)
        self.assertIn('FAQ / Частые вопросы', html)

    def test_dns_idle_page_has_no_compact_faq_wrap(self):
        html = self.client.get('/dns?lang=ru').get_data(as_text=True)
        self.assertIn('tool-faq-wrap', html)
        self.assertNotIn('tool-faq-wrap--compact', html)
        self.assertIn('tool-faq card-soft p-4', html)


if __name__ == '__main__':
    unittest.main()