import unittest
from unittest.mock import patch

import app as app_module

_STATUS_CHIPS_DOCK_STUB = {
    'items': [{
        'query': 'example.com',
        'kind': 'dns',
        'chip_kind_label': 'DNS',
        'domain_display': 'example.com',
        'repeat_url': '/dns?q=example.com',
        'view_url': '/history/dns/x',
        'status_tone': 'ok',
    }],
    'total': 1,
    'has_more': False,
    'history_url': '/history',
}


class UXSimpleModeTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_home_hero_submits_to_report(self):
        html = self.client.get('/?lang=ru').get_data(as_text=True)
        self.assertIn('action="/report"', html)
        self.assertIn('name="q"', html)
        self.assertIn('hero-home__form', html)
        self.assertIn('Полная проверка', html)

    def test_home_has_three_feature_cards(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertEqual(html.count('feature-card'), 3)

    def test_friendly_nav_labels_ru(self):
        html = self.client.get('/?lang=ru').get_data(as_text=True)
        self.assertIn('Кто владелец', html)
        self.assertIn('Куда ведёт', html)
        self.assertIn('Полная проверка', html)

    def test_domains_default_five_zones_and_show_all(self):
        html = self.client.get('/domains?lang=ru').get_data(as_text=True)
        self.assertIn('data-zone-extra', html)
        self.assertIn('data-zones-expand', html)
        self.assertIn('Показать все зоны', html)
        defaults = self.app.config.get('DOMAIN_DEFAULT_TLDS', [])
        self.assertEqual(len(defaults), 5)
        self.assertEqual(set(defaults), {'ru', 'рф', 'com', 'site', 'online'})

    def test_report_page_and_explain_partial(self):
        html = self.client.get('/report?lang=ru').get_data(as_text=True)
        self.assertIn('Полная проверка', html)
        self.assertIn('data-report-form', html)
        explain = self.app.jinja_env.get_template('_report_explain.html').render(
            explain_key='whois',
            tr=lambda ru, en: ru,
            get_locale=lambda: 'ru',
        )
        self.assertIn('Что это значит?', explain)
        self.assertIn('report-explain', explain)

    def test_report_progress_when_job_running(self):
        job_id = 'a1b2c3d4e5f6789012345678abcdef01'
        app_module._touch_report_job(
            job_id,
            status='running',
            progress_step='whois',
            source_input='example.com',
            domains=['example.com'],
            progress_domain_index=0,
            progress_domain_total=1,
            progress_domain='example.com',
        )
        html = self.client.get(f'/report?job={job_id}&q=example.com&lang=ru').get_data(as_text=True)
        self.assertIn('report-progress', html)
        self.assertIn('Проверяем владельца', html)

    def test_specialists_hint_collapsible(self):
        hint = self.app.jinja_env.get_template('_action_bar_hint.html').render(
            tr=lambda ru, en: ru,
        )
        self.assertIn('specialists-hint', hint)
        self.assertIn('Для специалистов', hint)

    def test_onboarding_only_on_home(self):
        home = self.client.get('/?lang=ru').get_data(as_text=True)
        whois = self.client.get('/whois?lang=ru').get_data(as_text=True)
        self.assertIn('data-onboarding', home)
        self.assertIn('data-onboarding-target', home)
        self.assertIn('onboarding--soft', home)
        self.assertIn('Пропустить', home)
        self.assertNotIn('id="onboarding"', whois)
        self.assertIn('data-onboarding-replay', whois)

    def test_onboarding_replay_in_footer(self):
        html = self.client.get('/?lang=ru').get_data(as_text=True)
        self.assertIn('data-onboarding-replay', html)
        self.assertIn('Подсказка', html)

    def test_monetization_slot_attribute(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('data-monetization-slot', html)

    def test_touch_report_job_merges_fields(self):
        job_id = 'abc123def4567890abc123def4567890'
        self.assertTrue(app_module._is_valid_report_job_id(job_id))
        app_module._touch_report_job(job_id, status='running', progress_step='dns')
        job = app_module._load_report_job(job_id)
        self.assertIsNotNone(job)
        self.assertEqual(job.get('status'), 'running')
        self.assertEqual(job.get('progress_step'), 'dns')

    def test_wave3_status_chip_and_ux_mode_markup(self):
        html = self.client.get('/security?lang=ru').get_data(as_text=True)
        self.assertIn('data-quick-actions-dock', html)
        self.assertIn('data-qa-dock-toggle', html)
        self.assertIn('confirm_ownership', html)
        self.assertIn('data-ux-mode-toggle', html)
        self.assertIn('data-ux-mode', html)

    def test_lookup_redirects_to_check(self):
        resp = self.client.get('/lookup/example.com', follow_redirects=False)
        self.assertEqual(resp.status_code, 301)
        self.assertIn('/check/example.com', resp.headers.get('Location', ''))

    def test_derive_check_status_ok_and_critical(self):
        with self.app.test_request_context('/'):
            ok = app_module._derive_check_status({
                'domain': 'example.com',
                'domain_display': 'example.com',
                'dns': {'has_records': True},
                'whois_expiry_urgency': None,
            })
            critical = app_module._derive_check_status({
                'domain': 'expired.com',
                'whois_expiry_urgency': {'urgency': 'expired'},
                'dns': {'has_records': True},
            })
        self.assertEqual(ok['status'], 'ok')
        self.assertEqual(critical['status'], 'critical')

    def test_check_dashboard_renders_with_mock_report(self):
        sample = {
            'domain': 'example.com',
            'domain_display': 'example.com',
            'dns': {'has_records': True, 'records': {'A': ['1.2.3.4']}},
            'whois': {
                'domain_unicode': 'example.com',
                'registrar': 'Test Registrar',
                'creation_date': '2000-01-01',
                'expiration_date': '2030-01-01',
            },
            'geo': {'ip': '1.2.3.4', 'asn': 'AS123', 'country_name': 'United States'},
            'reverse': {'ip': '1.2.3.4', 'ptr': ['example.com'], 'fcrdns_ok': True},
            'whois_expiry_urgency': None,
        }
        with patch.object(app_module, 'cache_json', return_value=sample):
            with patch.object(app_module, 'save_history', return_value=None):
                with patch.object(app_module, '_endpoint_ip_rate_limited', return_value=False):
                    resp = self.client.get('/check/example.com?lang=ru&run=1')
                    html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('check-dashboard', html)
        self.assertIn('__DT_LAST_CHECK__', html)
        self.assertIn('data-banner-priority', html)

    def test_single_domain_report_post_redirects_to_check(self):
        with patch.object(app_module, '_verify_form_recaptcha_if_needed', return_value=None):
            with patch.object(app_module, '_endpoint_ip_rate_limited', return_value=False):
                resp = self.client.post('/report', data={'q': 'example.com'}, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/check/example.com', resp.headers.get('Location', ''))


if __name__ == '__main__':
    unittest.main()