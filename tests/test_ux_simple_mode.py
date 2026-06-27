import unittest

import app as app_module


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

    def test_onboarding_present(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('data-onboarding', html)
        self.assertIn('onboarding__panel', html)

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


if __name__ == '__main__':
    unittest.main()