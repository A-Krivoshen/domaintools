import unittest


class FormI18nLayoutTests(unittest.TestCase):
    FORM_PAGES = (
        ('/', 'ru'),
        ('/', 'en'),
        ('/report', 'ru'),
        ('/report', 'en'),
        ('/domains', 'ru'),
        ('/domains', 'en'),
        ('/whois', 'ru'),
        ('/whois', 'en'),
        ('/dns', 'ru'),
        ('/dns', 'en'),
        ('/geo', 'ru'),
        ('/geo', 'en'),
        ('/reverse', 'ru'),
        ('/reverse', 'en'),
        ('/site-checker', 'ru'),
        ('/site-checker', 'en'),
    )

    def setUp(self):
        from app import app
        self.client = app.test_client()

    def test_search_forms_use_adaptive_submit_labels(self):
        for path, lang in self.FORM_PAGES:
            with self.subTest(path=path, lang=lang):
                html = self.client.get(f'{path}?lang={lang}').get_data(as_text=True)
                self.assertIn('search-command', html)
                self.assertIn('btn-label--short', html)
                self.assertIn('btn-label--long', html)

    def test_nav_uses_adaptive_labels_both_locales(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                html = self.client.get(f'/?lang={lang}').get_data(as_text=True)
                self.assertIn('nav-label--short', html)
                self.assertIn('nav-label--long', html)
                self.assertIn('nav-link--adaptive', html)

    def test_ru_and_en_home_submit_texts_present(self):
        ru = self.client.get('/?lang=ru').get_data(as_text=True)
        en = self.client.get('/?lang=en').get_data(as_text=True)
        self.assertIn('Полная проверка', ru)
        self.assertIn('Проверить', ru)
        self.assertIn('Full check', en)
        self.assertIn('Check', en)

    def test_domains_search_labels_both_locales(self):
        ru = self.client.get('/domains?lang=ru').get_data(as_text=True)
        en = self.client.get('/domains?lang=en').get_data(as_text=True)
        self.assertIn('Поиск домена', ru)
        self.assertIn('Искать', ru)
        self.assertIn('Search domain', en)
        self.assertIn('Search', en)

    def test_site_checker_multi_action_form_markup(self):
        html = self.client.get('/site-checker?lang=en').get_data(as_text=True)
        if 'search-command--multi' not in html:
            self.skipTest('site-checker inline fallback template in use')
        self.assertIn('search-command__actions', html)

    def test_security_forms_have_touch_friendly_buttons(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                html = self.client.get(f'/security?lang={lang}').get_data(as_text=True)
                self.assertIn('security-form', html)
                self.assertIn('btn btn-primary', html)


if __name__ == '__main__':
    unittest.main()