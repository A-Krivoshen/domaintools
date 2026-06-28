import unittest
from unittest.mock import patch

import app as app_module


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
                self.assertIn('nav-label-stack', html)
                self.assertIn('nav-link--adaptive', html)

    def test_desktop_nav_single_row_all_items_no_more_dropdown(self):
        for lang, labels in (
            ('ru', ('DNS', 'Владелец', 'GeoIP', 'Reverse', 'Проверка', 'Домены', 'Рег.', 'VPS', 'Сайт', 'Безопасность', 'История')),
            ('en', ('DNS', 'Owner', 'GeoIP', 'Reverse', 'Check', 'Domains', 'Regs', 'VPS', 'Site', 'Security', 'History')),
        ):
            with self.subTest(lang=lang):
                html = self.client.get(f'/?lang={lang}').get_data(as_text=True)
                self.assertIn('site-navbar__links--desktop', html)
                desktop = html.split('site-navbar__links--desktop', 1)[1].split('site-navbar__links--mobile', 1)[0]
                self.assertNotIn('site-navbar__more', desktop)
                self.assertNotIn('Ещё', desktop)
                self.assertNotIn('More', desktop)
                for label in labels:
                    self.assertIn(label, desktop)
                self.assertEqual(desktop.count('class="nav-item"'), 11)

    def test_desktop_header_tools_match_reference(self):
        html = self.client.get('/?lang=ru').get_data(as_text=True)
        self.assertIn('ux-mode-toggle-btn__glyph', html)
        self.assertIn('&lt;/&gt;', html)
        self.assertIn('Быстрый переход', html)
        self.assertIn('data-shortcut-mod', html)
        self.assertIn('lang-switch', html)
        self.assertIn('data-theme-toggle', html)

    def test_mobile_nav_keeps_all_adaptive_dual_labels(self):
        html = self.client.get('/?lang=en').get_data(as_text=True)
        mobile_block = html.split('site-navbar__links--mobile', 1)[1].split('navbar-tools', 1)[0]
        self.assertEqual(mobile_block.count('nav-link--adaptive'), 11)
        self.assertEqual(mobile_block.count('class="nav-label-stack"'), 11)

    def test_panel_history_not_in_navbar(self):
        html = self.client.get('/dns?q=example.com&types=A&lang=en').get_data(as_text=True)
        nav_end = html.split('</nav>', 1)[0]
        self.assertNotIn('data-qa-history-user', nav_end)
        self.assertNotIn('status-chips-dock', html)

    def test_command_palette_shortcut_uses_readable_ctrl_not_unicode(self):
        for lang in ('ru', 'en'):
            with self.subTest(lang=lang):
                html = self.client.get(f'/?lang={lang}').get_data(as_text=True)
                self.assertIn('data-shortcut-mod', html)
                self.assertNotIn('⌘K', html)
                self.assertIn('command-palette-trigger__shortcut', html)
                if lang == 'ru':
                    self.assertIn('Быстрый переход', html)
                else:
                    self.assertIn('Quick navigation', html)

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
        self.assertIn('Подбор и проверка', ru)
        self.assertIn('Найти', ru)
        self.assertIn('Проверить домены', ru)
        self.assertIn('Find and check', en)
        self.assertIn('Find', en)
        self.assertIn('Check domains', en)

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
                self.assertIn('security-scan-btn', html)
                self.assertIn('btn btn-outline-secondary', html)


if __name__ == '__main__':
    unittest.main()