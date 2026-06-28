import re
import unittest
from unittest.mock import patch

import app as app_module

_CYRILLIC_RE = re.compile(r'[а-яёА-ЯЁ]')

# Common Russian UI copy that must not appear on lang=en pages (visible markup).
_EN_PAGE_RU_LEAKS = (
    'Проверить домены',
    'Найти домены',
    'Подбор и проверка',
    'Полная проверка',
    'Проверить безопасность',
    'Куда ведёт',
    'Кто владелец',
    'Проверка сайта',
    'Скопировано!',
    'Перейти к содержимому',
    'Простой режим',
    'Режим специалиста',
    'Показать все зоны',
    'Скрыть лишние зоны',
    'Рекомендуемые',
    'Сброс',
    'Варианты транслитерации',
)

_EN_MAIN_PAGES = (
    '/',
    '/domains',
    '/report',
    '/whois',
    '/dns',
    '/check/example.com',
    '/security',
    '/hosting',
    '/registrars',
    '/geo',
    '/reverse',
    '/site-checker',
)


class I18nUserStringsTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def _get(self, path: str, lang: str):
        sep = '&' if '?' in path else '?'
        return self.client.get(f'{path}{sep}lang={lang}')

    def test_domains_page_ru_has_no_smart_query_english_leaks(self):
        html = self._get('/domains', 'ru').get_data(as_text=True)
        self.assertIn('lang="ru"', html)
        self.assertIn('Проверить домены', html)
        self.assertNotIn('Find domains', html)
        self.assertNotIn('Check domains', html)
        self.assertNotIn('Search availability', html)

    def test_domains_page_en_uses_english_submit_labels(self):
        html = self._get('/domains', 'en').get_data(as_text=True)
        self.assertIn('lang="en"', html)
        self.assertIn('Check domains', html)
        self.assertIn('Find and check', html)
        self.assertNotIn('Проверить домены', html)
        self.assertNotIn('Подбор и проверка', html)

    def test_domains_zone_counter_data_attrs_keep_both_locales(self):
        for lang, selected_ru, selected_en in (
            ('ru', 'Выбрано', 'Selected'),
            ('en', 'Выбрано', 'Selected'),
        ):
            with self.subTest(lang=lang):
                html = self._get('/domains', lang).get_data(as_text=True)
                self.assertIn(f'data-selected-label-ru="{selected_ru}"', html)
                self.assertIn(f'data-selected-label-en="{selected_en}"', html)
                self.assertIn('data-limit-label-ru="Рекомендованный лимит"', html)
                self.assertIn('data-limit-label-en="Recommended limit"', html)

    def test_en_main_pages_have_no_common_russian_ui_strings(self):
        for path in _EN_MAIN_PAGES:
            with self.subTest(path=path):
                html = self._get(path, 'en').get_data(as_text=True)
                self.assertRegex(html, r'lang="en"|lang=en')
                for phrase in _EN_PAGE_RU_LEAKS:
                    self.assertNotIn(phrase, html, msg=f'{path} leaked {phrase!r}')

    def test_en_mobile_nav_uses_english_long_labels(self):
        html = self._get('/', 'en').get_data(as_text=True)
        self.assertIn('nav-label--long">Full Check', html)
        self.assertIn('nav-label--long">Where It Points', html)
        self.assertIn('nav-label--long">Who Owns It', html)
        self.assertIn('nav-label--long">Site Checker', html)
        self.assertIn('nav-label--long">Check Security', html)
        long_labels = re.findall(r'nav-label--long">([^<]+)', html)
        cyrillic = [label for label in long_labels if _CYRILLIC_RE.search(label)]
        self.assertEqual(cyrillic, [])

    def test_api_resolve_en_has_no_cyrillic_in_labels(self):
        cases = (
            ('mybrand', 'domains'),
            ('mybrand', 'home'),
            ('example.com', 'check'),
            ('example.com', 'whois'),
            ('example.com', 'dns'),
            ('8.8.8.8', 'geo'),
            ('@@@', 'home'),
            ('coffee shop nyc', 'home'),
        )
        for query, context in cases:
            with self.subTest(query=query, context=context):
                resp = self.client.get(
                    f'/api/resolve?q={query}&context={context}&lang=en'
                )
                data = resp.get_json() or {}
                texts = [
                    data.get('action_label') or '',
                    data.get('intent_label') or '',
                    data.get('error') or '',
                ]
                for alt in data.get('alternatives') or []:
                    texts.append(alt.get('label') or '')
                for text in texts:
                    if text:
                        self.assertIsNone(
                            _CYRILLIC_RE.search(text),
                            msg=f'Cyrillic in {text!r} for q={query!r} context={context}',
                        )

    def test_api_resolve_label_domains_context_locales(self):
        for lang, action, intent_part in (
            ('ru', 'Проверить домены', 'Проверка доступности'),
            ('en', 'Check domains', 'Search availability'),
        ):
            with self.subTest(lang=lang):
                resp = self.client.get(f'/api/resolve?q=mybrand&context=domains&lang={lang}')
                data = resp.get_json()
                self.assertEqual(data.get('action_label'), action)
                self.assertIn(intent_part, data.get('intent_label', ''))

    def test_api_resolve_fqdn_check_context_locales(self):
        for lang, action_part in (
            ('ru', 'Проверить'),
            ('en', 'Check'),
        ):
            with self.subTest(lang=lang):
                resp = self.client.get(f'/api/resolve?q=example.com&context=check&lang={lang}')
                data = resp.get_json()
                self.assertIn(action_part, data.get('action_label', ''))

    def test_api_resolve_ideas_home_context_locales(self):
        for lang, action, intent_part in (
            ('ru', 'Подобрать имена', 'описание проекта'),
            ('en', 'Generate ideas', 'project description'),
        ):
            with self.subTest(lang=lang):
                resp = self.client.get(f'/api/resolve?q=coffee+shop+nyc&context=home&lang={lang}')
                data = resp.get_json()
                self.assertEqual(data.get('action_label'), action)
                self.assertIn(intent_part, data.get('intent_label', '').lower())

    def test_tool_rate_limit_message_locale(self):
        with patch.object(app_module, '_endpoint_ip_rate_limited', return_value=True):
            with app_module.app.test_request_context('/whois?lang=ru'):
                msg = app_module._tool_rate_limited('whois')
            self.assertIn('Слишком много запросов', msg or '')
            with app_module.app.test_request_context('/whois?lang=en'):
                msg_en = app_module._tool_rate_limited('whois')
            self.assertIn('Too many requests', msg_en or '')

    def test_security_host_validation_messages_locale(self):
        with app_module.app.test_request_context('/security?lang=ru'):
            host, err = app_module._normalize_security_host_input('')
            self.assertIsNone(host)
            self.assertEqual(err, 'Пустой хост')
        with app_module.app.test_request_context('/security?lang=en'):
            host, err = app_module._normalize_security_host_input('')
            self.assertEqual(err, 'Empty host')

    def test_captcha_error_messages_locale(self):
        cfg = app_module.app.config
        prev = cfg.get('SECURITY_RECAPTCHA_ENABLED')
        cfg['SECURITY_RECAPTCHA_ENABLED'] = True
        try:
            with app_module.app.test_request_context('/report?lang=ru', method='POST'):
                ok, err = app_module._verify_recaptcha_token('', action='form_submit')
            self.assertFalse(ok)
            self.assertEqual(err, 'Отсутствует токен captcha.')
            with app_module.app.test_request_context('/report?lang=en', method='POST'):
                ok, err = app_module._verify_recaptcha_token('', action='form_submit')
            self.assertFalse(ok)
            self.assertEqual(err, 'Captcha token is missing.')
        finally:
            cfg['SECURITY_RECAPTCHA_ENABLED'] = prev


if __name__ == '__main__':
    unittest.main()