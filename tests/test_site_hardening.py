import unittest

import app as app_module  # noqa: F401 - registers the blueprint on the Flask app
import flask_site_checker.blueprint as site_bp
import flask_site_checker.services as services


class _FakeHeadRedirect:
    status_code = 302
    headers = {'Location': 'http://127.0.0.1/admin'}
    is_redirect = True
    is_permanent_redirect = False
    url = 'https://example.com'


class SiteHardeningTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()
        self._cfg_snapshot = dict(self.app.config)
        self._verify_snapshot = site_bp._verify_site_checker_captcha
        self._resolve_dns_snapshot = site_bp.resolve_dns
        self._http_check_snapshot = site_bp.http_check
        self._ip_info_snapshot = site_bp.ip_info_for_domain
        self._services_getaddrinfo_snapshot = services.socket.getaddrinfo
        self._services_head_snapshot = services.requests.head
        self.app.config['TESTING'] = True

    def tearDown(self):
        self.app.config.clear()
        self.app.config.update(self._cfg_snapshot)
        site_bp._verify_site_checker_captcha = self._verify_snapshot
        site_bp.resolve_dns = self._resolve_dns_snapshot
        site_bp.http_check = self._http_check_snapshot
        site_bp.ip_info_for_domain = self._ip_info_snapshot
        services.socket.getaddrinfo = self._services_getaddrinfo_snapshot
        services.requests.head = self._services_head_snapshot

    def test_site_checker_captcha_error_skips_expensive_checks(self):
        site_bp._verify_site_checker_captcha = lambda: 'captcha required'

        def _must_not_run(*_args, **_kwargs):
            raise AssertionError('expensive check should not run after captcha failure')

        site_bp.resolve_dns = _must_not_run
        site_bp.http_check = _must_not_run
        site_bp.ip_info_for_domain = _must_not_run

        r = self.client.post('/site-checker', data={'domain': 'example.com'})
        self.assertEqual(r.status_code, 200)
        self.assertIn('captcha required', r.get_data(as_text=True))

    def test_site_checker_http_check_blocks_redirect_to_private_ip(self):
        def _fake_getaddrinfo(host, *_args, **_kwargs):
            if host == 'example.com':
                return [(None, None, None, None, ('93.184.216.34', 0))]
            if host == '127.0.0.1':
                return [(None, None, None, None, ('127.0.0.1', 0))]
            raise AssertionError(f'unexpected host: {host}')

        services.socket.getaddrinfo = _fake_getaddrinfo
        services.requests.head = lambda *_args, **_kwargs: _FakeHeadRedirect()

        result = services.http_check('example.com')
        self.assertEqual(result.get('http_code'), 302)
        self.assertIn('Resolved host does not have a public IP.', result.get('error') or '')


class ReportCaptchaTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()
        self._cfg_snapshot = dict(self.app.config)
        self._verify_snapshot = app_module._verify_form_recaptcha_if_needed
        self._pool_snapshot = app_module._REPORT_ASYNC_POOL
        self.app.config['TESTING'] = True

    def tearDown(self):
        self.app.config.clear()
        self.app.config.update(self._cfg_snapshot)
        app_module._verify_form_recaptcha_if_needed = self._verify_snapshot
        app_module._REPORT_ASYNC_POOL = self._pool_snapshot

    def test_domain_report_calls_captcha_validation_even_without_token(self):
        app_module._verify_form_recaptcha_if_needed = lambda: 'captcha required'

        class _MustNotQueue:
            def submit(self, *_args, **_kwargs):
                raise AssertionError('report job should not be queued after captcha failure')

        app_module._REPORT_ASYNC_POOL = _MustNotQueue()
        r = self.client.post('/report', data={'q': 'example.com, example.org'})
        self.assertEqual(r.status_code, 200)
        self.assertIn('captcha required', r.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
