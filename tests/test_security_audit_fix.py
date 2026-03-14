import unittest

import app as app_module


class _ImmediatePool:
    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)
        class _Done:
            def result(self):
                return None
        return _Done()


class _FailingPool:
    def submit(self, fn, *args, **kwargs):
        raise RuntimeError('pool down')


class SecurityAuditFixTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

        # snapshot mutable globals/config used in tests
        self._cfg_snapshot = dict(self.app.config)
        self._pool_snapshot = app_module._SECURITY_ASYNC_POOL
        self._job_local_snapshot = dict(app_module._SECURITY_JOB_LOCAL)
        self._run_port_snapshot = app_module._run_port_scan_result
        self._run_wp_snapshot = app_module._run_wp_scan_result

        self.app.config['TESTING'] = True
        self.app.config['SECURITY_RECAPTCHA_ENABLED'] = False
        self.app.config['SECURITY_METRICS_PUBLIC'] = False

    def tearDown(self):
        self.app.config.clear()
        self.app.config.update(self._cfg_snapshot)
        app_module._SECURITY_ASYNC_POOL = self._pool_snapshot
        app_module._SECURITY_JOB_LOCAL.clear()
        app_module._SECURITY_JOB_LOCAL.update(self._job_local_snapshot)
        app_module._run_port_scan_result = self._run_port_snapshot
        app_module._run_wp_scan_result = self._run_wp_snapshot

    def test_security_get_no_longer_runs_sync_fallback(self):
        def _must_not_run(*_a, **_kw):
            raise AssertionError('sync scan fallback should not execute on GET /security')

        app_module._run_port_scan_result = _must_not_run

        resp = self.client.get('/security?scan=ports&host=example.com&ports=80')
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertNotIn('sync scan fallback should not execute', body)

    def test_security_job_lifecycle_contains_duration_and_error_code(self):
        app_module._SECURITY_ASYNC_POOL = _ImmediatePool()

        def _fake_execute(job_id, job_kind, payload):
            app_module._save_security_job(job_id, {
                'status': 'done',
                'kind': job_kind,
                'payload': payload,
                'result': {'ok': True},
                'error': None,
                'error_code': None,
                'duration_ms': 7,
                'permalink': None,
            })

        original_execute = app_module._execute_security_job
        app_module._execute_security_job = _fake_execute
        try:
            r = self.client.post('/security', data={'scan': 'ports', 'host': 'example.com', 'ports': '80'})
            self.assertIn(r.status_code, (301, 302))
            location = r.headers.get('Location', '')
            self.assertIn('job=', location)
            job_id = location.split('job=', 1)[1].split('&', 1)[0]

            jr = self.client.get(f'/security/jobs/{job_id}')
            self.assertEqual(jr.status_code, 200)
            data = jr.get_json()
            self.assertTrue(data.get('ok'))
            self.assertEqual(data.get('status'), 'done')
            self.assertIn('duration_ms', data)
            self.assertIn('error_code', data)
        finally:
            app_module._execute_security_job = original_execute


    def test_security_invalid_host_returns_validation_error_without_request_context_failure(self):
        app_module._SECURITY_ASYNC_POOL = _ImmediatePool()

        r = self.client.post('/security', data={'scan': 'ports', 'host': '[io[o[o]', 'ports': '80'})
        self.assertIn(r.status_code, (301, 302))
        location = r.headers.get('Location', '')
        self.assertIn('job=', location)
        job_id = location.split('job=', 1)[1].split('&', 1)[0]

        jr = self.client.get(f'/security/jobs/{job_id}')
        self.assertEqual(jr.status_code, 200)
        data = jr.get_json()
        self.assertTrue(data.get('ok'))
        self.assertEqual(data.get('status'), 'failed')
        self.assertEqual(data.get('error_code'), 'validation_error')
        self.assertNotIn('Working outside of request context', data.get('error') or '')


    def test_security_submit_failure_sets_human_error_message(self):
        app_module._SECURITY_ASYNC_POOL = _FailingPool()

        r = self.client.post('/security', data={'scan': 'ports', 'host': 'example.com', 'ports': '80'})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('Could not start scan job. Please retry.', body)
        self.assertNotIn('pool down', body)


    def test_security_internal_job_error_is_sanitized(self):
        app_module._SECURITY_ASYNC_POOL = _ImmediatePool()

        def _boom(*_a, **_kw):
            raise RuntimeError('secret backend stacktrace marker')

        app_module._run_port_scan_result = _boom

        r = self.client.post('/security', data={'scan': 'ports', 'host': 'example.com', 'ports': '80'})
        self.assertIn(r.status_code, (301, 302))
        location = r.headers.get('Location', '')
        self.assertIn('job=', location)
        job_id = location.split('job=', 1)[1].split('&', 1)[0]

        jr = self.client.get(f'/security/jobs/{job_id}')
        self.assertEqual(jr.status_code, 200)
        data = jr.get_json()
        self.assertEqual(data.get('status'), 'failed')
        self.assertEqual(data.get('error_code'), 'internal_error')
        self.assertEqual(data.get('error'), 'Internal scan error. Please retry later.')
        self.assertNotIn('secret backend stacktrace marker', data.get('error') or '')

    def test_security_jobs_endpoint_rejects_invalid_job_id(self):
        r = self.client.get('/security/jobs/not-a-valid-id')
        self.assertEqual(r.status_code, 400)
        data = r.get_json()
        self.assertEqual(data.get('error'), 'invalid_job_id')

    def test_security_page_shows_error_for_invalid_job_id_query(self):
        r = self.client.get('/security?job=not-a-valid-id')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('Invalid scan job id.', body)

    def test_security_metrics_public_flag(self):
        r1 = self.client.get('/security/metrics')
        self.assertEqual(r1.status_code, 404)

        self.app.config['SECURITY_METRICS_PUBLIC'] = True
        r2 = self.client.get('/security/metrics')
        self.assertEqual(r2.status_code, 200)
        data = r2.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('day', data)
        self.assertIn('current_minute', data)


if __name__ == '__main__':
    unittest.main()
