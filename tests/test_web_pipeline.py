import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scanner.pipeline_runner import failed_result


class WebWorkerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot = tempfile.TemporaryDirectory()
        cls.environment = patch.dict(os.environ, {'SCAN_FOLDER': cls.boot.name, 'MOBSF_API_KEY': ''})
        cls.environment.start()
        from web.app import app
        cls.app = app

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()
        cls.boot.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.app.config.update(SCAN_FOLDER=self.temp.name, TESTING=True, APK_ANALYSIS_TIMEOUT=0.001)
        for name in ('apk', 'csv', 'uploads', 'other'):
            (Path(self.temp.name)/name).mkdir()
        self.client = self.app.test_client()

    def test_upload_real_worker_timeout_returns_504_not_safe(self):
        # Deliberately tiny deadline covers process start, preflight and layer 1.
        response = self.client.post('/scan/apk', data={'file': (io.BytesIO(b'not executed'), 'sample.apk')})
        self.assertEqual(response.status_code, 504)
        result = response.get_json()['ai_result']
        self.assertEqual(result['analysis_status'], 'timeout')
        self.assertEqual(result['verdict']['level'], 'unknown')
        self.assertIsNone(result['deep']['layer3']['score'])

    def test_upload_never_calls_layer1_in_web_process(self):
        failure = failed_result('worker timeout', 'sample.apk', 'timeout', 504)
        with patch('web.app.detector') as detector, \
             patch('web.app.analyze_apk_pipeline', return_value=failure) as worker, \
             patch('web.app.dynamic_task_queue.put') as queue:
            response = self.client.post('/scan/apk', data={'file': (io.BytesIO(b'bytes'), 'sample.apk')})
        self.assertEqual(response.status_code, 504)
        detector.analyze_apk.assert_not_called()
        queue.assert_not_called()
        self.assertTrue(Path(worker.call_args.args[0]).is_file())
        self.assertEqual(worker.call_args.kwargs['timeout'], 0.001)
        self.assertTrue(callable(worker.call_args.kwargs['progress']))

    def test_file_manager_uses_same_deadline_and_failure_contract(self):
        path = Path(self.temp.name)/'apk'/'test.apk';path.write_bytes(b'bytes')
        with patch('web.app.detector') as detector, \
             patch('web.app.analyze_apk_pipeline', return_value=failed_result('timeout', 'test.apk', 'timeout', 504)) as worker:
            response = self.client.get('/file-manager/scan/apk/test.apk')
        self.assertEqual(response.status_code, 504)
        detector.analyze_apk.assert_not_called()
        self.assertEqual(worker.call_args.kwargs['timeout'], 0.001)
        self.assertIsNone(response.get_json()['confidence'])

    def test_upload_preflight_rejection_and_bad_extension(self):
        self.app.config['APK_ANALYSIS_TIMEOUT'] = 30
        response = self.client.post('/scan/apk', data={'file': (io.BytesIO(b'not zip'), 'bad.apk')})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.get_json()['ai_result']['analysis_status'], 'rejected')
        response = self.client.post('/scan/apk', data={'file': (io.BytesIO(b'bytes'), 'other.txt')})
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
