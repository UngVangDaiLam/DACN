import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scanner.pipeline_runner import run_apk_analysis, _analyze_in_worker


class PipelineDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'fixture.apk'
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr('AndroidManifest.xml', b'not parsed in timeout tests')

    def test_real_worker_timeout_returns_unknown_for_every_layer(self):
        result = run_apk_analysis(self.path, timeout=0.001)
        self.assertFalse(result['success'])
        self.assertEqual(result['analysis_status'], 'timeout')
        self.assertEqual(result['http_status'], 504)
        self.assertIsNone(result['verdict']['final_score'])
        for key in ('layer2', 'layer3'):
            self.assertEqual(result['deep'][key]['status'], 'unavailable')
            self.assertIsNone(result['deep'][key]['score'])

    def test_preflight_rejection_never_starts_the_parsers(self):
        with patch('scanner.pipeline_runner.preflight', side_effect=ValueError('expansion limit')), \
             patch('scanner.deep_analysis.analyze_deep') as deep:
            result = _analyze_in_worker(self.path, 'fixture.apk')
        deep.assert_not_called()
        self.assertEqual(result['analysis_status'], 'rejected')
        self.assertEqual(result['http_status'], 422)

    def test_missing_model_preserves_layers_but_cannot_claim_safe(self):
        layer = {'status': 'completed', 'score': 0, 'available': True}
        deep_report = {'info': {'sha256': 'a'*64, 'version_name': '1'},
                       'layer2': layer, 'layer3': layer, 'rule_score': 0}
        with patch('scanner.detect_and_classify.MalwareDetector', side_effect=FileNotFoundError('model')), \
             patch('scanner.deep_analysis.analyze_deep', return_value=deep_report):
            result = _analyze_in_worker(self.path, 'fixture.apk')
        self.assertTrue(result['success'])
        self.assertTrue(result['analysis_incomplete'])
        self.assertEqual(result['deep']['layer3']['status'], 'completed')
        self.assertEqual(result['verdict']['level'], 'unknown')

    def test_worker_crash_does_not_become_score_zero(self):
        with patch('scanner.pipeline_runner.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'worker')):
            result = run_apk_analysis(self.path)
        self.assertFalse(result['success'])
        self.assertIsNone(result['deep']['layer2']['score'])

    def test_invalid_timeout_rejected(self):
        for value in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                run_apk_analysis(self.path, timeout=value)


if __name__ == '__main__':
    unittest.main()
