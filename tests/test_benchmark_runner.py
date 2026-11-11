import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_benchmark import run


class BenchmarkRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        apk = self.root/'fixture.apk.disabled'; apk.write_bytes(b'never execute this fixture')
        self.sha = hashlib.sha256(apk.read_bytes()).hexdigest()
        self.labels = self.root/'labels.json'
        self.labels.write_text(json.dumps([{'sample_id': 'S001', 'sha256': self.sha,
                                            'apk': apk.name, 'labels': {'reflection': True}}]))

    def test_existing_run_refused_without_overwriting(self):
        output = self.root/'old'; output.mkdir(); (output/'baseline.txt').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'đã tồn tại'):
            run(self.labels, output)
        self.assertEqual((output/'baseline.txt').read_text(), 'keep')

    def test_apk_hash_mismatch_fails_before_scanning_or_output(self):
        (self.root/'fixture.apk.disabled').write_bytes(b'changed')
        with patch('scanner.analysis_runner.run_deep_analysis') as scan:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                run(self.labels, self.root/'new')
        scan.assert_not_called(); self.assertFalse((self.root/'new').exists())

    def test_new_run_freezes_inputs_and_evaluates_actual_new_reports(self):
        finding = {'rule_id': 'reflection', 'class_name': 'Lapp/Main;'}
        layer = {'status': 'completed', 'available': True, 'sha256': self.sha,
                 'score': 1, 'findings': [finding], 'finding_count': 1}
        report = {'layer2': layer, 'layer3': dict(layer), 'info': {'sha256': self.sha}}
        before = self.labels.read_bytes()
        with patch('scanner.analysis_runner.run_deep_analysis', return_value=report):
            result = run(self.labels, self.root/'new', workers=1)
        self.assertEqual(result['techniques']['reflection']['tp'], 1)
        self.assertEqual(self.labels.read_bytes(), before)
        meta = json.loads((self.root/'new/run_metadata.json').read_text())
        self.assertEqual(meta['status'], 'completed')
        self.assertTrue(meta['inputs_and_detector_unchanged'])
        self.assertIn('S001.json', meta['report_sha256'])


if __name__ == '__main__':
    unittest.main()
