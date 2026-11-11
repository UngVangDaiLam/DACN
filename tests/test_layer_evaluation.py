import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_layers import evaluate, metrics


class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_and_fpr(self):
        result = metrics([(True, True), (True, False), (False, True), (False, False)])
        self.assertEqual([result[k] for k in ('tp', 'fp', 'fn', 'tn')], [1, 1, 1, 1])
        self.assertEqual(result['f1'], 0.5)
        self.assertEqual(result['false_positive_rate'], 0.5)

    def test_undefined_metrics_are_null_not_fake_perfect_scores(self):
        self.assertIsNone(metrics([])['recall'])
        self.assertIsNone(metrics([])['precision'])

    def make_manifest(self, root, duplicate=False):
        records = []
        for i, complete in enumerate((True, False)):
            layer = {'status': 'completed' if complete else 'unavailable', 'available': complete,
                     'score': 20 if complete else None, 'finding_count': 1 if complete else 0,
                     'findings': [{'rule_id': 'reflection'}] if complete else [],
                     'sha256': '0' * 64 if duplicate else f'{i:064x}'}
            path = root / f'{i}.json'
            path.write_text(json.dumps({'layer2': layer, 'layer3': layer}), encoding='utf-8')
            records.append({'report': path.name, 'sha256': layer['sha256'],
                            'layer2_positive': True, 'layer3_positive': True})
        labels = root / 'labels.json'
        labels.write_text(json.dumps(records), encoding='utf-8')
        return labels

    def test_incomplete_samples_report_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            result = evaluate(self.make_manifest(Path(temp)))
        self.assertEqual(result['layer2']['evaluated'], 1)
        self.assertEqual(result['layer2']['coverage'], 0.5)
        self.assertEqual(result['layer3']['unevaluated_sha256'], [f'{1:064x}'])

    def test_duplicate_sample_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                evaluate(self.make_manifest(Path(temp), duplicate=True))

    def test_label_string_is_not_treated_as_true(self):
        with tempfile.TemporaryDirectory() as temp:
            labels = self.make_manifest(Path(temp))
            records = json.loads(labels.read_text())
            records[0]['layer2_positive'] = 'false'
            labels.write_text(json.dumps(records))
            with self.assertRaises(ValueError):
                evaluate(labels)
