import csv
import json
from pathlib import Path
import tempfile
import unittest

from scripts.evaluate_layers import evaluate, metrics, load_records


class TechniqueEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sha = 'a' * 64

    def fixture(self, labels=None, findings=None, **extra):
        findings = findings or []
        layer = {'status': 'completed', 'available': True, 'truncated': False,
                 'sha256': self.sha, 'score': 1, 'findings': findings, 'finding_count': len(findings)}
        (self.root/'report.json').write_text(json.dumps({'layer2': dict(layer), 'layer3': dict(layer)}))
        row = {'sample_id': 'S001', 'sha256': self.sha, 'report': 'report.json',
               'labels': labels or {'reflection': True}, **extra}
        path = self.root/'labels.json'
        path.write_text(json.dumps([row]), encoding='utf-8')
        return path

    def test_unknown_is_excluded_not_tn(self):
        result = evaluate(self.fixture({'reflection': 'Chưa xác định'}))['techniques']['reflection']
        self.assertEqual(result['evaluated'], 0)
        self.assertEqual(result['tn'], 0)
        self.assertEqual(result['unknown_labels'], 1)
        self.assertEqual(result['exclusions'][0]['reason'], 'label_unknown')

    def test_technique_presence_does_not_use_aggregate_threshold(self):
        path = self.fixture(findings=[{'rule_id': 'reflection', 'class_name': 'Lapp/Main;'}])
        result = evaluate(path)['techniques']['reflection']
        self.assertEqual(result['tp'], 1)

    def test_no_gold_positives_keeps_f1_null_even_with_fp(self):
        result = metrics([(False, True)])
        self.assertEqual(result['fp'], 1)
        self.assertIsNone(result['recall'])
        self.assertIsNone(result['f1'])

    def test_scoped_labels_do_not_include_library_findings(self):
        path = self.fixture({'reflection': False}, [{'rule_id': 'reflection', 'class_name': 'Lsdk/Other;'}],
                            scope_classes=['Lapp/Main;'])
        self.assertEqual(evaluate(path)['techniques']['reflection']['tn'], 1)

    def test_file_indicator_is_not_compared_to_class_scope(self):
        path = self.fixture({'embedded_payload': False}, scope_classes=['Lapp/Main;'])
        result = evaluate(path)['techniques']['embedded_payload']
        self.assertEqual(result['evaluated'], 0)
        self.assertIn('scope', result['exclusions'][0]['reason'])

    def test_hash_mismatch_in_either_layer_rejected(self):
        path = self.fixture()
        report_path = self.root/'report.json'
        report = json.loads(report_path.read_text())
        report['layer3']['sha256'] = 'b' * 64
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            evaluate(path)

    def test_missing_expected_hash_rejected(self):
        path = self.fixture()
        rows = json.loads(path.read_text()); del rows[0]['sha256']
        path.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            evaluate(path)

    def test_missing_report_has_coverage_and_reason(self):
        path = self.fixture()
        (self.root/'report.json').unlink()
        result = evaluate(path)['techniques']['reflection']
        self.assertEqual(result['coverage'], 0)
        self.assertEqual(result['known_labels'], 1)
        self.assertEqual(result['exclusions'][0]['reason'], 'report_missing')

    def test_truncated_report_is_not_a_negative(self):
        path = self.fixture()
        report_path = self.root/'report.json'
        report = json.loads(report_path.read_text()); report['layer2']['truncated'] = True
        report_path.write_text(json.dumps(report))
        result = evaluate(path)['techniques']['reflection']
        self.assertEqual(result['fn'], 0)
        self.assertEqual(result['exclusions'][0]['reason'], 'truncated')

    def test_omitted_findings_cannot_silently_become_negative(self):
        path = self.fixture()
        report_path = self.root/'report.json'
        report = json.loads(report_path.read_text()); report['layer2']['finding_count'] = 3
        report_path.write_text(json.dumps(report))
        result = evaluate(path)['techniques']['reflection']
        self.assertEqual(result['evaluated'], 0)
        self.assertEqual(result['exclusions'][0]['reason'], 'truncated')

    def test_crypto_and_base64_api_are_not_encoded_constant_proof(self):
        path = self.fixture({'encoded_strings': False}, [{'rule_id': 'crypto'}, {'rule_id': 'base64_decode'}])
        self.assertEqual(evaluate(path)['techniques']['encoded_strings']['tn'], 1)

    def test_frozen_endpoint_remains_reflection_or_dynamic(self):
        path = self.fixture(findings=[{'rule_id': 'dynamic_dex', 'class_name': 'Lapp/Main;'}],
                            layer2_reflection=True, layer2_dynamic_dex=True, layer2_positive=True,
                            scope_classes=['Lapp/Main;'])
        result = evaluate(path)
        self.assertEqual(result['layer2']['tp'], 1)
        self.assertEqual(result['techniques']['reflection']['fn'], 1)
        self.assertEqual(result['techniques']['dynamic_loading']['tp'], 1)

    def test_long_csv_joins_manifest_and_rejects_duplicates(self):
        labels = self.root/'labels.csv'; manifest = self.root/'manifest.csv'
        with manifest.open('w', newline='', encoding='utf-8-sig') as stream:
            writer = csv.DictWriter(stream, fieldnames=['sample_id', 'sha256', 'local_path'])
            writer.writeheader(); writer.writerow({'sample_id': 'DB001', 'sha256': self.sha, 'local_path': 'sample.apk.disabled'})
        with labels.open('w', newline='', encoding='utf-8-sig') as stream:
            writer = csv.DictWriter(stream, fieldnames=['sample_id', 'technique', 'status'])
            writer.writeheader(); writer.writerow({'sample_id': 'DB001', 'technique': 'reflection', 'status': 'Có'})
        rows = load_records(labels, manifest, self.root/'reports')
        self.assertTrue(rows[0]['labels']['reflection'])
        self.assertEqual(rows[0]['sha256'], self.sha)
        with labels.open('a', newline='', encoding='utf-8') as stream:
            stream.write('DB001,reflection,Không\n')
        with self.assertRaisesRegex(ValueError, 'lặp'):
            load_records(labels, manifest)


if __name__ == '__main__':
    unittest.main()
