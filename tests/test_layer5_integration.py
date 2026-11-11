"""Contract checks between current layer reports and the fetched family-B scorer."""
import json
from pathlib import Path
import unittest

from scanner.analysis_runner import unavailable_report
from scanner.capabilities import capabilities_of
from scanner.code_layers import LAYER2_RULES, SOURCES, URI_SOURCES
from scanner.family_scores import score_family_b


def layer(*findings, **kwargs):
    return {'status': 'completed', 'available': True, 'findings': list(findings), **kwargs}


def finding(rule_id, **kwargs):
    return {'rule_id': rule_id, 'severity': 'info', 'origin': 'application', **kwargs}


class Layer5IntegrationTests(unittest.TestCase):
    def test_current_api_rules_and_all_sensitive_source_types_are_supported(self):
        for rule, *_ in LAYER2_RULES:
            with self.subTest(rule=rule):
                self.assertTrue(capabilities_of(finding(rule)))
        data_types = set(SOURCES.values()) | {data_type for _, data_type in URI_SOURCES}
        for data_type in data_types:
            with self.subTest(data_type=data_type):
                self.assertTrue(capabilities_of(finding('sensitive_network_same_method', data_types=[data_type])))

    def test_loader_api_combination_and_yara_are_one_capability(self):
        result = score_family_b(layer(
            finding('dynamic_dex', severity='medium'),
            finding('loader_with_encoding', severity='medium'),
            finding('yara_DEX_Dynamic_Load_Reflection', severity='low')), None)
        self.assertAlmostEqual(result['score'], .35)
        self.assertEqual(len(result['evidence']), 1)

    def test_unavailable_layers_do_not_become_clean_zero(self):
        report = unavailable_report('parser failed')
        result = score_family_b(report['layer2'], report['layer3'])
        self.assertFalse(result['available'])
        self.assertIsNone(result['score'])
        self.assertEqual(report['family_b']['status'], 'unavailable')

    def test_partial_or_truncated_evidence_has_no_completed_score(self):
        for kwargs in ({'status': 'partial'}, {'truncated': True}, {'analysis_errors': 1}):
            with self.subTest(kwargs=kwargs):
                result = score_family_b(layer(finding('reflection', severity='low'), **kwargs), layer())
                self.assertIsNone(result['score'])
                self.assertAlmostEqual(result['observed_score'], .15)
                self.assertEqual(result['status'], 'partial')

    def test_only_one_parsed_layer_cannot_hide_other_layer_failure(self):
        result = score_family_b(layer(), unavailable_report('failed')['layer3'])
        self.assertIsNone(result['score'])
        self.assertEqual(result['status'], 'partial')

    def test_unknown_rule_metadata_is_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            capabilities_of(finding('yara_unknown_rule', technique='dynamic_dex'))

    def test_saved_application_reports_can_feed_the_family_scorer(self):
        root = Path(__file__).resolve().parents[1] / 'reports'
        paths = sorted(root.glob('benchmark_*v2_2/reports/*.json'))
        if not paths:
            self.skipTest('Local application reports are not distributed with code')
        for path in paths:
            with self.subTest(report=path.name):
                report = json.loads(path.read_text(encoding='utf-8'))
                result = score_family_b(report['layer2'], report['layer3'])
                self.assertTrue(result['available'])
                self.assertTrue(0 <= result['observed_score'] <= .95)


if __name__ == '__main__':
    unittest.main()
