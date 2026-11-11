import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scanner.artifact_scan import scan_artifacts, _compile_rules, RULE_FILE
from scanner.analysis_runner import run_deep_analysis, preflight
from scanner.code_layers import analyze_code_layers, MAX_FINDINGS
from test_code_layers import Method, call, SOURCE, SINK, DEX, analyze


def string_ref(method, value, offset=8):
    return SimpleNamespace(get_value=lambda: value,
                           get_xref_from=lambda with_offset: [(None, method, offset)])


class CompletedCodeLayersTests(unittest.TestCase):
    def test_empty_analysis_is_unavailable_and_not_zero(self):
        report = analyze([])
        for layer in report.values():
            self.assertFalse(layer['available'])
            self.assertIsNone(layer['score'])
            self.assertEqual(layer['status'], 'unavailable')
            self.assertTrue(layer['requires_dynamic_confirmation'])

    def test_clean_analyzed_method_has_zero_score(self):
        for layer in analyze([Method('Lorg/example/Main;', 'clean')]).values():
            self.assertTrue(layer['available'])
            self.assertEqual(layer['score'], 0)

    def test_partial_analysis_does_not_claim_zero(self):
        method = Method('Lorg/example/Main;', 'broken')
        method.get_xref_to = lambda: (_ for _ in ()).throw(ValueError('broken method'))
        for layer in analyze([method]).values():
            self.assertEqual(layer['status'], 'partial')
            self.assertIsNone(layer['score'])
            self.assertIn('broken method', layer['issues'][0]['reason'])

    def test_sms_contentresolver_query_is_contextual_source(self):
        query = call('Landroid/content/ContentResolver;', 'query')
        method = Method('Lorg/example/Main;', 'sendSms', [query, SINK])
        report = analyze([method], [string_ref(method, 'content://sms/inbox')])
        hit = report['layer3']['findings'][0]
        self.assertEqual(hit['data_types'], ['SMS'])
        self.assertFalse(hit['flow_confirmed'])
        self.assertIn('uri_evidence', hit['sources'][0])

    def test_uri_without_query_does_not_become_source(self):
        method = Method('Lorg/example/Main;', 'send', [SINK])
        report = analyze([method], [string_ref(method, 'content://sms')])
        self.assertEqual(report['layer3']['finding_count'], 0)

    def test_uri_in_another_function_is_not_merged(self):
        method = Method('Lorg/example/Main;', 'send', [call('Landroid/content/ContentResolver;', 'query'), SINK])
        other = Method('Lorg/example/Main;', 'other')
        report = analyze([method, other], [string_ref(other, 'content://sms')])
        self.assertEqual(report['layer3']['finding_count'], 0)

    def test_uri_authority_boundary(self):
        method = Method('Lorg/example/Main;', 'send', [call('Landroid/content/ContentResolver;', 'query'), SINK])
        report = analyze([method], [string_ref(method, 'content://sms.evil/inbox')])
        self.assertEqual(report['layer3']['finding_count'], 0)

    def test_uri_detection_survives_string_preview_limit(self):
        method = Method('Lorg/example/Main;', 'send', [call('Landroid/content/ContentResolver;', 'query'), SINK])
        strings = [string_ref(method, f'https://example.com/{i}', i) for i in range(40)]
        strings.append(string_ref(method, 'content://sms/inbox', 100))
        self.assertEqual(analyze([method], strings)['layer3']['finding_count'], 1)

    def test_android_contacts_content_uri_static_field(self):
        method = Method('Lorg/example/Main;', 'send', [call('Landroid/content/ContentResolver;', 'query'), SINK])
        field = SimpleNamespace(get_field=lambda: SimpleNamespace(
            get_class_name=lambda: 'Landroid/provider/ContactsContract$Contacts;', get_name=lambda: 'CONTENT_URI'))
        method.get_xref_read = lambda: [(None, field, 12)]
        report = analyze([method])
        self.assertEqual(report['layer3']['findings'][0]['data_types'], ['Danh bạ'])

    def test_library_risk_is_discounted_not_silently_removed(self):
        own = analyze([Method('Lorg/example/Main;', 'send', [SOURCE, SINK])])['layer3']
        lib = analyze([Method('Lcom/google/sdk/Main;', 'send', [SOURCE, SINK])])['layer3']
        self.assertLess(lib['score'], own['score'])
        self.assertEqual(lib['finding_count'], 1)

    def test_androguard_raw_encoded_field_tuple(self):
        method = Method('Lorg/example/Main;', 'send', [call('Landroid/content/ContentResolver;', 'query'), SINK])
        field = SimpleNamespace(get_class_name=lambda: 'Landroid/provider/CallLog$Calls;', get_name=lambda: 'CONTENT_URI')
        method.get_xref_read = lambda: [(None, field, 12)]
        layer = analyze([method])['layer3']
        self.assertEqual(layer['status'], 'completed', layer['issues'])
        self.assertEqual(layer['findings'][0]['data_types'], ['Nhật ký cuộc gọi'])

    def test_same_rule_repeated_does_not_inflate_score(self):
        one = analyze([Method('Lorg/example/Main;', 'load', [DEX])])['layer2']['score']
        many = analyze([Method('Lorg/example/Main;', f'load{i}', [DEX]) for i in range(150)])['layer2']
        self.assertEqual(many['score'], one)
        self.assertEqual(many['finding_count'], 150)

    def test_truncated_report_still_scores_all_techniques(self):
        methods = [Method('Lorg/example/Main;', f'load{i}', [DEX]) for i in range(MAX_FINDINGS)]
        methods.append(Method('Lcom/google/sdk/Main;', 'reflect', [call('Ljava/lang/reflect/Method;', 'invoke')]))
        layer = analyze(methods)['layer2']
        self.assertTrue(layer['truncated'])
        self.assertGreater(layer['score'], 20)

    def test_evidence_ids_stable_and_duplicates_removed(self):
        method = Method('Lorg/example/Main;', 'load', [DEX])
        first = analyze([method, method])['layer2']
        second = analyze([method])['layer2']
        self.assertEqual(first['finding_count'], 1)
        self.assertEqual(first['findings'][0]['evidence_id'], second['findings'][0]['evidence_id'])

    def test_loader_and_cipher_have_correlated_evidence(self):
        method = Method('Lorg/example/Main;', 'load', [DEX, call('Ljavax/crypto/Cipher;', 'doFinal')])
        hits = analyze([method])['layer2']['findings']
        self.assertIn('loader_with_encoding', [f['rule_id'] for f in hits])

    def test_bytecode_unavailable_keeps_artifact_evidence_partial(self):
        artifact = {'available': True, 'status': 'completed', 'findings': [], 'issue_count': 0}
        report = analyze_code_layers(SimpleNamespace(get_package=lambda: ''), None, {}, artifact)
        self.assertEqual(report['layer2']['status'], 'partial')
        self.assertIsNone(report['layer2']['score'])
        self.assertEqual(report['layer3']['status'], 'unavailable')

    def test_file_level_evidence_does_not_require_java_caller(self):
        artifact = {'available': True, 'status': 'completed', 'issue_count': 0,
                    'findings': [{'rule_id': 'yara_test', 'title': 'test', 'file_path': 'classes.dex', 'severity': 'info'}]}
        analysis = SimpleNamespace(get_methods=lambda: [Method('Lorg/example/Main;', 'clean')], get_strings=lambda: [])
        report = analyze_code_layers(SimpleNamespace(get_package=lambda: 'org.example'), analysis, {}, artifact)
        self.assertEqual(report['layer2']['status'], 'completed')
        self.assertEqual(report['layer2']['findings'][0]['file_path'], 'classes.dex')

    def test_yara_and_bytecode_same_technique_do_not_add_twice(self):
        artifact = {'available': True, 'status': 'completed', 'issue_count': 0,
                    'findings': [{'rule_id': 'yara_dex', 'technique': 'dynamic_dex', 'title': 'test', 'file_path': 'classes.dex', 'severity': 'info'}]}
        analysis = SimpleNamespace(get_methods=lambda: [Method('Lorg/example/Main;', 'load', [DEX])], get_strings=lambda: [])
        report = analyze_code_layers(SimpleNamespace(get_package=lambda: 'org.example'), analysis, {}, artifact)
        self.assertEqual(report['layer2']['score'], 20)
        self.assertEqual(report['layer2']['finding_count'], 2)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.apk'

    def write_zip(self, members):
        with zipfile.ZipFile(self.path, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in members.items():
                z.writestr(name, data)

    def test_real_yara_rules_positive_and_negative(self):
        rules = _compile_rules(RULE_FILE.read_text(encoding='utf-8'))
        data = b'dex\n035\x00' + b'Ldalvik/system/DexClassLoader;\x00Ljava/lang/reflect/Method;'
        self.assertIn('DEX_Dynamic_Load_Reflection', [m.rule for m in rules.match(data=data)])
        self.assertFalse(rules.match(data=b'harmless text'))

    def test_scans_uncompressed_members_not_zip_container(self):
        self.write_zip({'AndroidManifest.xml': b'fixture', 'classes.dex': b'dex\n035\0Ldalvik/system/DexClassLoader;Ljava/lang/reflect/Method;',
                        'assets/renamed.png': b'dex\n035\0payload', 'lib/arm64-v8a/libx.so': b'\x7fELFdlopen dlsym'})
        report = scan_artifacts(self.path)
        self.assertEqual(report['yara_status'], 'completed')
        self.assertEqual(report['counts']['yara_matches'], 2)
        self.assertEqual(report['embedded_payloads'], ['assets/renamed.png'])
        self.assertEqual(report['payload_details'][0]['kind'], 'dex')
        self.assertTrue(any(f['matches'][0]['offset'] >= 0 for f in report['findings']))

    def test_native_magic_required_not_just_extension(self):
        self.write_zip({'lib/x.so': b'dlopen dlsym'})
        self.assertFalse(scan_artifacts(self.path)['findings'])

    def test_dex_entropy_is_reported_as_indicator(self):
        self.write_zip({'classes.dex': b'dex\n035\0' + bytes(range(256)) * 32})
        report = scan_artifacts(self.path)
        self.assertEqual(report['counts']['high_entropy_dex'], 1)
        self.assertIn('dex_high_entropy', [f['rule_id'] for f in report['findings']])

    def test_missing_yara_is_explicit_and_artifacts_still_work(self):
        self.write_zip({'assets/payload.bin': b'dex\n035\0embedded'})
        with patch('scanner.artifact_scan._compile_rules', side_effect=ImportError('missing yara')):
            result = scan_artifacts(self.path)
        self.assertEqual(result['yara_status'], 'unavailable')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['counts']['embedded_payloads'], 1)

    def test_resource_limit_reports_partial(self):
        self.write_zip({'assets/x.bin': b'X' * 100})
        with patch('scanner.artifact_scan.MAX_MEMBER_BYTES', 10):
            result = scan_artifacts(self.path)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['counts'].get('members_scanned', 0), 0)

    def test_artifact_timeout_reports_partial(self):
        self.write_zip({'assets/x.bin': b'X'})
        self.assertEqual(scan_artifacts(self.path, timeout=0)['status'], 'partial')

    def test_invalid_archive_is_unavailable(self):
        self.path.write_bytes(b'invalid')
        result = scan_artifacts(self.path)
        self.assertFalse(result['available'])
        self.assertTrue(result['issues'])

    def test_animation_zip_is_not_executable_payload(self):
        import io
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as nested:
            nested.writestr('animation.json', '{}')
        self.write_zip({'assets/animation.zip': buffer.getvalue()})
        report = scan_artifacts(self.path)
        self.assertEqual(report['counts']['other_archives'], 1)
        self.assertEqual(report['embedded_payloads'], [])

    def test_preflight_rejects_missing_manifest(self):
        self.write_zip({'classes.dex': b'dex'})
        with self.assertRaises(ValueError):
            preflight(self.path)

    def test_runner_timeout_reports_null_score(self):
        self.write_zip({'AndroidManifest.xml': b'fixture'})
        with patch('scanner.analysis_runner.subprocess.run', side_effect=subprocess.TimeoutExpired('worker', 1)):
            result = run_deep_analysis(self.path, timeout=1)
        self.assertIsNone(result['layer2']['score'])
        self.assertIn('worker đã dừng', result['analysis_error'])

    def test_invalid_apk_runner_returns_both_layers(self):
        self.path.write_bytes(b'not an APK')
        result = run_deep_analysis(self.path)
        self.assertEqual(result['layer2']['status'], 'unavailable')
        self.assertEqual(result['layer3']['status'], 'unavailable')
        json.dumps(result, allow_nan=False)

    def test_real_subprocess_timeout(self):
        self.write_zip({'AndroidManifest.xml': b'fixture'})
        result = run_deep_analysis(self.path, timeout=0.001)
        self.assertIn('Quá thời gian', result['analysis_error'])
        self.assertIsNone(result['layer3']['score'])


class RealDexTests(unittest.TestCase):
    def test_real_androguard_xrefs_find_exactly_the_same_method_pair(self):
        from androguard.misc import AnalyzeDex
        from androguard.session import Session
        from loguru import logger
        from dex_fixture import make_dex
        logger.remove()
        _, _, analysis = AnalyzeDex(make_dex(), session=Session(db_url='sqlite:///:memory:'), raw=True)
        report = analyze_code_layers(SimpleNamespace(get_package=lambda: 'org.example'), analysis, {})
        layer = report['layer3']
        self.assertEqual(layer['status'], 'completed', layer['issues'])
        self.assertEqual(layer['methods_scanned'], 4)
        self.assertEqual(layer['finding_count'], 1)
        hit = layer['findings'][0]
        self.assertEqual(hit['method_name'], 'leak')
        self.assertEqual(hit['sources'][0]['offset'], 0)
        self.assertEqual(hit['sinks'][0]['offset'], 6)
        self.assertFalse(hit['flow_confirmed'])


if __name__ == '__main__':
    unittest.main()
