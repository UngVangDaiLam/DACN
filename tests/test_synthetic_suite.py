"""Synthetic functional acceptance; intentionally separate from real APK evaluation."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.verify_synthetic_suite import check_frozen, parse_dump

ROOT=Path(__file__).resolve().parents[1]
SUITE=ROOT/'samples/synthetic_v1'
RUN=ROOT/'reports/synthetic_v1_detector_v2_2'


class IndependentSDKParserTests(unittest.TestCase):
    def test_overloads_and_code_unit_offsets_are_preserved(self):
        dump="""Class descriptor  : 'Lsample/Case;'
      name          : 'probe'
      type          : '(Landroid/location/Location;)D'
000100:                                        |[000100] sample.Case.probe:(Landroid/location/Location;)D
000110: 0000                                   |0001: invoke-virtual {v0}, Landroid/location/Location;.getLatitude:()D // method@0001
      name          : 'probe'
      type          : '(Ljava/net/HttpURLConnection;)Ljava/io/OutputStream;'
000120:                                        |[000120] sample.Case.probe:(Ljava/net/HttpURLConnection;)Ljava/io/OutputStream;
000130: 0000                                   |0000: invoke-virtual {v0}, Ljava/net/HttpURLConnection;.getOutputStream:()Ljava/io/OutputStream; // method@0002
"""
        parsed=parse_dump(dump)
        self.assertEqual(len(parsed['methods']),2)
        first,second=parsed['methods']
        self.assertNotEqual(first['descriptor'],second['descriptor'])
        self.assertEqual(first['calls'][0]['byte_offset'],2)
        self.assertEqual(len(first['calls']),1)
        self.assertEqual(len(second['calls']),1)

    def test_tampered_frozen_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'input.txt').write_text('original')
            sha=hashlib.sha256((root/'input.txt').read_bytes()).hexdigest()
            (root/'labels_frozen.json').write_text(json.dumps({'review_files':{'input.txt':sha}}))
            self.assertTrue(check_frozen(root)['frozen_inputs_verified'])
            (root/'input.txt').write_text('changed')
            with self.assertRaises(ValueError):check_frozen(root)


@unittest.skipUnless((SUITE/'labels_frozen.json').is_file(),'Build/verify synthetic suite first')
class FrozenSyntheticFixturesTests(unittest.TestCase):
    def setUp(self):
        self.rows=json.loads((SUITE/'labels.json').read_text(encoding='utf-8'))

    def test_all_frozen_inputs_match(self):
        self.assertTrue(check_frozen(SUITE)['frozen_inputs_verified'])

    def test_24_unique_real_apk_files_are_explicitly_synthetic(self):
        self.assertEqual(len(self.rows),24)
        self.assertEqual(len({r['sha256'] for r in self.rows}),24)
        for row in self.rows:
            self.assertEqual(row['dataset_type'],'synthetic')
            apk=SUITE/row['apk']
            self.assertEqual(hashlib.sha256(apk.read_bytes()).hexdigest(),row['sha256'])
            with zipfile.ZipFile(apk) as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn('classes.dex',archive.namelist())

    def test_gold_witnesses_precede_detector_and_have_empty_entrypoint(self):
        frozen=json.loads((SUITE/'labels_frozen.json').read_text(encoding='utf-8'))
        self.assertFalse(frozen['scanner_imported_for_labels'])
        for row in self.rows:
            review=json.loads((SUITE/row['evidence']).read_text(encoding='utf-8'))
            self.assertEqual(review['labels'],row['labels'])
            self.assertTrue(review['no_permissions'])
            self.assertTrue(review['empty_entrypoint_calls_no_probe'])
            self.assertTrue(review['signature_v2_verified'])

    def test_tier3_positive_and_negative_controls_are_distinct(self):
        positives={row['sample_id'] for row in self.rows if row['labels']['tier3_sensitive_network_same_method']}
        self.assertEqual(positives,{'SYN14','SYN19','SYN20','SYN23'})
        for sid in ['SYN15','SYN16','SYN17','SYN18','SYN21','SYN22','SYN24']:
            row=next(row for row in self.rows if row['sample_id']==sid)
            self.assertFalse(row['labels']['tier3_sensitive_network_same_method'])

    @unittest.skipUnless((RUN/'evaluation.json').is_file(),'Run synthetic benchmark first')
    def test_six_techniques_and_same_method_acceptance(self):
        evaluation=json.loads((RUN/'evaluation.json').read_text(encoding='utf-8'))
        self.assertEqual(evaluation['sample_count'],24)
        for key,result in evaluation['techniques'].items():
            with self.subTest(technique=key):
                self.assertEqual(result['unknown_labels'],0)
                self.assertEqual(result['evaluated'],24)
                self.assertGreater(result['tp'],0)
                self.assertGreater(result['tn'],0)
                self.assertEqual(result['fp'],0)
                self.assertEqual(result['fn'],0)


if __name__=='__main__':unittest.main()
