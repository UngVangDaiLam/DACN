"""Evaluate independent, hash-bound labels against saved static reports.

Accept frozen samples/labels.json, JSON records with labels={technique: status},
or long labels.csv with --manifest manifest.csv --reports-dir DIR.
No APK execution. Unknown labels and incomplete reports are never negatives.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

TECHNIQUES = {
    'dynamic_loading': ('layer2', {'dynamic_dex', 'loader_with_encoding'}),
    'reflection': ('layer2', {'reflection'}),
    'encoded_strings': ('layer2', {'encoded_string', 'encoded_string_reversal'}),
    'embedded_payload': ('layer2', {'embedded_payload'}),
    'native_loading': ('layer2', {'native_loading'}),
    'name_obfuscation': ('layer2', {'short_class_names'}),
    'tier3_sensitive_network_same_method': ('layer3', {'sensitive_network_same_method'}),
}
ALIASES = {'dynamic_dex': 'dynamic_loading', 'layer2_dynamic_dex': 'dynamic_loading',
           'layer2_reflection': 'reflection', 'layer3_positive': 'tier3_sensitive_network_same_method'}
STATUSES = {'Có': True, 'Không': False, 'Chưa xác định': None}


def metrics(pairs):
    tp = sum(t and p for t, p in pairs)
    fp = sum(not t and p for t, p in pairs)
    fn = sum(t and not p for t, p in pairs)
    tn = sum(not t and not p for t, p in pairs)
    positive = tp + fn
    return {'evaluated': len(pairs), 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'gold_positive': positive,
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / positive if positive else None,
            'false_positive_rate': fp / (fp + tn) if fp + tn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if positive and 2 * tp + fp + fn else None}


def truth_value(value):
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str) and value.strip() in STATUSES:
        return STATUSES[value.strip()]
    raise ValueError('Nhãn phải là boolean, null, Có/Không/Chưa xác định')


def load_records(labels_path, manifest_path=None, reports_dir=None):
    labels_path = Path(labels_path).resolve()
    report_root = Path(reports_dir).resolve() if reports_dir else labels_path.parent / 'reports'
    if labels_path.suffix.lower() == '.csv':
        if manifest_path is None:
            raise ValueError('CSV nhãn cần --manifest để ràng buộc SHA256 và APK')
        manifest_path = Path(manifest_path).resolve()
        grouped = {}
        with manifest_path.open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                sid = row['sample_id']
                if sid in grouped:
                    raise ValueError('sample_id lặp trong manifest: ' + sid)
                apk = row.get('local_path') or row.get('apk')
                grouped[sid] = {**row, 'labels': {}, 'report': str(report_root / (sid + '.json'))}
                if apk:
                    grouped[sid]['apk'] = str(manifest_path.parent / apk)
        with labels_path.open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                sid, key = row['sample_id'], row['technique']
                if sid not in grouped or key not in TECHNIQUES:
                    raise ValueError('Mẫu/kỹ thuật không hợp lệ: ' + sid + '/' + key)
                if key in grouped[sid]['labels']:
                    raise ValueError('Nhãn lặp: ' + sid + '/' + key)
                grouped[sid]['labels'][key] = truth_value(row['status'])
        records = list(grouped.values())
    else:
        records = json.loads(labels_path.read_text(encoding='utf-8-sig'))
        if isinstance(records, dict):
            records = records.get('records')
    if not isinstance(records, list) or not records:
        raise ValueError('Cần danh sách nhãn đã kiểm chứng, không rỗng')
    normalized, seen_sha, seen_sid = [], set(), set()
    for index, original in enumerate(records):
        row = dict(original)
        sha = row.get('sha256', '').lower()
        if not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('Nhãn phải có SHA256 APK đầy đủ (64 ký tự hex)')
        sid = row.get('sample_id', f'row_{index + 1:04d}')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', sid) or sid in ('.', '..'):
            raise ValueError('sample_id không hợp lệ')
        if sha in seen_sha or sid in seen_sid:
            raise ValueError('Nhãn lặp SHA256 hoặc sample_id: ' + sid)
        seen_sha.add(sha); seen_sid.add(sid)
        values = {key: None for key in TECHNIQUES}
        source = row.get('labels', {})
        if not isinstance(source, dict):
            raise ValueError('labels phải là object kỹ thuật -> trạng thái')
        for key, value in source.items():
            key = ALIASES.get(key, key)
            if key not in TECHNIQUES:
                raise ValueError('Kỹ thuật không hỗ trợ: ' + key)
            values[key] = truth_value(value)
        for key in ('layer2_reflection', 'layer2_dynamic_dex', 'layer3_positive'):
            if key in row:
                values[ALIASES[key]] = truth_value(row[key])
        classes = row.get('scope_classes')
        if classes is not None and (not isinstance(classes, list) or not classes or
                                    not all(isinstance(c, str) and c.startswith('L') and c.endswith(';') for c in classes)):
            raise ValueError('scope_classes phải là danh sách descriptor lớp đã review')
        report_path = Path(row['report']) if row.get('report') else report_root / (sid + '.json')
        if not report_path.is_absolute():
            report_path = labels_path.parent / report_path
        apk_path = Path(row['apk']) if row.get('apk') else None
        if apk_path and not apk_path.is_absolute():
            apk_path = labels_path.parent / apk_path
        row.update(sample_id=sid, sha256=sha, labels=values,
                   report=str(report_path.resolve()), apk=str(apk_path.resolve()) if apk_path else None)
        if 'layer2_positive' in row:
            row['layer2_positive'] = truth_value(row['layer2_positive'])
        normalized.append(row)
    return normalized


def unwrap_report(report):
    if 'ai_result' in report:
        return report['ai_result'].get('deep', {})
    return report.get('deep', report)


def _usable(layer):
    if not layer:
        return 'layer_missing'
    if layer.get('status') != 'completed' or layer.get('available') is not True:
        return 'analysis_' + str(layer.get('status', 'unavailable'))
    if layer.get('analysis_errors', 0):
        return 'analysis_errors'
    if layer.get('truncated'):
        return 'truncated'
    return None


def evaluate(labels_path, threshold=15, manifest_path=None, reports_dir=None):
    records = load_records(labels_path, manifest_path, reports_dir)
    keys = list(TECHNIQUES)
    legacy = any('layer2_positive' in row for row in records)
    if legacy:
        keys.append('layer2_legacy_endpoint')
    pairs = {key: [] for key in keys}
    skipped = {key: [] for key in keys}
    known = {key: 0 for key in keys}
    results = []
    for row in records:
        path = Path(row['report'])
        report, report_issue = {}, None
        try:
            report = unwrap_report(json.loads(path.read_text(encoding='utf-8-sig')))
            if not isinstance(report, dict) or not isinstance(report.get('info', {}), dict):
                raise ValueError('Invalid report envelope')
            for name in ('layer2', 'layer3'):
                layer = report.get(name, {})
                if not isinstance(layer, dict) or not isinstance(layer.get('findings', []), list):
                    raise ValueError('Invalid layer findings')
                if not all(isinstance(f, dict) for f in layer.get('findings', [])):
                    raise ValueError('Invalid finding record')
                count = layer.get('finding_count', len(layer.get('findings', [])))
                if type(count) is not int or count < 0 or count < len(layer.get('findings', [])):
                    raise ValueError('Invalid finding count')
                if count > len(layer.get('findings', [])):
                    layer['truncated'] = True
        except FileNotFoundError:
            report_issue = 'report_missing'
        except (ValueError, TypeError, AttributeError):
            report_issue = 'report_invalid'
        if not report_issue:
            hashes = [report.get('sha256'), report.get('info', {}).get('sha256')]
            hashes += [report.get(layer, {}).get('sha256') for layer in ('layer2', 'layer3')]
            hashes = [value.lower() for value in hashes if isinstance(value, str) and value]
            if not hashes or any(value != row['sha256'] for value in hashes):
                raise ValueError('Report APK hash mismatch: ' + row['sample_id'])
        classes = set(row['scope_classes']) if row.get('scope_classes') else None
        finding_sets = {}
        for name in ('layer2', 'layer3'):
            findings = report.get(name, {}).get('findings', [])
            finding_sets[name] = [f for f in findings if classes is None or f.get('class_name') in classes]
        entry = {'sample_id': row['sample_id'], 'sha256': row['sha256'], 'report': row['report'],
                 'scope': 'reviewed_classes' if classes is not None else 'whole_apk', 'techniques': {}}
        for key in keys:
            truth = row.get('layer2_positive') if key == 'layer2_legacy_endpoint' else row['labels'][key]
            if truth is not None:
                known[key] += 1
            name = 'layer2' if key == 'layer2_legacy_endpoint' else TECHNIQUES[key][0]
            layer = report.get(name, {})
            reason = 'label_unknown' if truth is None else report_issue or _usable(layer)
            if not reason and classes is not None and key in ('embedded_payload', 'name_obfuscation'):
                reason = 'file_level_indicator_outside_class_scope'
            prediction = None
            if not reason:
                if key == 'layer2_legacy_endpoint':
                    if 'layer2_reflection' in row and 'layer2_dynamic_dex' in row:
                        rules = TECHNIQUES['reflection'][1] | TECHNIQUES['dynamic_loading'][1]
                        prediction = any(f.get('rule_id') in rules for f in finding_sets['layer2'])
                    elif layer.get('score') is not None:
                        prediction = layer['score'] >= threshold
                    else:
                        reason = 'score_unavailable'
                else:
                    prediction = any(f.get('rule_id') in TECHNIQUES[key][1] for f in finding_sets[name])
            outcome = 'excluded' if reason else ('TP' if truth and prediction else 'FN' if truth else 'FP' if prediction else 'TN')
            entry['techniques'][key] = {'truth': truth, 'prediction': prediction,
                                         'outcome': outcome, 'excluded_reason': reason}
            if reason:
                skipped[key].append({'sample_id': row['sample_id'], 'sha256': row['sha256'], 'reason': reason})
            else:
                pairs[key].append((truth, prediction))
        results.append(entry)
    by_key = {key: {**metrics(pairs[key]), 'total': len(records), 'known_labels': known[key],
                    'unknown_labels': len(records) - known[key],
                    'label_coverage': known[key] / len(records),
                    'coverage': len(pairs[key]) / len(records),
                    'coverage_of_known_labels': len(pairs[key]) / known[key] if known[key] else None,
                    'unevaluated_sha256': [x['sha256'] for x in skipped[key]],
                    'exclusions': skipped[key]} for key in keys}
    result = {'schema_version': '2.0', 'sample_count': len(records), 'layer2_threshold': threshold,
              'labels_sha256': hashlib.sha256(Path(labels_path).read_bytes()).hexdigest(),
              'techniques': {key: by_key[key] for key in TECHNIQUES}, 'records': results,
              'layer3': by_key['tier3_sensitive_network_same_method'],
              'prediction_rules': {key: sorted(value[1]) for key, value in TECHNIQUES.items()},
              'limitations': ['Chưa xác định, report lỗi/thiếu/cắt và ngoài phạm vi được loại với lý do.',
                              'encoded_string và short_class_names là chỉ báo, không chứng minh mã hóa/làm rối.',
                              'Không gộp Cipher/Base64 decode thành encoded_strings; không dùng nhãn malware/benign.',
                              'Không có gold dương: recall/F1 null kể cả khi có false positive.',
                              'Tập đã dùng sửa luật là development/regression, không phải held-out accuracy.']}
    if legacy:
        result['layer2'] = by_key['layer2_legacy_endpoint']
        result['legacy_endpoint_note'] = 'Reflection OR dynamic when both labels exist; otherwise aggregate score threshold (not six-technique evaluation).'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('labels')
    parser.add_argument('--manifest')
    parser.add_argument('--reports-dir')
    parser.add_argument('--layer2-threshold', type=float, default=15)
    parser.add_argument('--output')
    args = parser.parse_args()
    if not 0 <= args.layer2_threshold <= 100:
        parser.error('Ngưỡng phải thuộc 0..100')
    result = evaluate(args.labels, args.layer2_threshold, args.manifest, args.reports_dir)
    content = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
    if args.output:
        Path(args.output).write_text(content, encoding='utf-8')
    else:
        print(content)


if __name__ == '__main__':
    main()
