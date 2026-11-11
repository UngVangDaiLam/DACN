"""Run offline static layers on hash-bound APKs into a NEW versioned directory.

python scripts/run_benchmark.py ../samples/labels.json --output-dir reports/run-v2
python scripts/run_benchmark.py labels.csv --manifest manifest.csv --output-dir reports/run-v2
Uses existing independent labels; never derives/changes labels from scanner output.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.evaluate_layers import load_records, evaluate


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')


def input_state(labels_path, manifest_path=None):
    paths = [Path(labels_path).resolve()]
    if manifest_path:
        paths.append(Path(manifest_path).resolve())
    frozen = paths[0].parent / 'labels_frozen.json'
    if frozen.exists():
        paths.append(frozen)
        # Verify original review inputs, not the old detector hashes: this is a new run.
        record = json.loads(frozen.read_text(encoding='utf-8'))
        for relative, expected in record.get('review_files', {}).items():
            path = (frozen.parent / relative).resolve()
            if not path.is_relative_to(frozen.parent) or digest(path) != expected:
                raise ValueError('Frozen review input changed: ' + relative)
            paths.append(path)
    return {str(path): digest(path) for path in paths}


def code_state():
    paths = list((ROOT / 'scanner').rglob('*.py')) + list((ROOT / 'scanner').rglob('*.yar'))
    paths += [Path(__file__), ROOT / 'scripts/evaluate_layers.py']
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def run(labels_path, output_dir, manifest_path=None, workers=2, timeout=180):
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('Số worker phải thuộc 1..4')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout phải là số hữu hạn lớn hơn 0')
    output = Path(output_dir).resolve()
    # Refuse existing output, including an empty directory: never overwrite a baseline.
    if output.exists():
        raise ValueError('Thư mục kết quả đã tồn tại; hãy dùng một phiên bản mới')
    records = load_records(labels_path, manifest_path, output / 'reports')
    frozen_inputs, frozen_code = input_state(labels_path, manifest_path), code_state()
    for row in records:
        if not row['apk'] or not Path(row['apk']).is_file() or digest(row['apk']) != row['sha256']:
            raise ValueError('APK missing/hash mismatch: ' + row['sample_id'])
    output.mkdir(parents=True)
    (output / 'reports').mkdir()
    now = lambda: datetime.now(timezone.utc).isoformat()
    versions = {}
    for name in ['androguard', 'yara-python', 'apkInspector']:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    meta = {'started_utc': now(), 'status': 'running', 'python': platform.python_version(),
            'dependencies': versions, 'input_sha256': frozen_inputs, 'detector_sha256': frozen_code,
            'workers': workers, 'timeout_seconds_per_apk': timeout, 'apk_execution': False,
            'network_used': False, 'dataset_role': 'development/regression; not held-out accuracy',
            'source_labels': str(Path(labels_path).resolve()), 'sample_count': len(records)}
    save(output / 'run_metadata.json', meta)
    from scanner.analysis_runner import run_deep_analysis

    def one(row):
        if digest(row['apk']) != row['sha256']:
            raise ValueError('APK changed before analysis: ' + row['sample_id'])
        report = run_deep_analysis(row['apk'], timeout=timeout)
        if digest(row['apk']) != row['sha256']:
            raise ValueError('APK changed during analysis: ' + row['sample_id'])
        report.setdefault('info', {}).setdefault('sha256', row['sha256'])
        if report['info'].get('sha256') is None:
            report['info']['sha256'] = row['sha256']
        report['benchmark'] = {'sample_id': row['sample_id'], 'apk_sha256_verified_before_and_after': row['sha256']}
        save(output / 'reports' / (row['sample_id'] + '.json'), report)
        return row['sample_id'], report['layer2']['status'], report['layer3']['status']

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(one, row) for row in records]
            for i, future in enumerate(as_completed(futures), 1):
                print(i, '/', len(records), *future.result(), flush=True)
        if frozen_inputs != input_state(labels_path, manifest_path) or frozen_code != code_state():
            raise ValueError('Review inputs or detector source changed during benchmark')
        # Explicit report fields in input JSON must not point back to baseline reports.
        # Normalize the new run's binding before evaluation, preserving labels and scope.
        normalized = [{**row, 'report': str(output / 'reports' / (row['sample_id'] + '.json'))} for row in records]
        save(output / 'evaluation_inputs.json', normalized)
        result = evaluate(output / 'evaluation_inputs.json')
        save(output / 'evaluation.json', result)
        meta.update(status='completed', finished_utc=now(), inputs_and_detector_unchanged=True,
                    report_sha256={p.name: digest(p) for p in sorted((output / 'reports').glob('*.json'))})
        save(output / 'run_metadata.json', meta)
        return result
    except BaseException as exc:
        meta.update(status='failed', finished_utc=now(), error=f'{type(exc).__name__}: {exc}')
        save(output / 'run_metadata.json', meta)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('labels')
    parser.add_argument('--manifest')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--timeout', type=float, default=180)
    args = parser.parse_args()
    result = run(args.labels, args.output_dir, args.manifest, args.workers, args.timeout)
    print(json.dumps({key: {k: value[k] for k in ['evaluated', 'tp', 'tn', 'fp', 'fn', 'recall', 'f1']}
                      for key, value in result['techniques'].items()}, indent=2))


if __name__ == '__main__':
    main()
