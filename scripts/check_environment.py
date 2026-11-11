"""Record runtime reproducibility and missing training inputs without loading models."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def audit():
    packages = {}
    for name in ['androguard', 'apkInspector', 'yara-python', 'flask', 'numpy',
                 'pandas', 'scikit-learn', 'xgboost', 'sklearn-compat']:
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    check = subprocess.run([sys.executable, '-B', '-m', 'pip', 'check'],
                           capture_output=True, text=True, timeout=60,
                           creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
    assets = {}
    for relative in ['models/static_model.pkl', 'models/static_label_encoder.pkl',
                     'models/static_feature_schema.json', 'dataset/processed/static_features.csv']:
        path = ROOT / relative
        if path.is_file():
            with path.open('rb') as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            assets[relative] = {'exists': True, 'sha256': sha, 'bytes': path.stat().st_size}
        else:
            assets[relative] = {'exists': False}
    return {'created_utc': datetime.now(timezone.utc).isoformat(), 'python': platform.python_version(),
            'platform': platform.platform(), 'packages': packages,
            'pip_check_ok': check.returncode == 0, 'pip_check_output': (check.stdout + check.stderr).strip(),
            'assets': assets,
            'training_reproducible': False,
            'training_note': 'Asset presence is insufficient to reproduce training; also requires provenance, splits, seed, exact environment and training records. No training was performed.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    args = parser.parse_args()
    result = audit()
    content = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(content, encoding='utf-8')
    else:
        print(content)


if __name__ == '__main__':
    main()
