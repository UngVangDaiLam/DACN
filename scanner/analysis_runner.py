"""Isolated, timed local static analysis. No model, network or APK execution required.

python -m scanner.analysis_runner sample.apk --output report.json
"""

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from scanner.code_layers import VERSION
from scanner.family_scores import score_family_b

ROOT = Path(__file__).resolve().parents[1]


def unavailable_report(reason, sha256=None):
    layer = {"available": False, "status": "unavailable", "version": VERSION,
             "stage": "implemented", "evidence_family": "code_behavior", "score": None,
             "score_kind": "heuristic_indicator_not_probability", "sha256": sha256,
             "methods_scanned": 0, "analysis_errors": 1, "finding_count": 0,
             "counts_by_origin": {}, "findings": [], "truncated": False,
             "issues": [{"component": "parser", "reason": reason}],
             "limitations": ["Không đủ bằng chứng phân tích; không được diễn giải là an toàn."],
             "requires_dynamic_confirmation": True}
    return {"layer2": dict(layer), "layer3": dict(layer), "analysis_error": reason,
            "family_b": score_family_b(layer, layer),
            "info": {"sha256": sha256, "version_name": "N/A"}}


def preflight(path):
    """Limit expansion before giving a ZIP/APK to Androguard or legacy helpers."""
    if path.stat().st_size > 500 * 1024 * 1024:
        raise ValueError("APK vượt giới hạn 500 MiB")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 20000:
            raise ValueError("APK vượt giới hạn 20.000 mục ZIP")
        if any(m.file_size > 64 * 1024 * 1024 for m in members):
            raise ValueError("Mục ZIP vượt giới hạn 64 MiB giải nén")
        if sum(m.file_size for m in members) > 512 * 1024 * 1024:
            raise ValueError("APK vượt giới hạn tổng 512 MiB giải nén")
        if "AndroidManifest.xml" not in archive.namelist():
            raise ValueError("Thiếu AndroidManifest.xml")


def run_deep_analysis(apk_path, timeout=180):
    path = Path(apk_path).resolve()
    started = time.monotonic()
    digest = None
    try:
        preflight(path)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", "-m",
                                 "scanner.analysis_runner", str(path), "--worker"],
                                cwd=str(ROOT), env=env, capture_output=False,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=True, **options)
        report = json.loads(result.stdout.decode("utf-8"))
        for name in ("layer2", "layer3"):
            if not isinstance(report.get(name), dict):
                raise ValueError("Worker thiếu kết quả tầng")
    except subprocess.TimeoutExpired:
        report = unavailable_report(f"Quá thời gian phân tích {timeout} giây; worker đã dừng", digest)
    except Exception as exc:
        report = unavailable_report(f"{type(exc).__name__}: {exc}", digest)
    report["analysis_seconds"] = round(time.monotonic() - started, 3)
    return report


def analyze_layer2(apk_path, timeout=180):
    return run_deep_analysis(apk_path, timeout)["layer2"]


def analyze_layer3(apk_path, timeout=180):
    return run_deep_analysis(apk_path, timeout)["layer3"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                from loguru import logger
                logger.remove()
                from scanner.deep_analysis import analyze_deep
                report = analyze_deep(args.apk)
        except Exception as exc:
            report = unavailable_report(f"{type(exc).__name__}: {exc}")
    else:
        report = run_deep_analysis(args.apk, args.timeout)
    content = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)
    if not args.worker and any(report[n]["status"] != "completed" for n in ("layer2", "layer3")):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
