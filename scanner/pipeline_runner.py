"""Bound the complete local APK analysis in one child process.

ZIP preflight, model loading, layer 1, and layers 2/3 share one deadline.
The child only reads APK data; it never installs/executes an APK or uses MobSF.
"""
import argparse
import contextlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

from scanner.analysis_runner import preflight, unavailable_report

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT = 180
PROGRESS_ENV = "DROIDGUARD_PROGRESS_FILE"


def _emit_worker_progress(stage, message):
    """Emit a small JSONL event for the parent process; never fail analysis."""
    target = os.environ.get(PROGRESS_ENV)
    if not target:
        return
    try:
        with open(target, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"stage": stage, "message": message}, ensure_ascii=False) + "\n")
            stream.flush()
    except OSError:
        pass


def _watch_progress(path, callback, stop_event):
    """Forward worker progress while subprocess.run is blocking this request."""
    offset = 0
    while not stop_event.wait(0.08):
        offset = _drain_progress(path, callback, offset)
    _drain_progress(path, callback, offset)


def _drain_progress(path, callback, offset):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            stream.seek(offset)
            for line in stream:
                try:
                    event = json.loads(line)
                    callback(event.get("stage", "working"), event.get("message", ""))
                except (ValueError, TypeError):
                    continue
            return stream.tell()
    except OSError:
        return offset


def failed_result(reason, filename, status="unavailable", http_status=503):
    return {
        "success": False, "type": "apk", "filename": filename,
        "error": reason, "analysis_incomplete": True,
        "incomplete_reasons": [reason], "analysis_status": status,
        "http_status": http_status, "label": "Không xác định", "class": None,
        "confidence": None, "probabilities": {}, "all_probabilities": {},
        "deep": unavailable_report(reason), "deep_error": reason,
        "verdict": {"verdict": "CHƯA ĐỦ BẰNG CHỨNG — cần kiểm tra thêm",
                    "level": "unknown", "final_score": None, "rule_score": None,
                    "ml_risk": None, "engines_agree": None},
        "apk_executed": False,
    }


def _analyze_in_worker(path, filename):
    # All APK parsing and model loading happen after preflight in this child.
    _emit_worker_progress("preflight_started", "Đang kiểm tra cấu trúc và giới hạn tệp APK")
    try:
        preflight(path)
    except Exception as exc:
        _emit_worker_progress("preflight_failed", "APK không vượt qua kiểm tra đầu vào")
        return failed_result(f"Preflight: {type(exc).__name__}: {exc}", filename,
                             "rejected", 422)
    _emit_worker_progress("preflight_completed", "Cấu trúc APK hợp lệ; bắt đầu đọc đặc trưng")
    from scanner.deep_analysis import analyze_deep, combine_verdict
    _emit_worker_progress("layer1_started", "Tầng 1 đang trích đặc trưng và chạy mô hình")
    try:
        from scanner.detect_and_classify import MalwareDetector
        result = MalwareDetector().analyze_apk(str(path), filename)
    except Exception as exc:
        result = {"success": False, "error": f"Tầng 1: {type(exc).__name__}: {exc}"}
    if not result.get("success"):
        # Missing ML/model must not prevent independent layer 2/3 evidence.
        reason = result.get("error", "Tầng 1 không khả dụng")
        result = {"success": True, "type": "apk", "filename": filename,
                  "analysis_incomplete": True, "incomplete_reasons": [reason],
                  "label": "Không xác định", "class": None, "confidence": None,
                  "probabilities": {}, "all_probabilities": {}, "notes": [reason]}
        _emit_worker_progress("layer1_unavailable", "Tầng 1 chưa xác định; tiếp tục phân tích mã độc lập")
    else:
        _emit_worker_progress("layer1_completed", "Tầng 1 đã hoàn tất")
    _emit_worker_progress("layers_started", "Tầng 2 và Tầng 3 đang đọc mã, tài nguyên và API")
    deep = analyze_deep(str(path))
    _emit_worker_progress("layers_completed", "Tầng 2 và Tầng 3 đã hoàn tất đối chiếu bằng chứng")
    result["deep"] = deep
    result["sha256"] = deep["info"]["sha256"]
    result["version"] = deep["info"]["version_name"]
    reliable = not (result.get("unreliable") or result.get("analysis_incomplete"))
    # Keep the existing combination inputs; never sum layer2/layer3 scores here.
    verdict = combine_verdict(result.get("class") or "1", result.get("confidence") or 0,
                              deep["rule_score"], ml_reliable=reliable)
    incomplete = not reliable or any(deep[name]["status"] != "completed"
                                     for name in ("layer2", "layer3"))
    result["layers_incomplete"] = any(deep[name]["status"] != "completed"
                                      for name in ("layer2", "layer3"))
    result["analysis_status"] = "partial" if incomplete else "completed"
    if incomplete and verdict["level"] == "safe":
        verdict.update(verdict="CHƯA ĐỦ BẰNG CHỨNG — cần kiểm tra thêm",
                       level="unknown", final_score=None)
    result["verdict"] = verdict
    result["apk_executed"] = False
    _emit_worker_progress("report_started", "Đang tổng hợp kết quả và bằng chứng")
    return result


def run_apk_analysis(apk_path, filename=None, timeout=DEFAULT_TIMEOUT, progress=None):
    """Return one stable report, including on timeout, without parsing in the caller."""
    path = Path(apk_path).resolve()
    filename = filename or path.name
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Thời gian phân tích phải là số hữu hạn lớn hơn 0")
    started = time.monotonic()
    progress_path = None
    progress_stop = None
    progress_thread = None
    try:
        # Cheap metadata check only; even ZIP directory parsing stays in the child.
        if path.stat().st_size > 500 * 1024 * 1024:
            return failed_result("APK vượt giới hạn 500 MiB", filename, "rejected", 413)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        if callable(progress):
            handle, progress_path = tempfile.mkstemp(prefix="droidguard-progress-", suffix=".jsonl")
            os.close(handle)
            env[PROGRESS_ENV] = progress_path
            progress_stop = threading.Event()
            progress_thread = threading.Thread(
                target=_watch_progress,
                args=(progress_path, progress, progress_stop),
                name="apk-progress-forwarder",
                daemon=True,
            )
            progress_thread.start()
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        process = subprocess.run(
            [sys.executable, "-X", "utf8", "-B", "-m", "scanner.pipeline_runner",
             str(path), "--worker", "--filename", filename],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=True, **options)
        result = json.loads(process.stdout.decode("utf-8"))
        if not isinstance(result, dict) or type(result.get("success")) is not bool:
            raise ValueError("Worker trả báo cáo không hợp lệ")
        if not all(isinstance(result.get("deep", {}).get(name), dict)
                   for name in ("layer2", "layer3")):
            raise ValueError("Worker thiếu báo cáo Tầng 2/3")
    except subprocess.TimeoutExpired:
        result = failed_result(f"Quá thời gian phân tích toàn bộ {timeout:g} giây; worker đã dừng",
                               filename, "timeout", 504)
    except Exception as exc:
        result = failed_result(f"{type(exc).__name__}: {exc}", filename)
    finally:
        if progress_stop is not None:
            progress_stop.set()
        if progress_thread is not None:
            progress_thread.join(timeout=1)
        if progress_path:
            with contextlib.suppress(OSError):
                os.unlink(progress_path)
    result["analysis_seconds"] = round(time.monotonic() - started, 3)
    result["analysis_timeout_seconds"] = timeout
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    parser.add_argument("--filename")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--output")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                from loguru import logger
                logger.remove()
                report = _analyze_in_worker(Path(args.apk), args.filename or Path(args.apk).name)
        except Exception as exc:
            report = failed_result(f"{type(exc).__name__}: {exc}", args.filename or Path(args.apk).name)
    else:
        report = run_apk_analysis(args.apk, args.filename, args.timeout)
    content = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)
    if not args.worker and report.get("analysis_status") != "completed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
