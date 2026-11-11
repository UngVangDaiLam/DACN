"""Queue Tầng 4 jobs for a configured sandbox connector.

ANDROWALL_LAYER4_COMMAND is a JSON array of command arguments. The connector
receives the saved APK path and SHA256 as its last two arguments, and writes one
runner report as UTF-8 JSON to stdout. The connector verifies the transferred APK
before running it and owns sandbox checks and snapshot reset.
"""

import hashlib
import json
import queue
import subprocess
import threading
import uuid


class Layer4ReportError(Exception):
    """An error suitable for display in the scan UI."""


class Layer4Jobs:
    def __init__(self, setting, statuses):
        self.statuses = statuses
        self.command = json.loads(setting) if setting else []
        if not isinstance(self.command, list) or any(
            not isinstance(arg, str) or not arg or "\0" in arg for arg in self.command
        ):
            raise ValueError("ANDROWALL_LAYER4_COMMAND phải là mảng JSON chứa các đối số.")

        self.pending = queue.Queue(maxsize=4)
        if self.command:
            threading.Thread(target=self.work, daemon=True, name="androwall-layer4").start()

    def submit(self, filepath, sha256):
        if not self.command:
            return None

        task_id = str(uuid.uuid4())
        self.statuses[task_id] = {"status": "queued", "message": "Đã xếp hàng phân tích động."}
        try:
            self.pending.put_nowait((task_id, filepath, sha256))
        except queue.Full:
            self.statuses[task_id] = {"status": "error", "message": "Hàng đợi Tầng 4 đã đầy."}
        return task_id

    def work(self):
        while True:
            task_id, filepath, sha256 = self.pending.get()
            try:
                self.statuses[task_id] = {
                    "status": "running", "message": "Đang chạy APK trong sandbox."
                }
                self.statuses[task_id] = self.run(filepath, sha256)
            except subprocess.TimeoutExpired:
                self.statuses[task_id] = {
                    "status": "error", "message": "Tầng 4 hết thời gian chờ báo cáo."
                }
            except Layer4ReportError as exc:
                self.statuses[task_id] = {"status": "error", "message": str(exc)}
            except (OSError, ValueError):
                self.statuses[task_id] = {
                    "status": "error",
                    "message": "Tầng 4 không đọc được APK hoặc phản hồi từ bộ kết nối.",
                }
            finally:
                self.pending.task_done()

    def run(self, filepath, sha256):
        with open(filepath, "rb") as apk:
            if hashlib.file_digest(apk, "sha256").hexdigest() != sha256:
                raise Layer4ReportError("SHA256 của APK đã lưu không khớp với lượt quét.")

        result = subprocess.run(
            [*self.command, filepath, sha256],
            capture_output=True, timeout=180, encoding="utf-8", check=False,
        )
        if result.returncode:
            raise Layer4ReportError("Bộ kết nối sandbox trả lỗi.")

        report = json.loads(result.stdout)
        if not isinstance(report, dict) or report.get("layer") != 4:
            raise Layer4ReportError("Bộ kết nối trả báo cáo Tầng 4 không hợp lệ.")
        if report.get("sha256") != sha256:
            raise Layer4ReportError("SHA256 của báo cáo Tầng 4 không khớp với APK.")
        if report.get("status") != "completed":
            status = report.get("status")
            if status in ("install_failed", "package_unknown", "not_launched", "hooks_failed"):
                raise Layer4ReportError(f"Sandbox không hoàn tất lượt chạy ({status}).")
            raise Layer4ReportError("Sandbox không hoàn tất lượt chạy.")
        if report.get("dynamic_available") != 1 or report.get("hooks_ready") is not True:
            raise Layer4ReportError("Báo cáo Tầng 4 thiếu xác nhận hook sẵn sàng.")

        events = report.get("events")
        event_count = report.get("event_count")
        if (
            not isinstance(events, list) or type(event_count) is not int
            or event_count < len(events)
            or (event_count != len(events) and report.get("truncated") is not True)
            or any(not isinstance(event, dict) for event in events)
        ):
            raise Layer4ReportError("Danh sách sự kiện trong báo cáo Tầng 4 không hợp lệ.")

        return {
            "status": "completed",
            "message": "Đã hoàn tất phân tích động.",
            "report": {
                "event_count": event_count,
                "events": [
                    {key: str(event.get(key, ""))[:500] for key in ("capability", "api", "detail")}
                    for event in events[:50]
                ],
            },
        }
