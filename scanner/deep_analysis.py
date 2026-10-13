# scanner/deep_analysis.py
"""
Phân tích chuyên sâu APK hoàn toàn cục bộ (thay thế phụ thuộc vào MobSF).

Các lớp phân tích:
  1. Thông tin APK + chữ ký số (chứng chỉ, debug cert, tự ký, scheme v1/v2/v3)
  2. Quyền (phân nhóm theo mức nguy hiểm) + tổ hợp quyền nguy hiểm
  3. Thành phần Manifest (exported không có permission, service/receiver nhạy cảm, cờ debuggable/backup/cleartext)
  4. API đáng ngờ trong bytecode (SMS, reflection, DexClassLoader, Runtime.exec, root, mã hoá...)
  5. Chỉ báo từ chuỗi (URL, IP, email, lệnh su, địa chỉ ví/telegram bot...)
  6. Chỉ báo che giấu/đóng gói (entropy DEX, tên lớp bị làm rối, payload nhúng, thư viện native)

Mỗi phát hiện (finding) có severity + điểm; tổng hợp thành rule_score 0-100.
Hàm combine_verdict() kết hợp rule_score với xác suất của model ML để ra kết luận cuối.
"""

import re
import hashlib
from collections import Counter, defaultdict

from androguard.misc import AnalyzeAPK
from scanner.code_layers import analyze_code_layers

try:  # androguard ghi log DEBUG rất nhiều → chỉ giữ WARNING trở lên
    import sys as _sys
    from loguru import logger as _logger
    _logger.remove()
    _logger.add(_sys.stderr, level="WARNING")
except Exception:
    pass

# ---------------------------------------------------------------- QUYỀN
CRITICAL_PERMS = {
    "BIND_ACCESSIBILITY_SERVICE": "Điều khiển/đọc màn hình (lạm dụng bởi banking trojan)",
    "BIND_DEVICE_ADMIN": "Quyền quản trị thiết bị (khó gỡ, khoá máy)",
    "SYSTEM_ALERT_WINDOW": "Vẽ đè lên ứng dụng khác (overlay phishing)",
    "REQUEST_INSTALL_PACKAGES": "Tự cài thêm APK khác",
    "READ_SMS": "Đọc tin nhắn (đánh cắp OTP)",
    "RECEIVE_SMS": "Chặn tin nhắn đến",
    "SEND_SMS": "Gửi tin nhắn (SMS tính phí/spam)",
    "WRITE_SMS": "Ghi/sửa tin nhắn",
    "PROCESS_OUTGOING_CALLS": "Giám sát/chuyển hướng cuộc gọi",
    "MANAGE_EXTERNAL_STORAGE": "Truy cập toàn bộ bộ nhớ",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Đọc mọi thông báo (có OTP)",
}
DANGEROUS_PERMS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG", "CALL_PHONE",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "ANSWER_PHONE_CALLS", "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_CALENDAR", "WRITE_CALENDAR",
    "GET_ACCOUNTS", "USE_BIOMETRIC", "PACKAGE_USAGE_STATS", "GET_TASKS", "DISABLE_KEYGUARD",
    "KILL_BACKGROUND_PROCESSES", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "READ_PROFILE",
}

PERM_COMBOS = [
    ({"READ_SMS", "INTERNET"}, "Có thể đánh cắp mã OTP và gửi về máy chủ từ xa", 15),
    ({"RECEIVE_SMS", "INTERNET"}, "Có thể chặn SMS đến và chuyển ra ngoài", 12),
    ({"RECORD_AUDIO", "INTERNET"}, "Có thể nghe lén và truyền âm thanh lên mạng", 10),
    ({"ACCESS_FINE_LOCATION", "INTERNET"}, "Có thể theo dõi vị trí GPS và gửi về máy chủ", 2),
    ({"READ_CONTACTS", "SEND_SMS"}, "Có thể phát tán spam SMS tới toàn bộ danh bạ", 15),
    ({"CAMERA", "INTERNET"}, "Có thể chụp ảnh bí mật và upload lên mạng", 2),
    ({"READ_CALL_LOG", "INTERNET"}, "Có thể rò rỉ lịch sử cuộc gọi ra ngoài", 6),
    ({"WRITE_EXTERNAL_STORAGE", "READ_SMS"}, "Có thể sao chép tin nhắn vào thẻ nhớ", 8),
    ({"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"}, "Overlay + Accessibility: mô hình tấn công của banking trojan", 25),
    ({"RECEIVE_BOOT_COMPLETED", "BIND_DEVICE_ADMIN"}, "Tự khởi động cùng máy với quyền quản trị thiết bị", 12),
    ({"REQUEST_INSTALL_PACKAGES", "INTERNET"}, "Có thể tải và cài APK khác (dropper)", 6),
]

# ---------------------------------------------------------------- API ĐÁNG NGỜ
# (class_substring, method_name | None, nhãn, nhóm, điểm)
SUSPICIOUS_APIS = [
    ("Landroid/telephony/SmsManager;", "sendTextMessage", "Gửi SMS ngầm", "SMS", 10),
    ("Landroid/telephony/SmsManager;", "sendMultipartTextMessage", "Gửi SMS nhiều phần", "SMS", 10),
    ("Landroid/telephony/SmsManager;", "sendDataMessage", "Gửi SMS dữ liệu", "SMS", 10),
    ("Landroid/provider/Telephony$Sms", None, "Truy vấn hộp thư SMS", "SMS", 6),
    ("Landroid/telephony/TelephonyManager;", "getDeviceId", "Đọc IMEI", "Thiết bị", 4),
    ("Landroid/telephony/TelephonyManager;", "getSubscriberId", "Đọc IMSI", "Thiết bị", 4),
    ("Landroid/telephony/TelephonyManager;", "getLine1Number", "Đọc số điện thoại", "Thiết bị", 4),
    ("Ldalvik/system/DexClassLoader;", None, "Nạp mã DEX động (có thể giấu payload)", "Nạp mã động", 12),
    ("Ldalvik/system/PathClassLoader;", None, "Nạp lớp từ đường dẫn tuỳ ý", "Nạp mã động", 4),
    ("Ldalvik/system/InMemoryDexClassLoader;", None, "Nạp DEX trong bộ nhớ (kỹ thuật packer)", "Nạp mã động", 14),
    ("Ljava/lang/Runtime;", "exec", "Thực thi lệnh shell", "Thực thi lệnh", 10),
    ("Ljava/lang/ProcessBuilder;", "start", "Khởi chạy tiến trình hệ thống", "Thực thi lệnh", 8),
    ("Ljava/lang/reflect/Method;", "invoke", "Reflection (gọi hàm gián tiếp)", "Che giấu", 3),
    ("Ljavax/crypto/Cipher;", "doFinal", "Mã hoá/giải mã dữ liệu", "Mã hoá", 2),
    ("Landroid/app/admin/DevicePolicyManager;", "lockNow", "Khoá màn hình thiết bị", "Quản trị TB", 14),
    ("Landroid/app/admin/DevicePolicyManager;", "resetPassword", "Đặt lại mật khẩu thiết bị", "Quản trị TB", 18),
    ("Landroid/app/admin/DevicePolicyManager;", "wipeData", "Xoá sạch dữ liệu thiết bị", "Quản trị TB", 18),
    ("Landroid/accessibilityservice/AccessibilityService;", None, "Dịch vụ Accessibility", "Accessibility", 8),
    ("Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction", "Tự thao tác lên giao diện ứng dụng khác", "Accessibility", 10),
    ("Landroid/media/MediaRecorder;", "start", "Ghi âm/ghi hình", "Giám sát", 5),
    ("Landroid/hardware/Camera;", "takePicture", "Chụp ảnh ngầm", "Giám sát", 5),
    ("Landroid/location/LocationManager;", "requestLocationUpdates", "Theo dõi vị trí liên tục", "Giám sát", 3),
    ("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting", "Ẩn/hiện thành phần (ẩn icon)", "Che giấu", 8),
    ("Landroid/content/pm/PackageInstaller;", None, "Cài đặt gói ứng dụng", "Cài đặt", 6),
    ("Landroid/app/DownloadManager;", None, "Tải tệp từ mạng", "Mạng", 3),
    ("Ljava/net/HttpURLConnection;", "connect", "Kết nối HTTP", "Mạng", 0),
    ("Landroid/webkit/WebView;", "addJavascriptInterface", "Cầu nối JavaScript → Java", "Web", 5),
    ("Landroid/content/ClipboardManager;", "getPrimaryClip", "Đọc clipboard", "Giám sát", 4),
    ("Landroid/telephony/gsm/SmsManager;", "sendTextMessage", "Gửi SMS (API cũ)", "SMS", 10),
]

# ---------------------------------------------------------------- CHUỖI
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{2,40}@[A-Za-z0-9.-]{2,40}\.[A-Za-z]{2,10}\b")
SUSPICIOUS_STRINGS = [
    (re.compile(r"/system/(?:bin|xbin)/su\b|\bsu -c\b|Superuser\.apk|com\.topjohnwu\.magisk"), "Dấu hiệu tìm/dùng quyền root", 4),
    (re.compile(r"api\.telegram\.org/bot"), "Kênh điều khiển qua Telegram bot", 14),
    (re.compile(r"\b(?:bitcoin|monero|stratum\+tcp)\b", re.I), "Dấu hiệu đào tiền ảo", 8),
    (re.compile(r"\.onion\b"), "Địa chỉ Tor (.onion)", 10),
    (re.compile(r"pastebin\.com/raw|raw\.githubusercontent\.com"), "Tải cấu hình/payload từ dịch vụ công cộng", 4),
]
SHORTENER_HOSTS = ("bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "shorturl.at")
BENIGN_URL_HOSTS = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org", "android.com", "google.com",
    "googleapis.com", "gstatic.com", "github.com", "mozilla.org", "example.com", "w3.org",
)

CATEGORY_CAPS = {"Bytecode": 30, "Quyền": 30, "Chuỗi": 20, "Che giấu": 20, "Manifest": 10, "Chữ ký": 12}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(severity, title, detail="", score=0, category=""):
    return {"severity": severity, "title": title, "detail": detail, "score": score, "category": category}


def _short(perm):
    return perm.split(".")[-1]


def _entropy(data):
    import math
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(-sum(c / total * math.log2(c / total) for c in counts.values()), 3)


# ---------------------------------------------------------------- CHỮ KÝ
def _analyze_certificate(a):
    info = {"signed": False, "schemes": [], "certificates": []}
    findings = []
    try:
        schemes = [n for n, f in (("v1", a.is_signed_v1), ("v2", a.is_signed_v2), ("v3", a.is_signed_v3)) if f()]
    except Exception:
        schemes = []
    info["schemes"] = schemes
    info["signed"] = bool(schemes)

    try:
        certs = a.get_certificates() or []
    except Exception:
        certs = []
    for c in certs[:3]:
        try:
            subject = c.subject.human_friendly
            issuer = c.issuer.human_friendly
            entry = {
                "subject": subject,
                "issuer": issuer,
                "self_signed": subject == issuer,
                "sha256": c.sha256_fingerprint.replace(" ", "").lower() if hasattr(c, "sha256_fingerprint") else "",
                "valid_from": str(c["tbs_certificate"]["validity"]["not_before"].native),
                "valid_to": str(c["tbs_certificate"]["validity"]["not_after"].native),
                "algorithm": c.signature_algo,
            }
            info["certificates"].append(entry)
            if "android debug" in subject.lower():
                findings.append(_finding("high", "Ký bằng chứng chỉ DEBUG của Android",
                                         "APK phát hành thật không dùng chứng chỉ debug.", 10, "Chữ ký"))
            if entry["algorithm"] and "md5" in entry["algorithm"].lower():
                findings.append(_finding("medium", "Chứng chỉ dùng thuật toán yếu (MD5)", entry["algorithm"], 5, "Chữ ký"))
            if entry["algorithm"] and "sha1" in entry["algorithm"].lower() and "v2" not in schemes:
                findings.append(_finding("low", "Chứng chỉ dùng SHA-1", entry["algorithm"], 2, "Chữ ký"))
        except Exception:
            continue

    if not info["signed"]:
        findings.append(_finding("high", "APK không có chữ ký số hợp lệ", "", 12, "Chữ ký"))
    elif schemes == ["v1"]:
        findings.append(_finding("low", "Chỉ ký bằng scheme v1 (dễ bị Janus)", "", 3, "Chữ ký"))
    if info["certificates"] and all(c["self_signed"] for c in info["certificates"]):
        # Gần như mọi APK Android đều tự ký → chỉ ghi nhận, không cộng điểm
        findings.append(_finding("info", "Chứng chỉ tự ký (bình thường với APK Android)", "", 0, "Chữ ký"))
    return info, findings


# ---------------------------------------------------------------- MANIFEST
def _analyze_manifest(a):
    findings = []
    perms = sorted(set(a.get_permissions() or []))
    short = {_short(p) for p in perms}

    critical = [{"name": p, "reason": CRITICAL_PERMS[_short(p)]} for p in perms if _short(p) in CRITICAL_PERMS]
    dangerous = [p for p in perms if _short(p) in DANGEROUS_PERMS]
    custom = [p for p in perms if not p.startswith("android.permission.") and not p.startswith("com.android.")]

    if critical:
        findings.append(_finding(
            "high" if len(critical) >= 3 else "medium",
            f"{len(critical)} quyền cực kỳ nhạy cảm",
            "; ".join(_short(c["name"]) for c in critical),
            min(30, 6 * len(critical)), "Quyền"))
    if len(dangerous) >= 8:
        findings.append(_finding("medium", f"Xin quá nhiều quyền nguy hiểm ({len(dangerous)})", "", 6, "Quyền"))

    combos = []
    for req, msg, pts in PERM_COMBOS:
        if req.issubset(short):
            combos.append(msg)
            findings.append(_finding("high" if pts >= 12 else "medium" if pts >= 6 else "low", "Tổ hợp quyền nguy hiểm", msg, pts, "Quyền"))

    flags = {}
    try:
        flags["debuggable"] = bool(a.is_debuggable())
    except Exception:
        flags["debuggable"] = False
    try:
        flags["allow_backup"] = bool(a.is_allow_backup())
    except Exception:
        flags["allow_backup"] = False
    try:
        app_el = a.get_android_manifest_xml().find("application")
        ns = "{http://schemas.android.com/apk/res/android}"
        flags["uses_cleartext_traffic"] = app_el is not None and app_el.get(ns + "usesCleartextTraffic") == "true"
    except Exception:
        flags["uses_cleartext_traffic"] = False
    if flags["debuggable"]:
        findings.append(_finding("high", "Ứng dụng bật debuggable", "Cho phép gắn debugger, đọc dữ liệu ứng dụng.", 8, "Manifest"))
    if flags["uses_cleartext_traffic"]:
        findings.append(_finding("low", "Cho phép lưu lượng HTTP không mã hoá", "", 2, "Manifest"))

    components = {}
    exported_unprotected = []
    ns = "{http://schemas.android.com/apk/res/android}"
    try:
        root = a.get_android_manifest_xml()
        app_el = root.find("application")
        for tag in ("activity", "service", "receiver", "provider"):
            els = list(app_el.iter(tag)) if app_el is not None else []
            components[tag] = len(els)
            for el in els:
                name = el.get(ns + "name", "")
                exported = el.get(ns + "exported")
                has_filter = el.find("intent-filter") is not None
                is_exported = exported == "true" or (exported is None and has_filter)
                if is_exported and not el.get(ns + "permission") and tag in ("service", "receiver", "provider"):
                    exported_unprotected.append(f"{tag}: {name}")
    except Exception:
        for tag, getter in (("activity", a.get_activities), ("service", a.get_services),
                            ("receiver", a.get_receivers), ("provider", a.get_providers)):
            try:
                components[tag] = len(getter() or [])
            except Exception:
                components[tag] = 0
    if exported_unprotected:
        findings.append(_finding(
            "low" if len(exported_unprotected) < 5 else "medium",
            f"{len(exported_unprotected)} service/receiver/provider exported không có permission bảo vệ",
            "; ".join(exported_unprotected[:5]), min(6, len(exported_unprotected)), "Manifest"))

    # Service nhạy cảm
    sensitive_services = []
    try:
        for s in a.get_services() or []:
            sensitive_services.append(s)
        sensitive_services = [s for s in sensitive_services if re.search(r"accessib|devicead|notificationlisten", s, re.I)]
    except Exception:
        pass

    return {
        "permissions": perms,
        "critical_permissions": critical,
        "dangerous_permissions": dangerous,
        "custom_permissions": custom,
        "permission_combos": combos,
        "flags": flags,
        "components": components,
        "exported_unprotected": exported_unprotected[:30],
        "sensitive_services": sensitive_services[:10],
    }, findings


# ---------------------------------------------------------------- BYTECODE / CHUỖI
def _analyze_bytecode(dx, d_list, has_accessibility_service=False):
    findings = []
    api_hits = defaultdict(set)  # nhãn -> {class->method}
    api_meta = {}

    try:
        for m in dx.get_methods():
            try:
                if not m.is_external():
                    continue
                cls = str(m.class_name)
                name = str(m.name)
            except Exception:
                continue
            for pat, meth, label, cat, score in SUSPICIOUS_APIS:
                if cls.startswith(pat) and (meth is None or name == meth):
                    api_hits[label].add(f"{cls[1:-1].replace('/', '.')}.{name}")
                    api_meta[label] = (cat, score)
    except Exception:
        pass

    apis = []
    for label, refs in api_hits.items():
        cat, score = api_meta[label]
        apis.append({"label": label, "category": cat, "score": score, "refs": sorted(refs)[:5]})
    if not has_accessibility_service:
        # Thư viện bên thứ ba hay tham chiếu lớp Accessibility; chỉ đáng ngờ khi app tự khai báo service
        for item in apis:
            if item["category"] == "Accessibility":
                item["score"] = 0
    apis.sort(key=lambda x: -x["score"])

    by_cat = defaultdict(int)
    for item in apis:
        by_cat[item["category"]] += item["score"]
    for cat, pts in by_cat.items():
        if pts <= 0:
            continue
        labels = [i["label"] for i in apis if i["category"] == cat and i["score"] > 0]
        sev = "high" if pts >= 18 else "medium" if pts >= 8 else "low"
        findings.append(_finding(sev, f"API nhạy cảm — {cat}", "; ".join(labels), min(pts, 10), "Bytecode"))

    # Chuỗi
    urls, ips, emails, str_findings = set(), set(), set(), []
    total_strings = 0
    try:
        for sa in dx.get_strings():
            try:
                s = str(sa.get_value())
            except Exception:
                continue
            total_strings += 1
            if len(s) > 400:
                continue
            for u in URL_RE.findall(s):
                urls.add(u)
            for ip in IP_RE.findall(s):
                if not ip.startswith(("0.", "127.", "255.")) and ip != "1.0.0.0":
                    ips.add(ip)
            for e in EMAIL_RE.findall(s):
                emails.add(e)
            for rx, label, score in SUSPICIOUS_STRINGS:
                if rx.search(s):
                    str_findings.append((label, score))
    except Exception:
        pass

    seen = {}
    for label, score in str_findings:
        seen[label] = max(seen.get(label, 0), score)
    for label, score in seen.items():
        findings.append(_finding("high" if score >= 10 else "medium", label, "", score, "Chuỗi"))

    def host(u):
        m = re.match(r"https?://([^/:?#]+)", u)
        return m.group(1).lower() if m else ""

    interesting_urls = sorted(u for u in urls if not any(host(u).endswith(b) for b in BENIGN_URL_HOSTS))
    shorteners = [u for u in interesting_urls if host(u) in SHORTENER_HOSTS]
    ip_urls = [u for u in interesting_urls if IP_RE.fullmatch(host(u) or "")]
    if shorteners:
        findings.append(_finding("medium", "Chứa link rút gọn", "; ".join(shorteners[:3]), 2, "Chuỗi"))
    if ip_urls:
        findings.append(_finding("medium", "Kết nối trực tiếp tới địa chỉ IP", "; ".join(ip_urls[:3]), 6, "Chuỗi"))

    return {
        "suspicious_apis": apis,
        "urls": interesting_urls[:40],
        "url_total": len(urls),
        "ips": sorted(ips)[:20],
        "emails": sorted(emails)[:15],
        "string_count": total_strings,
    }, findings


# ---------------------------------------------------------------- CHE GIẤU / ĐÓNG GÓI
def _analyze_obfuscation(a, dx):
    findings = []
    files = []
    try:
        files = a.get_files()
    except Exception:
        pass

    dex_bytes = b""
    dex_files = [f for f in files if f.endswith(".dex")]
    try:
        for f in dex_files:
            dex_bytes += a.get_file(f)
    except Exception:
        pass
    entropy = _entropy(dex_bytes[:2_000_000])

    # Tên lớp bị làm rối: lớp gốc của app có tên 1-2 ký tự
    short_cls, total_cls = 0, 0
    try:
        for c in dx.get_classes():
            if c.is_external():
                continue
            name = str(c.name)[1:-1].split("/")[-1].split("$")[0]
            total_cls += 1
            if len(name) <= 2:
                short_cls += 1
    except Exception:
        pass
    ratio = round(short_cls / total_cls, 3) if total_cls else 0.0

    native_libs = sorted({f for f in files if f.endswith(".so")})
    abis = sorted({f.split("/")[1] for f in native_libs if f.startswith("lib/") and f.count("/") >= 2})
    embedded = []
    for f in files:
        low = f.lower()
        if f.startswith("assets/") or f.startswith("res/raw/"):
            if low.endswith((".apk", ".dex", ".jar", ".bin", ".dat", ".enc")):
                try:
                    head = a.get_file(f)[:4]
                except Exception:
                    head = b""
                if low.endswith((".apk", ".dex", ".jar")) or head[:2] == b"PK" or head[:3] == b"dex":
                    embedded.append(f)

    if len(dex_files) > 3:
        findings.append(_finding("low", f"Nhiều tệp DEX ({len(dex_files)})", "Multidex hoặc packer.", 2, "Che giấu"))
    if entropy >= 7.5:
        findings.append(_finding("medium", f"Entropy DEX rất cao ({entropy})", "Mã có thể bị nén/mã hoá (packer).", 6, "Che giấu"))
    if total_cls >= 30 and ratio >= 0.5:
        findings.append(_finding("low", f"{int(ratio * 100)}% lớp có tên 1-2 ký tự", "Dấu hiệu làm rối mã (ProGuard/R8 hoặc cố ý che giấu).", 3, "Che giấu"))
    if embedded:
        findings.append(_finding("high", "Nhúng sẵn payload (APK/DEX/JAR) trong assets", "; ".join(embedded[:3]), 14, "Che giấu"))

    return {
        "dex_count": len(dex_files),
        "dex_entropy": entropy,
        "obfuscated_class_ratio": ratio,
        "class_count": total_cls,
        "native_libs": native_libs[:20],
        "native_abis": abis,
        "embedded_payloads": embedded[:10],
        "file_count": len(files),
    }, findings


# ---------------------------------------------------------------- ĐIỂM TỔNG
def _grade(score):
    if score >= 70:
        return "Rất cao"
    if score >= 45:
        return "Cao"
    if score >= 20:
        return "Trung bình"
    return "Thấp"


def analyze_deep(apk_path):
    """Chạy toàn bộ các lớp phân tích tĩnh cục bộ. Trả về dict báo cáo (JSON-serializable)."""
    a, d, dx = AnalyzeAPK(apk_path)

    with open(apk_path, "rb") as f:
        data = f.read()
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    def safe(fn, default="N/A"):
        try:
            v = fn()
            return v if v not in (None, "") else default
        except Exception:
            return default

    info = {
        "package_name": safe(a.get_package),
        "app_name": safe(a.get_app_name),
        "version_name": safe(a.get_androidversion_name),
        "version_code": safe(a.get_androidversion_code),
        "min_sdk": safe(a.get_min_sdk_version),
        "target_sdk": safe(a.get_target_sdk_version),
        "main_activity": safe(a.get_main_activity),
        "file_size_kb": round(len(data) / 1024, 1),
        **hashes,
    }

    cert, f_cert = _analyze_certificate(a)
    manifest, f_man = _analyze_manifest(a)
    bytecode, f_code = _analyze_bytecode(dx, d, bool(manifest["sensitive_services"]) and any("accessib" in s.lower() for s in manifest["sensitive_services"]))
    obf, f_obf = _analyze_obfuscation(a, dx)
    code_layers = analyze_code_layers(a, dx, obf)

    findings = f_cert + f_man + f_code + f_obf
    findings.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], -x["score"]))
    category_scores = defaultdict(int)
    for f in findings:
        category_scores[f["category"]] += f["score"]
    # Giới hạn đóng góp mỗi nhóm để ứng dụng lớn (nhiều SDK) không đạt điểm tối đa chỉ vì số lượng
    capped = {c: min(v, CATEGORY_CAPS.get(c, 10)) for c, v in category_scores.items()}
    # App rất lớn chứa nhiều SDK nên tham chiếu API nhạy cảm là bình thường → giảm trọng số bytecode
    n_cls = obf["class_count"]
    size_factor = 1.0 if n_cls < 3000 else 0.6 if n_cls < 10000 else 0.4
    if "Bytecode" in capped:
        capped["Bytecode"] = round(capped["Bytecode"] * size_factor, 1)
    rule_score = min(100, sum(capped.values()))

    return {
        "info": info,
        **code_layers,
        "certificate": cert,
        "manifest": manifest,
        "bytecode": bytecode,
        "obfuscation": obf,
        "findings": findings,
        "rule_score": rule_score,
        "rule_grade": _grade(rule_score),
        "category_scores": dict(category_scores),
        "category_scores_capped": capped,
    }


# ---------------------------------------------------------------- KẾT HỢP ML + LUẬT
def combine_verdict(ml_class, ml_confidence, rule_score, ml_reliable=True):
    """
    Kết hợp mô hình học máy và điểm luật thành điểm rủi ro cuối (0-100).

    ml_class: '1' = benign, khác = mã độc. ml_confidence: 0-100.
    Nếu model không đáng tin (chưa train bản tĩnh), chỉ dựa vào luật.
    """
    if ml_reliable:
        ml_risk = (100 - ml_confidence) if ml_class == "1" else ml_confidence
        # Luật có trọng số lớn hơn khi model nói "an toàn" nhưng luật thấy nhiều dấu hiệu
        final = round(0.5 * ml_risk + 0.5 * rule_score)
        # Hai nguồn bất đồng mạnh → lấy giá trị cao hơn một phần (ưu tiên an toàn)
        final = max(final, round(0.75 * max(ml_risk, rule_score)))
    else:
        ml_risk = None
        final = round(rule_score)
    final = max(0, min(100, final))

    if final >= 75:
        verdict, level = "NGUY HIỂM — nhiều bằng chứng mã độc", "danger"
    elif final >= 55:
        verdict, level = "ĐÁNG NGỜ — nên gỡ hoặc kiểm tra kỹ", "warning"
    elif final >= 25:
        verdict, level = "CẦN LƯU Ý — có một số hành vi rủi ro", "caution"
    else:
        verdict, level = "AN TOÀN — chưa thấy dấu hiệu bất thường", "safe"

    agreement = None
    if ml_reliable:
        agreement = (ml_risk >= 45) == (rule_score >= 45)
    return {
        "final_score": final,
        "verdict": verdict,
        "level": level,
        "ml_risk": ml_risk,
        "rule_score": rule_score,
        "engines_agree": agreement,
    }
