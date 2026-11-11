"""Layers 2/3: versioned static evidence from Androguard cross references.

No APK execution, decryption or taint analysis. Both layers belong to the
same evidence family and intentionally do not modify the legacy risk score.
"""

import re
import base64
import hashlib
import time
from collections import Counter
from scanner.string_constants import reversed_name_evidence

VERSION = "2.2.0"

MAX_FINDINGS = 100
MAX_CALLS_PER_FINDING = 20
ORIGIN_PRIORITY = {"application": 0, "unknown": 1, "third_party": 2}
LIBRARY_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Lcom/google/", "Lcom/facebook/", "Lcom/unity3d/", "Lokhttp3/",
    "Lokio/", "Lretrofit2/", "Lorg/apache/", "Lio/reactivex/",
    "Lcom/squareup/", "Lcom/bumptech/", "Lcom/airbnb/", "Lorg/chromium/",
    "Lio/flutter/", "Lcom/tencent/", "Lcom/alibaba/", "Lorg/jetbrains/",
)

LAYER2_RULES = (
    ("dynamic_dex", "Nạp DEX động", "medium", {
        ("Ldalvik/system/DexClassLoader;", "<init>"),
        ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
        ("Ldalvik/system/DexFile;", "loadDex"),
        ("Ldalvik/system/PathClassLoader;", "<init>"),
        ("Ldalvik/system/DelegateLastClassLoader;", "<init>"),
        ("Ldalvik/system/DexFile;", "<init>"),
    }),
    ("reflection", "Gọi hàm qua reflection", "low", {
        ("Ljava/lang/reflect/Method;", "invoke"),
        ("Ljava/lang/Class;", "forName"),
        ("Ljava/lang/Class;", "getDeclaredMethod"),
        ("Ljava/lang/Class;", "getMethod"),
        ("Ljava/lang/Class;", "newInstance"),
        ("Ljava/lang/reflect/Constructor;", "newInstance"),
    }),
    ("crypto", "Mã hóa hoặc giải mã dữ liệu", "info", {
        ("Ljavax/crypto/Cipher;", "doFinal"),
        ("Ljavax/crypto/Cipher;", "getInstance"),
    }),
    ("native_loading", "Nạp thư viện native", "info", {
        ("Ljava/lang/System;", "load"), ("Ljava/lang/System;", "loadLibrary"),
        ("Ljava/lang/Runtime;", "load"), ("Ljava/lang/Runtime;", "loadLibrary"),
    }),
    ("base64_decode", "Giải mã biểu diễn Base64", "info", {
        ("Landroid/util/Base64;", "decode"),
        ("Ljava/util/Base64$Decoder;", "decode"),
    }),
)

SOURCES = {
    ("Landroid/telephony/SmsMessage;", "getMessageBody"): "SMS",
    ("Landroid/telephony/SmsMessage;", "getDisplayMessageBody"): "SMS",
    ("Landroid/telephony/TelephonyManager;", "getDeviceId"): "Định danh thiết bị",
    ("Landroid/telephony/TelephonyManager;", "getImei"): "Định danh thiết bị",
    ("Landroid/telephony/TelephonyManager;", "getSubscriberId"): "Định danh thuê bao",
    ("Landroid/telephony/TelephonyManager;", "getLine1Number"): "Số điện thoại",
    ("Landroid/location/Location;", "getLatitude"): "Vị trí",
    ("Landroid/location/Location;", "getLongitude"): "Vị trí",
    ("Landroid/location/LocationManager;", "getLastKnownLocation"): "Vị trí",
    ("Landroid/hardware/Camera;", "takePicture"): "Camera",
    ("Landroid/content/ClipboardManager;", "getPrimaryClip"): "Clipboard",
    ("Landroid/telephony/TelephonyManager;", "getMeid"): "Định danh thiết bị",
    ("Landroid/telephony/TelephonyManager;", "getSimSerialNumber"): "Định danh thuê bao",
    ("Landroid/accounts/AccountManager;", "getAccounts"): "Tài khoản",
    ("Landroid/accounts/AccountManager;", "getAccountsByType"): "Tài khoản",
    ("Landroid/location/LocationManager;", "requestLocationUpdates"): "Vị trí",
    ("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation"): "Vị trí",
    ("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getCurrentLocation"): "Vị trí",
    ("Landroid/hardware/camera2/CameraCaptureSession;", "capture"): "Camera",
    ("Landroid/media/AudioRecord;", "read"): "Âm thanh",
    ("Landroid/media/MediaRecorder;", "start"): "Âm thanh/hình ảnh",
    ("Landroid/service/notification/StatusBarNotification;", "getNotification"): "Thông báo",
}
SINKS = {
    ("Ljava/net/URLConnection;", "getOutputStream"),
    ("Ljava/net/HttpURLConnection;", "getOutputStream"),
    ("Ljavax/net/ssl/HttpsURLConnection;", "getOutputStream"),
    ("Ljava/net/Socket;", "getOutputStream"),
    ("Ljava/net/DatagramSocket;", "send"),
    ("Lokhttp3/Call;", "execute"), ("Lokhttp3/Call;", "enqueue"),
    ("Lokhttp3/RealCall;", "execute"), ("Lokhttp3/RealCall;", "enqueue"),
    ("Lokhttp3/internal/connection/RealCall;", "execute"),
    ("Lokhttp3/internal/connection/RealCall;", "enqueue"),
    ("Lorg/apache/http/client/HttpClient;", "execute"),
    ("Lorg/apache/http/impl/client/DefaultHttpClient;", "execute"),
    ("Lcom/squareup/okhttp/Call;", "execute"), ("Lcom/squareup/okhttp/Call;", "enqueue"),
    ("Lretrofit2/Call;", "execute"), ("Lretrofit2/Call;", "enqueue"),
    ("Landroid/webkit/WebView;", "postUrl"),
    ("Lokhttp3/WebSocket;", "send"),
}

URI_SOURCES = (("content://sms", "SMS"), ("content://mms", "MMS"),
               ("content://com.android.contacts", "Danh bạ"), ("content://contacts", "Danh bạ"),
               ("content://call_log", "Nhật ký cuộc gọi"),
               ("content://com.android.calendar", "Lịch"))


def method_info(method):
    raw = method.get_method()
    return {
        "class_name": str(raw.get_class_name()),
        "method_name": str(raw.get_name()),
        "descriptor": str(raw.get_descriptor()),
    }


def origin_for(class_name, package):
    # Prefixes are a heuristic, not proof of ownership or trust.
    if class_name.startswith(LIBRARY_PREFIXES):
        return "third_party"
    app_prefix = "L" + package.replace(".", "/") + "/" if package else None
    if app_prefix and class_name.startswith(app_prefix):
        return "application"
    return "unknown"


def encoded_candidate(value):
    """Conservative hint only; encoded strings are common in benign apps."""
    if not 80 <= len(value) <= 4096:
        return False
    if len(set(value)) < 16:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value))


def analyze_code_layers(apk, analysis, obfuscation, artifact_report=None):
    started = time.monotonic()
    package = apk.get_package() or ""
    layer2, layer3 = [], []
    counts2, counts3 = Counter(), Counter()
    scanned, errors = 0, 0
    issues = []
    dedup = {id(layer2): set(), id(layer3): set()}
    score_totals = {id(layer2): {}, id(layer3): {}}
    weights = {"dynamic_dex": 20, "reflection": 4, "crypto": 2, "native_loading": 2,
               "encoded_string": 3, "base64_decode": 1, "loader_with_encoding": 35,
               "embedded_payload": 12, "short_class_names": 5, "encoded_string_reversal": 3}
    method_strings = {}
    provider_strings = {}
    def issue(component, exc):
        nonlocal errors
        errors += 1
        if len(issues) < 20:
            issues.append({"component": component, "reason": f"{type(exc).__name__}: {exc}"})
    # Index only candidate strings, retaining their caller and bytecode offset.
    encoded = {}
    try:
        for string_index, string in enumerate(analysis.get_strings()):
            if string_index >= 500000 or time.monotonic() - started > 90:
                issue("strings", TimeoutError("Giới hạn chuỗi/thời gian phân tích"))
                break
            try:
                value = str(string.get_value())
                is_encoded = encoded_candidate(value)
                if not is_encoded and not value.startswith(("content://", "http://", "https://")):
                    continue
                for _, caller, offset in string.get_xref_from(with_offset=True):
                    key = tuple(method_info(caller).values())
                    all_strings = method_strings.setdefault(key, [])
                    if len(all_strings) < 32:
                        all_strings.append({"value": value[:512], "offset": int(offset)})
                    if any(value == prefix or value.startswith(prefix + '/') for prefix, _ in URI_SOURCES):
                        providers = provider_strings.setdefault(key, {})
                        # Keep one example per provider even after the general preview fills up.
                        prefix = next(prefix for prefix, _ in URI_SOURCES if value == prefix or value.startswith(prefix + '/'))
                        providers.setdefault(prefix, {"value": value[:512], "offset": int(offset)})
                    if not is_encoded:
                        continue
                    bucket = encoded.setdefault(key, [])
                    if len(bucket) < 3:
                        evidence = {"value": value[:160], "length": len(value),
                                    "offset": int(offset), "preview_truncated": len(value) > 160}
                        try:
                            decoded = base64.b64decode(value, validate=True)
                            evidence["decoded_kind"] = "dex" if decoded.startswith(b"dex\n") else "zip" if decoded.startswith(b"PK\x03\x04") else "other"
                        except ValueError:
                            evidence["decoded_kind"] = "unverified"
                        bucket.append(evidence)
            except Exception as exc:
                issue("strings", exc)
    except Exception as exc:
        issue("strings", exc)

    def record(target, counts, finding):
        # Stable evidence IDs are shared across exports and future arbitration.
        identity = [finding.get(k, "") for k in ("rule_id", "class_name", "method_name", "descriptor", "file_path")]
        finding["evidence_id"] = hashlib.sha256("|".join(identity).encode()).hexdigest()[:20]
        if finding["evidence_id"] in dedup[id(target)]:
            return
        dedup[id(target)].add(finding["evidence_id"])
        weight = weights.get(finding["rule_id"], 2) if target is layer2 else 20 + 5 * min(3, len(finding.get("data_types", [])))
        factor = {"application": 1.0, "unknown": 0.75, "third_party": 0.25}[finding["origin"]]
        totals = score_totals[id(target)]
        technique = finding.get('technique', finding['rule_id'])
        if technique == 'loader_with_encoding':
            technique = 'dynamic_dex'
        totals[technique] = max(totals.get(technique, 0), weight * factor)
        counts[finding["origin"]] += 1
        if len(target) < MAX_FINDINGS:
            target.append(finding)
        else:
            # Keep application evidence visible even when SDKs fill the report.
            worst = max(range(len(target)), key=lambda i: ORIGIN_PRIORITY[target[i]["origin"]])
            if ORIGIN_PRIORITY[finding["origin"]] < ORIGIN_PRIORITY[target[worst]["origin"]]:
                target[worst] = finding

    try:
        methods = list(analysis.get_methods()) if analysis is not None else []
    except Exception as exc:
        issue("methods", exc)
        methods = []
    for method in methods:
        if scanned >= 250000 or time.monotonic() - started > 90:
            issue("methods", TimeoutError("Giới hạn số hàm/thời gian phân tích"))
            break
        try:
            if method.is_external():
                continue
            info = method_info(method)
            scanned += 1
            origin = origin_for(info["class_name"], package)
            calls = []
            for _, callee, offset in method.get_xref_to():
                call = method_info(callee)
                call["offset"] = int(offset)
                calls.append(call)
            calls.sort(key=lambda c: (c["offset"], c["class_name"], c["method_name"], c["descriptor"]))
            base = {**info, "origin": origin, "evidence_family": "code_behavior"}
            techniques = set()
            if any(c['method_name'] == 'reverse' and c['class_name'] in
                   ('Ljava/lang/StringBuffer;', 'Ljava/lang/StringBuilder;') for c in calls):
                for proof in reversed_name_evidence(method):
                    record(layer2, counts2, {**base, 'rule_id': 'encoded_string_reversal',
                           'title': 'Chuỗi hằng đảo ngược dùng làm tên reflection', 'severity': 'info',
                           'string_proof': proof, 'flow_confirmed': False})
            for rule_id, title, severity, targets in LAYER2_RULES:
                hits = [c for c in calls if (c["class_name"], c["method_name"]) in targets]
                if hits:
                    techniques.add(rule_id)
                    record(layer2, counts2, {**base, "rule_id": rule_id, "title": title,
                           "severity": severity, "calls": hits[:MAX_CALLS_PER_FINDING],
                           "call_count": len(hits)})
            strings = encoded.get(tuple(info.values()), [])
            if strings:
                record(layer2, counts2, {**base, "rule_id": "encoded_string",
                       "title": "Chuỗi dài có dạng Base64 (chưa xác nhận mã hóa)",
                       "severity": "info", "strings": strings})
            key = tuple(info.values())
            context_strings = list(provider_strings.get(key, {}).values()) + method_strings.get(key, [])
            # Android commonly supplies content URIs through framework static fields.
            if hasattr(method, "get_xref_read"):
                for reference in method.get_xref_read():
                    _, field = reference[:2]
                    raw_field = field.get_field() if hasattr(field, 'get_field') else field
                    owner, field_name = str(raw_field.get_class_name()), str(raw_field.get_name())
                    if field_name == "CONTENT_URI":
                        uri = ("content://sms" if owner.startswith("Landroid/provider/Telephony$Sms") else
                               "content://mms" if owner.startswith("Landroid/provider/Telephony$Mms") else
                               "content://com.android.contacts" if owner.startswith("Landroid/provider/ContactsContract$") else
                               "content://call_log" if owner == "Landroid/provider/CallLog$Calls;" else
                               "content://com.android.calendar" if owner.startswith("Landroid/provider/CalendarContract$") else None)
                        if uri:
                            context_strings = context_strings + [{"value": uri, "offset": None,
                                                                  "field": owner + "->" + field_name}]
            if "dynamic_dex" in techniques and ("crypto" in techniques or strings):
                record(layer2, counts2, {**base, "rule_id": "loader_with_encoding",
                       "title": "Nạp mã động cùng xử lý mã hóa trong một hàm",
                       "severity": "medium", "calls": calls[:MAX_CALLS_PER_FINDING],
                       "strings": strings, "flow_confirmed": False})
            sources = [dict(c, data_type=SOURCES[(c["class_name"], c["method_name"])])
                       for c in calls if (c["class_name"], c["method_name"]) in SOURCES]
            sinks = [c for c in calls if (c["class_name"], c["method_name"]) in SINKS]
            for c in calls:
                if c["class_name"] == "Landroid/content/ContentResolver;" and c["method_name"] in ("query", "openInputStream", "openFileDescriptor"):
                    for uri_prefix, data_type in URI_SOURCES:
                        # Boundary prevents content://sms.example from becoming an SMS source.
                        uris = [s for s in context_strings if s["value"] == uri_prefix or
                                s["value"].startswith(uri_prefix + "/")]
                        if uris:
                            sources.append(dict(c, data_type=data_type, uri_evidence=uris[:3],
                                                source_basis="URI và truy vấn cùng hàm; chưa theo dõi thanh ghi"))
            if sources and sinks:
                record(layer3, counts3, {**base, "rule_id": "sensitive_network_same_method",
                       "title": "API nhạy cảm và API mạng cùng một hàm",
                       "severity": "low" if origin == "third_party" else "medium",
                       "sources": sources[:MAX_CALLS_PER_FINDING],
                       "sinks": sinks[:MAX_CALLS_PER_FINDING],
                       "source_count": len(sources), "sink_count": len(sinks),
                       "data_types": sorted({c["data_type"] for c in sources}),
                       "strings": context_strings[:8],
                       "source_before_sink": any(s["offset"] < k["offset"] for s in sources for k in sinks),
                       "flow_confirmed": False})
        except Exception as exc:
            issue("method", exc)

    # Artifact/YARA matches have file offsets, not a fabricated Java caller.
    artifacts = artifact_report or {}
    for finding in artifacts.get("findings", []):
        record(layer2, counts2, {**finding, "origin": "unknown", "evidence_family": "code_behavior"})
    for payload in artifacts.get("payload_details", []):
        record(layer2, counts2, {"rule_id": "embedded_payload", "title": "Tệp thực thi nhúng trong tài nguyên",
               "severity": "low", "origin": "unknown", "evidence_family": "code_behavior", **payload})
    for technique in artifacts.get('indicator_techniques', []):
        score_totals[id(layer2)][technique] = max(score_totals[id(layer2)].get(technique, 0), 1.5)

    # Compute short-name ratios separately from known SDKs, never use whole-app size as trust.
    class_counts, short_counts = Counter(), Counter()
    if analysis is not None and hasattr(analysis, "get_classes"):
        try:
            for cls in analysis.get_classes():
                if cls.is_external():
                    continue
                name = str(cls.name)
                origin = origin_for(name, package)
                class_counts[origin] += 1
                if len(name.rstrip(";").rsplit("/", 1)[-1].split("$")[0]) <= 2:
                    short_counts[origin] += 1
        except Exception as exc:
            issue("classes", exc)
    for origin, total in class_counts.items():
        ratio = short_counts[origin] / total
        if total >= 30 and ratio >= 0.5:
            record(layer2, counts2, {"rule_id": "short_class_names", "title": "Nhiều tên lớp ngắn (có thể do R8/ProGuard)",
                   "origin": origin, "evidence_family": "code_behavior", "severity": "info", "ratio": round(ratio, 3),
                   "class_count": total})

    def result(findings, counts, limitations):
        total = sum(counts.values())
        findings.sort(key=lambda f: (ORIGIN_PRIORITY[f["origin"]], f.get("class_name", ""),
                                     f.get("method_name", ""), f.get("descriptor", ""),
                                     f["rule_id"], f.get("file_path", "")))
        status = "unavailable" if not scanned else "partial" if errors else "completed"
        return {"status": status, "stage": "implemented", "available": bool(scanned), "version": VERSION,
                "evidence_family": "code_behavior", "methods_scanned": scanned,
                "analysis_errors": errors, "finding_count": total,
                "counts_by_origin": dict(counts), "findings": findings,
                "truncated": total > len(findings), "limitations": limitations, "issues": issues,
                "score_kind": "heuristic_indicator_not_probability",
                "score": None, "requires_dynamic_confirmation": bool(total) or status != "completed",
                "rule_count": len(LAYER2_RULES) if findings is layer2 else len(SOURCES) + len(URI_SOURCES) + len(SINKS)}

    reports = {
        "layer2": {**result(layer2, counts2, [
            "Chỉ nhận diện dấu hiệu; reflection, mã hóa và native không đồng nghĩa mã độc.",
            "YARA nhận diện chỉ báo; chưa giải mã payload hay phân tích ngữ nghĩa mã native.",
            "Phân loại thư viện theo tiền tố; mã ngoài danh sách được ghi là chưa xác định.",
        ]), "artifacts": {
            **artifacts,
            "embedded_payloads": artifacts.get("embedded_payloads", obfuscation.get("embedded_payloads", [])),
            "native_libs": artifacts.get("native_libs", obfuscation.get("native_libs", [])),
            "dex_entropy": obfuscation.get("dex_entropy", 0),
            "obfuscated_class_ratio": obfuscation.get("obfuscated_class_ratio", 0),
            "classes_by_origin": dict(class_counts), "short_classes_by_origin": dict(short_counts),
        }},
        "layer3": result(layer3, counts3, [
            "API cùng hàm chỉ là nguy cơ; chưa chứng minh dữ liệu được gửi ra mạng.",
            "Chưa theo dõi luồng dữ liệu, nhánh thực thi, lời gọi qua nhiều hàm hoặc reflection.",
            "Chỉ bao phủ danh sách API đã cấu hình; không có phát hiện không có nghĩa an toàn.",
        ]),
    }
    if artifact_report is not None:
        l2 = reports["layer2"]
        l2["available"] = bool(scanned) or artifacts.get("available", False)
        l2["status"] = "completed" if scanned and not errors and artifacts.get("status") == "completed" else "partial" if l2["available"] else "unavailable"
        l2["analysis_errors"] += artifacts.get("issue_count", 0)
        l2["issues"] = (issues + artifacts.get("issues", []))[:30]
        l2["requires_dynamic_confirmation"] = bool(l2['finding_count']) or l2['status'] != 'completed'
    # Technique scores saturate per rule and origin. They are never malware probabilities.
    for name, layer in reports.items():
        if layer["status"] != "completed":
            continue  # missing/partial evidence must not masquerade as score zero
        layer["score"] = round(min(100, sum(score_totals[id(layer2 if name == 'layer2' else layer3)].values())), 1)
    return reports
