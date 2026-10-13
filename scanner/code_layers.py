"""Prototype layers 2/3: static evidence from Androguard cross references.

No APK execution, decryption or taint analysis. Both layers belong to the
same evidence family and intentionally do not modify the legacy risk score.
"""

import re
from collections import Counter

MAX_FINDINGS = 100
MAX_CALLS_PER_FINDING = 20
ORIGIN_PRIORITY = {"application": 0, "unknown": 1, "third_party": 2}
LIBRARY_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Lcom/google/", "Lcom/facebook/", "Lcom/unity3d/", "Lokhttp3/",
    "Lokio/", "Lretrofit2/", "Lorg/apache/", "Lio/reactivex/",
)

LAYER2_RULES = (
    ("dynamic_dex", "Nạp DEX động", "medium", {
        ("Ldalvik/system/DexClassLoader;", "<init>"),
        ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
        ("Ldalvik/system/DexFile;", "loadDex"),
    }),
    ("reflection", "Gọi hàm qua reflection", "low", {
        ("Ljava/lang/reflect/Method;", "invoke"),
        ("Ljava/lang/Class;", "forName"),
    }),
    ("crypto", "Mã hóa hoặc giải mã dữ liệu", "info", {
        ("Ljavax/crypto/Cipher;", "doFinal"),
    }),
    ("native_loading", "Nạp thư viện native", "info", {
        ("Ljava/lang/System;", "load"), ("Ljava/lang/System;", "loadLibrary"),
        ("Ljava/lang/Runtime;", "load"), ("Ljava/lang/Runtime;", "loadLibrary"),
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
}


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


def analyze_code_layers(apk, analysis, obfuscation):
    package = apk.get_package() or ""
    layer2, layer3 = [], []
    counts2, counts3 = Counter(), Counter()
    scanned, errors = 0, 0
    # Index only candidate strings, retaining their caller and bytecode offset.
    encoded = {}
    try:
        for string in analysis.get_strings():
            try:
                value = str(string.get_value())
                if not encoded_candidate(value):
                    continue
                for _, caller, offset in string.get_xref_from(with_offset=True):
                    key = tuple(method_info(caller).values())
                    bucket = encoded.setdefault(key, [])
                    if len(bucket) < 3:
                        bucket.append({"value": value[:160], "length": len(value),
                                       "offset": int(offset), "preview_truncated": len(value) > 160})
            except Exception:
                errors += 1
    except Exception:
        errors += 1

    def record(target, counts, finding):
        counts[finding["origin"]] += 1
        if len(target) < MAX_FINDINGS:
            target.append(finding)
        else:
            # Keep application evidence visible even when SDKs fill the report.
            worst = max(range(len(target)), key=lambda i: ORIGIN_PRIORITY[target[i]["origin"]])
            if ORIGIN_PRIORITY[finding["origin"]] < ORIGIN_PRIORITY[target[worst]["origin"]]:
                target[worst] = finding

    for method in analysis.get_methods():
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
            for rule_id, title, severity, targets in LAYER2_RULES:
                hits = [c for c in calls if (c["class_name"], c["method_name"]) in targets]
                if hits:
                    record(layer2, counts2, {**base, "rule_id": rule_id, "title": title,
                           "severity": severity, "calls": hits[:MAX_CALLS_PER_FINDING],
                           "call_count": len(hits)})
            strings = encoded.get(tuple(info.values()), [])
            if strings:
                record(layer2, counts2, {**base, "rule_id": "encoded_string",
                       "title": "Chuỗi dài có dạng Base64 (chưa xác nhận mã hóa)",
                       "severity": "info", "strings": strings})
            sources = [dict(c, data_type=SOURCES[(c["class_name"], c["method_name"])])
                       for c in calls if (c["class_name"], c["method_name"]) in SOURCES]
            sinks = [c for c in calls if (c["class_name"], c["method_name"]) in SINKS]
            if sources and sinks:
                record(layer3, counts3, {**base, "rule_id": "sensitive_network_same_method",
                       "title": "API nhạy cảm và API mạng cùng một hàm",
                       "severity": "low" if origin == "third_party" else "medium",
                       "sources": sources[:MAX_CALLS_PER_FINDING],
                       "sinks": sinks[:MAX_CALLS_PER_FINDING],
                       "source_count": len(sources), "sink_count": len(sinks),
                       "data_types": sorted({c["data_type"] for c in sources}),
                       "flow_confirmed": False})
        except Exception:
            errors += 1

    def result(findings, counts, limitations):
        total = sum(counts.values())
        findings.sort(key=lambda f: (ORIGIN_PRIORITY[f["origin"]], f["class_name"],
                                     f["method_name"], f["descriptor"], f["rule_id"]))
        return {"status": "partial" if errors else "completed", "stage": "prototype",
                "evidence_family": "code_behavior", "methods_scanned": scanned,
                "analysis_errors": errors, "finding_count": total,
                "counts_by_origin": dict(counts), "findings": findings,
                "truncated": total > len(findings), "limitations": limitations}

    return {
        "layer2": {**result(layer2, counts2, [
            "Chỉ nhận diện dấu hiệu; reflection, mã hóa và native không đồng nghĩa mã độc.",
            "Chưa tích hợp YARA, giải mã payload hoặc phân tích mã native.",
            "Phân loại thư viện theo tiền tố; mã ngoài danh sách được ghi là chưa xác định.",
        ]), "artifacts": {
            "embedded_payloads": obfuscation.get("embedded_payloads", []),
            "native_libs": obfuscation.get("native_libs", []),
            "dex_entropy": obfuscation.get("dex_entropy", 0),
            "obfuscated_class_ratio": obfuscation.get("obfuscated_class_ratio", 0),
        }},
        "layer3": result(layer3, counts3, [
            "API cùng hàm chỉ là nguy cơ; chưa chứng minh dữ liệu được gửi ra mạng.",
            "Chưa theo dõi luồng dữ liệu, nhánh thực thi, lời gọi qua nhiều hàm hoặc reflection.",
            "Chỉ bao phủ danh sách API đã cấu hình; không có phát hiện không có nghĩa an toàn.",
        ]),
    }
