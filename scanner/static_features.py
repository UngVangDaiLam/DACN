# scanner/static_features.py
"""
Module dung chung de trich dac trung TINH that tu APK.
QUAN TRONG: day la noi DUY NHAT dinh nghia bo dac trung Tang 1.
Ca luc train (build_static_dataset.py) va luc app chay that (apk_analyzer.py)
deu phai import va goi dung ham extract_features() trong file nay -
khong duoc tu suy doan / dem cot / them dummy o bat ky noi nao khac.
Do la nguyen nhan gay loi feature-mismatch cua ban dau.
"""

import os
import math
import hashlib
from collections import Counter

from androguard.misc import AnalyzeAPK

# ===================== SCHEMA DAC TRUNG (CO DINH) =====================

# Danh sach quyen dang chu y (co the mo rong them sau, nhung phai retrain
# lai toan bo neu doi danh sach nay).
PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.GET_TASKS",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.READ_CALENDAR",
    "android.permission.BLUETOOTH",
]

# Mot tap con opcode Dalvik pho bien, co dinh (KHONG phu thuoc vao batch
# dang xu ly) -> dam bao vector luon cung do dai bat ke APK nao.
OPCODES = [
    "invoke-virtual", "invoke-direct", "invoke-static", "invoke-interface",
    "invoke-super", "move-result", "move-result-object", "new-instance",
    "new-array", "const-string", "const/4", "const", "iget", "iput",
    "sget", "sput", "if-eqz", "if-nez", "goto", "return-void",
    "return", "return-object", "check-cast", "instance-of",
    "array-length", "throw",
]

MANIFEST_FLAGS = ["is_debuggable", "is_allow_backup", "has_native_lib"]
COMPONENT_COUNTS = [
    "num_activities", "num_services", "num_receivers", "num_providers",
    "num_exported_activities", "num_exported_services", "num_exported_receivers",
]
MISC_NUMERIC = ["min_sdk", "target_sdk", "file_size_kb", "dex_entropy", "num_permissions"]

# Thu tu cot CO DINH, dung cho ca train va inference.
FEATURE_SCHEMA = (
    [f"perm__{p.split('.')[-1]}" for p in PERMISSIONS]
    + MANIFEST_FLAGS
    + COMPONENT_COUNTS
    + MISC_NUMERIC
    + [f"opcode__{o}" for o in OPCODES]
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _has_intent_filter(apk, itemtype, name):
    try:
        f = apk.get_intent_filters(itemtype, name)
        return bool(f and (f.get("action") or f.get("category")))
    except Exception:
        return False


def _opcode_histogram(dex_list):
    """Dem tan suat cac opcode trong OPCODES tren toan bo method cua APK."""
    counts = Counter()
    total = 0
    for dex in dex_list:
        try:
            for method in dex.get_methods():
                code = method.get_code()
                if not code:
                    continue
                for instr in code.get_bc().get_instructions():
                    name = instr.get_name()
                    total += 1
                    if name in OPCODES:
                        counts[name] += 1
        except Exception:
            continue
    if total == 0:
        return {f"opcode__{o}": 0.0 for o in OPCODES}
    return {f"opcode__{o}": round(counts.get(o, 0) / total, 6) for o in OPCODES}


def extract_features(apk_path: str) -> dict:
    """
    Tra ve dict CHINH XAC cac khoa trong FEATURE_SCHEMA (khong thua, khong thieu),
    cong them vai truong metadata (khong dua vao model): sha256, package_name.
    """
    a, d, dx = AnalyzeAPK(apk_path)

    perms = set(a.get_permissions())
    features = {}

    for p in PERMISSIONS:
        features[f"perm__{p.split('.')[-1]}"] = int(p in perms)

    try:
        features["is_debuggable"] = int(bool(a.is_debuggable()))
    except Exception:
        features["is_debuggable"] = 0
    try:
        features["is_allow_backup"] = int(bool(a.is_allow_backup()))
    except Exception:
        features["is_allow_backup"] = 0
    try:
        libs = a.get_libraries() if hasattr(a, "get_libraries") else []
        has_so = any(f.endswith(".so") for f in a.get_files())
        features["has_native_lib"] = int(bool(libs) or has_so)
    except Exception:
        features["has_native_lib"] = 0

    activities = a.get_activities() or []
    services = a.get_services() or []
    receivers = a.get_receivers() or []
    providers = a.get_providers() or []

    features["num_activities"] = len(activities)
    features["num_services"] = len(services)
    features["num_receivers"] = len(receivers)
    features["num_providers"] = len(providers)
    features["num_exported_activities"] = sum(
        1 for c in activities if _has_intent_filter(a, "activity", c))
    features["num_exported_services"] = sum(
        1 for c in services if _has_intent_filter(a, "service", c))
    features["num_exported_receivers"] = sum(
        1 for c in receivers if _has_intent_filter(a, "receiver", c))

    try:
        features["min_sdk"] = int(a.get_min_sdk_version() or 0)
    except Exception:
        features["min_sdk"] = 0
    try:
        features["target_sdk"] = int(a.get_target_sdk_version() or 0)
    except Exception:
        features["target_sdk"] = 0

    features["file_size_kb"] = round(os.path.getsize(apk_path) / 1024, 2)
    features["num_permissions"] = len(perms)

    try:
        dex_bytes = b"".join(
            a.get_file(f) for f in a.get_files() if f.endswith(".dex")
        )
        features["dex_entropy"] = _shannon_entropy(dex_bytes)
    except Exception:
        features["dex_entropy"] = 0.0

    try:
        features.update(_opcode_histogram(d))
    except Exception:
        features.update({f"opcode__{o}": 0.0 for o in OPCODES})

    with open(apk_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    ordered = {k: features.get(k, 0) for k in FEATURE_SCHEMA}
    ordered["sha256"] = sha256
    ordered["package_name"] = a.get_package()
    return ordered
