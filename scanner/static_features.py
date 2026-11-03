# scanner/static_features.py
"""
Module dung chung de trich dac trung TINH that tu APK.
QUAN TRONG: day la noi DUY NHAT dinh nghia bo dac trung Tang 1.
Ca luc train (build_static_dataset.py) va luc app chay that (detect_and_classify.py)
deu phai import va goi dung ham extract_features() trong file nay -
khong duoc tu suy doan / dem cot / them dummy o bat ky noi nao khac.

PHIEN BAN 2 (chong anti-analysis):
- Ma doc hien dai co tinh lam meo AndroidManifest.xml (chen chunk la, sai header size)
  khien androguard doc ra package=None, 0 quyen. Khi do module tu chuyen sang doc
  manifest bang apkInspector (thu vien viet rieng cho APK bi tamper).
- Them 2 dac trung: manifest_tampered, zip_tampered (0/1) tu apkInspector.indicators.
- Sua is_debuggable / is_allow_backup: androguard 4.x KHONG co 2 ham nay
  (ban cu luon tra 0) -> nay doc truc tiep thuoc tinh trong <application>.
"""

import io
import os
import re
import math
import hashlib
import logging
import warnings
from collections import Counter

from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from apkInspector.axml import parse_apk_for_manifest
from apkInspector.indicators import apk_tampering_check

logging.getLogger("apkInspector").setLevel(logging.ERROR)

# ===================== SCHEMA DAC TRUNG (CO DINH) =====================

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

OPCODES = [
    "invoke-virtual", "invoke-direct", "invoke-static", "invoke-interface",
    "invoke-super", "move-result", "move-result-object", "new-instance",
    "new-array", "const-string", "const/4", "const", "iget", "iput",
    "sget", "sput", "if-eqz", "if-nez", "goto", "return-void",
    "return", "return-object", "check-cast", "instance-of",
    "array-length", "throw",
]

MANIFEST_FLAGS = ["is_debuggable", "is_allow_backup", "has_native_lib"]
TAMPER_FLAGS = ["manifest_tampered", "zip_tampered"]
COMPONENT_COUNTS = [
    "num_activities", "num_services", "num_receivers", "num_providers",
    "num_exported_activities", "num_exported_services", "num_exported_receivers",
]
MISC_NUMERIC = ["min_sdk", "target_sdk", "file_size_kb", "dex_entropy", "num_permissions"]

# Thu tu cot CO DINH (73 cot), dung cho ca train va inference.
FEATURE_SCHEMA = (
    [f"perm__{p.split('.')[-1]}" for p in PERMISSIONS]
    + MANIFEST_FLAGS
    + TAMPER_FLAGS
    + COMPONENT_COUNTS
    + MISC_NUMERIC
    + [f"opcode__{o}" for o in OPCODES]
)

_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


# ===================== HAM PHU =====================

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


def _to_int(v) -> int:
    try:
        return int(str(v).strip(), 0)
    except Exception:
        return 0


def _flag_true(v) -> int:
    return int(str(v).strip().lower() in ("true", "1", "-1", "0xffffffff"))


def _has_intent_filter(apk, itemtype, name):
    try:
        f = apk.get_intent_filters(itemtype, name)
        return bool(f and (f.get("action") or f.get("category")))
    except Exception:
        return False


def _opcode_histogram(dx):
    """
    Dem tan suat cac opcode trong OPCODES tren toan bo method cua APK.
    Nhan dx (Analysis): o androguard 4.x, dex.get_methods() tra MethodIdItem
    (khong co get_code) nen phai duyet qua dx.get_methods().
    """
    counts = Counter()
    total = 0
    for m in (dx.get_methods() if dx is not None else []):
        if m.is_external():
            continue
        for instr in m.get_method().get_instructions():
            name = instr.get_name()
            total += 1
            if name in OPCODES:
                counts[name] += 1
    if total == 0:
        warnings.warn("Khong dem duoc lenh DEX nao, cac cot opcode__* = 0.0")
        return {f"opcode__{o}": 0.0 for o in OPCODES}
    return {f"opcode__{o}": round(counts.get(o, 0) / total, 6) for o in OPCODES}


# ===================== DOC MANIFEST: 2 NGUON =====================

def _manifest_androguard(a) -> dict:
    """Doc manifest bang androguard (nguon chinh)."""
    activities = a.get_activities() or []
    services = a.get_services() or []
    receivers = a.get_receivers() or []
    providers = a.get_providers() or []
    allow_backup = a.get_attribute_value("application", "allowBackup")
    return {
        "package": a.get_package() or None,
        "perms": set(a.get_permissions() or []),
        "num_activities": len(activities),
        "num_services": len(services),
        "num_receivers": len(receivers),
        "num_providers": len(providers),
        "num_exported_activities": sum(1 for c in activities if _has_intent_filter(a, "activity", c)),
        "num_exported_services": sum(1 for c in services if _has_intent_filter(a, "service", c)),
        "num_exported_receivers": sum(1 for c in receivers if _has_intent_filter(a, "receiver", c)),
        "min_sdk": _to_int(a.get_min_sdk_version() or 0),
        "target_sdk": _to_int(a.get_target_sdk_version() or 0),
        "is_debuggable": _flag_true(a.get_attribute_value("application", "debuggable")),
        # Android mac dinh allowBackup = true neu khong khai bao
        "is_allow_backup": 1 if allow_backup is None else _flag_true(allow_backup),
    }


def _attr(tag_text: str, name: str):
    m = re.search(r'\b(?:\w+:)?' + re.escape(name) + r'="([^"]*)"', tag_text)
    return m.group(1) if m else None


def _manifest_from_xml(xml: str) -> dict:
    """Phan tich XML (do apkInspector giai ma) - quy tac dem giong androguard."""
    res = {k: 0 for k in COMPONENT_COUNTS}
    res.update({"package": None, "perms": set(), "min_sdk": 0, "target_sdk": 0,
                "is_debuggable": 0, "is_allow_backup": 1})

    m = re.search(r"<manifest\b[^>]*>", xml)
    if m:
        res["package"] = _attr(m.group(0), "package")

    # Chi dem <uses-permission> (khong dem uses-permission-sdk-23) giong androguard
    for tag in re.findall(r"<uses-permission[\s>][^>]*>?", xml):
        name = _attr(tag, "name")
        if name:
            res["perms"].add(name)

    m = re.search(r"<uses-sdk\b[^>]*>", xml)
    if m:
        res["min_sdk"] = _to_int(_attr(m.group(0), "minSdkVersion") or 0)
        res["target_sdk"] = _to_int(_attr(m.group(0), "targetSdkVersion") or 0)

    m = re.search(r"<application\b[^>]*>", xml)
    if m:
        res["is_debuggable"] = _flag_true(_attr(m.group(0), "debuggable"))
        ab = _attr(m.group(0), "allowBackup")
        res["is_allow_backup"] = 1 if ab is None else _flag_true(ab)

    # Duyet the theo thu tu de biet component nao co intent-filter chua action/category
    stack = []          # [ten_the, ...]
    comp = None         # [loai_component, da_exported]
    in_filter = False
    for close, tag in re.findall(r"<(/?)([A-Za-z][\w.-]*)", xml):
        if not close:
            if tag in _COMPONENT_TAGS and comp is None:
                res[f"num_{tag}s" if tag != "activity" else "num_activities"] += 1
                comp = [tag, False]
            elif tag == "intent-filter" and comp is not None:
                in_filter = True
            elif tag in ("action", "category") and in_filter and comp is not None:
                comp[1] = True
            stack.append(tag)
        else:
            if stack:
                stack.pop()
            if tag == "intent-filter":
                in_filter = False
            elif comp is not None and tag == comp[0]:
                if comp[1] and comp[0] != "provider":
                    key = "num_exported_activities" if comp[0] == "activity" else f"num_exported_{comp[0]}s"
                    res[key] += 1
                comp = None
    return res


def _manifest_apkinspector(apk_path: str):
    try:
        return _manifest_from_xml(parse_apk_for_manifest(apk_path))
    except Exception:
        return None


def _tamper_flags(apk_bytes: bytes) -> dict:
    try:
        t = apk_tampering_check(io.BytesIO(apk_bytes), strict=False)
        return {"manifest_tampered": int(bool(t.get("manifest tampering"))),
                "zip_tampered": int(bool(t.get("zip tampering")))}
    except Exception:
        # Khong phan tich duoc cau truc -> bat thuong, coi nhu bi tamper
        return {"manifest_tampered": 1, "zip_tampered": 1}


# ===================== HAM CHINH =====================

def extract_features(apk_path: str) -> dict:
    """
    Tra ve dict CHINH XAC cac khoa trong FEATURE_SCHEMA (khong thua, khong thieu),
    cong them metadata (khong dua vao model): sha256, package_name, manifest_source.
    """
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        # DEX bi lam hong -> van doc manifest/quyen/component, opcode = 0.0
        warnings.warn(f"AnalyzeAPK loi, chi doc manifest: {e!r}")
        a, d, dx = APK(apk_path), [], None
    with open(apk_path, "rb") as f:
        apk_bytes = f.read()

    man = _manifest_androguard(a)
    source = "androguard"
    # androguard bi danh lua (manifest lam meo) -> dung apkInspector
    if not man["package"] or not man["perms"]:
        alt = _manifest_apkinspector(apk_path)
        if alt and (alt["package"] or alt["perms"]) and len(alt["perms"]) >= len(man["perms"]):
            man, source = alt, "apkInspector"

    perms = man["perms"]
    features = {}
    for p in PERMISSIONS:
        features[f"perm__{p.split('.')[-1]}"] = int(p in perms)

    features["is_debuggable"] = man["is_debuggable"]
    features["is_allow_backup"] = man["is_allow_backup"]
    try:
        features["has_native_lib"] = int(any(f.endswith(".so") for f in a.get_files()))
    except Exception:
        features["has_native_lib"] = 0

    features.update(_tamper_flags(apk_bytes))

    for k in COMPONENT_COUNTS:
        features[k] = man[k]
    features["min_sdk"] = man["min_sdk"]
    features["target_sdk"] = man["target_sdk"]
    features["file_size_kb"] = round(os.path.getsize(apk_path) / 1024, 2)
    features["num_permissions"] = len(perms)

    try:
        dex_bytes = b"".join(a.get_file(f) for f in a.get_files() if f.endswith(".dex"))
        features["dex_entropy"] = _shannon_entropy(dex_bytes)
    except Exception:
        features["dex_entropy"] = 0.0

    try:
        features.update(_opcode_histogram(dx))
    except Exception as e:
        warnings.warn(f"Loi dem opcode: {e!r}")
        features.update({f"opcode__{o}": 0.0 for o in OPCODES})

    ordered = {k: features.get(k, 0) for k in FEATURE_SCHEMA}
    ordered["sha256"] = hashlib.sha256(apk_bytes).hexdigest()
    ordered["package_name"] = man["package"]
    ordered["manifest_source"] = source
    return ordered
