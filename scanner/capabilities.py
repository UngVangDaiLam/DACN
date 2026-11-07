"""Tang 5 - Danh sach nang luc (capability) dung chung va bo gop hoc B.

Chuyen output hien co cua Tang 2/3 (code_layers.py) thanh bang chung theo capability,
KHONG can sua code cua An: neu finding da co truong 'capability' thi dung, neu chua co
thi suy ra tu rule_id (+ data_type voi Tang 3). Moi capability chi tinh MOT lan trong
hoc B du xuat hien o ca Tang 2 va Tang 3.

Cac he so SEVERITY_WEIGHT / ORIGIN_FACTOR la DE XUAT, chua hieu chinh tren tap sach.
"""

FAMILY_A, FAMILY_B, FAMILY_C = "static_structure", "code_behavior", "dynamic_behavior"

CAPABILITIES = {
    # ho B (Tang 2 + 3)
    "dynamic_code_loading": FAMILY_B,
    "native_code_loading": FAMILY_B,
    "reflection_use": FAMILY_B,
    "crypto_use": FAMILY_B,
    "encoded_payload_hint": FAMILY_B,
    "sms_exfiltration_risk": FAMILY_B,
    "location_exfiltration_risk": FAMILY_B,
    "device_id_exfiltration_risk": FAMILY_B,
    "phone_number_exfiltration_risk": FAMILY_B,
    "camera_exfiltration_risk": FAMILY_B,
    "clipboard_exfiltration_risk": FAMILY_B,
    # ho C (Tang 4) - de san, Tang 4 chua lam
    "accessibility_abuse": FAMILY_C,
    "overlay": FAMILY_C,
    "sms_send": FAMILY_C,
    "nfc_relay": FAMILY_C,
    "device_admin": FAMILY_C,
    "hide_icon": FAMILY_C,
    "screen_capture": FAMILY_C,
    "keylogging": FAMILY_C,
}

RULE_TO_CAPABILITY = {
    "dynamic_dex": "dynamic_code_loading",
    "native_loading": "native_code_loading",
    "reflection": "reflection_use",
    "crypto": "crypto_use",
    "encoded_string": "encoded_payload_hint",
}

DATA_TYPE_TO_CAPABILITY = {  # Tang 3: rule sensitive_network_same_method
    "SMS": "sms_exfiltration_risk",
    "Vị trí": "location_exfiltration_risk",
    "Định danh thiết bị": "device_id_exfiltration_risk",
    "Định danh thuê bao": "device_id_exfiltration_risk",
    "Số điện thoại": "phone_number_exfiltration_risk",
    "Camera": "camera_exfiltration_risk",
    "Clipboard": "clipboard_exfiltration_risk",
}

SEVERITY_WEIGHT = {"info": 0.05, "low": 0.15, "medium": 0.35}
ORIGIN_FACTOR = {"application": 1.0, "unknown": 0.6, "third_party": 0.15}
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2}


def capabilities_of(finding):
    """Tra ve danh sach capability cua mot finding. Ten la hoac khong anh xa duoc -> loi."""
    cap = finding.get("capability")
    if cap:
        caps = [cap]
    elif finding.get("rule_id") == "sensitive_network_same_method":
        caps = []
        for dt in finding.get("data_types") or []:
            if dt not in DATA_TYPE_TO_CAPABILITY:
                raise ValueError("data_type chua co capability: %r" % dt)
            c = DATA_TYPE_TO_CAPABILITY[dt]
            if c not in caps:
                caps.append(c)
    elif finding.get("rule_id") in RULE_TO_CAPABILITY:
        caps = [RULE_TO_CAPABILITY[finding["rule_id"]]]
    else:
        raise ValueError("rule_id chua co capability: %r" % finding.get("rule_id"))
    for c in caps:
        if c not in CAPABILITIES:
            raise ValueError("capability khong co trong danh sach chung: %r" % c)
    return caps


def merge_family_b(*layers):
    """Gop findings cua cac tang (dict layer2/layer3 hoac None) theo capability.

    Tra ve {capability: {severity, origin, weight, count, rules, layers}}.
    weight = SEVERITY_WEIGHT[severity] * ORIGIN_FACTOR[origin], lay MAX giua cac finding
    (khong cong don) de mot capability khong bi dem nhieu lan. Tang vang mat bi bo qua.
    """
    merged = {}
    for layer in layers:
        if not layer:
            continue
        for f in layer.get("findings") or []:
            sev, origin = f.get("severity"), f.get("origin", "unknown")
            if sev not in SEVERITY_WEIGHT:
                raise ValueError("severity la: %r" % sev)
            if origin not in ORIGIN_FACTOR:
                raise ValueError("origin la: %r" % origin)
            w = SEVERITY_WEIGHT[sev] * ORIGIN_FACTOR[origin]
            for cap in capabilities_of(f):
                if CAPABILITIES[cap] != FAMILY_B:
                    raise ValueError("%s khong thuoc ho B" % cap)
                m = merged.setdefault(cap, {"severity": sev, "origin": origin, "weight": 0.0,
                                            "count": 0, "rules": set(), "layers": set()})
                m["count"] += 1
                m["rules"].add(f.get("rule_id"))
                if layer.get("layer") is not None:
                    m["layers"].add(layer["layer"])
                if w > m["weight"]:
                    m.update(weight=w, severity=sev, origin=origin)
                elif w == m["weight"] and _SEV_ORDER[sev] > _SEV_ORDER[m["severity"]]:
                    m["severity"] = sev
    return merged
