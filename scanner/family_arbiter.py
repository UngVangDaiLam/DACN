r"""Tang 5 - Bo trong tai XAC NHAN CHEO THEO HO BANG CHUNG (phuong phap chinh cua de cuong).

Ba ho: A = cau truc tinh (Tang 1), B = hanh vi trong ma (Tang 2 + 3), C = hanh vi dong (Tang 4).
Moi ho cho mot diem trong [0, 1]; KHONG cong diem giua cac ho.

Luat:
  * >= 2 ho khac nhau cung vuot nguong           -> Nguy hiem   (danger)
  * dung 1 ho vuot nguong MANH                   -> Dang ngo    (warning) + de nghi Tang 4
  * dung 1 ho vuot nguong (yeu)                  -> Can luu y   (caution)
  * khong ho nao vuot, ho A va B deu day du      -> An toan     (safe)
  * khong ho nao vuot nhung thieu/khuyet ho A, B -> Chua du bang chung (unknown)
  * APK bi lam meo (manifest/zip) ma ra An toan  -> toi thieu Can luu y
Ho vang mat KHONG duoc tinh la "sach". Ho C vang mat (Tang 4 chua chay) duoc ghi ro.

NGUONG: doc tu models/arbiter_thresholds.json neu co (tao boi scanner/calibrate_arbiter.py,
hieu chinh tren tap sach theo ti le bao dong gia muc tieu). Neu chua co file -> dung
DEFAULT_THRESHOLDS (DE XUAT, thresholds_calibrated=False).

NGU CANH CAI DAT (de cuong): nguon cai tin cay, chu ky nha phat trien da biet, thoi gian dung
-> GIAM diem; dich vu tro nang, quyen quan tri thiet bi -> TANG diem. Tong dieu chinh bi chan
trong [CONTEXT_MIN, CONTEXT_MAX]; cac he so la DE XUAT. Thong tin khong co (None) -> khong
dieu chinh (khong doan). APK bi lam meo -> khong duoc giam diem.

Chay thu:  .\venv\Scripts\python.exe -B tests\test_family_arbiter.py -v
"""
import json
import os

from scanner.capabilities import FAMILY_A, FAMILY_B, FAMILY_C

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THRESHOLDS_PATH = os.path.join(ROOT, "models", "arbiter_thresholds.json")
KNOWN_SIGNERS_PATH = os.path.join(ROOT, "models", "known_signers.json")

# (nguong vuot, nguong vuot manh) - DE XUAT, dung khi chua co file hieu chinh
DEFAULT_THRESHOLDS = {"A": (0.60, 0.85), "B": (0.50, 0.75), "C": (0.50, 0.75)}
THRESHOLDS = DEFAULT_THRESHOLDS  # ten cu, giu de tuong thich
FAMILY_KEYS = ("A", "B", "C")
FAMILY_NAME = {"A": FAMILY_A, "B": FAMILY_B, "C": FAMILY_C}
FAMILY_LABEL = {"A": "Họ A — Cấu trúc tĩnh (Tầng 1)",
                "B": "Họ B — Hành vi trong mã (Tầng 2 + 3)",
                "C": "Họ C — Hành vi động (Tầng 4)"}
BENIGN_LABEL = "Benign"
LEVELS = ("safe", "caution", "warning", "danger")   # thu tu tang dan; 'unknown' dung rieng

VERDICT_TEXT = {
    "danger": "NGUY HIỂM — nhiều họ bằng chứng độc lập cùng xác nhận",
    "warning": "ĐÁNG NGỜ — một họ bằng chứng báo mạnh, nên chạy phân tích động",
    "caution": "CẦN LƯU Ý — một họ bằng chứng vượt ngưỡng",
    "safe": "AN TOÀN — không họ bằng chứng nào vượt ngưỡng",
    "unknown": "CHƯA ĐỦ BẰNG CHỨNG — cần kiểm tra thêm",
}
ACTION_TEXT = {
    "danger": "Đề nghị gỡ ứng dụng hoặc thu hồi quyền nhạy cảm (cần người dùng xác nhận).",
    "warning": "Đưa sang Tầng 4 (sandbox); hạn chế cấp quyền cho tới khi có kết quả.",
    "caution": "Theo dõi; xem lại các quyền đã cấp và nguồn cài đặt.",
    "safe": "Không cần hành động.",
    "unknown": "Phân tích lại hoặc chạy Tầng 4 trước khi tin cậy ứng dụng.",
}

# ---- Ngu canh cai dat (he so DE XUAT) ----
TRUSTED_INSTALLERS = {"com.android.vending", "com.sec.android.app.samsungapps",
                      "com.huawei.appmarket", "com.xiaomi.mipicks", "com.amazon.venezia"}
CONTEXT_DELTA = {"trusted_install_source": -0.05, "known_signer": -0.10, "long_usage": -0.05,
                 "accessibility_service": +0.05, "device_admin": +0.05}
CONTEXT_LABEL = {"trusted_install_source": "Cài từ kho ứng dụng tin cậy",
                 "known_signer": "Chữ ký nhà phát triển đã biết",
                 "long_usage": "Đã dùng lâu trên thiết bị",
                 "accessibility_service": "Khai báo dịch vụ trợ năng",
                 "device_admin": "Khai báo quyền quản trị thiết bị"}
LONG_USAGE_DAYS = 90
CONTEXT_MIN, CONTEXT_MAX = -0.15, 0.10


# ---------------------------------------------------------------- nguong
def validate_thresholds(th):
    out = {}
    for k in FAMILY_KEYS:
        if k not in th:
            raise ValueError("thieu nguong ho %s" % k)
        weak, strong = (float(x) for x in th[k])
        if not 0.0 < weak <= strong <= 1.0:
            raise ValueError("nguong ho %s khong hop le: %r" % (k, th[k]))
        out[k] = (weak, strong)
    return out


_cache = {"path": None, "mtime": None, "value": None}


def load_thresholds(path=None):
    """Tra ve (thresholds, calibrated, meta). File hong -> bao loi, khong am tham dung mac dinh."""
    path = path or THRESHOLDS_PATH
    if not os.path.exists(path):
        return dict(DEFAULT_THRESHOLDS), False, {"source": "default (de xuat, chua hieu chinh)"}
    mtime = os.path.getmtime(path)
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["value"]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    th = dict(DEFAULT_THRESHOLDS)
    th.update({k: tuple(v) for k, v in (data.get("thresholds") or {}).items()})
    value = (validate_thresholds(th), bool(data.get("calibrated")),
             dict(data.get("meta") or {}, source=os.path.basename(path),
                  calibrated_families=sorted((data.get("thresholds") or {}).keys())))
    _cache.update(path=path, mtime=mtime, value=value)
    return value


# ---------------------------------------------------------------- ngu canh
def load_known_signers(path=None):
    """Danh sach SHA-256 chung chi nha phat trien da biet (nhom tu dien). Khong co file -> rong."""
    path = path or KNOWN_SIGNERS_PATH
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("signers", data) if isinstance(data, dict) else data
    out = set()
    for it in items:
        sha = it.get("sha256") if isinstance(it, dict) else it
        if isinstance(sha, str) and len(sha.replace(":", "")) == 64:
            out.add(sha.replace(":", "").lower())
    return out


def build_context(deep=None, device=None, known_signers=None):
    """Gom ngu canh tu bao cao tinh (deep_analysis) va tu thiet bi (ADB, neu co).

    device = {'installer': 'com.android.vending', 'usage_days': 120} hoac None.
    Gia tri None nghia la KHONG BIET -> khong dieu chinh.
    """
    ctx = {"trusted_install_source": None, "known_signer": None, "long_usage": None,
           "accessibility_service": None, "device_admin": None, "details": {}}
    if deep:
        man = deep.get("manifest") or {}
        text = " ".join(list(man.get("permissions") or []) + list(man.get("sensitive_services") or [])
                        + [c.get("name", "") for c in man.get("critical_permissions") or []
                           if isinstance(c, dict)])
        low = text.lower()
        if man:
            ctx["accessibility_service"] = "bind_accessibility_service" in low or "accessib" in low
            ctx["device_admin"] = "bind_device_admin" in low or "devicead" in low
        certs = (deep.get("certificate") or {}).get("certificates") or []
        shas = {str(c.get("sha256", "")).lower() for c in certs if c.get("sha256")}
        if shas:
            signers = load_known_signers() if known_signers is None else set(known_signers)
            if signers:                       # chua co danh sach -> khong biet, khong phai "la"
                ctx["known_signer"] = bool(shas & signers)
            ctx["details"]["signer_sha256"] = sorted(shas)
    if device:
        if device.get("installer") is not None:
            ctx["trusted_install_source"] = device["installer"] in TRUSTED_INSTALLERS
            ctx["details"]["installer"] = device["installer"]
        if device.get("usage_days") is not None:
            ctx["long_usage"] = float(device["usage_days"]) >= LONG_USAGE_DAYS
            ctx["details"]["usage_days"] = device["usage_days"]
    return ctx


def context_adjustment(context, tampered=False):
    """Tra ve (delta, items). Chi cac muc co gia tri True moi dieu chinh."""
    items, delta = [], 0.0
    for key, d in CONTEXT_DELTA.items():
        if (context or {}).get(key) is True:
            if d < 0 and tampered:
                items.append({"key": key, "label": CONTEXT_LABEL[key], "delta": 0.0,
                              "note": "bỏ qua vì APK bị làm méo"})
                continue
            items.append({"key": key, "label": CONTEXT_LABEL[key], "delta": d})
            delta += d
    clamped = max(CONTEXT_MIN, min(CONTEXT_MAX, delta))
    return round(clamped, 4), items


# ---------------------------------------------------------------- diem tung ho
def _absent(key, reason, th):
    return {"key": key, "family": FAMILY_NAME[key], "label": FAMILY_LABEL[key],
            "available": False, "partial": False, "score": None, "raw_score": None,
            "threshold": th[key][0], "strong_threshold": th[key][1],
            "over": False, "strength": None, "evidence": [], "notes": [reason]}


def _family(key, score, th, partial=False, evidence=None, notes=None):
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0.0 <= score <= 1.0:
        raise ValueError("diem ho %s ngoai [0,1]: %r" % (key, score))
    f = {"key": key, "family": FAMILY_NAME[key], "label": FAMILY_LABEL[key],
         "available": True, "partial": bool(partial), "raw_score": round(float(score), 4),
         "threshold": th[key][0], "strong_threshold": th[key][1],
         "evidence": list(evidence or []), "notes": list(notes or [])}
    return _rescore(f, score)


def _rescore(f, score):
    score = min(1.0, max(0.0, float(score)))
    f["score"] = round(score, 4)
    f["strength"] = ("strong" if score >= f["strong_threshold"]
                     else "weak" if score >= f["threshold"] else None)
    f["over"] = f["strength"] is not None
    return f


def score_a_from_probs(probs):
    """1 - P(Benign); chap nhan thang 0-1 hoac %."""
    p_benign = float(probs[BENIGN_LABEL])
    if p_benign > 1.0:
        p_benign /= 100.0
    return min(1.0, max(0.0, 1.0 - p_benign))


def family_a_from_layer1(layer1, th=None):
    """Diem ho A = 1 - P(Benign) cua Tang 1. Tang 1 thieu/khong tin cay -> vang mat."""
    th = th or DEFAULT_THRESHOLDS
    if not layer1 or not layer1.get("success", True):
        return _absent("A", "Tầng 1 không khả dụng", th)
    if layer1.get("analysis_incomplete") or layer1.get("unreliable"):
        return _absent("A", "Tầng 1 chưa đủ tin cậy (phân tích không đầy đủ)", th)
    probs = layer1.get("probabilities") or {}
    if BENIGN_LABEL not in probs:
        return _absent("A", "Tầng 1 không trả xác suất lớp Benign", th)
    evidence = [{"label": k, "probability": round(float(v), 2)}
                for k, v in sorted(probs.items(), key=lambda kv: -float(kv[1]))]
    notes = []
    if layer1.get("manifest_tampered") or layer1.get("zip_tampered"):
        notes.append("APK có dấu hiệu bị làm méo (manifest/zip)")
    return _family("A", score_a_from_probs(probs), th, evidence=evidence, notes=notes)


def family_b_from_report(family_b, th=None):
    """Dung score cua family_scores.score_family_b; neu bi cat/khuyet thi dung observed_score
    lam CAN DUOI va danh dau partial (khong coi la diem day du)."""
    th = th or DEFAULT_THRESHOLDS
    if not family_b or not family_b.get("available") or family_b.get("status") == "unavailable":
        return _absent("B", "Tầng 2 và Tầng 3 không khả dụng", th)
    notes = list(family_b.get("notes") or [])
    score, partial = family_b.get("score"), False
    if score is None:
        score, partial = family_b.get("observed_score"), True
        if score is None:
            return _absent("B", "Họ B không có điểm quan sát được", th)
        notes.append("Điểm là cận dưới: bằng chứng bị cắt bớt hoặc phân tích chưa đầy đủ")
    return _family("B", score, th, partial, family_b.get("evidence"), notes)


def family_c_from_layer4(layer4, th=None):
    """Hop dong cho Tang 4: dict {'score': 0..1, 'evidence': [{'capability':..}], 'partial': bool}.
    None / available=False / score=None -> vang mat."""
    th = th or DEFAULT_THRESHOLDS
    if not layer4 or layer4.get("available") is False or layer4.get("score") is None:
        return _absent("C", "Tầng 4 (phân tích động) chưa chạy", th)
    return _family("C", layer4["score"], th, layer4.get("partial"), layer4.get("evidence"),
                   layer4.get("notes"))


# ---------------------------------------------------------------- luat ket luan
def decide_level(over_strengths, core_complete, tampered=False):
    """Luat thuan (dung chung cho pipeline va script danh gia).

    over_strengths: danh sach 'weak'/'strong' cua cac ho VUOT nguong.
    core_complete: ho A va B deu co mat va day du.
    """
    if len(over_strengths) >= 2:
        level = "danger"
    elif len(over_strengths) == 1:
        level = "warning" if over_strengths[0] == "strong" else "caution"
    else:
        level = "safe" if core_complete else "unknown"
    if tampered and level == "safe":
        level = "caution"
    return level


def arbitrate(layer1=None, family_b=None, layer4=None, context=None, thresholds=None):
    """Ket luan 4 muc tu ba ho bang chung.

    thresholds: dict {'A': (yeu, manh), ...}; None -> doc file hieu chinh / mac dinh.
    context: dict tu build_context(); None -> khong ap dung ngu canh.
    """
    if thresholds is None:
        th, calibrated, th_meta = load_thresholds()
    else:
        th, calibrated, th_meta = validate_thresholds(thresholds), False, {"source": "tham so"}
    fams = [family_a_from_layer1(layer1, th), family_b_from_report(family_b, th),
            family_c_from_layer4(layer4, th)]
    tampered = bool(layer1 and (layer1.get("manifest_tampered") or layer1.get("zip_tampered")))

    delta, ctx_items = context_adjustment(context, tampered) if context else (0.0, [])
    if delta:
        for f in fams:
            if f["available"]:
                _rescore(f, f["raw_score"] + delta)

    by_key = {f["key"]: f for f in fams}
    over = [f for f in fams if f["over"]]
    absent = [f["key"] for f in fams if not f["available"]]
    core_complete = all(by_key[k]["available"] and not by_key[k]["partial"] for k in ("A", "B"))
    level = decide_level([f["strength"] for f in over], core_complete, tampered)

    reasons = []
    if len(over) >= 2:
        reasons.append("Các họ %s cùng vượt ngưỡng (xác nhận chéo)" % ", ".join(f["key"] for f in over))
    elif len(over) == 1:
        f = over[0]
        strong = f["strength"] == "strong"
        reasons.append("Chỉ họ %s vượt ngưỡng (%s): %.2f ≥ %.2f — chưa có họ khác xác nhận"
                       % (f["key"], "mạnh" if strong else "yếu", f["score"],
                          f["strong_threshold"] if strong else f["threshold"]))
    elif core_complete:
        reasons.append("Họ A và B đều đầy đủ và dưới ngưỡng")
    else:
        reasons.append("Không họ nào vượt ngưỡng nhưng họ A/B vắng mặt hoặc chưa đầy đủ — "
                       "không coi là sạch")
    if tampered and level == "caution" and not over:
        reasons.append("APK bị làm méo manifest/zip — tối thiểu Cần lưu ý")
    if delta:
        reasons.append("Ngữ cảnh cài đặt điều chỉnh điểm mỗi họ %+.2f" % delta)
    for f in fams:
        if not f["available"]:
            reasons.append("Họ %s vắng mặt: %s" % (f["key"], f["notes"][0]))

    capabilities = sorted({e["capability"] for f in fams for e in f["evidence"]
                           if isinstance(e, dict) and e.get("capability")})
    return {
        "method": "family_cross_confirmation",
        "level": level,
        "verdict": VERDICT_TEXT[level],
        "action": ACTION_TEXT[level],
        "families": fams,
        "families_over": [f["key"] for f in over],
        "families_absent": absent,
        "capabilities": capabilities,
        "reasons": reasons,
        "recommend_dynamic": level in ("warning", "caution", "unknown") and "C" in absent,
        "thresholds_calibrated": calibrated,
        "thresholds_meta": th_meta,
        "context_applied": bool(context),
        "context_delta": delta,
        "context_items": ctx_items,
        "context_unknown": sorted(k for k in CONTEXT_DELTA if (context or {}).get(k) is None)
        if context else sorted(CONTEXT_DELTA),
    }
