"""Tang 5 - Meta-arbiter (5.1b: hop dong du lieu + bo phieu co trong so).

Dau vao L1 = dict tra ve tu MalwareDetector.analyze_apk (xac suat tinh bang %,
khoa theo TEN lop, KHONG theo vi tri). Dau vao L4 = dict {ten lop: xac suat 0-1}.
"""
import math
import numbers
import os

CLASSES =["Benign", "Adware", "Banking", "SMS", "Riskware"]  # chi de kiem tra tap ten lop
BENIGN = "Benign"
UNKNOWN = "Không xác định"
WEIGHTS = {"L1": 0.45, "L4": 0.45, "L2": 0.05, "L3": 0.05}  # trong so tay
# arbitrate(): CHI doi L2 -> 0 (xem docstring arbitrate). Cac trong so/nguong khac giu nguyen.
ARBITRATE_WEIGHTS = dict(WEIGHTS, L2=0.0)
MIN_VOTERS = 1          # so tang "bo phieu" (L1/L4) toi thieu
CONFLICT_GAP = 0.5      # L1 va L4 lech P(doc) > nguong -> mau thuan
T_MAL, T_HIGH = 0.5, 0.8
ERA_BIASED = {"Adware"}  # nhan ho co the phan anh THOI DAI mau (xem buoc 5.2), khong phai hanh vi


def _absent(name, why):
    return {"name": name, "available": False, "probs": None,
            "risk": None, "evidence": [why]}


def _as_number(name, x):
    """Chi nhan so thuc (int/float/numpy), KHONG nhan bool, chuoi, NaN. Sai -> ValueError."""
    if isinstance(x, bool) or not isinstance(x, numbers.Real):
        raise ValueError("%s: diem phai la so, nhan %r (%s)" % (name, x, type(x).__name__))
    x = float(x)
    if math.isnan(x):
        raise ValueError("%s: diem la NaN (lop vang mat phai truyen None)" % name)
    return x


def _norm(name, probs, scale=1.0):
    """Kiem tra tap ten lop + tong = 1, doi ve thang 0-1. Sai -> bao loi, khong tu sua."""
    if set(probs) != set(CLASSES):
        raise ValueError("%s: tap lop %s khac %s" % (name, sorted(probs), sorted(CLASSES)))
    p = {k: float(v) / scale for k, v in probs.items()}
    s = sum(p.values())
    if abs(s - 1.0) > 0.02:
        raise ValueError("%s: tong xac suat = %.4f (can = 1)" % (name, s))
    return p


def from_layer1(res):
    """res = ket qua MalwareDetector.analyze_apk(...) (hoac None)."""
    res = res or {}
    tamper = bool(res.get("manifest_tampered") or res.get("zip_tampered"))
    probs = res.get("probabilities")
    if not res or res.get("analysis_incomplete") or not probs:
        why = "Tang 1: phan tich khong day du"
        if res.get("incomplete_reasons"):
            why += " (%s)" % "; ".join(map(str, res["incomplete_reasons"][:2]))
        r = _absent("L1", why)
    else:
        p = _norm("L1", probs, 100.0)   # L1 tra ve %
        ev = ["Tang 1: P(doc)=%.2f" % (1 - p[BENIGN])]
        for c in (res.get("top_contributing") or [])[:3]:
            ev.append("Tang 1: dac trung %s (SHAP %+.2f)" % (c["name"], c["shap"]))
        r = {"name": "L1", "available": True, "probs": p, "risk": None,
             "evidence": ev}
    r["tamper"] = tamper
    if tamper:
        r["evidence"].append("Tang 1: manifest/zip bi lam meo (chong phan tich)")
    return r


def from_layer4(probs):
    """probs = {ten lop: xac suat 0-1} hoac None."""
    if probs is None:
        return _absent("L4", "Tang 4: khong co bao cao dong")
    p = _norm("L4", probs)
    return {"name": "L4", "available": True, "probs": p, "risk": None,
            "evidence": ["Tang 4: P(doc)=%.2f" % (1 - p[BENIGN])]}


def from_layer2(d):
    """d = analyze_layer2(apk) -> {available, obfuscation_score, evidence}."""
    s = (d or {}).get("obfuscation_score")
    if not d or not d.get("available") or s is None:
        return _absent("L2", "Tang 2: vang mat")
    s = _as_number("L2", s)
    if not 0.0 <= s <= 1.0:  # risk phai cung thang 0-1 voi xac suat
        raise ValueError("L2: obfuscation_score ngoai thang 0-1: %r" % s)
    return {"name": "L2", "available": True, "probs": None, "risk": s,
            "evidence": ["Tang 2: muc lam roi=%.2f" % s] + list(d.get("evidence", []))}


def from_layer3(rule_score):
    """rule_score thang 0-100 (deep_analysis) -> risk thang 0-1."""
    if rule_score is None:
        return _absent("L3", "Tang 3: vang mat")
    v = _as_number("L3", rule_score)
    if not 0.0 <= v <= 100.0:
        raise ValueError("L3: rule_score ngoai thang 0-100: %r" % rule_score)
    r = v / 100.0  # khong doan thang: 0.36 -> 0.0036 (co y)
    return {"name": "L3", "available": True, "probs": None, "risk": r,
            "evidence": ["Tang 3: rule_score=%g/100" % v]}


def weighted_vote(layers, weights=WEIGHTS):
    """layers: list ket qua tu from_layerX. Tra dict ket luan."""
    av = [l for l in layers if l["available"]]
    ev = [e for l in layers for e in l["evidence"]]
    tamper = any(l.get("tamper") for l in layers)
    voters = [l for l in av if l["probs"] is not None]
    out = {"label": UNKNOWN, "risk_level": UNKNOWN,
           "p_malicious": None, "confidence": None, "class_probs": None,
           "layers_present": [l["name"] for l in av], "evidence": ev,
           "reason": "", "era_biased": False}
    if len(voters) < MIN_VOTERS:
        out["reason"] = "Thieu tang bo phieu (L1/L4)"
        return out
    if len(voters) == 2:
        gap = abs(voters[0]["probs"][BENIGN] - voters[1]["probs"][BENIGN])
        if gap > CONFLICT_GAP:
            out["reason"] = "L1 va L4 mau thuan (lech %.2f)" % gap
            return out
    # Tang vang mat -> bo ra, chuan hoa lai trong so (KHONG dien 0)
    w = {l["name"]: weights[l["name"]] for l in av}
    tw = sum(w[l["name"]] for l in voters)
    cp = {c: sum(w[l["name"]] * l["probs"][c] for l in voters) / tw
          for c in CLASSES}
    p_mal = 1 - cp[BENIGN]
    # tang trong so 0 van nam trong layers_present/evidence nhung khong vao phep tinh
    # (tranh chia cho 0 khi chi con tang trong so 0)
    risks = [l for l in av if l["risk"] is not None and w[l["name"]] > 0]
    if risks:  # L2/L3: chi nhich nhe p_mal, khong tu quyet dinh nhan
        aw = sum(w[l["name"]] for l in risks)
        r = sum(w[l["name"]] * l["risk"] for l in risks) / aw
        p_mal = (1 - aw) * p_mal + aw * r
    out["p_malicious"], out["class_probs"] = round(p_mal, 4), cp
    if p_mal >= T_MAL:
        mal = {c: cp[c] for c in CLASSES if c != BENIGN}
        out["label"] = max(mal, key=mal.get)
        out["confidence"] = round(p_mal, 4)
        out["risk_level"] = "Cao" if p_mal >= T_HIGH else "Trung bình"
        if out["label"] in ERA_BIASED:
            out["era_biased"] = True
            out["evidence"].append("Luu y: nhan '%s' co the phan anh thoi dai cua mau, "
                                   "chi nen tin ket luan doc/sach" % out["label"])
    else:
        out["confidence"] = round(1 - p_mal, 4)
        l1_on = any(l["name"] == "L1" for l in voters)
        l3 = next((l for l in av if l["name"] == "L3" and l["risk"] is not None), None)
        # Luat mau thuan MOT CHIEU (dung san T_MAL, T_HIGH; khong them nguong moi):
        # ket luan sach (p_mal < T_MAL) + L1 co mat + L3 >= T_HIGH -> khong dam ket luan.
        # KHONG lam chieu nguoc (L1 doc, L3 thap): L3 chi bat ~45% mau doc (Pha C).
        if l1_on and l3 is not None and l3["risk"] >= T_HIGH:
            out["reason"] = ("L1 sạch nhưng L3 rất cao (rule_score=%g/100 >= %g)"
                             % (l3["risk"] * 100, T_HIGH * 100))
            out["label"] = out["risk_level"] = UNKNOWN
        elif tamper:  # nhan "sach" nhung manifest bi lam meo -> khong dam ket luan
            out["reason"] = "Du doan sach nhung co dau hieu chong phan tich"
            out["label"] = out["risk_level"] = UNKNOWN
        else:
            out["label"], out["risk_level"] = BENIGN, "Thấp"
    return out


_DETECTOR = None  # nap model Tang 1 mot lan


def _default_detector():
    global _DETECTOR
    if _DETECTOR is None:
        from scanner.detect_and_classify import MalwareDetector
        _DETECTOR = MalwareDetector()
    return _DETECTOR


def arbitrate(apk_path, detector=None, deep_fn=None, weights=None):
    """Phan xu 1 APK: L1 (MalwareDetector.analyze_apk) + L3 va L2 gan dung (analyze_deep),
    L4 = None (chua co bao cao dong), roi weighted_vote.

    * L2 GAN DUNG = obfuscation.obfuscated_class_ratio cua analyze_deep, trong so 0:
      chi hien trong evidence va layers_present, KHONG anh huong p_malicious. Ly do:
      (1) khong phai L2 that (chi do ti le ten lop bi thu gon, ProGuard/R8 cua app sach cung co);
      (2) khong doc lap voi L3 (rule_score da gom nhom lam roi);
      (3) Pha C: AUC 0,497 (n=139, chi minh hoa) ~ ngau nhien.
      Cac trong so va nguong khac giu nguyen WEIGHTS/T_MAL/T_HIGH, KHONG chinh theo 139 mau.
    * Tang loi/vang -> absent (KHONG dien 0); loi ghi vao layer_errors.
    * "Khong xac dinh" khi thieu tang bo phieu (L1/L4) hoac L1-L4 mau thuan (weighted_vote).
    * Khong dung deep_analysis.combine_verdict. VirusTotal (neu co) KHONG la dau vao.
    detector / deep_fn: tiem phu thuoc (de test bang mock); mac dinh dung module that.
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(apk_path)
    weights = ARBITRATE_WEIGHTS if weights is None else weights
    errors = []

    # --- L1
    res1 = None
    try:
        res1 = (detector or _default_detector()).analyze_apk(apk_path, os.path.basename(apk_path))
        if not res1 or not res1.get("success", False):
            errors.append("L1: %s" % ((res1 or {}).get("error") or "khong co ket qua"))
            res1 = None
    except Exception as e:
        errors.append("L1: %s: %s" % (type(e).__name__, e))
    try:
        l1 = from_layer1(res1)
    except ValueError as e:  # sai hop dong du lieu -> vang, khong tu sua
        errors.append("L1: %s" % e)
        l1 = from_layer1(None)

    # --- L3 + L2 gan dung (cung 1 lan analyze_deep)
    deep = None
    try:
        if deep_fn is None:
            from scanner.deep_analysis import analyze_deep as deep_fn
        deep = deep_fn(apk_path)
    except Exception as e:
        errors.append("L2/L3 (analyze_deep): %s: %s" % (type(e).__name__, e))
    deep = deep or {}
    ratio = (deep.get("obfuscation") or {}).get("obfuscated_class_ratio")
    try:
        l2 = from_layer2(None if ratio is None else {
            "available": True, "obfuscation_score": ratio,
            "evidence": ["Tang 2 (gan dung, trong so %.2f): obfuscated_class_ratio, "
                         "khong phai L2 that" % weights["L2"]]})
    except ValueError as e:
        errors.append(str(e))
        l2 = from_layer2(None)
    try:
        l3 = from_layer3(deep.get("rule_score"))
    except ValueError as e:
        errors.append(str(e))
        l3 = from_layer3(None)

    l4 = from_layer4(None)
    layers = [l1, l4, l2, l3]
    out = weighted_vote(layers, weights=weights)
    out.update(
        evidence_by_layer={l["name"]: list(l["evidence"]) for l in layers},
        layer_errors=errors,
        weights_used=dict(weights),
        sha256=(res1 or {}).get("sha256"),
        package_name=(res1 or {}).get("package_name"),
    )
    return out


if __name__ == "__main__":
    # Gia lap dung dinh dang MalwareDetector: khoa theo ten, don vi %, thu tu abc
    l1 = {"analysis_incomplete": False, "manifest_tampered": 0, "zip_tampered": 0,
          "probabilities": {"Adware": 5.0, "Banking": 60.0, "Benign": 10.0,
                            "Riskware": 15.0, "SMS": 10.0}}
    l4 = {"Benign": 0.1, "Adware": 0.1, "Banking": 0.5, "SMS": 0.1, "Riskware": 0.2}
    r = weighted_vote([from_layer1(l1), from_layer4(l4),
                       from_layer2(None), from_layer3(None)])
    print(r["label"], r["p_malicious"])
