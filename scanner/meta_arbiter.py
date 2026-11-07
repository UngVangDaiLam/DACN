"""Tang 5 - Meta-arbiter (5.1b: hop dong du lieu + bo phieu co trong so).

Dau vao L1 = dict tra ve tu MalwareDetector.analyze_apk (xac suat tinh bang %,
khoa theo TEN lop, KHONG theo vi tri). Dau vao L4 = dict {ten lop: xac suat 0-1}.
"""
CLASSES = ["Benign", "Adware", "Banking", "SMS", "Riskware"]  # chi de kiem tra tap ten lop
BENIGN = "Benign"
UNKNOWN = "Không xác định"
WEIGHTS = {"L1": 0.45, "L4": 0.45, "L2": 0.05, "L3": 0.05}  # trong so tay
MIN_VOTERS = 1          # so tang "bo phieu" (L1/L4) toi thieu
CONFLICT_GAP = 0.5      # L1 va L4 lech P(doc) > nguong -> mau thuan
T_MAL, T_HIGH = 0.5, 0.8
ERA_BIASED = {"Adware"}  # nhan ho co the phan anh THOI DAI mau (xem buoc 5.2), khong phai hanh vi


def _absent(name, why):
    return {"name": name, "available": False, "probs": None,
            "risk": None, "evidence": [why]}


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
    s = float(s)
    if not 0.0 <= s <= 1.0:  # risk phai cung thang 0-1 voi xac suat
        raise ValueError("L2: obfuscation_score ngoai thang 0-1: %r" % s)
    return {"name": "L2", "available": True, "probs": None, "risk": s,
            "evidence": ["Tang 2: muc lam roi=%.2f" % s] + list(d.get("evidence", []))}


def from_layer3(rule_score):
    """rule_score thang 0-100 (deep_analysis) -> risk thang 0-1."""
    if rule_score is None:
        return _absent("L3", "Tang 3: vang mat")
    r = float(rule_score) / 100.0
    if not 0.0 <= r <= 1.0:
        raise ValueError("L3: rule_score ngoai thang 0-100: %r" % rule_score)
    return {"name": "L3", "available": True, "probs": None, "risk": r,
            "evidence": ["Tang 3: rule_score=%.0f/100" % float(rule_score)]}


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
    risks = [l for l in av if l["risk"] is not None]
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
        if tamper:  # nhan "sach" nhung manifest bi lam meo -> khong dam ket luan
            out["reason"] = "Du doan sach nhung co dau hieu chong phan tich"
            out["label"] = out["risk_level"] = UNKNOWN
        else:
            out["label"], out["risk_level"] = BENIGN, "Thấp"
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
