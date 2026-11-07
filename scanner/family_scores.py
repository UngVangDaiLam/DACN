"""Tang 5 - Diem tung ho bang chung, thang [0, 1].

Hien co: ho B (hanh vi trong ma = Tang 2 + 3). Ho A, C se them sau.
Ho vang mat -> available=False, score=None (KHONG dien 0, khong phai 'sach').
Layer co mat nhung khong co finding -> available=True, score=0.0.
"""
from scanner.capabilities import FAMILY_B, merge_family_b

CAP_B = 0.95  # tran diem ho B (DE XUAT, chua hieu chinh)


def noisy_or(weights, cap=1.0):
    p = 1.0
    for w in weights:
        if not 0.0 <= w <= 1.0:
            raise ValueError("trong so ngoai [0,1]: %r" % w)
        p *= 1.0 - w
    return min(cap, 1.0 - p)


def score_family_b(layer2, layer3, cap=CAP_B):
    """layer2/layer3: dict layerN cua Tang 2/3 hoac None neu tang vang mat."""
    present = [l for l in (layer2, layer3) if l is not None]
    if not present:
        return {"family": FAMILY_B, "available": False, "score": None, "evidence": [],
                "notes": ["Tang 2 va Tang 3 deu vang mat"]}
    notes = []
    if any(l.get("status") == "partial" for l in present):
        notes.append("Phan tich khong day du (status=partial): diem co the thap hon thuc te")
    if any(l.get("truncated") for l in present):
        notes.append("Danh sach finding bi cat bot (truncated)")
    merged = merge_family_b(*present)
    items = sorted(merged.items(), key=lambda kv: (-kv[1]["weight"], kv[0]))
    score = noisy_or([m["weight"] for _, m in items], cap)
    evidence = [{"capability": c, "severity": m["severity"], "origin": m["origin"],
                 "weight": round(m["weight"], 4), "count": m["count"],
                 "rules": sorted(m["rules"]), "layers": sorted(m["layers"])}
                for c, m in items]
    return {"family": FAMILY_B, "available": True, "score": round(score, 4),
            "evidence": evidence, "notes": notes}
