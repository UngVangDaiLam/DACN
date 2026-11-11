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
    """Score observed capabilities, not a calibrated malware probability.

    Incomplete/truncated inputs retain evidence and observed_score, but score
    stays None. Legacy test/adapter dictionaries without status remain supported.
    """
    supplied = [l for l in (layer2, layer3) if l is not None]
    present = [l for l in supplied if l.get('available') is not False
               and l.get('status') != 'unavailable']
    if not present:
        return {"family": FAMILY_B, "available": False, "status": "unavailable",
                "score": None, "observed_score": None, "evidence": [],
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
    incomplete = len(present) != len(supplied) or any(
        l.get('status', 'completed') != 'completed' or l.get('analysis_errors', 0)
        or l.get('truncated') for l in present)
    if len(present) != len(supplied):
        notes.append('Mot tang khong kha dung: khong coi bang chung thieu la diem 0')
    # The retained findings can provide an observed score, but partial/truncated
    # evidence must not expose it as a completed score (including a clean zero).
    return {"family": FAMILY_B, "available": True,
            "status": "partial" if incomplete else "completed",
            "score": None if incomplete else round(score, 4),
            "observed_score": round(score, 4), "evidence": evidence, "notes": notes}
