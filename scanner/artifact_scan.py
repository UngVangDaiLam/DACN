"""Bounded, offline ZIP-member inspection and local YARA rules. Never executes payloads."""

import hashlib
import io
import math
import time
import zipfile
from collections import Counter
from functools import lru_cache
from pathlib import Path

RULE_FILE = Path(__file__).with_name("rules") / "layer2.yar"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_ARTIFACTS = 200
MAX_YARA_FINDINGS = 100


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()), 4)


@lru_cache(maxsize=4)
def _compile_rules(source):
    import yara
    return yara.compile(source=source, includes=False)


def scan_artifacts(apk_path, timeout=30):
    started = time.monotonic()
    issues, findings, payloads, native, dex = [], [], [], [], []
    counts = Counter()
    techniques = set()
    bytes_scanned = 0
    rules = None
    try:
        source = RULE_FILE.read_text(encoding="utf-8")
        rule_hash = hashlib.sha256(source.encode()).hexdigest()
        rules = _compile_rules(source)
        yara_status = "completed"
    except Exception as exc:
        rule_hash = None
        yara_status = "unavailable"
        issues.append({"component": "yara", "reason": f"{type(exc).__name__}: {exc}"})
    archive_readable = False
    try:
        with zipfile.ZipFile(apk_path) as archive:
            archive_readable = True
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                issues.append({"component": "archive", "reason": "Giới hạn số mục ZIP"})
            for member in sorted(entries[:MAX_ENTRIES], key=lambda m: m.filename):
                name = member.filename
                if member.is_dir():
                    continue
                # Look inside resources even if the extension disguises the payload.
                if not (name.endswith(".dex") or name.endswith(".so") or
                        name.startswith(("assets/", "res/raw/"))):
                    continue
                if time.monotonic() - started >= timeout:
                    issues.append({"component": "archive", "reason": "Hết thời gian quét tài nguyên"})
                    break
                if member.file_size > MAX_MEMBER_BYTES or bytes_scanned + member.file_size > MAX_TOTAL_BYTES:
                    issues.append({"component": "archive", "file_path": name, "reason": "Vượt giới hạn byte giải nén"})
                    continue
                try:
                    with archive.open(member) as stream:
                        data = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES or bytes_scanned + len(data) > MAX_TOTAL_BYTES:
                        raise ValueError("Vượt giới hạn byte giải nén")
                    bytes_scanned += len(data)
                    counts["members_scanned"] += 1
                    embedded = name.startswith(("assets/", "res/raw/"))
                    kind = "dex" if data.startswith(b"dex\n") else "zip" if data.startswith(b"PK\x03\x04") else "elf" if data.startswith(b"\x7fELF") else None
                    if embedded and kind == "zip":
                        try:
                            with zipfile.ZipFile(io.BytesIO(data)) as nested:
                                names = nested.namelist()[:MAX_ENTRIES]
                            kind = "apk" if "AndroidManifest.xml" in names else "jar" if any(n.endswith(".class") for n in names) else "dex_archive" if any(n.endswith(".dex") for n in names) else "archive"
                        except zipfile.BadZipFile:
                            kind = "unverified_zip"
                        if kind in ("archive", "unverified_zip"):
                            counts["other_archives"] += 1
                    if embedded and kind in ("dex", "apk", "jar", "dex_archive", "elf"):
                        counts["embedded_payloads"] += 1
                        if len(payloads) < MAX_ARTIFACTS:
                            payloads.append({"file_path": name, "kind": kind,
                                             "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
                    if kind == "elf" or name.endswith(".so"):
                        counts["native_libs"] += 1
                        if len(native) < MAX_ARTIFACTS:
                            native.append(name)
                    if kind == "dex" and not embedded:
                        counts["dex_files"] += 1
                        dex_entropy = entropy(data)
                        if len(dex) < MAX_ARTIFACTS:
                            dex.append({"file_path": name, "entropy": dex_entropy, "size": len(data)})
                        if dex_entropy >= 7.5:
                            counts['high_entropy_dex'] += 1
                            techniques.add('dex_high_entropy')
                            if len(findings) < MAX_YARA_FINDINGS:
                                findings.append({'rule_id': 'dex_high_entropy', 'title': 'Entropy DEX cao (cần đối chiếu thêm)',
                                                 'severity': 'info', 'file_path': name, 'entropy': dex_entropy})
                    # Report entropy as an indicator, not confirmation of encryption.
                    if embedded and not kind and len(data) >= 1024:
                        ent = entropy(data[:1024 * 1024])
                        if ent >= 7.5 and name.lower().endswith((".bin", ".dat", ".enc", ".dex", ".jar", ".apk")):
                            counts["high_entropy_resources"] += 1
                            techniques.add('resource_high_entropy')
                            if len(findings) < MAX_YARA_FINDINGS:
                                findings.append({"rule_id": "resource_high_entropy", "title": "Tài nguyên entropy cao (có thể nén hoặc mã hóa)",
                                                 "severity": "info", "file_path": name, "entropy": ent})
                    if rules is not None:
                        remaining = max(1, math.ceil(timeout - (time.monotonic() - started)))
                        for hit in rules.match(data=data, timeout=min(3, remaining)):
                            counts["yara_matches"] += 1
                            techniques.add(hit.meta.get('technique', 'yara_' + hit.rule))
                            if len(findings) >= MAX_YARA_FINDINGS:
                                continue
                            matches = []
                            for string in hit.strings:
                                for instance in string.instances[:3]:
                                    matches.append({"identifier": string.identifier, "offset": int(instance.offset),
                                                    "value": bytes(instance.matched_data)[:100].decode("utf-8", "replace")})
                            findings.append({"rule_id": "yara_" + hit.rule, "title": hit.meta.get("title", hit.rule),
                                             "severity": hit.meta.get("severity", "info"), "technique": hit.meta.get("technique"),
                                             "file_path": name, "matches": matches[:12]})
                except Exception as exc:
                    issues.append({"component": "artifact", "file_path": name, "reason": f"{type(exc).__name__}: {exc}"})
                    if rules is not None:
                        yara_status = "partial"
    except Exception as exc:
        issues.append({"component": "archive", "reason": f"{type(exc).__name__}: {exc}"})
    # Any skipped member means YARA did not cover the complete requested scope.
    if rules is not None and issues:
        yara_status = "partial"
    return {"available": archive_readable, "status": "partial" if issues else "completed",
            "yara_status": yara_status, "rules_sha256": rule_hash, "findings": findings,
            "indicator_techniques": sorted(techniques),
            "embedded_payloads": [p["file_path"] for p in payloads], "payload_details": payloads,
            "native_libs": native, "dex_files": dex, "counts": dict(counts),
            "issues": issues[:30], "issue_count": len(issues), "bytes_scanned": bytes_scanned,
            "truncated": counts["embedded_payloads"] > len(payloads) or counts["native_libs"] > len(native)
                         or counts["yara_matches"] + counts["high_entropy_resources"] + counts['high_entropy_dex'] > len(findings),
            "limits": {"member_bytes": MAX_MEMBER_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                       "entries": MAX_ENTRIES, "timeout_seconds": timeout}}
