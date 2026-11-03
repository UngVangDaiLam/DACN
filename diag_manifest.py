r"""
diag_manifest.py - So sanh androguard va apkInspector khi doc AndroidManifest
cua 1 APK (dung de kiem tra APK co bi lam meo manifest hay khong).

CHAY:
  .\venv\Scripts\python.exe diag_manifest.py <duong_dan_apk>
"""
import io
import re
import sys

from loguru import logger

logger.remove()
logger.add(sys.stderr, level="CRITICAL")  # tat log cua androguard

import logging
logging.disable(logging.WARNING)          # tat log cua apkInspector

from androguard.core.apk import APK
from apkInspector.axml import parse_apk_for_manifest
from apkInspector.indicators import apk_tampering_check


def summarize_xml(xml: str) -> dict:
    perms = set()
    for tag in re.findall(r"<uses-permission[^>]*>", xml):
        perms.update(v for v in re.findall(r'"([A-Za-z0-9_.]+)"', tag) if "." in v)
    pkg = re.search(r'<manifest\b[^>]*?\bpackage="([^"]+)"', xml)
    return {
        "package": pkg.group(1) if pkg else None,
        "permissions": len(perms),
        "activities": len(re.findall(r"<activity[\s>]", xml)),
        "services": len(re.findall(r"<service[\s>]", xml)),
        "receivers": len(re.findall(r"<receiver[\s>]", xml)),
        "providers": len(re.findall(r"<provider[\s>]", xml)),
        "sample_perms": sorted(perms)[:8],
    }


def main(path):
    print(f"=== {path}")
    try:
        a = APK(path)
        print("[androguard]  package:", a.get_package(),
              "| perms:", len(a.get_permissions()),
              "| act/svc/rcv/prv:", len(a.get_activities()), len(a.get_services()),
              len(a.get_receivers()), len(a.get_providers()))
    except Exception as e:
        print("[androguard]  LOI:", type(e).__name__, e)

    try:
        xml = parse_apk_for_manifest(path)
        s = summarize_xml(xml)
        print("[apkInspector] package:", s["package"],
              "| perms:", s["permissions"],
              "| act/svc/rcv/prv:", s["activities"], s["services"],
              s["receivers"], s["providers"])
        print("[apkInspector] vi du quyen:", s["sample_perms"])
    except Exception as e:
        print("[apkInspector] LOI:", type(e).__name__, e)

    try:
        with open(path, "rb") as f:
            t = apk_tampering_check(io.BytesIO(f.read()), strict=False)
        print("[tamper] zip     :", t.get("zip tampering") or "khong phat hien")
        print("[tamper] manifest:", t.get("manifest tampering") or "khong phat hien")
    except Exception as e:
        print("[tamper] LOI:", type(e).__name__, e)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Cach dung: python diag_manifest.py <file.apk> [file2.apk ...]")
    for p in sys.argv[1:]:
        main(p)
