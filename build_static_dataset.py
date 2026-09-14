r"""
build_static_dataset.py
Quet toan bo APK that trong dataset/raw_apk/{malicious/<nhom>,benign}/,
goi extract_features() (dung chung voi apk_analyzer.py) cho tung file,
xuat ra dataset/processed/static_features.csv - day la CSV duy nhat dung
de train lai model Tang 1 moi.

CHAY:
  .\venv\Scripts\python.exe build_static_dataset.py
"""

import os
import sys
import csv
import time

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="ERROR")
except Exception:
    pass

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scanner.static_features import extract_features, FEATURE_SCHEMA

RAW_ROOT = "dataset/raw_apk"
OUT_PATH = "dataset/processed/static_features.csv"


def find_apks():
    """Tra ve list (apk_path, label) - label la ten thu muc con."""
    items = []
    benign_dir = os.path.join(RAW_ROOT, "benign")
    if os.path.isdir(benign_dir):
        for fn in os.listdir(benign_dir):
            if fn.lower().endswith(".apk"):
                items.append((os.path.join(benign_dir, fn), "Benign"))

    malicious_dir = os.path.join(RAW_ROOT, "malicious")
    if os.path.isdir(malicious_dir):
        for cat in os.listdir(malicious_dir):
            cat_dir = os.path.join(malicious_dir, cat)
            if not os.path.isdir(cat_dir):
                continue
            for fn in os.listdir(cat_dir):
                if fn.lower().endswith(".apk"):
                    items.append((os.path.join(cat_dir, fn), cat))
    return items


def main():
    items = find_apks()
    print(f"Tim thay {len(items)} file APK trong {RAW_ROOT}/")
    if not items:
        print("Chua co APK nao. Chay download_malwarebazaar.py / download_fdroid.py truoc.")
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    fieldnames = FEATURE_SCHEMA + ["sha256", "package_name", "label"]

    ok, fail = 0, 0
    t0 = time.time()
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i, (apk_path, label) in enumerate(items, 1):
            try:
                feats = extract_features(apk_path)
                feats["label"] = label
                writer.writerow(feats)
                ok += 1
                print(f"[{i}/{len(items)}] OK  {label:10s} {os.path.basename(apk_path)}")
            except Exception as e:
                fail += 1
                print(f"[{i}/{len(items)}] LOI {label:10s} {os.path.basename(apk_path)}: {e}")

    dt = time.time() - t0
    print(f"\nHoan tat trong {dt:.1f}s. Thanh cong: {ok}, Loi: {fail}.")
    print(f"Da ghi: {OUT_PATH}")
    print(f"So dac trung moi mau: {len(FEATURE_SCHEMA)} (co dinh, khong co cot dummy).")


if __name__ == "__main__":
    main()
