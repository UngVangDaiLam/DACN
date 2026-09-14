"""
download_fdroid.py
Tai mau APK "sach" (benign) that tu kho F-Droid - ma nguon mo, tai cong khai,
hop phap 100%, khong vuong ban quyen nhu tai tu APKPure/CH Play.

CHAY:
  .\venv\Scripts\python.exe download_fdroid.py

Luu y: file danh muc index-v2.json cua F-Droid kha lon (co the vai chuc MB,
liet ke toan bo ~4000+ app), nen buoc dau co the mat 1-2 phut de tai + parse.
"""

import requests, os, csv, sys, random, hashlib
from datetime import datetime

INDEX_URL = "https://f-droid.org/repo/index-v2.json"
REPO_BASE = "https://f-droid.org/repo"
OUTPUT_DIR = "dataset/raw_apk/benign"
MANIFEST_PATH = "dataset/raw_apk/manifest.csv"
TARGET_COUNT = 80
SEED = 42


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)

    print("Dang tai danh muc F-Droid (index-v2.json)...")
    r = requests.get(INDEX_URL, timeout=180)
    r.raise_for_status()
    index = r.json()

    packages = index.get("packages")
    if not packages:
        print("Khong tim thay khoa 'packages'. Cac khoa cap cao nhat trong index:",
              list(index.keys()))
        print("    -> Bao toi noi dung nay, co the F-Droid da doi cau truc index.")
        sys.exit(1)

    print(f"   Tong so app trong repo: {len(packages)}")

    candidates = []
    for pkg_name, pkg_data in packages.items():
        versions = pkg_data.get("versions") or {}
        if not versions:
            continue
        try:
            latest_key = max(versions, key=lambda k: versions[k].get("added", 0))
        except ValueError:
            continue
        v = versions[latest_key]
        file_info = v.get("file") or {}
        file_name = file_info.get("name")
        if not file_name:
            continue
        candidates.append((pkg_name, file_name.lstrip("/")))

    print(f"   Co {len(candidates)} app hop le de chon ngau nhien.")
    if not candidates:
        print("Danh sach rong - cau truc 1 package mau de debug:",
              next(iter(packages.values())) if packages else None)
        sys.exit(1)

    random.seed(SEED)
    random.shuffle(candidates)

    manifest_rows = []
    downloaded = 0
    for pkg_name, file_name in candidates:
        if downloaded >= TARGET_COUNT:
            break
        url = f"{REPO_BASE}/{file_name}"
        out_path = os.path.join(OUTPUT_DIR, file_name.replace("/", "_"))
        if os.path.exists(out_path):
            downloaded += 1
            continue
        try:
            resp = requests.get(url, timeout=60)
            if resp.status_code != 200 or len(resp.content) < 1000:
                continue
        except Exception as e:
            print(f"   Loi tai {pkg_name}: {e}")
            continue

        with open(out_path, "wb") as f:
            f.write(resp.content)

        downloaded += 1
        digest = sha256_of(resp.content)
        print(f"[{downloaded}/{TARGET_COUNT}] {pkg_name}")
        manifest_rows.append({
            "sha256": digest, "category": "Benign", "signature": pkg_name,
            "source": "F-Droid", "downloaded_at": datetime.now().isoformat(),
            "path": out_path,
        })

    write_header = not os.path.exists(MANIFEST_PATH) or os.path.getsize(MANIFEST_PATH) == 0
    with open(MANIFEST_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sha256", "category", "signature",
                                                "source", "downloaded_at", "path"])
        if write_header:
            writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"\nDa tai {downloaded}/{TARGET_COUNT} mau sach vao {OUTPUT_DIR}")
    print(f"Da ghi nhat ky vao {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
