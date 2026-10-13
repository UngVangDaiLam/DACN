"""Run the real Flask APK upload pipeline without a browser or MobSF.

Usage: python -B tests/smoke_apk_layers.py path/to/sample.apk
Only static analysis is performed. Uploads are stored in a temporary folder.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    apk_path = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="apk_layers_") as scan_dir:
        os.environ["SCAN_FOLDER"] = scan_dir
        os.environ["MOBSF_API_KEY"] = ""
        from web.app import app, detector

        with app.test_client() as client:
            assert client.get("/scan").status_code == 200
            with apk_path.open("rb") as stream:
                response = client.post("/scan/apk", data={"file": (stream, apk_path.name)})
            assert response.status_code == 200, response.get_data(as_text=True)[:1000]
            payload = response.get_json()
            assert payload["success"], payload
            result = payload["ai_result"]
            assert "deep_error" not in result, result.get("deep_error")
            assert payload["task_id"] is None
            for key in ("layer2", "layer3"):
                layer = result["deep"][key]
                assert layer["status"] == "completed", layer
                assert layer["methods_scanned"] > 0
                print(key, json.dumps({k: layer[k] for k in
                    ("status", "methods_scanned", "finding_count", "counts_by_origin", "truncated")}, ensure_ascii=False))

            # Exercise file-manager response integration without parsing a large APK twice.
            with patch.object(detector, "analyze_apk", return_value={k: v for k, v in result.items() if k not in ("deep", "verdict")}), \
                 patch("web.app.analyze_deep", return_value=result["deep"]):
                response = client.get("/file-manager/scan/apk/" + result["filename"])
                assert response.status_code == 200
                assert response.get_json()["deep"]["layer3"]["status"] == "completed"
            print("PASS: real APK upload + report JSON + scan page + file-manager integration")


if __name__ == "__main__":
    main()
