"""Real parser and Flask checks with a tiny non-executed DEX fixture.

Uses only the manifest of the supplied APK; never executes or installs an APK.
python -B tests/smoke_layer_contract.py APKPure_v3.20.6504_apkpure.com.apk
"""
import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dex_fixture import make_dex


def main():
    with zipfile.ZipFile(sys.argv[1]) as original:
        manifest = original.read('AndroidManifest.xml')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as fixture:
        fixture.writestr('AndroidManifest.xml', manifest)
        fixture.writestr('classes.dex', make_dex())
        fixture.writestr('assets/hidden.img', b'dex\n035\0static test fixture only')
    with tempfile.TemporaryDirectory() as temp:
        os.environ['SCAN_FOLDER'] = temp
        os.environ['MOBSF_API_KEY'] = ''
        from web.app import app
        from scanner.pipeline_runner import failed_result
        with app.test_client() as client:
            response = client.post('/scan/apk', data={'file': (io.BytesIO(buffer.getvalue()), 'fixture.apk')})
            assert response.status_code == 200
            result = response.get_json()['ai_result']
            assert not result.get('deep_error'), result.get('deep_error')
            assert result['deep']['layer3']['status'] == 'completed'
            assert result['deep']['layer3']['finding_count'] == 1
            assert result['deep']['layer3']['findings'][0]['method_name'] == 'leak'
            assert result['deep']['layer2']['artifacts']['counts']['embedded_payloads'] == 1
            filename = result['filename']
            # Real file-manager parser path, not a cached/mocked report.
            response = client.get('/file-manager/scan/apk/' + filename)
            assert response.status_code == 200
            assert response.get_json()['deep']['layer3']['finding_count'] == 1
            # No result must be misreported as a clean layer when the worker fails.
            with patch('web.app.analyze_apk_pipeline', return_value=failed_result('test timeout', filename)):
                response = client.get('/file-manager/scan/apk/' + filename)
                data = response.get_json()
                assert response.status_code == 503
                assert data['deep']['layer3']['status'] == 'unavailable'
                assert data['deep']['layer3']['score'] is None
                assert data['verdict']['level'] == 'unknown'
                assert data['deep_error'] == 'test timeout'
            assert client.get('/file-manager/scan/invalid/x.apk').status_code == 400
            damaged = io.BytesIO()
            with zipfile.ZipFile(damaged, 'w') as z:
                z.writestr('AndroidManifest.xml', manifest)
                z.writestr('classes.dex', b'dex\n035\0broken fixture')
            response = client.post('/scan/apk', data={'file': (io.BytesIO(damaged.getvalue()), 'broken.apk')})
            assert response.status_code == 200
            incomplete = response.get_json()['ai_result']
            assert incomplete['analysis_incomplete']
            assert incomplete['confidence'] is None
            assert incomplete['deep']['layer3']['status'] == 'unavailable'
            assert incomplete['deep']['layer3']['score'] is None
            assert incomplete.get('verdict', {}).get('level') != 'safe'
            print('PASS: real DEX positive layer 3, disguised payload, upload + real file manager, unavailable state')
            print(json.dumps({name: {k: result['deep'][name][k] for k in ('status', 'score', 'finding_count')}
                              for name in ('layer2', 'layer3')}))


if __name__ == '__main__':
    main()
