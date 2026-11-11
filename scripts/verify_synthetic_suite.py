"""Independently verify synthetic gold using Android SDK dexdump, not scanner/Androguard.

No target-scanner imports or predictions. Only our explicitly bounded fixture
taxonomy is verified; this is not a general obfuscation/malware detector.
"""
import argparse
import base64
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_frozen(root):
    root=Path(root).resolve()
    frozen=json.loads((root/'labels_frozen.json').read_text(encoding='utf-8'))
    for relative,expected in frozen['review_files'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or digest(path)!=expected:
            raise ValueError('Frozen review input changed: '+relative)
    return {'frozen_inputs_verified':True,'files_checked':len(frozen['review_files'])}


def parse_dump(text):
    methods=[];classes=[];owner=name=descriptor=None;current=None
    for line in text.splitlines():
        match=re.match(r"\s*Class descriptor\s*:\s*'([^']+)'",line)
        if match:
            owner=match[1];classes.append(owner);current=None
        match=re.match(r"\s*name\s*:\s*'([^']+)'",line)
        if match:name=match[1]
        match=re.match(r"\s*type\s*:\s*'(\([^']+)'",line)
        if match:descriptor=match[1]
        if re.match(r'^\s*[0-9a-f]+:\s*\|\[[0-9a-f]+\]',line):
            current={'class':owner,'name':name,'descriptor':descriptor,'calls':[],'strings':[],'instructions':[]}
            methods.append(current)
        match=re.match(r'^\s*([0-9a-f]+):.*\|([0-9a-f]+):\s*(.+)$',line)
        if match and current:
            offset=int(match[2],16)*2;ins=match[3]
            current['instructions'].append({'byte_offset':offset,'text':ins})
            call=re.search(r'(L[^;\s]+;)\.([^:\s]+):(\([^\s]*\)[^\s]+)\s*// method@',ins)
            if ins.startswith('invoke-') and call:
                current['calls'].append({'api':call[1]+'->'+call[2]+call[3],'byte_offset':offset,'text':ins})
            string=re.search(r'const-string(?:/jumbo)?\s+[^,]+,\s*"(.*)"\s*// string@',ins)
            if string:current['strings'].append({'value':string[1],'byte_offset':offset})
    return {'classes':classes,'methods':methods}


def verify(root,sdk, jdk,build_tools='35.0.0',freeze=False):
    root=Path(root).resolve();tools=Path(sdk)/'build-tools'/build_tools
    java=Path(jdk)/'bin/java.exe'
    if freeze and (root/'labels_frozen.json').exists():raise ValueError('Refuse to rewrite frozen gold')
    if (root/'labels_frozen.json').exists():return check_frozen(root)
    records=json.loads((root/'candidate_labels.json').read_text(encoding='utf-8'))
    contract=json.loads((root/'design_contract.json').read_text(encoding='utf-8'))
    expected={x['sample_id']:x for x in contract['cases']}
    def run(args):
        result=subprocess.run([str(x) for x in args],capture_output=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise ValueError(result.stdout.decode('utf-8','replace')+result.stderr.decode('utf-8','replace'))
        return result.stdout.decode('utf-8','replace')
    source_apis={'Landroid/location/Location;->getLatitude()D','Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;'}
    sink_apis={'Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;','Landroid/webkit/WebView;->postUrl(Ljava/lang/String;[B)V'}
    manifest_rows=[];label_rows=[]
    for row in records:
        sid=row['sample_id'];spec=expected[sid];apk=root/row['apk'];assert digest(apk)==row['sha256']
        badging=run([tools/'aapt2.exe','dump','badging',apk])
        assert f"name='{row['package']}'" in badging and "versionCode='1'" in badging
        assert 'uses-permission:' not in badging and 'uses-permission-sdk-' not in badging
        (root/'evidence'/f'{sid}_badging.txt').write_text(badging,encoding='utf-8')
        signature=run([java,'-jar',tools/'lib/apksigner.jar','verify','--verbose','--print-certs',apk])
        assert 'Verified using v2 scheme (APK Signature Scheme v2): true' in signature
        (root/'evidence'/f'{sid}_signature.txt').write_text(signature,encoding='utf-8')
        with zipfile.ZipFile(apk) as z:
            assert z.testzip() is None
            dex=z.read('classes.dex');assert dex[12:32]==hashlib.sha1(dex[32:]).digest()
            assert struct.unpack('<I',dex[8:12])[0]==zlib.adler32(dex[12:])&0xffffffff
            with tempfile.TemporaryDirectory() as temp:
                p=Path(temp)/'classes.dex';p.write_bytes(dex)
                dump=run([tools/'dexdump.exe','-d',p])
            (root/'evidence'/f'{sid}_dexdump.txt').write_text(dump,encoding='utf-8')
            parsed=parse_dump(dump);assert parsed['methods']
            calls=[c for m in parsed['methods'] for c in m['calls']]
            apis={c['api'] for c in calls};strings=[s['value'] for m in parsed['methods'] for s in m['strings']]
            embedded=[];native=[]
            for entry in z.infolist():
                if entry.is_dir():continue
                data=z.read(entry)
                if entry.filename.startswith(('assets/','res/raw/')):
                    if data.startswith(b'dex\n'):
                        assert data[12:32]==hashlib.sha1(data[32:]).digest()
                        embedded.append({'entry':entry.filename,'sha256':hashlib.sha256(data).hexdigest(),'kind':'dex'})
                    elif data.startswith(b'PK\x03\x04'):
                        import io
                        with zipfile.ZipFile(io.BytesIO(data)) as nested:
                            assert not any(n.endswith(('.dex','.class','.so','.apk')) for n in nested.namelist())
                if data.startswith(b'\x7fELF'):
                    assert data[4]==2 and struct.unpack('<H',data[18:20])[0]==183
                    native.append(entry.filename)
        direct_dynamic=[c for c in calls if c['api'].startswith('Ldalvik/system/DexClassLoader;-><init>(')]
        reflection=[c for c in calls if c['api'].startswith(('Ljava/lang/Class;->getMethod(', 'Ljava/lang/Class;->forName(', 'Ljava/lang/reflect/Method;->invoke('))]
        native_loading=[c for c in calls if c['api'].startswith('Ljava/lang/System;->loadLibrary(')]
        encoded=[]
        for m in parsed['methods']:
            targets={c['api'] for c in m['calls']}
            if any(x.startswith('Landroid/util/Base64;->decode(') for x in targets):
                for string in m['strings']:
                    try:decoded=base64.b64decode(string['value'],validate=True)
                    except Exception:continue
                    if decoded.startswith(b'SYNTHETIC_ONLY:'):
                        encoded.append({'method':m['class']+'->'+m['name']+m['descriptor'],'literal':string,'decoded':decoded.decode('utf-8'),'basis':'Source constant argument and SDK DEX decode invocation corroborate exact built-in data transform.'})
            if any(x.startswith('Ljava/lang/StringBuffer;->reverse(') for x in targets):
                assert any(x.startswith('Ljava/lang/Class;->getMethod(') for x in targets)
                for string in m['strings']:
                    if string['value']=='htgnel':encoded.append({'method':m['class']+'->'+m['name']+m['descriptor'],'literal':string,'decoded':'length','basis':'Source StringBuffer literal/reverse/toString/getMethod chain plus corresponding SDK DEX instructions.'})
        mapping=root/'evidence'/f'{sid}_mapping.txt'
        rename=[]
        if mapping.exists():
            for original,changed in re.findall(r'^([^ #\s]+) -> ([^\s]+):$',mapping.read_text(encoding='utf-8'),re.M):
                if original!=changed:
                    assert 'L'+changed.replace('.','/')+';' in parsed['classes']
                    rename.append({'original':original,'dex_class':'L'+changed.replace('.','/')+';'})
            assert len(rename)>=40
        else:
            # Exact Java source class names survive D8; no inference from name lengths.
            originals={'L'+row['package'].replace('.','/')+'/'+p.stem+';' for p in (root/row['source']).glob('*.java')}
            assert set(parsed['classes'])==originals,(sid,set(parsed['classes'])^originals)
        pairs=[]
        for m in parsed['methods']:
            sources=[c for c in m['calls'] if c['api'] in source_apis]
            provider=[c for c in m['calls'] if c['api'].startswith('Landroid/content/ContentResolver;->query(')]
            uris=[s for s in m['strings'] if s['value']=='content://contacts' or s['value'].startswith('content://contacts/')]
            if uris:sources+=provider
            sinks=[c for c in m['calls'] if c['api'] in sink_apis]
            if sources and sinks:pairs.append({'class':m['class'],'method':m['name'],'descriptor':m['descriptor'],'sources':sources,'sinks':sinks,'uri_evidence':uris})
        activity=[m for m in parsed['methods'] if m['class']=='L'+row['package'].replace('.','/')+'/EmptyActivity;' and m['name']=='onCreate']
        assert len(activity)==1 and all(c['api'].startswith('Landroid/app/Activity;->onCreate(') for c in activity[0]['calls'])
        actual={'dynamic_loading':bool(direct_dynamic),'reflection':bool(reflection),'encoded_strings':bool(encoded),
                'embedded_payload':bool(embedded),'native_loading':bool(native_loading),'name_obfuscation':bool(rename),
                'tier3_sensitive_network_same_method':bool(pairs)}
        assert actual==spec['labels']==row['labels'],(sid,actual,spec['labels'])
        evidence={'sample_id':sid,'dataset_type':'synthetic','apk_sha256':row['sha256'],'verifier':'Android SDK dexdump/aapt2/apksigner + source/R8 mapping; no scanner/Androguard',
                  'labels':actual,'dynamic_loading':direct_dynamic,'reflection':reflection,'encoded_strings':encoded,
                  'embedded_payload':embedded,'native_loading':native_loading,'native_files':native,
                  'name_obfuscation':rename,'same_method_pairs':pairs,'all_methods':parsed['methods'],
                  'no_permissions':True,'empty_entrypoint_calls_no_probe':True,'signature_v2_verified':True,
                  'negative_basis':'Enumerated all built DEX methods/classes, exact source class correspondence or R8 mapping, source-designed literals and every packaged asset; no runtime inference.'}
        (root/row['evidence']).write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8')
        manifest_rows.append({'sample_id':sid,'dataset_type':'synthetic','name':row['benchmark_case'],'package':row['package'],
                              'version_name':'1.0-synthetic','version_code':1,'sha256':row['sha256'],'size_bytes':apk.stat().st_size,
                              'local_path':row['apk'],'source_url':'locally-authored-controlled-fixture; not collected malware',
                              'evidence_path':row['evidence'],'apk_execution':'Không'})
        for key,value in actual.items():label_rows.append({'sample_id':sid,'technique':key,'status':'Có' if value else 'Không','evidence_path':row['evidence']})
        print('VERIFIED',sid,flush=True)
    for name,rows in [('manifest.csv',manifest_rows),('labels.csv',label_rows)]:
        with (root/name).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    (root/'labels.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    if freeze:
        paths=[]
        for p in root.rglob('*'):
            if p.is_file() and not p.relative_to(root).parts[0]=='build' and p.name!='labels_frozen.json':paths.append(p)
        (root/'labels_frozen.json').write_text(json.dumps({'dataset_type':'synthetic','review_files':{p.relative_to(root).as_posix():digest(p) for p in sorted(paths)},
          'label_origin':'Designed source + independent SDK verification, frozen before target scanner. One reviewer, no second-human adjudication.',
          'apk_execution':False,'scanner_imported_for_labels':False},ensure_ascii=False,indent=2),encoding='utf-8')
    return {'samples':len(records),'label_cells':len(label_rows),'gold_positive':{k:sum(row['labels'][k] for row in records) for k in records[0]['labels']}}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('suite');p.add_argument('--freeze',action='store_true')
    p.add_argument('--sdk',default=str(Path.home()/'AppData/Local/Android/Sdk'));p.add_argument('--jdk',default='C:/Program Files/Java/jdk-23')
    args=p.parse_args();print(json.dumps(verify(args.suite,args.sdk,args.jdk,freeze=args.freeze),indent=2))


if __name__=='__main__':main()
