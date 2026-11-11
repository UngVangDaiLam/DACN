"""Build honest synthetic APK fixtures offline with Android SDK/JDK, never run APKs.

No Gradle, network, emulator or APK execution. Output is a new directory only.
All exercise methods are unreferenced by the empty launcher Activity; no permissions.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cases():
    def case(sid, title, body, positives=(), asset=None, obfuscate=False, helpers=False):
        keys = ['dynamic_loading', 'reflection', 'encoded_strings', 'embedded_payload',
                'native_loading', 'name_obfuscation', 'tier3_sensitive_network_same_method']
        return {'sample_id': sid, 'title': title, 'body': body, 'labels': {k: k in positives for k in keys},
                'asset': asset, 'obfuscate': obfuscate, 'helpers': helpers}
    return [
        case('SYN01','Clean negative control','public static String probe(){return "SYNTHETIC_PLAINTEXT";}'),
        case('SYN02','Reflection lookup and invoke','public static Object probe() throws Exception { return String.class.getMethod("length").invoke("STATIC_ONLY"); }', ['reflection']),
        case('SYN03','Local DEX loader','public static ClassLoader probe(android.content.Context c){return new dalvik.system.DexClassLoader(c.getFilesDir()+"/synthetic.jar",c.getCodeCacheDir().getPath(),null,c.getClassLoader());}', ['dynamic_loading']),
        case('SYN04','Class lookup is not DEX loading','public static Class<?> probe() throws Exception {return Class.forName("java.lang.String");}', ['reflection']),
        case('SYN05','Reversed method-name constant','public static java.lang.reflect.Method probe() throws Exception {String n=new StringBuffer("htgnel").reverse().toString();return String.class.getMethod(n);}', ['reflection','encoded_strings']),
        case('SYN06','Verified Base64 constant','public static String probe(){return new String(android.util.Base64.decode("'+base64.b64encode(b'SYNTHETIC_ONLY: This is a deliberately encoded harmless constant for offline static analysis, not private data.').decode()+'",0),java.nio.charset.StandardCharsets.UTF_8);}', ['encoded_strings']),
        case('SYN07','Cipher API is not encoded constant','public static byte[] probe(javax.crypto.Cipher c,byte[] input) throws Exception{return c.doFinal(input);}'),
        case('SYN08','DEX hidden behind image extension','public static String probe(){return "SYNTHETIC_EMBEDDED_MARKER";}', ['embedded_payload'], asset='dex'),
        case('SYN09','Non-executable animation archive','public static String probe(){return "SYNTHETIC_ARCHIVE_ONLY";}', asset='archive'),
        case('SYN10','Native library load API','public static void probe(){System.loadLibrary("synthetic");}', ['native_loading'], asset='native'),
        case('SYN11','ELF present without load API','public static String probe(){return "SYNTHETIC_ELF_PRESENT_ONLY";}', asset='native'),
        case('SYN12','R8 verified renaming','public static int probe(){return new DescriptiveMarker00().marker();}', ['name_obfuscation'], obfuscate=True, helpers=True),
        case('SYN13','Readable names control','public static int probe(){return new DescriptiveMarker00().marker();}', helpers=True),
        case('SYN14','Sensitive and network in same method','public static void probe(android.location.Location l,java.net.HttpURLConnection c) throws Exception {double value=l.getLatitude();c.getOutputStream().write(Double.toString(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));}', ['tier3_sensitive_network_same_method']),
        case('SYN15','Source and network separate methods','public static double read(android.location.Location l){return l.getLatitude();} public static java.io.OutputStream send(java.net.HttpURLConnection c) throws Exception{return c.getOutputStream();}'),
        case('SYN16','Overloads must stay separate','public static double probe(android.location.Location l){return l.getLatitude();} public static java.io.OutputStream probe(java.net.HttpURLConnection c) throws Exception{return c.getOutputStream();}'),
        case('SYN17','Network only','public static java.io.OutputStream probe(java.net.HttpURLConnection c) throws Exception{return c.getOutputStream();}'),
        case('SYN18','SMS is not IP network','public static void probe(android.location.Location l,android.telephony.SmsManager s){double marker=l.getLatitude();s.sendTextMessage("000",null,"SYNTHETIC_TEST_ONLY",null,null);}'),
        case('SYN19','Exclusive branches still co-occur','public static void probe(boolean branch,android.location.Location l,java.net.HttpURLConnection c) throws Exception {if(branch){l.getLatitude();}else{c.getOutputStream();}}', ['tier3_sensitive_network_same_method']),
        case('SYN20','Sensitive provider and network','public static void probe(android.content.ContentResolver r,java.net.HttpURLConnection c) throws Exception {r.query(android.net.Uri.parse("content://contacts/people"),null,null,null,null);c.getOutputStream();}', ['tier3_sensitive_network_same_method']),
        case('SYN21','URI authority boundary negative','public static void probe(android.content.ContentResolver r,java.net.HttpURLConnection c) throws Exception {r.query(android.net.Uri.parse("content://sms.example/items"),null,null,null,null);c.getOutputStream();}'),
        case('SYN22','Sensitive API only','public static double probe(android.location.Location l){return l.getLatitude();}'),
        case('SYN23','Clipboard and WebView POST','public static void probe(android.content.ClipboardManager c,android.webkit.WebView w){c.getPrimaryClip();w.postUrl("http://127.0.0.1:9/synthetic",new byte[]{83,89,78});}', ['tier3_sensitive_network_same_method']),
        case('SYN24','Interprocedural flow is outside criterion','public static void probe(android.location.Location l,java.net.HttpURLConnection c) throws Exception {double value=l.getLatitude();send(c);} public static java.io.OutputStream send(java.net.HttpURLConnection c) throws Exception{return c.getOutputStream();}'),
    ]


def build(output, sdk, jdk, build_tools='35.0.0', api='android-33', ndk='28.2.13676358'):
    output, sdk, jdk = Path(output).resolve(), Path(sdk).resolve(), Path(jdk).resolve()
    if output.exists():
        raise ValueError('Output already exists; use a new suite version')
    tools = sdk/'build-tools'/build_tools
    java, javac, keytool = [jdk/'bin'/name for name in ['java.exe','javac.exe','keytool.exe']]
    android = sdk/'platforms'/api/'android.jar'
    d8 = tools/'lib/d8.jar'; aapt = tools/'aapt2.exe'; signer = tools/'lib/apksigner.jar'
    clang = sdk/'ndk'/ndk/'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
    for p in [java,javac,keytool,android,d8,aapt,signer,clang,tools/'dexdump.exe']:
        if not p.is_file(): raise FileNotFoundError(p)
    output.mkdir(parents=True)
    scratch = output/'build'; scratch.mkdir()
    (output/'apks').mkdir(); (output/'source').mkdir(); (output/'evidence').mkdir()
    log=[]
    def run(args, cwd=None):
        args=[str(a) for a in args]
        result=subprocess.run(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
        text=result.stdout.decode('utf-8',errors='replace')
        log.append({'argv':args,'exit_code':result.returncode,'output':text})
        (output/'build_log.json').write_text(json.dumps(log,ensure_ascii=False,indent=2),encoding='utf-8')
        if result.returncode:raise RuntimeError('Build tool failed: '+str(args[:3])+'\n'+text[-5000:])
        return text
    versions={'jdk':run([java,'-version']),'javac':run([javac,'-version']),
              'aapt2':run([aapt,'version']),'d8':run([java,'-cp',d8,'com.android.tools.r8.D8','--version'])}
    tool_paths=[java,javac,android,d8,aapt,signer,clang,tools/'dexdump.exe']
    (output/'toolchain.json').write_text(json.dumps({'versions':versions,'sha256':{str(p):sha(p) for p in tool_paths},'network_used':False},indent=2),encoding='utf-8')
    # A dedicated disposable signing identity, never a user/production certificate.
    key=scratch/'synthetic.p12'
    run([keytool,'-genkeypair','-noprompt','-keystore',key,'-storetype','PKCS12','-storepass','synthetic-only',
         '-keypass','synthetic-only','-alias','fixture','-keyalg','RSA','-keysize','2048','-validity','3650','-dname','CN=StaticTestOnly'])
    native_source=output/'source/synthetic_native.c'
    native_source.write_text('/* Harmless marker: no constructors, JNI, IO or network. */\nint synthetic_probe(void){return 42;}\n',encoding='utf-8')
    native=scratch/'libsynthetic.so'
    run([clang,'--target=aarch64-linux-android23','-shared','-nostdlib','-fPIC','-Wl,-soname,libsynthetic.so',native_source,'-o',native])
    # A payload with only a constant-returning method; compiled, never executed.
    ps=output/'source/PayloadMarker.java'
    ps.write_text('package org.dacn.syntheticpayload; public class PayloadMarker { public static String marker(){return "HARMLESS_SYNTHETIC_PAYLOAD";} }',encoding='utf-8')
    pc=scratch/'payload_classes';pc.mkdir();pd=scratch/'payload_dex';pd.mkdir()
    run([javac,'-proc:none','-source','8','-target','8','-bootclasspath',android,'-d',pc,ps])
    def jar(directory,target):
        with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
            for p in sorted(directory.rglob('*.class')):z.write(p,p.relative_to(directory).as_posix())
    pj=scratch/'payload_classes.jar';jar(pc,pj)
    run([java,'-cp',d8,'com.android.tools.r8.D8','--min-api','23','--lib',android,'--output',pd,pj])
    spec=cases()
    (output/'design_contract.json').write_text(json.dumps({'dataset_type':'synthetic','created_utc':datetime.now(timezone.utc).isoformat(),
      'scope':'All packaged code; static API presence and same-method co-occurrence, not runtime reachability or dataflow.',
      'safety':'Empty Activity does not invoke probes; no uses-permission; no receivers/services; no APK installed or executed.',
      'tier3_network':'IP only. SMS excluded. Different branches in same method count positive; different methods/overloads do not.',
      'labels_origin':'Designed first, independently verified from SDK dexdump/source/mapping before detector use.',
      'cases':spec},ensure_ascii=False,indent=2),encoding='utf-8')
    records=[]
    for item in spec:
        sid=item['sample_id']; package='org.dacn.syntest.'+sid.lower()
        src=output/'source'/sid;src.mkdir();work=scratch/sid;work.mkdir()
        classes=work/'classes';classes.mkdir();dex=work/'dex';dex.mkdir()
        activity=src/'EmptyActivity.java'
        activity.write_text('package '+package+';\npublic class EmptyActivity extends android.app.Activity {\n @Override public void onCreate(android.os.Bundle b){super.onCreate(b);}\n}\n',encoding='utf-8')
        java_source=src/'SyntheticCase.java'
        java_source.write_text('package '+package+';\n/** SYNTHETIC. Static-only unreferenced probe. Never execute APK. */\npublic class SyntheticCase {\n'+item['body']+'\n}\n',encoding='utf-8')
        if item['helpers']:
            for n in range(40):
                (src/f'DescriptiveMarker{n:02}.java').write_text(f'package {package}; public class DescriptiveMarker{n:02} {{public int marker(){{return {n};}}}}\n',encoding='utf-8')
        manifest=src/'AndroidManifest.xml'
        manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="1" android:versionName="1.0-synthetic">
<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33"/>
<application android:label="SYNTHETIC {sid}" android:allowBackup="false" android:debuggable="false">
<activity android:name="{package}.EmptyActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
</application></manifest>''',encoding='utf-8')
        run([javac,'-proc:none','-source','8','-target','8','-g','-bootclasspath',android,'-d',classes,*sorted(src.glob('*.java'))])
        cj=work/'classes.jar';jar(classes,cj)
        if item['obfuscate']:
            config=src/'r8-rules.pro';mapping=output/'evidence'/f'{sid}_mapping.txt'
            config.write_text(f'-dontshrink\n-dontoptimize\n-keep public class {package}.EmptyActivity {{ *; }}\n-printmapping {mapping.as_posix()}\n',encoding='utf-8')
            run([java,'-cp',d8,'com.android.tools.r8.R8','--min-api','23','--lib',android,'--pg-conf',config,'--output',dex,cj])
        else:
            run([java,'-cp',d8,'com.android.tools.r8.D8','--min-api','23','--lib',android,'--output',dex,cj])
        unsigned=work/'unsigned.apk'
        run([aapt,'link','-I',android,'--manifest',manifest,'--min-sdk-version','23','--target-sdk-version','33','-o',unsigned])
        with zipfile.ZipFile(unsigned,'a',zipfile.ZIP_DEFLATED) as z:
            z.write(dex/'classes.dex','classes.dex')
            if item['asset']=='dex':z.write(pd/'classes.dex','assets/harmless_image.png')
            if item['asset']=='archive':
                import io
                b=io.BytesIO()
                with zipfile.ZipFile(b,'w') as nested:nested.writestr('animation.json','{"synthetic":true}');nested.writestr('README.txt','NO EXECUTABLE CODE')
                z.writestr('assets/animation.zip',b.getvalue())
            if item['asset']=='native':z.write(native,'lib/arm64-v8a/libsynthetic.so')
        signed=output/'apks'/f'{sid}.apk.disabled'
        run([java,'-jar',signer,'sign','--ks',key,'--ks-key-alias','fixture','--ks-pass','pass:synthetic-only','--key-pass','pass:synthetic-only','--out',signed,unsigned])
        sig=run([java,'-jar',signer,'verify','--verbose','--print-certs',signed])
        (output/'evidence'/f'{sid}_signature.txt').write_text(sig,encoding='utf-8')
        dump=run([tools/'dexdump.exe','-d',dex/'classes.dex'])
        (output/'evidence'/f'{sid}_dexdump.txt').write_text(dump,encoding='utf-8')
        records.append({'sample_id':sid,'dataset_type':'synthetic','benchmark_case':item['title'],
                        'sha256':sha(signed),'apk':signed.relative_to(output).as_posix(),
                        'package':package,'version_name':'1.0-synthetic','version_code':1,
                        'source':f'source/{sid}','evidence':f'evidence/{sid}_review.json',
                        'labels':item['labels']})
        print('BUILT',sid,item['title'],flush=True)
    (output/'candidate_labels.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Built',len(records),'synthetic APKs. Candidate labels require independent verification/freeze before benchmark.')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--sdk',default=str(Path.home()/'AppData/Local/Android/Sdk'))
    parser.add_argument('--jdk',default='C:/Program Files/Java/jdk-23')
    parser.add_argument('--build-tools',default='35.0.0')
    args=parser.parse_args();build(args.output,args.sdk,args.jdk,args.build_tools)


if __name__=='__main__':main()
