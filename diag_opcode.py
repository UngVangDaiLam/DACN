import glob, sys, traceback
from loguru import logger
logger.remove(); logger.add(sys.stderr, level="ERROR")
from androguard.misc import AnalyzeAPK

p = sorted(glob.glob("dataset/raw_apk/benign/*.apk"))[0]
print("APK:", p)
a, d, dx = AnalyzeAPK(p)
print("type(d):", type(d), "| len:", len(d) if hasattr(d, "__len__") else "n/a")
dexes = d if isinstance(d, list) else [d]
dex = dexes[0]
print("type(dex):", type(dex))
print("co get_methods:", hasattr(dex, "get_methods"))
try:
    methods = list(dex.get_methods())
    print("so method:", len(methods))
    found = False
    for m in methods:
        code = m.get_code()
        if not code:
            continue
        ins = list(code.get_bc().get_instructions())
        if ins:
            print("OK duong dex.get_methods | so lenh:", len(ins), "| lenh dau:", ins[0].get_name())
            found = True
            break
    if not found:
        print("khong method nao co lenh")
except Exception:
    print("LOI o duong dex.get_methods():")
    traceback.print_exc()

print("--- duong thay the qua dx (Analysis) ---")
try:
    for m in dx.get_methods():
        if m.is_external():
            continue
        ins = list(m.get_method().get_instructions())
        if ins:
            print("OK duong dx.get_methods | so lenh:", len(ins), "| lenh dau:", ins[0].get_name())
            break
except Exception:
    print("LOI o duong dx.get_methods():")
    traceback.print_exc()