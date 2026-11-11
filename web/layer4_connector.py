r"""Bo ket noi Tang 4: gui APK sang cong layer4_gate tren VM 101 qua SSH.

web/layer4_jobs.py goi file nay qua ANDROWALL_LAYER4_COMMAND:

    ANDROWALL_LAYER4_COMMAND='["python","/app/web/layer4_connector.py"]'
    LAYER4_SSH_TARGET=cherry@<IP Tailscale cua VM 101>

va tu them 2 doi so cuoi: <duong dan APK> <SHA256>. APK di qua stdin cua mot phien
SSH duy nhat; cong tra mot dong JSON; file nay in ra stdout dung report.json cua
bo chay (layer = 4) de layer4_jobs kiem tra tiep.

Ma thoat: 0 = co bao cao (xem "status" ben trong); 2 = cau hinh/doi so sai;
3 = cong khong tao duoc bao cao; 4 = loi SSH hoac phan hoi khong hop le.
Ly do loi in ra stderr. Khong bao gio tat kiem tra khoa may chu (StrictHostKeyChecking).
"""
import json
import os
import re
import subprocess
import sys

KEY = os.environ.get('LAYER4_SSH_KEY', '/run/layer4_ssh/id_ed25519')
KNOWN_HOSTS = os.environ.get('LAYER4_SSH_KNOWN_HOSTS', '/run/layer4_ssh/known_hosts')
GATE = '~/lab/layer4_gate'
MAX_REPLY_BYTES = 25 * 1024 * 1024


def fail(code, message):
    sys.stderr.write('layer4_connector: %s\n' % message)
    sys.exit(code)


def main(argv):
    if len(argv) != 2:
        fail(2, 'can dung 2 doi so: <apk> <sha256>')
    apk, sha256 = argv
    if not re.fullmatch(r'[0-9a-f]{64}', sha256):
        fail(2, 'SHA256 khong hop le')
    target = os.environ.get('LAYER4_SSH_TARGET', '')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.:-]{1,253}', target):
        fail(2, 'LAYER4_SSH_TARGET phai co dang user@host')
    duration = os.environ.get('LAYER4_DURATION', '60')
    if not re.fullmatch(r'[0-9]{1,4}', duration):
        fail(2, 'LAYER4_DURATION phai la so giay')
    for path in (KEY, KNOWN_HOSTS, apk):
        if not os.path.isfile(path):
            fail(2, 'khong thay file: %s' % path)

    cmd = ['ssh', '-i', KEY, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + KNOWN_HOSTS,
           '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15',
           '-o', 'ServerAliveCountMax=4', '-T', target, '%s run %s' % (GATE, duration)]
    with open(apk, 'rb') as src:
        p = subprocess.run(cmd, stdin=src, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out = p.stdout[:MAX_REPLY_BYTES + 1]
    if len(out) > MAX_REPLY_BYTES:
        fail(4, 'phan hoi cua cong qua lon')
    try:
        reply = json.loads(out.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        reply = None
    if not isinstance(reply, dict) or 'gate_version' not in reply:
        err = p.stderr.decode('utf-8', 'replace').strip()[-300:]
        fail(4, 'SSH/cong khong tra JSON hop le (ma thoat ssh %d): %s' % (p.returncode, err))

    report = reply.get('report')
    if not isinstance(report, dict):
        fail(3, 'cong khong co bao cao: %s (%s)' % (reply.get('status'), reply.get('note')))
    if report.get('sha256') != sha256:
        fail(4, 'SHA256 trong bao cao khac APK da gui')
    sys.stdout.write(json.dumps(report, ensure_ascii=True))
    sys.stdout.flush()


if __name__ == '__main__':
    main(sys.argv[1:])
