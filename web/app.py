# web/app.py
import pandas as pd
import numpy as np
import joblib
import os
import sys
import uuid
import queue
import threading
from datetime import datetime
import requests
from flask import Flask, request, render_template, jsonify
from dotenv import load_dotenv
 
# ============ NẠP BIẾN MÔI TRƯỜNG TỪ FILE .env ============
# Chạy từ gốc dự án (vd: .\venv\Scripts\python.exe web\app.py) nên .env ở gốc dự án sẽ được tự tìm thấy.
load_dotenv()
 
# ============ CẤU HÌNH MOBSF (KALI SERVER) ============
KALI_IP              = os.environ.get("MOBSF_KALI_IP", "127.0.0.1")
MOBSF_API_URL        = f"http://{KALI_IP}:8000/api/v1"
API_KEY              = os.environ.get("MOBSF_API_KEY", "")
 
# IP Windows nhìn từ Kali qua Tailscale + cổng ADB của Genymotion
WINDOWS_IP_FROM_KALI = os.environ.get("WINDOWS_IP_FROM_KALI", "")
WINDOWS_ADB_PORT     = int(os.environ.get("WINDOWS_ADB_PORT", "5556"))
 
if not API_KEY:
    print("⚠️  CẢNH BÁO: Chưa thiết lập MOBSF_API_KEY trong file .env — các chức năng gọi MobSF sẽ lỗi 401/403.")
if not WINDOWS_IP_FROM_KALI:
    print("⚠️  CẢNH BÁO: Chưa thiết lập WINDOWS_IP_FROM_KALI trong file .env — Dynamic Analyzer sẽ không kết nối được ADB.")
 
# ============ KHỞI TẠO HÀNG ĐỢI (TASK QUEUE) ============
dynamic_task_queue = queue.Queue()
analysis_results = {} # Lưu kết quả trạng thái
 
# Thêm đường dẫn để import scanner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.detect_and_classify import MalwareDetector
 
import numpy as np
 
def numpy_safe(obj):
    """Đệ quy convert numpy types sang Python native để jsonify không lỗi"""
    if isinstance(obj, dict):
        return {k: numpy_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [numpy_safe(i) for i in obj]
    if isinstance(obj, np.integer): return int(obj)
    if isinstance(obj, np.floating): return round(float(obj), 4)
    if isinstance(obj, np.ndarray): return obj.tolist()
    return obj
 
app = Flask(__name__)
 
# ============ SESSION LOG & CRASH LOG ============
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_LOG = os.path.join(_APP_DIR, 'latest_scan.log')
CRASH_LOG   = os.path.join(_APP_DIR, 'error_crash.log')
 
def _log(message, level='INFO', new_scan=False):
    """Ghi dòng log vào latest_scan.log. new_scan=True xóa log cũ (mode w)."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    line = f"[{timestamp}] [{level}] {message}\n"
    mode = 'w' if new_scan else 'a'
    try:
        with open(SESSION_LOG, mode, encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass
 
def _crash(message, exc=None):
    """Ghi lỗi vào error_crash.log (chế độ append để cộng dồn)."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(CRASH_LOG, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n[{timestamp}] ERROR: {message}\n")
            if exc:
                import traceback as tb
                f.write(tb.format_exc())
    except Exception:
        pass
 
# Override jsonify để tự động xử lý numpy types (tương thích Flask 2 + 3)
from flask import json as flask_json
_orig_jsonify = jsonify
def jsonify(*args, **kwargs):
    if args and len(args) == 1 and isinstance(args[0], dict):
        args = (numpy_safe(args[0]),)
    elif kwargs:
        kwargs = numpy_safe(kwargs)
    return _orig_jsonify(*args, **kwargs)
app.config['SCAN_FOLDER'] = r'C:\scans'
app.config['UPLOAD_FOLDER'] = r'C:\scans\uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
 
# Tạo thư mục
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'csv'), exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'apk'), exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'other'), exist_ok=True)
 
print("="*60)
print("🦾 ANDROID MALWARE DETECTION SYSTEM")
print("="*60)
 
# Khởi tạo detector
try:
    detector = MalwareDetector()
    print("✅ Detector loaded successfully!")
    print(f"✅ Can classify: {detector.class_names}")
except Exception as e:
    print(f"❌ Error loading detector: {e}")
    sys.exit(1)
 
print("="*60)
 
# ============ WORKER PHÂN TÍCH TĨNH MOBSF (BACKGROUND WORKER) ============
def mobsf_static_worker():
    """Upload APK lên MobSF, kích hoạt Static Analysis, trả về link xem báo cáo."""
    while True:
        task = dynamic_task_queue.get()
        task_id  = task['task_id']
        filepath = task['filepath']
        headers  = {"Authorization": API_KEY}
 
        try:
            # ── BƯỚC 1: Upload APK ──────────────────────────────────────────
            analysis_results[task_id]['message'] = "Đang upload APK lên MobSF (Kali)..."
            apk_filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                upload_res = requests.post(
                    f"{MOBSF_API_URL}/upload",
                    headers=headers,
                    files={'file': (apk_filename, f, 'application/octet-stream')},
                    timeout=120
                )
            if upload_res.status_code != 200:
                raise Exception(f"Upload lỗi {upload_res.status_code}: {upload_res.text[:200]}")
 
            mobsf_hash = upload_res.json().get('hash')
            if not mobsf_hash:
                raise Exception(f"Không nhận được hash từ MobSF: {upload_res.text[:200]}")
            print(f"[MobSF] Upload OK — hash: {mobsf_hash}")
 
            # ── BƯỚC 2: Kích hoạt Static Analysis (apktool, dex2jar, ...) ───
            analysis_results[task_id]['message'] = "MobSF đang phân tích tĩnh (apktool / dex2jar)..."
            scan_res = requests.post(
                f"{MOBSF_API_URL}/scan",
                headers=headers,
                data={'hash': mobsf_hash},
                timeout=180
            )
            print(f"[MobSF] Scan status: {scan_res.status_code}")
 
            # ── HOÀN THÀNH: trả về link xem báo cáo ────────────────────────
            analysis_results[task_id].update({
                "status": "completed",
                "message": "✅ Phân tích tĩnh hoàn tất! Nhấn nút để xem báo cáo đầy đủ.",
                "mobsf_hash": mobsf_hash,
                "mobsf_link": f"http://{KALI_IP}:8000/static_analyzer/{mobsf_hash}/"
            })
            print(f"[MobSF] Task {task_id} hoàn thành.")
 
        except requests.exceptions.ConnectionError:
            analysis_results[task_id].update({
                "status": "offline",
                "message": "⚠️ Không kết nối được tới máy chủ Kali. MobSF có thể đang tắt."
            })
        except Exception as e:
            _crash(f"mobsf_static_worker task={task_id}", exc=e)
            analysis_results[task_id].update({
                "status": "error",
                "message": f"❌ {str(e)}"
            })
        finally:
            dynamic_task_queue.task_done()
 
# Kích hoạt luồng ngầm ngay khi Flask khởi động
threading.Thread(target=mobsf_static_worker, daemon=True).start()
 
# =====================================================================
 
# ============ FILE MANAGEMENT & MOBSF HELPERS ============
def get_files_in_directory(directory):
    """Lấy danh sách file trong thư mục"""
    files = []
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    'name': filename,
                    'size_mb': round(stat.st_size / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'ext': filename.split('.')[-1].lower() if '.' in filename else 'unknown'
                })
    return sorted(files, key=lambda x: x['modified'], reverse=True)
 
def upload_to_mobsf(filepath):
    """Hàm dự phòng gọi upload trực tiếp (Nếu cần)"""
    url = f"{MOBSF_API_URL}/upload"
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f, 'application/octet-stream')}
            response = requests.post(url, headers={"Authorization": API_KEY}, files=files, timeout=30)
            if response.status_code == 200:
                return response.json().get("hash")
    except Exception as e:
        print(f"[-] Lỗi MobSF: {e}")
    return None
 
    return sorted(files, key=lambda x: x['modified'], reverse=True)
 
def save_uploaded_file(file, subfolder):
    """Lưu file với tên hoàn toàn sạch (chỉ timestamp + số) để tránh Errno 22"""
    ext = os.path.splitext(file.filename)[1].lower()  # .apk / .csv
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_filename = f"scan_{timestamp}{ext}"           # VD: scan_20260507_175000.apk
    filepath = os.path.join(app.config['SCAN_FOLDER'], subfolder, new_filename)
    file.save(filepath)
    return new_filename, filepath
 
# ============ ROUTES ============
@app.route('/')
def index():
    return render_template('index.html')
 
@app.route('/scan')
def scan_page():
    return render_template('scan.html')
 
@app.route('/scan/csv', methods=['POST'])
def scan_csv():
    """API quét file CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
 
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
 
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'error': 'Only CSV files are supported'}), 400
 
    filename, filepath = save_uploaded_file(file, 'csv')
    try:
        result = detector.analyze_csv(filepath, filename)
        if 'first_sample' in result and 'confidence' in result['first_sample']:
            result['first_sample']['confidence'] = round(float(result['first_sample']['confidence']), 2)
        return jsonify(result)
    except Exception as e:
        import traceback
        print(f"[✗] analyze_csv lỗi: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
 
@app.route('/scan/apk', methods=['POST'])
def scan_apk():
    """API quét file APK (Kết hợp AI + Hàng đợi MobSF)"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
 
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
 
    # Xóa log cũ, bắt đầu phiên mới
    _log(f"=== BẮT ĐẦU PHÂN TÍCH: {file.filename} ===", new_scan=True)
 
    try:
        # 1. Đọc bytes trực tiếp từ upload stream trước khi đụng đến disk
        # (tránh [Errno 22] Invalid argument khi Python 3.14/Windows đọc file vừa ghi)
        file_bytes = file.read()
        _log(f"Đã đọc {len(file_bytes):,} bytes từ upload stream.")
 
        # 2. Lưu bytes xuống disk (để MobSF upload sau)
        filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.apk"
        filepath = os.path.join(app.config['SCAN_FOLDER'], 'apk', filename)
        with open(filepath, 'wb') as _dst:
            _dst.write(file_bytes)
        _log(f"Đã lưu: {filename}")
 
        # 3. AI phân tích tĩnh — truyền bytes trực tiếp, không đọc lại từ disk
        _log("Đang khởi động Androguard — giải nén APK, đọc DEX bytecode...")
        ai_result = detector.analyze_apk(file_bytes, filename)
 
        if not ai_result.get('success'):
            raise Exception(ai_result.get('error', 'Lỗi phân tích APK'))
 
        _log(f"Trích xuất xong {ai_result.get('total_permissions', 0)} quyền từ AndroidManifest.xml.")
        _log(f"Số đặc trưng khớp với model: {ai_result.get('feature_count', 0)}/{len(detector.scaler.mean_)}.")
        _log(f"SHA256: {ai_result.get('sha256', 'N/A')}")
 
        vec = ai_result.get('binary_vector_sample', [])
        _log(f"Vector nhị phân (20 cột đầu): [{', '.join(str(v) for v in vec)}]")
 
        _log(f"Đang bơm vector vào model XGBoost (.predict_proba)...")
        _log(f"KẾT QUẢ: {ai_result.get('name')} — Độ tin cậy: {ai_result.get('confidence')}%", level='SUCCESS')
 
        risk_combos = ai_result.get('risk_combos', [])
        if risk_combos:
            for combo in risk_combos:
                _log(f"[CẢNH BÁO TỔ HỢP QUYỀN] {combo}", level='WARN')
        else:
            _log("Không phát hiện tổ hợp quyền nguy hiểm.", level='INFO')
 
        if 'confidence' in ai_result:
            ai_result['confidence'] = round(float(ai_result['confidence']), 2)
 
        # 4. Xếp hàng MobSF
        task_id = str(uuid.uuid4())
        dynamic_task_queue.put({'task_id': task_id, 'filepath': filepath, 'filename': filename})
        analysis_results[task_id] = {
            "status": "queued",
            "message": f"Đang xếp hàng... (Vị trí: {dynamic_task_queue.qsize()})"
        }
        _log("Đã xếp hàng MobSF Dynamic Analysis.")
        _log("=== HOÀN TẤT PHÂN TÍCH TĨNH ===", level='SUCCESS')
 
        return jsonify({
            'success': True,
            'ai_result': ai_result,
            'task_id': task_id,
            'message': 'AI đã quét xong, đang chuyển sang MobSF...'
        })
 
    except Exception as e:
        _log(f"LỖI NGHIÊM TRỌNG: {str(e)}", level='ERROR')
        _crash(f"scan_apk thất bại cho file: {file.filename}", exc=e)
        return jsonify({'success': False, 'error': str(e)}), 500
 
@app.route('/api/scan-log', methods=['GET'])
def get_scan_log():
    """Trả về nội dung log phiên quét hiện tại cho terminal UI."""
    try:
        with open(SESSION_LOG, 'r', encoding='utf-8') as f:
            lines = [l.rstrip('\n') for l in f.readlines()]
        return jsonify({'lines': lines[-100:]})
    except FileNotFoundError:
        return jsonify({'lines': []})
 
@app.route('/api/status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    """API để Frontend hỏi thăm tiến độ của Genymotion"""
    result = analysis_results.get(task_id)
    if not result:
        return jsonify({"error": "Không tìm thấy tác vụ"}), 404
    return jsonify(result)
 
@app.route('/api/mobsf_report/<mobsf_hash>', methods=['GET'])
def get_mobsf_report(mobsf_hash):
    """Proxy lấy báo cáo JSON từ MobSF trên Kali (tránh CORS)"""
    try:
        headers = {"Authorization": API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        # Lấy báo cáo static
        static_res = requests.post(
            f"{MOBSF_API_URL}/report_json",
            headers=headers,
            data={"hash": mobsf_hash},
            timeout=15
        )
        if static_res.status_code != 200:
            return jsonify({"error": f"MobSF trả lỗi {static_res.status_code}"}), 502
 
        report = static_res.json()
 
        # Trích xuất các trường quan trọng để hiển thị
        permissions = report.get("permissions", {})
        dangerous_perms = [p for p, v in permissions.items()
                           if isinstance(v, dict) and v.get("status", "").lower().strip() == "dangerous"]
 
        activities = report.get("activities", [])
        services = report.get("services", [])
        receivers = report.get("receivers", [])
 
        security_score = report.get("appsec", {})
        urls = report.get("urls", [])
        emails = report.get("emails", [])
        strings = report.get("strings", [])[:20]
 
        # Certificate info
        cert = report.get("certificate_analysis", {})
 
        return jsonify({
            "success": True,
            "app_name": report.get("app_name", "N/A"),
            "package_name": report.get("package_name", "N/A"),
            "version_name": report.get("version_name", "N/A"),
            "min_sdk": report.get("min_sdk", "N/A"),
            "target_sdk": report.get("target_sdk", "N/A"),
            "file_size": report.get("size", "N/A"),
            "md5": report.get("md5", "N/A"),
            "sha256": report.get("sha256", "N/A"),
            "dangerous_permissions": dangerous_perms,
            "all_permissions": list(permissions.keys()),
            "activities_count": len(activities),
            "services_count": len(services),
            "receivers_count": len(receivers),
            "urls": [u.get("url", "") for u in urls[:15]] if isinstance(urls, list) else [],
            "emails": emails[:10],
            "strings_sample": strings,
            "security_score": security_score,
            "certificate": cert,
            "mobsf_link": f"http://{KALI_IP}:8000/static_analyzer/{mobsf_hash}/"
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Không kết nối được tới máy chủ Kali. Kiểm tra lại IP/mạng."}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route('/file-manager')
def file_manager():
    """File Manager"""
    csv_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'csv'))
    apk_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'apk'))
    other_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'other'))
 
    return render_template('file_manager.html',
                         csv_files=csv_files,
                         apk_files=apk_files,
                         other_files=other_files)
 
@app.route('/file-manager/scan/<subfolder>/<path:filename>')
def scan_file_in_manager(subfolder, filename):
    """Quét file trong file manager"""
    filepath = os.path.join(app.config['SCAN_FOLDER'], subfolder, filename)
 
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
 
    try:
        if subfolder == 'csv':
            result = detector.analyze_csv(filepath, filename)
        elif subfolder == 'apk':
            import tempfile, shutil
            with tempfile.NamedTemporaryFile(suffix='.apk', delete=False, dir='C:\\scans') as tmp:
                tmp_path = tmp.name
            shutil.copy2(filepath, tmp_path)
            try:
                result = detector.analyze_apk(tmp_path, filename)
            finally:
                try: os.remove(tmp_path)
                except: pass
        else:
            return jsonify({'success': False, 'error': 'Unsupported file type'}), 400
        if 'confidence' in result: result['confidence'] = float(result['confidence'])
        return jsonify(result)
    except Exception as e:
        import traceback
        print(f"[✗] scan_file_in_manager lỗi: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
 
@app.route('/file-manager/upload', methods=['POST'])
def file_manager_upload():
    """Upload file vào file manager (CSV hoặc APK)"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Không có file được gửi lên'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Chưa chọn file'}), 400
 
    ext = os.path.splitext(file.filename)[1].lower()
    if ext == '.csv':
        subfolder = 'csv'
    elif ext == '.apk':
        subfolder = 'apk'
    else:
        return jsonify({'success': False, 'error': f'Định dạng {ext} không được hỗ trợ'}), 400
 
    try:
        filename, filepath = save_uploaded_file(file, subfolder)
        return jsonify({
            'success': True,
            'message': f'Upload thành công: {filename}',
            'filename': filename,
            'subfolder': subfolder
        })
    except Exception as e:
        import traceback
        print(f"[✗] file_manager_upload lỗi: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
 
 
@app.route('/file-manager/delete/<subfolder>/<path:filename>', methods=['DELETE'])
def delete_file(subfolder, filename):
    """Xóa file"""
    filepath = os.path.join(app.config['SCAN_FOLDER'], subfolder, filename)
 
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({'success': True, 'message': f'Đã xóa {filename}'})
    return jsonify({'success': False, 'error': 'File not found'}), 404
 
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
 
@app.route('/history/data')
def history_data():
    """Tương thích mã cũ gọi AJAX; dữ liệu thật nằm ở localStorage phía trình duyệt."""
    return jsonify([])
 
@app.route('/history')
def history_page():
    return render_template('history.html')
 
@app.route('/about')
def about():
    return render_template('about.html')
 
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok'})
 
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 ANDROID MALWARE DETECTION SYSTEM")
    print("="*60)
    print("📱 Web: http://localhost:5000")
    print("🔍 Scan CSV/APK: http://localhost:5000/scan")
    print("📁 File Manager: http://localhost:5000/file-manager")
    print("="*60)
    app.run(debug=True, host='0.0.0.0', port=5000)
 