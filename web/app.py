# web/app.py
import pandas as pd
import numpy as np
import joblib
import os
import sys
import time
import uuid
import queue
import threading
from datetime import datetime
from werkzeug.utils import secure_filename
import requests
from flask import Flask, request, render_template, jsonify
import queue
import threading
import subprocess
import time
import uuid
# ============ CẤU HÌNH MOBSF (KALI SERVER) ============
KALI_IP = "100.100.105.42"  # <--- THAY BẰNG IP THẬT CỦA KALI (hostname -I)
MOBSF_API_URL = f"http://100.100.105.42:8000/api/v1"
API_KEY = "3daad9019246918ab1834046e66d0ada76a6981c1583785ef9c116b05e0203cd"
# ============ KHỞI TẠO HÀNG ĐỢI (TASK QUEUE) ============
dynamic_task_queue = queue.Queue()
analysis_results = {} # Lưu kết quả trạng thái

# Thêm đường dẫn để import scanner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.detect_and_classify import MalwareDetector

app = Flask(__name__)
app.config['SCAN_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scans')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
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

# ============ WORKER PHÂN TÍCH ĐỘNG (BACKGROUND WORKER) ============
# Cấu hình đường dẫn AVD
AVD_NAME = "Pixel_4a" # Thay bằng tên AVD API 30 bạn vừa tạo (viết liền, thay dấu cách bằng _)
EMULATOR_PATH = r"C:\Users\An\AppData\Local\Android\Sdk\emulator\emulator.exe" 

# Định nghĩa Worker
def mobsf_dynamic_worker():
    while True:
        task = dynamic_task_queue.get()
        task_id = task['task_id']
        filepath = task['filepath']
        headers = {"Authorization": API_KEY}

        try:
            # 1. BẬT MÁY ẢO AVD NGẦM
            print(f"[*] [Task {task_id}] Đang đánh thức AVD...")
            subprocess.Popen([
                EMULATOR_PATH, "-avd", AVD_NAME, 
                "-no-window", "-no-audio", "-no-snapshot-save"
            ])
            time.sleep(15) # Chờ AVD khởi động
            
            # Kết nối ADB
            subprocess.run(["adb", "connect", "127.0.0.1:5554"], capture_output=True)
            subprocess.run(["adb", "root"], capture_output=True)

            # 2. UPLOAD VÀ QUÉT TĨNH MOBSF
            analysis_results[task_id]['message'] = "Đang đẩy file vào máy chủ Kali..."
            with open(filepath, 'rb') as f:
                upload_res = requests.post(f"{MOBSF_API_URL}/upload", headers=headers, files={'file': f}).json()
            
            mobsf_hash = upload_res.get('hash')
            if not mobsf_hash: raise Exception("Upload MobSF thất bại")

            analysis_results[task_id]['message'] = "Đang mổ xẻ mã nguồn (Static Analysis)..."
            requests.post(f"{MOBSF_API_URL}/scan", headers=headers, data={'hash': mobsf_hash})

            # 3. QUÉT ĐỘNG TRÊN AVD
            analysis_results[task_id]['message'] = "Đang chạy mã độc trong Sandbox..."
            requests.post(f"{MOBSF_API_URL}/dynamic/start_analysis", headers=headers, data={'hash': mobsf_hash})
            
            time.sleep(40) # Cho mã độc chạy 40s để lưu log

            analysis_results[task_id]['message'] = "Đang trích xuất báo cáo..."
            requests.post(f"{MOBSF_API_URL}/dynamic/stop_analysis", headers=headers, data={'hash': mobsf_hash})

            # Xong việc!
            analysis_results[task_id].update({
                "status": "completed",
                "message": "Phân tích động hoàn tất!",
                "mobsf_link": f"http://{KALI_IP}:8000/static_analyzer/{mobsf_hash}/"
            })

        except Exception as e:
            analysis_results[task_id].update({"status": "error", "message": f"Lỗi: {str(e)}"})
        finally:
            # 4. TẮT AVD ĐỂ GIẢI PHÓNG RAM
            print("[*] Đang dọn dẹp và tắt AVD...")
            subprocess.run(["adb", "emu", "kill"], capture_output=True)
            dynamic_task_queue.task_done()

# Kích hoạt luồng chạy ngầm ngay khi Server Flask khởi động
threading.Thread(target=mobsf_dynamic_worker, daemon=True).start()

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
    """Lưu file upload"""
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_filename = f"{timestamp}_{filename}"
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
    result = detector.analyze_csv(filepath, filename)
    if 'first_sample' in result and 'confidence' in result['first_sample']:
        result['first_sample']['confidence'] = round(float(result['first_sample']['confidence']), 2)

    return jsonify(result)

@app.route('/scan/apk', methods=['POST'])
def scan_apk():
    """API quét file APK (Kết hợp AI + Hàng đợi MobSF)"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    # 1. Lưu file và quét cực nhanh bằng AI (Machine Learning)
    filename, filepath = save_uploaded_file(file, 'apk')
    ai_result = detector.analyze_apk(filepath, filename)
    if 'confidence' in ai_result: 
        ai_result['confidence'] = round(float(ai_result['confidence']), 2)

    # 2. Xếp hàng cho Phân tích Động (Dynamic Analysis Queue)
    task_id = str(uuid.uuid4())
    dynamic_task_queue.put({
        'task_id': task_id,
        'filepath': filepath,
        'filename': filename
    })

    # Khởi tạo trạng thái cho Frontend theo dõi
    analysis_results[task_id] = {
        "status": "queued",
        "message": f"Đang xếp hàng... (Vị trí: {dynamic_task_queue.qsize()})"
    }

    # Trả về kết quả AI lập tức + Mã Task ID để Frontend hỏi thăm (Polling)
    return jsonify({
        'success': True,
        'ai_result': ai_result,
        'task_id': task_id,
        'message': 'Đã nhận file, AI đã quét xong, đang chuyển sang MobSF...'
    })

@app.route('/api/status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    """API để Frontend hỏi thăm tiến độ của Genymotion"""
    result = analysis_results.get(task_id)
    if not result:
        return jsonify({"error": "Không tìm thấy tác vụ"}), 404
    return jsonify(result)

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

@app.route('/file-manager/scan/<subfolder>/<filename>')
def scan_file_in_manager(subfolder, filename):
    """Quét file trong file manager"""
    filepath = os.path.join(app.config['SCAN_FOLDER'], subfolder, filename)
    
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    if subfolder == 'csv':
        result = detector.analyze_csv(filepath, filename)
    elif subfolder == 'apk':
        result = detector.analyze_apk(filepath, filename)
    else:
        return jsonify({'success': False, 'error': 'Unsupported file type'}), 400
    if 'confidence' in result: result['confidence'] = float(result['confidence'])
    return jsonify(result)

@app.route('/file-manager/delete/<subfolder>/<filename>', methods=['DELETE'])
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
