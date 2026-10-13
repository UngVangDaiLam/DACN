# Dùng Python nhẹ
FROM python:3.10-slim

# Set working dir
WORKDIR /app

# Copy requirements trước (tối ưu build)
COPY requirements.txt .

# Cài thư viện
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ project
COPY . .

# Thư mục lưu file quét (mount volume vào đây nếu muốn giữ dữ liệu)
ENV SCAN_FOLDER=/app/scans

# Mở port
EXPOSE 5000

# Chạy Flask bằng gunicorn (production).
# 1 worker + nhiều thread: trạng thái tác vụ MobSF nằm trong bộ nhớ của process nên không chia sẻ được giữa nhiều worker.
CMD ["gunicorn", "-w", "1", "--threads", "4", "--timeout", "300", "-b", "0.0.0.0:5000", "web.app:app"]