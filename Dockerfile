# Dùng Python nhẹ
FROM python:3.13-slim

# Thư mục làm việc
WORKDIR /app

# Copy requirements trước để tận dụng build cache
COPY requirements.txt .

# Cài thư viện Python
RUN pip install --no-cache-dir -r requirements.txt

# Cài ssh và scp để kết nối runner trên VM 101
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy toàn bộ project
COPY . .

# Thư mục lưu file quét
ENV SCAN_FOLDER=/app/scans

# Mở port
EXPOSE 5000

# Chạy Flask bằng Gunicorn trong production.
# Dùng 1 worker vì trạng thái tác vụ nằm trong bộ nhớ của process.
CMD ["gunicorn", "-w", "1", "--threads", "4", "--timeout", "300", "-b", "0.0.0.0:5000", "web.app:app"]