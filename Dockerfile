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

# Mở port
EXPOSE 5000

# Chạy Flask bằng gunicorn (production)
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "web.app:app"]