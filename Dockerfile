FROM python:3.13-alpine

RUN apk upgrade --no-cache

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip uninstall -y setuptools pip wheel 2>/dev/null; true

COPY app.py .

EXPOSE 9099

CMD ["gunicorn", "--bind", "0.0.0.0:9099", "--workers", "2", "--timeout", "120", "app:app"]
