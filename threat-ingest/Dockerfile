FROM python:3.12-slim
WORKDIR /app
COPY threat-ingest/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/production_check.py ./shared_production_check.py
COPY threat-ingest/ingest.py ./ingest.py
COPY threat-ingest/main.py .
CMD ["python", "main.py"]