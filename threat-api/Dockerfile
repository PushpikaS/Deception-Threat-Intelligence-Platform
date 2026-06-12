FROM python:3.12-slim
WORKDIR /app
COPY threat-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/mitre.py ./shared_mitre.py
COPY shared/taxonomy.py ./shared_taxonomy.py
COPY shared/mitre_util.py ./shared_mitre_util.py
COPY shared/production_check.py ./shared_production_check.py
COPY threat-api/ .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]