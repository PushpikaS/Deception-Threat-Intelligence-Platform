FROM python:3.12-slim
WORKDIR /app
RUN mkdir -p /data/geoip
COPY threat-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/mitre.py ./shared_mitre.py
COPY shared/taxonomy.py ./shared_taxonomy.py
COPY shared/production_check.py ./shared_production_check.py
COPY shared/traps.py ./shared_traps.py
COPY shared/trap_registry.json ./trap_registry.json
COPY threat-engine/ .
CMD ["python", "engine.py"]
