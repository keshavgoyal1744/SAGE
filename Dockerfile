FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinelgraph ./sentinelgraph
COPY data ./data

ENV SENTINELGRAPH_DB=/data/sentinelgraph.db
EXPOSE 8088

CMD ["python", "-m", "uvicorn", "sentinelgraph.app:app", "--host", "0.0.0.0", "--port", "8088"]
