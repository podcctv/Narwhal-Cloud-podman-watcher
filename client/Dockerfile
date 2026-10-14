FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY operations.py .
COPY security_banner.py .
COPY abuse_detection.py abuse_collection.py abuse_guard.py network_quarantine.py ./
COPY tcp_probe.py .

CMD ["python", "agent.py"]
