FROM python:3.12-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nftables libnetfilter-queue1 iproute2 util-linux && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY operations.py .
COPY disk_cleanup.py disk_cleanup_worker.py ./
COPY security_banner.py .
COPY abuse_detection.py abuse_collection.py abuse_guard.py network_quarantine.py ./
COPY admission_policy.py admission_linux.py admission_guard.py admission_observe.py ./
COPY pasarguard_guard.py ./
COPY tcp_probe.py .
COPY socks_detector.py .
COPY host_security_audit.py .
COPY vmess_guard.py .
COPY manual_bandwidth.py .
COPY cpu_guard.py .

CMD ["python", "agent.py"]
