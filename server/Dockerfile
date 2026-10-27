FROM python:3.12-slim
ARG APP_VERSION=dev
ARG APP_REVISION=unknown
ENV NARWHAL_VERSION=$APP_VERSION
ENV NARWHAL_REVISION=$APP_REVISION
LABEL org.opencontainers.image.version=$APP_VERSION
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY abuse_api.py .
COPY admission_api.py .
COPY ip_reputation.py .
COPY disk_cleanup.py .
COPY connection_policy.py .
COPY inbound_assessment.py .
COPY database_telemetry.py .
COPY gfw_monitor.py .
COPY operations.py operations_api.py buyer_notifications.py buyer_mapping.py buyer_content.py investigation.py dashboard_auth.py commerce.py tcping.py ./
COPY fleet_updates.py ./
COPY maintain_db.py .
COPY static/ static/
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
