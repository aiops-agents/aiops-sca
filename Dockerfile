FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Versions pinned for repeatable builds
ARG TFLINT_VERSION=0.53.0
ARG TFSEC_VERSION=1.28.1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates jq unzip wget bash \
    && rm -rf /var/lib/apt/lists/*

# Install TFLint
RUN wget -q https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_amd64.zip \
    && unzip tflint_linux_amd64.zip -d /usr/local/bin \
    && rm tflint_linux_amd64.zip \
    && tflint --version

# Install tfsec
RUN wget -q https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64 \
    -O /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec \
    && tfsec --version

WORKDIR /app

# Python deps (checkov + SDKs)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && checkov --version

COPY entrypoint.py /app/entrypoint.py

ENTRYPOINT ["python", "/app/entrypoint.py"]
