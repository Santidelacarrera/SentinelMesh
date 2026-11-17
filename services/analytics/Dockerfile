FROM python:3.13-slim
WORKDIR /srv
# OS packages with known fixes (zlib) are upgraded; pip is removed afterwards: the runtime never installs anything
# and pip's vendored libraries only add scanner findings.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip
COPY app app
USER nobody
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
