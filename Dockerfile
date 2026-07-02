FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY broker/ broker/
COPY cli/ cli/
# Bake the default (deny-heavy) policy file so the image is safe to run
# without mounts; compose volume mounts override it.
COPY policies/ policies/
RUN useradd --create-home --uid 1000 agentgate \
    && mkdir -p data logs state \
    && chown -R agentgate:agentgate /app
USER agentgate
EXPOSE 8848
CMD ["python", "-m", "broker.main"]
