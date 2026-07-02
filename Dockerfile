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
# In-image defaults match the mounted-volume layout (compose overrides via
# environment; without these, defaults would anchor to ~/.agentgate).
ENV POLICIES_PATH=/app/policies/policies.yaml \
    STATE_PATH=/app/state/mode.json \
    LOGS_PATH=/app/logs/audit.log \
    CREDENTIALS_PATH=/app/data/credentials.json \
    CONNECTIONS_PATH=/app/data/connections.json \
    AGENTS_PATH=/app/data/agents.json
EXPOSE 8848
CMD ["python", "-m", "broker.main"]
