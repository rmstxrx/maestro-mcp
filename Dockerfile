FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client patch tmux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY patches/streamable_http_409.patch /tmp/streamable_http_409.patch
# Work around stale Streamable HTTP SSE sessions after Claude.ai/cloudflared reconnects.
# Related upstream context: https://github.com/modelcontextprotocol/python-sdk/issues?q=is%3Aissue%20streamable%20http%20sse
RUN target=/usr/local/lib/python3.12/site-packages/mcp/server/streamable_http.py && \
    if grep -Fq 'Replacing stale SSE stream for session %s' "$target"; then \
        echo "streamable_http SSE reconnect patch already applied"; \
    else \
        patch --batch --forward "$target" < /tmp/streamable_http_409.patch; \
    fi && \
    rm -f /tmp/streamable_http_409.patch

COPY . .

RUN mkdir -p /root/.ssh/sockets && chmod +x /app/entrypoint.sh

EXPOSE 8222

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "server.py", "--transport", "streamable-http", "--port", "8222", "--host", "0.0.0.0"]
