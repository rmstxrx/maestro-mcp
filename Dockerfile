FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /root/.ssh/sockets && chmod +x /app/entrypoint.sh

EXPOSE 8222

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "server.py", "--transport", "streamable-http", "--port", "8222", "--host", "0.0.0.0"]
