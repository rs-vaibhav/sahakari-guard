FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SG_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sahakari_guard ./sahakari_guard

RUN useradd --create-home --uid 10001 guard && mkdir -p /data && chown guard /data
USER guard
VOLUME ["/data"]
EXPOSE 8000

# Inside a container the server must listen on all interfaces; protect it with SG_API_KEY
# when the port is reachable from the bank network.
CMD ["python", "-m", "sahakari_guard", "serve", "--host", "0.0.0.0", "--port", "8000"]
