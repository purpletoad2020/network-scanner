# ── Network Scanner Docker Image ──
# Build:  docker build -t network-scanner .
# Run:    docker compose up -d
#         http://localhost:5000

FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="Network Scanner & Topology Mapper"
LABEL org.opencontainers.image.description="Dockerized web GUI for local network scanning and interactive topology mapping"
LABEL org.opencontainers.image.source="https://github.com/your-org/network-scanner"

# ── System dependencies ──
# tcpdump, iproute2, and net-tools are needed for scapy / route detection
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    net-tools \
    tcpdump \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── App source ──
COPY scan.py .
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Flask runs on 5000
EXPOSE 5000

# Capabilities needed for raw sockets (ARP / ICMP)
# The container must run with NET_ADMIN and NET_RAW (set in compose)
CMD ["python", "app.py"]