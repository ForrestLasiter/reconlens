# ---- Stage 1: build the ProjectDiscovery recon tools ----
# The ProjectDiscovery tools track recent Go releases; golang:1-bookworm is
# always the latest 1.x (>=1.27 at time of writing), which they all build on.
FROM golang:1-bookworm AS tools

# libpcap is needed to build naabu (we run it in connect-scan mode at runtime,
# which does not require raw sockets / root).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out
RUN mkdir -p /out

# Pinned-ish via @latest for a first build; see README to pin versions.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ---- Stage 2: runtime ----
FROM python:3.12-slim-bookworm

# libpcap runtime for naabu; ca-certificates for TLS lookups.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Persistent homes for nuclei templates + PD configs (mounted as a volume).
ENV HOME=/root
EXPOSE 8077

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8077"]
