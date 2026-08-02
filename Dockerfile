FROM debian:bookworm-slim AS fetch

ARG NAABU_VERSION=2.6.1
ARG NUCLEI_VERSION=3.11.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dl
RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    mkdir -p /out; \
    wget -q "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${arch}.zip" -O naabu.zip; \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip" -O nuclei.zip; \
    unzip -q -o naabu.zip -d naabu_d; \
    unzip -q -o nuclei.zip -d nuclei_d; \
    install -m 0755 naabu_d/naabu /out/naabu; \
    install -m 0755 nuclei_d/nuclei /out/nuclei


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libpcap0.8 \
        ca-certificates \
        jq \
        bash \
        coreutils \
        python3 \
        python3-flask \
    && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /out/naabu /usr/local/bin/naabu
COPY --from=fetch /out/nuclei /usr/local/bin/nuclei

ENV HOME=/root

# Bake the template set into the image so a fresh appliance can scan without
# first pulling ~10k templates over the client's network.
RUN nuclei -update-templates -silent || nuclei -update-templates || true

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

COPY webui /opt/webui

VOLUME ["/output", "/targets"]

EXPOSE 8080

# Default entrypoint stays the CLI scanner; the web service overrides it.
ENTRYPOINT ["/usr/local/bin/scan.sh"]
