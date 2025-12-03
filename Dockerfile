FROM debian:stable

# Install all required tools
RUN set -e && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        mkcert \
        openssh-client \
        build-essential \
        libssl-dev \
        libcurl4-openssl-dev \
        libexpat1-dev \
        gettext \
        zlib1g-dev \
        git
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin

# The binary will be mounted at runtime
# Just create a placeholder to ensure the directory exists
RUN mkdir -p /usr/local/bin

# Default command (will be overridden at runtime)
CMD ["/usr/local/bin/bitswan", "automation-server-daemon", "__run"]

