# Open Bastion SSH Backend (Unconfigured) - For Enrollment Demo
#
# This container is NOT pre-configured with a server token.
# It must be enrolled manually using the Device Authorization flow.

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nscd \
    sudo \
    libcurl4-gnutls-dev \
    libjson-c-dev \
    libssl-dev \
    libpam0g-dev \
    curl \
    jq \
    openssl \
    cmake \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/run/sshd \
    /var/cache/open-bastion \
    && chmod 750 /var/cache/open-bastion

# Build PAM and NSS modules from source
COPY CMakeLists.txt /src/open-bastion/
COPY src/ /src/open-bastion/src/
COPY include/ /src/open-bastion/include/
COPY nss/ /src/open-bastion/nss/
COPY scripts/ /src/open-bastion/scripts/
WORKDIR /src/open-bastion
RUN mkdir -p build && cd build && \
    cmake -DBUILD_TESTING=OFF .. && \
    make -j$(nproc) && \
    cp pam_openbastion.so /usr/lib/x86_64-linux-gnu/security/ && \
    cp nss/libnss_openbastion.so.2 /lib/x86_64-linux-gnu/ && \
    cp ../scripts/ob-enroll /usr/sbin/ && \
    chmod 755 /usr/sbin/ob-enroll && \
    ldconfig && \
    cd / && rm -rf /src/open-bastion/build

# NO configuration is done here - this simulates a fresh installation
# PAM, NSS, and SSHD must be configured manually following the README

# Fix PAM loginuid for Docker (standard Debian issue)
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Startup script (minimal - no token configuration)
COPY docker-demo-cert/backend-new/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
