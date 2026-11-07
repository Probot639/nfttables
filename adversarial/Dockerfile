FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    musl-tools \
    strace \
    auditd \
    sysstat \
    inotify-tools \
    bpfcc-tools \
    linux-tools-common \
    python3 \
    python3-pip \
    jq \
    procps \
    iproute2 \
    netcat-openbsd \
    binutils \
    nftables \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir psutil watchdog

WORKDIR /opt/nfttables

# Copy source and build
COPY *.c *.h Makefile ./
COPY tools/ ./tools/
RUN make clean && make all && cp nfttables nfttables-debug && strip -s nfttables

# Copy blue team scripts
COPY adversarial/blue-team/ /opt/blue-team/
COPY adversarial/red-team/ /opt/red-team/

# Copy the test harness
COPY adversarial/harness.sh /opt/harness.sh
RUN chmod +x /opt/harness.sh /opt/red-team/*.sh /opt/blue-team/*.py 2>/dev/null; true

ENTRYPOINT ["/opt/harness.sh"]
