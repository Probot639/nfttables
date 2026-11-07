FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY *.c *.h Makefile ./
COPY tools/ ./tools/
RUN make clean && make all && cp nfttables nfttables-release && strip -s nfttables-release

# ----------------------------------------------------------
# Red team: just the binary on a minimal box
# ----------------------------------------------------------
FROM ubuntu:22.04 AS red

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps strace gdb python3 vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash redteam
COPY --from=builder /build/nfttables /home/redteam/nfttables
COPY --from=builder /build/nfttables-release /home/redteam/nfttables-release
RUN chown redteam:redteam /home/redteam/nfttables /home/redteam/nfttables-release

COPY test/red-entry.sh /entry.sh
RUN chmod +x /entry.sh

USER redteam
WORKDIR /home/redteam
ENTRYPOINT ["/entry.sh"]

# ----------------------------------------------------------
# Blue team: monitoring station
# ----------------------------------------------------------
FROM ubuntu:22.04 AS blue

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    strace auditd inotify-tools bpfcc-tools \
    python3 python3-pip jq procps iproute2 \
    binutils nftables less \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir psutil watchdog

RUN useradd -m -s /bin/bash analyst

COPY adversarial/blue-team/ /home/analyst/blue-team/
COPY test/score.sh /usr/local/bin/score.sh
RUN chmod +x /usr/local/bin/score.sh /home/analyst/blue-team/*.py 2>/dev/null; true
RUN mkdir -p /reports && chown analyst:analyst /reports

COPY test/blue-entry.sh /entry.sh
RUN chmod +x /entry.sh

USER analyst
WORKDIR /home/analyst
ENTRYPOINT ["/entry.sh"]

# ----------------------------------------------------------
# Root observer: everything
# ----------------------------------------------------------
FROM ubuntu:22.04 AS root

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    strace ltrace gdb auditd inotify-tools bpfcc-tools \
    python3 python3-pip jq procps iproute2 \
    binutils nftables vim less \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir psutil watchdog

COPY --from=builder /build/nfttables /root/nfttables
COPY --from=builder /build/nfttables-release /root/nfttables-release
COPY adversarial/blue-team/ /root/blue-team/
COPY test/score.sh /usr/local/bin/score.sh
RUN chmod +x /usr/local/bin/score.sh /root/blue-team/*.py 2>/dev/null; true
RUN mkdir -p /reports

COPY test/root-entry.sh /entry.sh
RUN chmod +x /entry.sh

WORKDIR /root
ENTRYPOINT ["/entry.sh"]
