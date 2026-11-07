CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wno-unused-parameter -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS :=

SRCS := main.c netlink.c detect.c wallet.c \
        offsets.c kaslr.c vmlinux.c gadgets.c spray.c \
        cve_2024_1086.c cve_2023_32233.c rugpull.c \
        obf.c stealth.c
OBJS := $(SRCS:.c=.o)
BIN  := nfttables

HDRS := nfttables.h arch.h offsets.h obf.h stealth.h

.PHONY: all clean static release install

all: _obf_data.h $(BIN)

# generate encrypted string table before compiling
_obf_data.h: tools/gen_obf.py
	python3 tools/gen_obf.py > $@

# obf.c needs the generated header
obf.o: obf.c obf.h _obf_data.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# musl static build for deployment
static: CC := musl-gcc
static: CFLAGS += -static
static: LDFLAGS += -static
static: _obf_data.h $(BIN)

# stripped release binary (RELEASE strips verbose logging)
release: CFLAGS += -DRELEASE
release: static
	strip -s $(BIN)
	@echo "$(BIN): $$(wc -c < $(BIN)) bytes"

# install to /bin (stripped)
install: release
	cp $(BIN) /bin/$(BIN)
	chmod 755 /bin/$(BIN)

clean:
	rm -f $(OBJS) $(BIN) _obf_data.h
