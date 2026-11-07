CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wno-unused-parameter -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS :=

SRCS := main.c netlink.c detect.c wallet.c \
        offsets.c kaslr.c vmlinux.c gadgets.c spray.c \
        cve_2024_1086.c cve_2023_32233.c rugpull.c
OBJS := $(SRCS:.c=.o)
BIN  := nfttables

HDRS := nfttables.h arch.h offsets.h

.PHONY: all clean static release

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# musl static build for deployment
static: CC := musl-gcc
static: CFLAGS += -static
static: LDFLAGS += -static
static: $(BIN)

# stripped + packed release binary
release: static
	strip -s $(BIN)
	@echo "$(BIN): $$(wc -c < $(BIN)) bytes"

clean:
	rm -f $(OBJS) $(BIN)
