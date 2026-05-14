CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -g

SRC_DIR  = src
INC_DIR  = include
BUILD_DIR = build

HAS_PCAP := $(shell test -f /usr/include/pcap.h && echo yes)

ifeq ($(HAS_PCAP),yes)
LDFLAGS ?= -lpcap
SRCS = $(filter-out $(SRC_DIR)/capture_stub.c,$(wildcard $(SRC_DIR)/*.c))
else
$(warning libpcap not found — building without live capture support)
LDFLAGS ?=
SRCS = $(filter-out $(SRC_DIR)/capture.c,$(wildcard $(SRC_DIR)/*.c))
endif

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
TARGET = tiny-dpi-engine

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

test: $(TARGET)
	@echo "Running unit tests..."
	@$(CC) -std=c11 -Wall -Wextra -I$(INC_DIR) -o $(BUILD_DIR)/test_main \
		tests/test_main.c src/proto.c src/packet.c src/flow.c src/aho_corasick.c src/signatures.c src/stats.c src/classify.c $(LDFLAGS)
	@./$(BUILD_DIR)/test_main

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
