CC ?= gcc
CFLAGS ?= -g -O0 -Wall -Wextra
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer
BUILD_DIR = build

.PHONY: all clean test-packet test-auth test-frame asan-packet asan-auth asan-frame

all: $(BUILD_DIR)/packet_parser_harness $(BUILD_DIR)/auth_session_harness $(BUILD_DIR)/frame_alloc_harness

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/packet_parser_harness: src/packet_parser.c include/packet_parser.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DPACKET_PARSER_STANDALONE src/packet_parser.c -o $@

$(BUILD_DIR)/auth_session_harness: src/auth_session.c include/auth_session.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DAUTH_SESSION_STANDALONE src/auth_session.c -o $@

$(BUILD_DIR)/frame_alloc_harness: src/frame_alloc.c include/frame_alloc.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DFRAME_ALLOC_STANDALONE src/frame_alloc.c -o $@

asan-packet: | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -DPACKET_PARSER_STANDALONE src/packet_parser.c -o $(BUILD_DIR)/packet_parser_asan
	./$(BUILD_DIR)/packet_parser_asan

asan-auth: | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -DAUTH_SESSION_STANDALONE src/auth_session.c -o $(BUILD_DIR)/auth_session_asan
	./$(BUILD_DIR)/auth_session_asan

asan-frame: | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -DFRAME_ALLOC_STANDALONE src/frame_alloc.c -o $(BUILD_DIR)/frame_alloc_asan
	./$(BUILD_DIR)/frame_alloc_asan

test-packet:
	python3 tests/test_regression_packet.py

test-auth:
	python3 tests/test_regression_auth.py

test-frame:
	python3 tests/test_regression_frame.py

clean:
	rm -rf $(BUILD_DIR)
