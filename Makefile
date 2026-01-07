CC = gcc
CFLAGS = -Wall -Wextra -Werror -fsanitize=address -fsanitize=leak -g -I$(INCLUDE_DIR)
LDFLAGS = -fsanitize=address -fsanitize=leak -pthread
AR = ar
RANLIB = ranlib

SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

SERVER_APP = repa          
CLIENT_APP = repactl       

ALL_SOURCES = $(wildcard $(SRC_DIR)/*.c)

SERVER_SOURCES = $(filter-out $(SRC_DIR)/repactl.c, $(ALL_SOURCES))

CLIENT_SOURCES = $(SRC_DIR)/repactl.c

SERVER_OBJECTS = $(SERVER_SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean test repa repactl

all: repa repactl

repa: $(SERVER_OBJECTS) | $(BUILD_DIR)
	$(CC) $(SERVER_OBJECTS) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_APP)

repactl: $(CLIENT_OBJECTS) | $(BUILD_DIR)
	$(CC) $(CLIENT_OBJECTS) $(LDFLAGS) -lreadline -o $(BUILD_DIR)/$(CLIENT_APP)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

test: repa
	$(CC) $(CFLAGS) -L$(BUILD_DIR) -I$(INCLUDE_DIR) tests/test.c -o tests/test $(LDFLAGS) -pthread
	./tests/test

clean:
	rm -rf $(BUILD_DIR) tests/test

run-server: repa
	./$(BUILD_DIR)/$(SERVER_APP)

run-client: repactl
	./$(BUILD_DIR)/$(CLIENT_APP)