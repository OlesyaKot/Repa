CC = gcc
CFLAGS = -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -g -pthread -I$(INCLUDE_DIR) -MMD -MP
LDFLAGS = -fsanitize=address,undefined -pthread
AR = ar
RANLIB = ranlib

SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

SERVER_APP = repa
CLIENT_APP = repactl

ALL_SOURCES = $(wildcard $(SRC_DIR)/*.c)

# Server: without repactl.c
SERVER_SOURCES = $(filter-out $(SRC_DIR)/repactl.c, $(ALL_SOURCES))
SERVER_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SOURCES))

# Client: only repactl.c 
CLIENT_SOURCES = $(wildcard $(SRC_DIR)/repactl.c)
CLIENT_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CLIENT_SOURCES))

.PHONY: all clean repa repactl run-server run-client

all: repa
ifneq ($(CLIENT_SOURCES),)
all: repactl
endif

repa: $(SERVER_OBJECTS) | $(BUILD_DIR)
	$(CC) $(SERVER_OBJECTS) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_APP)

repactl: $(CLIENT_OBJECTS) | $(BUILD_DIR)
	$(CC) $(CLIENT_OBJECTS) $(LDFLAGS) -lreadline -o $(BUILD_DIR)/$(CLIENT_APP)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

-include $(SERVER_OBJECTS:.o=.d)
ifneq ($(CLIENT_OBJECTS),)
-include $(CLIENT_OBJECTS:.o=.d)
endif

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

run-server: repa
	./$(BUILD_DIR)/$(SERVER_APP)

run-client: repactl
	./$(BUILD_DIR)/$(CLIENT_APP)
