# Компилятор и флаги
CC = gcc
CFLAGS = -Wall -Wextra -Werror -fsanitize=address -fsanitize=leak -g -I$(INCLUDE_DIR)
LDFLAGS = -fsanitize=address -fsanitize=leak  # Санитайзеры нужно линковать тоже!
AR = ar
RANLIB = ranlib

# Директории
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
LIB_NAME = libmyrepa.a
APP_NAME = repa  # ← имя исполняемого файла

# Исходники библиотеки
LIB_SOURCES = $(wildcard $(SRC_DIR)/*.c)
# Исключим main.c из библиотеки, если он есть!
LIB_SOURCES := $(filter-out $(SRC_DIR)/main.c, $(LIB_SOURCES))
LIB_SOURCES := $(filter-out $(SRC_DIR)/repa.c, $(LIB_SOURCES))

# Объектные файлы библиотеки
LIB_OBJECTS = $(LIB_SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Файл с main
MAIN_SOURCE = $(SRC_DIR)/main.c  # или $(SRC_DIR)/repa.c — выберите один!
MAIN_OBJECT = $(BUILD_DIR)/main.o

# Цели
.PHONY: all clean test repa

all: repa

# Собираем исполняемый файл
repa: $(BUILD_DIR)/$(LIB_NAME) $(MAIN_OBJECT) | $(BUILD_DIR)
	$(CC) $(MAIN_OBJECT) -L$(BUILD_DIR) -lmyrepa $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)

# Собираем библиотеку
$(BUILD_DIR)/$(LIB_NAME): $(LIB_OBJECTS) | $(BUILD_DIR)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# Компиляция .c → .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Создание директории
$(BUILD_DIR):
	mkdir -p $@

# Тесты (как раньше)
test: all
	$(CC) $(CFLAGS) -L$(BUILD_DIR) -I$(INCLUDE_DIR) tests/test.c -o tests/test -lmyrepa $(LDFLAGS)
	./tests/test

# Уборка
clean:
	rm -rf $(BUILD_DIR) tests/test

# Удобная команда для быстрого запуска
run: repa
	./$(BUILD_DIR)/$(APP_NAME)