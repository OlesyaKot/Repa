#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "resp_command_parser.h"
#include "logger.h"

static void *resp_alloc(const size_t size){
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (ptr == MAP_FAILED) ? NULL : ptr;
}

static void resp_free(void *ptr, const size_t size) {
  if (ptr && ptr != MAP_FAILED) {
    munmap(ptr, size);
  }
}

static bool parse_integer(const char *str, const size_t len, int64_t *out) {
  if (len == 0) return false;
  const char *end = str + len;
  const char *ptr = str;
  int sign = 1;
  int64_t value = 0;

  if (*ptr == '-') {
    sign = -1;
    ptr++;
    if (ptr >= end) return false;
  } else if (*ptr == '+') {
    ptr++;
    if (ptr >= end) return false;
  }

  if (ptr == end) return false;

  while (ptr < end) {
    if (!isdigit((unsigned char)*ptr)) return false;
    if (__builtin_mul_overflow(value, 10, &value) || __builtin_add_overflow(value, (*ptr - '0'), &value)) {
      return false;
    }
    ptr++;
  }

  *out = sign * value;
  return true;
}

static char *parse_bulk_string(const char **start_ptr, const char *end_ptr, size_t *out_len) {
  const char *ptr = *start_ptr;
  int64_t len;
  char *data;

  if (ptr >= end_ptr || *ptr != '$') return NULL;
  ptr++;

  const char *num_start = ptr;
  while (ptr < end_ptr && *ptr != '\r') ptr++;
  if (ptr >= end_ptr || ptr + 1 >= end_ptr || ptr[1] != '\n') return NULL;

  if (!parse_integer(num_start, ptr - num_start, &len)) return NULL;
  ptr += 2;  // skip \r\n

  if (len == -1) {
    *out_len = 0;
    *start_ptr = ptr;
    return NULL;  // nil
  }

  if (len < 0 || len > MAX_COMMAND_LEN || ptr + len + 2 > end_ptr) {
    return NULL;
  }

  data = resp_alloc((size_t)len + 1);
  if (!data) return NULL;

  if (len > 0) {
    memcpy(data, ptr, (size_t)len);
  }
  data[len] = '\0'; 

  ptr += len;
  if (ptr + 2 > end_ptr || ptr[0] != '\r' || ptr[1] != '\n') {
    resp_free(data, (size_t)len + 1);
    return NULL;
  }
  ptr += 2;

  *out_len = (size_t)len;
  *start_ptr = ptr;
  return data;  
}

static bool parse_command(const char **start_ptr, const char *end_ptr, resp_command *cmd) {
  const char *ptr = *start_ptr;
  int64_t count;

  if (ptr >= end_ptr || *ptr != '*') return false;

  ptr++;
  const char *num_start = ptr;
  while (ptr < end_ptr && *ptr != '\r') ptr++;
  if (ptr >= end_ptr || ptr + 1 >= end_ptr || ptr[1] != '\n') return false;

  if (!parse_integer(num_start, ptr - num_start, &count)) return false;
  ptr += 2;  // \r\n

  if (count < 0 || count > MAX_COMMAND_ARGS) return false;

  if (count == 0) {
    cmd->command = NULL;
    cmd->command_len = 0;
    cmd->args = NULL;
    cmd->args_lens = NULL;
    cmd->args_num = 0;
    *start_ptr = ptr;
    return true;
  }

  cmd->args = resp_alloc(sizeof(char *) * (size_t)count);
  if (!cmd->args) {
    return false;
  }
  cmd->args_lens = resp_alloc(sizeof(size_t) * (size_t)count);
  if (!cmd->args_lens) {
    resp_free(cmd->args, sizeof(char *) * (size_t)count);
    return false;
  }

  for (size_t i = 0; i < (size_t)count; ++i) {
    size_t arg_len;
    cmd->args[i] = parse_bulk_string(&ptr, end_ptr, &arg_len);
    if (!cmd->args[i] && arg_len != 0) {
      // parsing error
      for (size_t j; j < i; ++j) {
        resp_free(cmd->args[j], cmd->args_lens[j] + 1);
      }
      resp_free(cmd->args, sizeof(char *) * (size_t)count);
      resp_free(cmd->args_lens, sizeof(size_t) * (size_t)count);
      return false;
    }
    cmd->args_lens[i] = arg_len;
  }

  // command name = first arg
  if (count > 0) {
    if (cmd->args_lens[0] > 0) {
      cmd->command = resp_alloc(cmd->args_lens[0]);
      if (!cmd->command) {
        for (int64_t i = 0; i < count; i++) {
          if (cmd->args[i]) resp_free(cmd->args[i], cmd->args_lens[i]);
        }
        resp_free(cmd->args, sizeof(char *) * count);
        resp_free(cmd->args_lens, sizeof(size_t) * count);
        return false;
      }
      memcpy(cmd->command, cmd->args[0], cmd->args_lens[0]);
    } else {
      cmd->command = NULL; 
    }
    cmd->command_len = cmd->args_lens[0];

    if (count > 1) {
      memmove(cmd->args, cmd->args + 1, sizeof(char *) * ((size_t)count - 1));
      memmove(cmd->args_lens, cmd->args_lens + 1,
              sizeof(size_t) * ((size_t)count - 1));
      cmd->args_num = (size_t)count - 1;
    } else {
      resp_free(cmd->args, sizeof(char *) * count);
      resp_free(cmd->args_lens, sizeof(size_t) * count);
      cmd->args = NULL;
      cmd->args_lens = NULL;
      cmd->args_num = 0;
    }
  }

  *start_ptr = ptr;
  return true;
}

resp_list_commands* resp_parse(const char* buffer, const size_t len, size_t* consumed) {
  if (!buffer || len == 0 || !consumed) {
    if (consumed)
      *consumed = 0;
    return NULL;
  }

  *consumed = 0;
  const char *start_ptr = buffer;
  const char *end_ptr = buffer + len;
  size_t commands_parsed = 0;
  size_t capacity = INIT_CAP;
  resp_command *commands = resp_alloc(sizeof(resp_command) * INIT_CAP);
  if (!commands)
    return NULL;

  while (start_ptr < end_ptr) {
    if (start_ptr + 1 > end_ptr) break;

    // RESP2 commands starts with *, +, -, :, $
    char start_type = *start_ptr;
    if (start_type != '*' && start_type != '+' && start_type != '-' && start_type != ':' && start_type != '$') {
      break;
    }

    const char *cmd_start = start_ptr;
    resp_command cmd = {0};

    if (!parse_command(&start_ptr, end_ptr, &cmd)) {
      // not full command or error
      if (cmd.args) {
        for (size_t i = 0; i < cmd.args_num; ++i) {
          if (cmd.args[i])
            resp_free(cmd.args[i], cmd.args_lens[i]);
        }
        resp_free(cmd.args, sizeof(char *) * cmd.args_num);
        resp_free(cmd.args_lens, sizeof(size_t) * cmd.args_num);
      }
      break;
    }

    // add command to list
    if (commands_parsed >= capacity) {
      size_t new_cap = capacity * 2;
      resp_command *new_commands = resp_alloc(sizeof(resp_command) * new_cap);
      if (!new_commands) {
        // free curr cmd
        if (cmd.args) {
          for (size_t i = 0; i < cmd.args_num; i++) {
            if (cmd.args[i]) resp_free(cmd.args[i], cmd.args_lens[i]);
          }
          resp_free(cmd.args, sizeof(char *) * cmd.args_num);
          resp_free(cmd.args_lens, sizeof(size_t) * cmd.args_num);
        }
        // free other cmd
        for (size_t i = 0; i < commands_parsed; i++) {
          if (commands[i].command)
            resp_free(commands[i].command, commands[i].command_len);
          if (commands[i].args) {
            for (size_t j = 0; j < commands[i].args_num; j++) {
              if (commands[i].args[j])
                resp_free(commands[i].args[j], commands[i].args_lens[j]);
            }
            resp_free(commands[i].args, sizeof(char *) * commands[i].args_num);
            resp_free(commands[i].args_lens, sizeof(size_t) * commands[i].args_num);
          }
        }
        resp_free(commands, sizeof(resp_command) * capacity);
        *consumed = cmd_start - buffer;
        return NULL;
      }
      memcpy(new_commands, commands, sizeof(resp_command) * capacity);
      resp_free(commands, sizeof(resp_command) * capacity);
      commands = new_commands;
      capacity = new_cap;
    }

    commands[commands_parsed] = cmd;
    commands_parsed++;
  }

  if (commands_parsed == 0) {
    resp_free(commands, sizeof(resp_command) * capacity);
    *consumed = 0;
    return NULL;
  }

  size_t calculated_consumed = start_ptr - buffer;
  if (calculated_consumed > len) {
    logger_error("Parser overflow: %zu > %zu", calculated_consumed, len);

    for (size_t i = 0; i < commands_parsed; i++) {
      if (commands[i].command)
        resp_free(commands[i].command, commands[i].command_len);
      if (commands[i].args) {
        for (size_t j = 0; j < commands[i].args_num; j++) {
          if (commands[i].args[j])
            resp_free(commands[i].args[j], commands[i].args_lens[j]);
        }
        resp_free(commands[i].args, sizeof(char *) * commands[i].args_num);
        resp_free(commands[i].args_lens, sizeof(size_t) * commands[i].args_num);
      }
    }
    resp_free(commands, sizeof(resp_command) * capacity);

    *consumed = 0;
    return NULL;
  }

  resp_list_commands *result = resp_alloc(sizeof(resp_list_commands));
  if (!result) {
    for (size_t i = 0; i < commands_parsed; i++) {
      if (commands[i].command) resp_free(commands[i].command, commands[i].command_len);
      if (commands[i].args) {
        for (size_t j = 0; j < commands[i].args_num; j++) {
          if (commands[i].args[j])
            resp_free(commands[i].args[j], commands[i].args_lens[j]);
        }
        resp_free(commands[i].args, sizeof(char *) * commands[i].args_num);
        resp_free(commands[i].args_lens, sizeof(size_t) * commands[i].args_num);
      }
    }
    resp_free(commands, sizeof(resp_command) * capacity);
    *consumed = start_ptr - buffer;
    return NULL;
  }

  result->commands = commands;
  result->num_commands = commands_parsed;
  *consumed = start_ptr - buffer;
  return result;
}

void resp_free_command_list(resp_list_commands *list) {
  if (!list) return;

  for (size_t i = 0; i < list->num_commands; i++) {
    if (list->commands[i].command) {
      resp_free(list->commands[i].command, list->commands[i].command_len);
    }

    if (list->commands[i].args) {
      for (size_t j = 0; j < list->commands[i].args_num; j++) {
        if (list->commands[i].args[j]) {
          resp_free(list->commands[i].args[j], list->commands[i].args_lens[j] + 1);
        }
      }

      resp_free(list->commands[i].args, sizeof(char *) * list->commands[i].args_num);
      resp_free(list->commands[i].args_lens, sizeof(size_t) * list->commands[i].args_num);
    }
  }
  resp_free(list->commands, sizeof(resp_command) * list->num_commands);
  resp_free(list, sizeof(resp_list_commands));
}

// Serialization
char *resp_serialize_simple_string(const char *str) {
  if (!str) return NULL;

  size_t len = strlen(str);
  size_t total_len = 1 + len + 2 + 1;  // +\r\n\0
  char *buffer = resp_alloc(total_len);
  if (!buffer) return NULL;

  int written = snprintf(buffer, total_len, "+%s\r\n", str);
  if (written < 0 || (size_t)written >= total_len) {
    resp_free(buffer, total_len);
    return NULL;
  }
  return buffer;
}

char *resp_serialize_error(const char *msg) {
  if (!msg) return NULL;

  size_t len = strlen(msg);
  size_t total_len = 1 + len + 2 + 1;  // -\r\n\0
  char *buffer = resp_alloc(total_len);
  if (!buffer) return NULL;

  int written = snprintf(buffer, total_len, "-%s\r\n", msg);
  if (written < 0 || (size_t)written >= total_len) {
    resp_free(buffer, total_len);
    return NULL;
  }
  return buffer;
}

char *resp_serialize_bulk_string(const char *data, const size_t len) {
  size_t num_len = 1;
  size_t tmp = len;
  size_t total_len = 0;
  char *buffer;
  int written;

  while (tmp >= INIT_CAP) {
    num_len++;
    tmp /= INIT_CAP;
  }

  total_len = 1 + num_len + 2 + len + 2 + 1;  // $<num>\r\n<data>\r\n\0
  buffer = resp_alloc(total_len);
  if (!buffer) return NULL;
  written = snprintf(buffer, total_len, "$%zu\r\n", len);
  if (written < 0 || (size_t)written >= total_len) {
    resp_free(buffer, total_len);
    return NULL;
  }
  if (len > 0) {
    memcpy(buffer + written, data, len);
    memcpy(buffer + written + len, "\r\n", 2);
  } else {
    memcpy(buffer + written, "\r\n", 2);
  }
  return buffer;
}

char *resp_serialize_nil(void) {
  char *buffer = resp_alloc(TOTAL_LEN_NIL);  // $-1\r\n\0
  if (buffer) snprintf(buffer, TOTAL_LEN_NIL, "$-1\r\n");
  return buffer;
}

char *resp_serialize_integer(int64_t num) {
  char *buffer = resp_alloc(TOTAL_LEN_INT);
  int written;
  if (!buffer) return NULL;

  written = snprintf(buffer, TOTAL_LEN_INT, ":%ld\r\n", num);
  if (written < 0 || (size_t)written >= TOTAL_LEN_INT) {
    resp_free(buffer, TOTAL_LEN_INT);
    return NULL;
  }
  return buffer;
}

void resp_free_serialized(char *serialized) {
  if (serialized) {
    size_t len = strlen(serialized) + 1;
    resp_free(serialized, len);
  }
}
