#include "resp_command_parser.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

#define MAX_COMMAND_ARGS 64
#define MAX_COMMAND_LEN 1024 * 1024  // 1MB
#define INIT_CAP 4
#define TOTAL_LEN_NIL 7   // "$-1\r\n\0"
#define TOTAL_LEN_INT 32  // for int64 + \r\n\0

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
    if (value > (INT64_MAX / 10)) return false;
    value *= 10;

    int digit = (*ptr - '0');
    if (value > (INT64_MAX - digit)) return false;
    value += digit;
    ptr++;
  }

  *out = sign * value;
  return true;
}

static char *parse_bulk_string(const char **start_ptr, const char *end_ptr, size_t *out_len, bool *is_nil) {
  const char *ptr = *start_ptr;
  int64_t len;
  char *data;
  *is_nil = false;

  if (ptr >= end_ptr || *ptr != '$') return NULL;
  ptr++;

  const char *num_start = ptr;
  while (ptr < end_ptr && *ptr != '\r') ptr++;
  if (ptr >= end_ptr || ptr + 1 >= end_ptr || ptr[1] != '\n') return NULL;

  if (!parse_integer(num_start, ptr - num_start, &len)) return NULL;
  ptr += 2;  // skip \r\n

  if (len == -1) {
    *out_len = 0;
    *is_nil = true;
    *start_ptr = ptr;
    return NULL;
  }

  if (len < 0 || len > MAX_COMMAND_LEN || ptr + len + 2 > end_ptr) {
    return NULL;
  }

  data = malloc(len + 1);
  if (!data) return NULL;

  if (len > 0) {
    memcpy(data, ptr, (size_t)len);
  }
  data[len] = '\0';
  *out_len = (size_t)len;
  ptr += len;
  
  if (ptr + 2 > end_ptr || ptr[0] != '\r' || ptr[1] != '\n') {
    free(data);
    return NULL;
  }
  ptr += 2;

  *start_ptr = ptr;
  return data;
}

static bool parse_resp_array(const char **start_ptr, const char *end_ptr, resp_command *cmd) {
  const char *ptr = *start_ptr;
  int64_t count;

  if (ptr >= end_ptr || *ptr != '*') return false;

  ptr++;
  const char *num_start = ptr;
  while (ptr < end_ptr && *ptr != '\r') ptr++;
  if (ptr >= end_ptr || ptr + 1 >= end_ptr || ptr[1] != '\n') return false;

  if (!parse_integer(num_start, ptr - num_start, &count)) return false;
  ptr += 2;

  if (count < 0 || count > MAX_COMMAND_ARGS) return false;

  if (count == 0) {
    memset(cmd, 0, sizeof(resp_command));
    *start_ptr = ptr;
    return true;
  }

  cmd->args = calloc(count, sizeof(char *));
  if (!cmd->args) 
    return false;

  cmd->args_lens = calloc(count, sizeof(size_t));
  if (!cmd->args_lens) {
    free(cmd->args);
    cmd->args = NULL;
    return false;
  }

  for (int i = 0; i < count; ++i) {
    bool is_nil = false;
    size_t arg_len = 0;
    char *arg = parse_bulk_string(&ptr, end_ptr, &arg_len, &is_nil);

    if (!arg && !is_nil) {
      for (int j = 0; j < i; ++j) {
        free(cmd->args[j]);
      }
      free(cmd->args);
      free(cmd->args_lens);
      memset(cmd, 0, sizeof(resp_command));
      return false;
    }

    cmd->args[i] = arg;
    cmd->args_lens[i] = arg_len;
  }

  if (count > 0 && cmd->args[0]) {
    cmd->command = strdup(cmd->args[0]);
    cmd->command_len = cmd->args_lens[0];
    if (!cmd->command) {
      for (int i = 0; i < count; ++i) {
        free(cmd->args[i]);
      }
      free(cmd->args);
      free(cmd->args_lens);
      memset(cmd, 0, sizeof(resp_command));
      return false;
    }

    free(cmd->args[0]);
    if (count > 1) {
      memmove(cmd->args, cmd->args + 1, sizeof(char *) * (count - 1));
      memmove(cmd->args_lens, cmd->args_lens + 1, sizeof(size_t) * (count - 1));
      cmd->args_num = (size_t)count - 1;
    } else {
      free(cmd->args);
      free(cmd->args_lens);
      cmd->args = NULL;
      cmd->args_lens = NULL;
      cmd->args_num = 0;
    }
  } else {
    for (int i = 0; i < count; ++i) {
      free(cmd->args[i]);
    }
    free(cmd->args);
    free(cmd->args_lens);
    memset(cmd, 0, sizeof(resp_command));
    return false;
  }

  *start_ptr = ptr;
  return true;
}

static bool parse_simple_line(const char **start_ptr, const char *end_ptr, resp_command *cmd) {
  const char *ptr = *start_ptr;
  const char *line_end = ptr;

  while (line_end < end_ptr && *line_end != '\r' && *line_end != '\n') {
    line_end++;
  }

  if (line_end == ptr) return false;

  size_t line_len = line_end - ptr;
  char *line_copy = malloc(line_len + 1);
  if (!line_copy) return false;
  memcpy(line_copy, ptr, line_len);
  line_copy[line_len] = '\0';

  char *argv[MAX_COMMAND_ARGS];
  int argc = 0;
  char *saveptr = NULL;
  char *token = strtok_r(line_copy, " \t", &saveptr);

  while (token && argc < MAX_COMMAND_ARGS) {
    argv[argc] = strdup(token);
    if (!argv[argc]) {
      for (int i = 0; i < argc; i++) {
        free(argv[i]);
      }
      free(line_copy);
      return false;
    }
    argc++;
    token = strtok_r(NULL, " \t", &saveptr);
  }

  if (argc == 0) {
    free(line_copy);
    return false;
  }

  cmd->command = argv[0];
  cmd->command_len = strlen(argv[0]);
  cmd->args_num = argc - 1;

  if (cmd->args_num > 0) {
    cmd->args = malloc(sizeof(char *) * cmd->args_num);
    if (!cmd->args) {
      for (int i = 0; i < argc; i++){ 
        free(argv[i]);
      }
      free(line_copy);
      return false;
    }
    cmd->args_lens = malloc(sizeof(size_t) * cmd->args_num);
    if (!cmd->args_lens) {
      free(cmd->args);
      for (int i = 0; i < argc; i++) free(argv[i]);
      free(line_copy);
      return false;
    }

    for (size_t i = 0; i < cmd->args_num; i++) {
      cmd->args[i] = argv[i + 1];
      cmd->args_lens[i] = strlen(argv[i + 1]);
    }
  } else {
    cmd->args = NULL;
    cmd->args_lens = NULL;
  }

  for (int i = 1; i < argc; i++) {
    free(argv[i]); 
  }
  free(line_copy);

  ptr = line_end;
  if (ptr < end_ptr && *ptr == '\r') ptr++;
  if (ptr < end_ptr && *ptr == '\n') ptr++;

  *start_ptr = ptr;
  return true;
}

static bool parse_command(const char **start_ptr, const char *end_ptr, resp_command *cmd) {
  const char *ptr = *start_ptr;

  if (ptr >= end_ptr) return false;

  if (*ptr == '*') {
    return parse_resp_array(start_ptr, end_ptr, cmd);
  } else {
    return parse_simple_line(start_ptr, end_ptr, cmd);
  }
}

static void resp_free_command(resp_command *cmd) {
  if (!cmd) return;

  free(cmd->command);
  cmd->command = NULL;

  if (cmd->args) {
    for (size_t i = 0; i < cmd->args_num; i++) {
      free(cmd->args[i]);
      cmd->args[i] = NULL;
    }
    free(cmd->args);
    cmd->args = NULL;
  }

  free(cmd->args_lens);
  cmd->args_lens = NULL;
  cmd->command_len = 0;
  cmd->args_num = 0;
}

resp_list_commands *resp_parse(const char *buffer, const size_t len, size_t *consumed) {
  if (!buffer || len == 0 || !consumed) {
    if (consumed) *consumed = 0;
    return NULL;
  }

  *consumed = 0;
  const char *start_ptr = buffer;
  const char *end_ptr = buffer + len;
  size_t commands_parsed = 0;
  size_t capacity = INIT_CAP;
  resp_command *commands = malloc(sizeof(resp_command) * INIT_CAP);
  if (!commands) return NULL;

  memset(commands, 0, sizeof(resp_command) * capacity);

  while (start_ptr < end_ptr) {
    if (commands_parsed == 0) {
      while (start_ptr < end_ptr &&
             (*start_ptr == ' ' || *start_ptr == '\r' || *start_ptr == '\n')) {
        start_ptr++;
      }
    }

    if (start_ptr >= end_ptr) break;

    const char *cmd_start = start_ptr;
    resp_command cmd = {0};

    if (!parse_command(&start_ptr, end_ptr, &cmd)) {
      if (commands_parsed > 0) {
        break;
      } else {
        for (size_t i = 0; i < commands_parsed; i++) {
          resp_free_command(&commands[i]);
        }
        free(commands);
        *consumed = 0;
        return NULL;
      }
    }

    if (commands_parsed >= capacity) {
      size_t new_cap = capacity * 2;
      resp_command *new_commands = malloc(sizeof(resp_command) * new_cap);
      if (!new_commands) {
        resp_free_command(&cmd);
        for (size_t i = 0; i < commands_parsed; i++) {
          resp_free_command(&commands[i]);
        }
        free(commands);
        *consumed = cmd_start - buffer;
        return NULL;
      }

      memcpy(new_commands, commands, sizeof(resp_command) * capacity);
      memset(new_commands + capacity, 0, sizeof(resp_command) * (new_cap - capacity));
      free(commands);
      commands = new_commands;
      capacity = new_cap;
    }

    commands[commands_parsed] = cmd;
    commands_parsed++;
  }

  if (commands_parsed == 0) {
    free(commands);
    *consumed = 0;
    return NULL;
  }

  *consumed = start_ptr - buffer;

  resp_list_commands *result = malloc(sizeof(resp_list_commands));
  if (!result) {
    for (size_t i = 0; i < commands_parsed; i++) {
      resp_free_command(&commands[i]);
    }
    free(commands);
    *consumed = 0;
    return NULL;
  }

  result->commands = commands;
  result->num_commands = commands_parsed;
  return result;
}

void resp_free_command_list(resp_list_commands *list) {
  if (!list) return;

  for (size_t i = 0; i < list->num_commands; i++) {
    resp_free_command(&list->commands[i]);
  }

  free(list->commands);
  free(list);
}

char *resp_serialize_simple_string(const char *str) {
  if (!str) return NULL;

  size_t len = strlen(str);
  size_t total_len = 1 + len + 2 + 1;
  char *buffer = malloc(total_len);
  if (!buffer) return NULL;

  int written = snprintf(buffer, total_len, "+%s\r\n", str);
  if (written < 0 || (size_t)written >= total_len) {
    free(buffer);
    return NULL;
  }
  return buffer;
}

char *resp_serialize_error(const char *msg) {
  if (!msg) return NULL;

  size_t len = strlen(msg);
  size_t total_len = 1 + len + 2 + 1;
  char *buffer = malloc(total_len);
  if (!buffer) return NULL;

  int written = snprintf(buffer, total_len, "-%s\r\n", msg);
  if (written < 0 || (size_t)written >= total_len) {
    free(buffer);
    return NULL;
  }
  return buffer;
}

char *resp_serialize_bulk_string(const char *data, const size_t len) {
  if (!data && len > 0) {
    return NULL;
  }

  size_t num_len = 1;
  for (size_t n = len; n >= 10; n /= 10) {
    num_len++;
  }

  size_t total_len = 1 + num_len + 2 + len + 2 + 1;
  char *buffer = malloc(total_len);
  if (!buffer) return NULL;

  int written = snprintf(buffer, total_len, "$%zu\r\n", len);
  if (written < 0 || (size_t)written >= total_len) {
    free(buffer);
    return NULL;
  }

  if (len > 0) {
    memcpy(buffer + written, data, len);
  }

  memcpy(buffer + written + len, "\r\n", 2);
  buffer[total_len - 1] = '\0';

  return buffer;
}

char *resp_serialize_nil(void) {
  char *buffer = malloc(TOTAL_LEN_NIL);
  if (!buffer) return NULL;
  snprintf(buffer, TOTAL_LEN_NIL, "$-1\r\n");
  return buffer;
}

char *resp_serialize_integer(int64_t num) {
  int written;
  char *buffer = malloc(TOTAL_LEN_INT);
  if (!buffer) return NULL;

  written = snprintf(buffer, TOTAL_LEN_INT, ":%" PRId64 "\r\n", num);
  if (written < 0 || (size_t)written >= TOTAL_LEN_INT) {
    free(buffer);
    return NULL;
  }
  return buffer;
}
