#ifndef INCLUDE_RESP_COMMAND_PARSER_H
#define INCLUDE_RESP_COMMAND_PARSER_H

#include <inttypes.h>
#include <stdlib.h>

#define INIT_CAP 8
#define TOTAL_LEN_INT 25
#define TOTAL_LEN_NIL 6
#define MAX_COMMAND_ARGS 100
#define MAX_COMMAND_LEN (1024 * 1024)

typedef struct {
  char *command;
  char **args;
  size_t *args_lens;
  size_t command_len;
  size_t args_num;
} resp_command;

typedef struct {
  resp_command *commands;
  size_t num_commands;
} resp_list_commands;

resp_list_commands *resp_parse(const char *buffer, const size_t len, size_t *consumed);
void resp_free_command_list(resp_list_commands *list);
char *resp_serialize_simple_string(const char *str);
char *resp_serialize_error(const char *msg);
char *resp_serialize_bulk_string(const char *data, size_t len);
char *resp_serialize_nil(void);
char *resp_serialize_integer(int64_t num);
void resp_free_serialized(char *serialized);

#endif
