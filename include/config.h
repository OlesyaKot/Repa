#ifndef INCLUDE_CONFIG_H
#define INCLUDE_CONFIG_H

#include <stdbool.h>
#include <stdlib.h>

#include "logger.h"

void config_init(int argc, char *argv[]);
void config_destroy(void);
bool config_set(const char *param, const char *value);
int config_get_port(void);
size_t config_get_max_memory_bytes(void);
int config_get_default_ttl_sec(void);
int config_get_workers(void);
logger_level config_get_log_level(void);
char *config_get_param(const char *param);
char *config_get_log_output(void);
char *config_get_default_user(void);
char *config_get_default_password(void);

#endif
