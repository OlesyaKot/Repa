#ifndef INCLUDE_CONFIG_H
#define INCLUDE_CONFIG_H

#include <stdbool.h>

#include "logger.h"

#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 512
#define TO_BYTES (1024 * 1024)

#define DEFAULT_PORT 6379
#define DEFAULT_USER "admin"
#define DEFAULT_PASSWORD "admin"
#define DEFAULT_MAX_MEM_BYTES (256U * 1024 * 1024)
#define DEFAULT_TTL_SEC 0
#define DEFAULT_NUM_WORKERS 4
#define DEFAULT_LOG_LEVEL INFO
#define DEFAULT_CONFIG_PATH "repa.conf"

void config_init(int argc, char *argv[]);
void config_destroy();
bool config_set(const char *param, const char *value);
int config_get_port();
size_t config_get_max_memory_bytes();
int config_get_default_ttl_sec();
int config_get_workers();
logger_level config_get_log_level();
char *config_get_param(const char *param);
char *config_get_log_output();
char *config_get_default_user();
char *config_get_default_password();

#endif
