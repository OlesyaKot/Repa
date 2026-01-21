#define _GNU_SOURCE

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 512
#define TO_BYTES (1024 * 1024)

#define MAX_NUM_WORKERS 1024
#define DEFAULT_PORT 6380
#define DEFAULT_USER "admin"
#define DEFAULT_PASSWORD "admin"
#define DEFAULT_MAX_MEM_BYTES (256U * TO_BYTES)
#define DEFAULT_TTL_SEC 0
#define DEFAULT_NUM_WORKERS 4
#define DEFAULT_LOG_LEVEL INFO
#define DEFAULT_CONFIG_PATH "repa.conf"
#define RADIX 10
#define MAX_PORT 65535

// Priority: CONFIG SET > CLI > файл > defaults

typedef struct {
  int port;
  char *default_user;
  char *default_password;
  size_t max_memory_size_bytes;
  int default_ttl_sec;
  int num_workers;
  logger_level log_level;
  char *log_output;
  bool is_init;
  pthread_mutex_t mutex;
} repa_config;

static repa_config config;

static void config_set_defaults(void) {
  config.port = DEFAULT_PORT;

  config.default_user = strdup(DEFAULT_USER);
  if (!config.default_user) 
    return;

  config.default_password = strdup(DEFAULT_PASSWORD);
  if (!config.default_password) {
    free(config.default_user);
    config.default_user = NULL;
    return;
  }

  config.max_memory_size_bytes = DEFAULT_MAX_MEM_BYTES;
  config.default_ttl_sec = DEFAULT_TTL_SEC;
  config.num_workers = DEFAULT_NUM_WORKERS;
  config.log_level = DEFAULT_LOG_LEVEL;
  config.log_output = NULL;
  config.is_init = false;
}

static void parse_int(const char *str, int *out) {
  if (!str || !out) return;

  char *end;
  errno = 0;
  long val = strtol(str, &end, RADIX);
  if (errno || *end != '\0' || val < 0 || val > INT_MAX) return;
  *out = (int)val;
}

static void parse_size_t(const char *str, size_t *out) {
  if (!str || !out) return;
  char *end;
  errno = 0;
  unsigned long long val = strtoull(str, &end, RADIX);
  if (errno || *end != '\0') return;
  *out = (size_t)val;
}

static void handle_port(const char *value) {
  parse_int(value, &config.port);
}

static void handle_max_memory_mb(const char *value) {
  size_t mb;
  parse_size_t(value, &mb);
  if(mb == 0 || mb > (SIZE_MAX / TO_BYTES)) {
    return;
  }

  config.max_memory_size_bytes = mb * TO_BYTES;
}

static void handle_workers(const char *value) {
  parse_int(value, &config.num_workers);
}

static void handle_default_ttl(const char *value) {
  parse_int(value, &config.default_ttl_sec);
}

static void handle_verbose(void) {
  config.log_level = DEBUG;
}

static void print_help_and_exit() {
  printf(
      "Usage: repa [OPTIONS]\n"
      "  --port <num>            (default: %d)\n"
      "  --config <path>         (default: %s)\n"
      "  --verbose               Enable debug logging\n"
      "  --max-memory-mb <num>   Max memory in MB (default: %zu)\n"
      "  --workers <num>         (default: %d)\n"
      "  --default-ttl <sec>     (default: %d)\n",
      DEFAULT_PORT, DEFAULT_CONFIG_PATH,
      (size_t)(DEFAULT_MAX_MEM_BYTES / TO_BYTES), DEFAULT_NUM_WORKERS,
      DEFAULT_TTL_SEC);
  exit(0);
}

static void handle_help(void) {
  print_help_and_exit();
}

static const char *get_config_path_from_cli(const int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      return argv[i + 1];
    }
  }
  return DEFAULT_CONFIG_PATH;
}

static void apply_cli_flags(const int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      handle_port(argv[i + 1]);
      i++; 
    } else if (strcmp(argv[i], "--max-memory-mb") == 0 && i + 1 < argc) {
      handle_max_memory_mb(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
      handle_workers(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "--default-ttl") == 0 && i + 1 < argc) {
      handle_default_ttl(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "--verbose") == 0) {
      handle_verbose();
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "--h") == 0) {
      handle_help();
    } 
  }
}

static bool config_load_file(const char *path) {
  int fd = -1;
  struct stat sb;
  size_t file_size;
  char *data = NULL;
  bool success = false;

  fd = open(path, O_RDONLY);
  if (fd == -1) {
    return false;
  }

  if (fstat(fd, &sb) == -1) {
    goto CLEANUP;
  }

  if (sb.st_size == 0) {
    success = true;
    goto CLEANUP;
  }

  file_size = (size_t)sb.st_size;
  data = malloc(file_size);
  if (!data) {
    goto CLEANUP;
  }

  ssize_t bytes_read = read(fd, data, file_size);
  if (bytes_read != (ssize_t)file_size) {
    goto CLEANUP;
  }

  char *start = data;
  char *end = data + file_size;

  while (start < end) {
    char *end_of_line = memchr(start, '\n', end - start);
    if (!end_of_line){
      end_of_line = end;
    }

    char *curr = start;
    while (curr < end_of_line && isspace((unsigned char)*curr)) curr++;
    if (curr >= end_of_line || *curr == '#') {
      start = end_of_line + 1;
      continue;
    }

    char *eq = memchr(curr, '=', end_of_line - curr);
    if (!eq) {
      start = end_of_line + 1;
      continue;
    }

    size_t key_len = eq - curr;
    while (key_len > 0 && isspace((unsigned char)curr[key_len - 1])) key_len--;
    if (key_len == 0 || key_len >= MAX_KEY_LEN) {
      start = end_of_line + 1;
      continue;
    }

    char key[MAX_KEY_LEN];
    memcpy(key, curr, key_len);
    key[key_len] = '\0';

    char *val_start = eq + 1;
    while (val_start < end_of_line && isspace((unsigned char)*val_start))
      val_start++;
    char *val_end = end_of_line;
    while (val_end > val_start && isspace((unsigned char)val_end[-1]))
      val_end--;
    size_t val_len = val_end - val_start;
    if (val_len >= MAX_VALUE_LEN) {
      start = end_of_line + 1;
      continue;
    }

    char value[MAX_VALUE_LEN] = {0};
    if (val_len > 0) memcpy(value, val_start, val_len);

    if (strcmp(key, "port") == 0) {
      int port = 0;
      parse_int(value, &port);
      if (port > 0 && port <= MAX_PORT) {
        config.port = port;
      }
    } else if (strcmp(key, "default_user") == 0) {
      char *new_user = strdup(value);
      if (!new_user) {
        goto CLEANUP;
      }
      free(config.default_user);
      config.default_user = new_user;
    } else if (strcmp(key, "default_password") == 0) {
      char *new_password = strdup(value);
      if (!new_password) {
        goto CLEANUP;
      }
      free(config.default_password);
      config.default_password = new_password;
    } else if (strcmp(key, "max_memory_mb") == 0) {
      size_t mb = 0;
      parse_size_t(value, &mb);
      if (mb > 0 && mb <= (SIZE_MAX / TO_BYTES)) {
        config.max_memory_size_bytes = mb * TO_BYTES;
      }
    } else if (strcmp(key, "default_ttl") == 0) {
      int ttl = 0;
      parse_int(value, &ttl);
      if (ttl >= 0) {
        config.default_ttl_sec = ttl;
      }
    } else if (strcmp(key, "workers") == 0) {
      int workers;
      parse_int(value, &workers);
      if (workers > 0 && workers <= MAX_NUM_WORKERS) {
        config.num_workers = workers;
      }
    } else if (strcmp(key, "log_level") == 0) {
      config.log_level = logger_level_from_string(value);
    } else if (strcmp(key, "log_output") == 0) {
      char *new_log_output = strdup(value);
      if (!new_log_output) {
        goto CLEANUP;
      }
      free(config.log_output);
      config.log_output = new_log_output;
    } 

    start = end_of_line + 1;
  }

  success = true;

CLEANUP:
  if (data) free(data);
  if (fd != -1) close(fd);
  return success;
}

void config_init(const int argc, char *argv[]) {
  if (pthread_mutex_init(&config.mutex, NULL) != 0) {
    exit(1);
  }

  pthread_mutex_lock(&config.mutex);
  if (!config.is_init) {
    config_set_defaults();

    if (!config.default_user || !config.default_password) {
      pthread_mutex_unlock(&config.mutex);
      pthread_mutex_destroy(&config.mutex);
      exit(1);
    }

    const char *config_path = get_config_path_from_cli(argc, argv);
    config_load_file(config_path);
    apply_cli_flags(argc, argv);

    config.is_init = true;
  }
  pthread_mutex_unlock(&config.mutex);
}

void config_destroy(void) {
  pthread_mutex_lock(&config.mutex);
  if (config.is_init) {
    free(config.default_user);
    free(config.default_password);
    free(config.log_output);
    config.default_user = NULL;
    config.default_password = NULL;
    config.log_output = NULL;
    config.is_init = false;
  }
  pthread_mutex_unlock(&config.mutex);
  pthread_mutex_destroy(&config.mutex);
}

bool config_set(const char *param, const char *value) {
  bool result = false;
  if (!param || !value) return false;

  pthread_mutex_lock(&config.mutex);
  if (!config.is_init) {
    pthread_mutex_unlock(&config.mutex);
    return false;
  }

  result = false;

  if (strcasecmp(param, "maxmemory") == 0) {
    size_t bytes = 0;
    parse_size_t(value, &bytes);
    if (bytes > 0) {
      config.max_memory_size_bytes = bytes;
      result = true;
    }
  } else if (strcasecmp(param, "loglevel") == 0) {
    config.log_level = logger_level_from_string(value);
    result = true;
  } else if (strcasecmp(param, "requirepass") == 0) {
    char *new_pass = strdup(value);
    if (new_pass) {
      free(config.default_password);
      config.default_password = new_pass;
      result = true;
    }
  }

  pthread_mutex_unlock(&config.mutex);
  return result;
}

// Getters
int config_get_port(void) {
  return config.port;
}

char *config_get_param(const char *param) {
  char *result = NULL;
  if (!param)
    return NULL;

  pthread_mutex_lock(&config.mutex);

  if (!config.is_init) {
    pthread_mutex_unlock(&config.mutex);
    return NULL;
  }

  if (strcasecmp(param, "maxmemory") == 0) {
    if (asprintf(&result, "%zu", config.max_memory_size_bytes) == -1) {
      result = NULL; 
    }
  } else if (strcasecmp(param, "loglevel") == 0) {
    const char *tmp = NULL;
    if (config.log_level == DEBUG) {
      tmp = "debug";
    } else if (config.log_level == WARNING) {
      tmp = "warning";
    } else if (config.log_level == ERROR) {
      tmp = "error";
    } else {
      tmp = "notice";  // Redis default for INFO
    }
    result = strdup(tmp);
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for loglevel");
    }
  } else if (strcasecmp(param, "requirepass") == 0) {
    const char *tmp = config.default_password ? config.default_password : "";
    result = strdup(tmp);
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for requirepass");
    }
  } else if (strcasecmp(param, "port") == 0) {
    if (asprintf(&result, "%d", config.port) == -1) {
      result = NULL;
    }
  } else if (strcasecmp(param, "maxmemory-policy") == 0) {
    result = strdup("noeviction");
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for maxmemory-policy");
    }
  } else if (strcasecmp(param, "tcp-keepalive") == 0) {
    result = strdup("0");
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for tcp-keepalive");
    }
  } else if (strcasecmp(param, "save") == 0) {
    result = strdup("");
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for save");
    }
  } else if (strcasecmp(param, "appendonly") == 0) {
    result = strdup("no");
    if (!result) {
      logger_error("config_get_param: failed to allocate memory for appendonly");
    }
  }

  pthread_mutex_unlock(&config.mutex);
  return result;
}

size_t config_get_max_memory_bytes(void) {
  return config.max_memory_size_bytes;
}

int config_get_default_ttl_sec(void) { 
  return config.default_ttl_sec; 
}

int config_get_workers(void) { 
  return config.num_workers; 
}

logger_level config_get_log_level(void) { 
  return config.log_level; 
}

char *config_get_log_output(void) { 
  return config.log_output; 
}

char *config_get_default_user(void) { 
  return config.default_user; 
}

char *config_get_default_password(void) { 
  return config.default_password; 
}
