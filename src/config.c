#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"

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

static char *config_strdup(const char *str) {
  size_t len;
  char *copy;

  if (!str) return NULL;
  len = strlen(str) + 1;
  copy = mmap(NULL, len, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (copy == MAP_FAILED) return NULL;
  memcpy(copy, str, len);
  return copy;
}

static void config_free_str(char *str) {
  if (str) {
    munmap(str, strlen(str) + 1);
  }
}

static char *config_asprintf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  char *buf;
  int len = vsnprintf(NULL, 0, format, args);
  va_end(args);

  if (len <= 0) return NULL;

  buf = mmap(NULL, len + 1, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED) return NULL;

  va_start(args, format);
  vsnprintf(buf, len + 1, format, args);
  va_end(args);

  return buf;
}

static void config_set_defaults(void) {
  config.port = DEFAULT_PORT;
  config.default_user = config_strdup(DEFAULT_USER);
  config.default_password = config_strdup(DEFAULT_PASSWORD);
  config.max_memory_size_bytes = DEFAULT_MAX_MEM_BYTES;
  config.default_ttl_sec = DEFAULT_TTL_SEC;
  config.num_workers = DEFAULT_NUM_WORKERS;
  config.log_level = DEFAULT_LOG_LEVEL;
  config.log_output = NULL;
}

static bool parse_int(const char *str, int *out) {
  if (!str) return false;
  char *end;
  errno = 0;
  long val = strtol(str, &end, RADIX);
  if (errno || *end != '\0' || val < 0 || val > INT_MAX) return false;
  *out = (int)val;
  return true;
}

static bool parse_size_t(const char *str, size_t *out) {
  if (!str) return false;
  char *end;
  errno = 0;
  unsigned long long val = strtoull(str, &end, RADIX);
  if (errno || *end != '\0') return false;
  *out = (size_t)val;
  return true;
}

static bool handle_port(const char *value) {
  return parse_int(value, &config.port);
}

static bool handle_max_memory_mb(const char *value) {
  size_t mb;
  if (!parse_size_t(value, &mb)) return false;
  config.max_memory_size_bytes = mb * TO_BYTES;
  return true;
}

static bool handle_workers(const char *value) {
  return parse_int(value, &config.num_workers);
}

static bool handle_default_ttl(const char *value) {
  return parse_int(value, &config.default_ttl_sec);
}

static bool handle_verbose(const char *value) {
  (void)value;
  config.log_level = DEBUG;
  return true;
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

static bool handle_help(const char *value) {
  (void)value;
  print_help_and_exit();
  return true;
}

static const char *get_config_path_from_cli(const int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      return argv[++i];
    }
  }
  return DEFAULT_CONFIG_PATH;
}

static void apply_cli_flags(const int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      handle_port(argv[++i]);
    } else if (strcmp(argv[i], "--max-memory-mb") == 0 && i + 1 < argc) {
      handle_max_memory_mb(argv[++i]);
    } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
      handle_workers(argv[++i]);
    } else if (strcmp(argv[i], "--default-ttl") == 0 && i + 1 < argc) {
      handle_default_ttl(argv[++i]);
    } else if (strcmp(argv[i], "--verbose") == 0) {
      handle_verbose(NULL);
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "--h") == 0) {
      handle_help(NULL);
    }
  }
}

static bool config_load_file(const char *path) {
  int fd;
  struct stat sb;
  size_t file_size;
  char *data;
  char *start;
  char *end;

  fd = open(path, O_RDONLY);
  if (fd == -1) {
    if (errno != ENOENT) {
      logger_error("Failed to open config file: %s", path);
    }
    return false;
  }

  if (fstat(fd, &sb) == -1) {
    close(fd);
    return false;
  }

  if (sb.st_size == 0) {
    close(fd);
    return true;
  }

  file_size = (size_t)sb.st_size;
  data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    close(fd);
    return false;
  }

  start = data;
  end = data + file_size;

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
      int port;
      if (parse_int(value, &port)) config.port = port;
    } else if (strcmp(key, "default_user") == 0) {
      config_free_str(config.default_user);
      config.default_user = config_strdup(value);
    } else if (strcmp(key, "default_password") == 0) {
      config_free_str(config.default_password);
      config.default_password = config_strdup(value);
    } else if (strcmp(key, "max_memory_mb") == 0) {
      size_t mb;
      if (parse_size_t(value, &mb)) {
        config.max_memory_size_bytes = mb * TO_BYTES;
      }
    } else if (strcmp(key, "default_ttl") == 0) {
      int ttl;
      if (parse_int(value, &ttl)) config.default_ttl_sec = ttl;
    } else if (strcmp(key, "workers") == 0) {
      int workers;
      if (parse_int(value, &workers)) config.num_workers = workers;
    } else if (strcmp(key, "log_level") == 0) {
      config.log_level = logger_level_from_string(value);
    } else if (strcmp(key, "log_output") == 0) {
      config_free_str(config.log_output);
      config.log_output = config_strdup(value);
    }

    start = end_of_line + 1;
  }

  munmap(data, file_size);
  close(fd);
  return true;
}

void config_init(const int argc, char *argv[]) {
  if (pthread_mutex_init(&config.mutex, NULL) != 0) {
    logger_error("Failed to initialize config mutex");
    exit(1);
  }

  pthread_mutex_lock(&config.mutex);
  if (!config.is_init) {
    config_set_defaults();
    const char *config_path = get_config_path_from_cli(argc, argv);
    config_load_file(config_path);
    apply_cli_flags(argc, argv);

    config.is_init = true;
  }
  pthread_mutex_unlock(&config.mutex);
}

void config_destroy() {
  pthread_mutex_lock(&config.mutex);
  if (config.is_init) {
    config_free_str(config.default_user);
    config_free_str(config.default_password);
    config_free_str(config.log_output);
    config.is_init = false;
  }
  pthread_mutex_unlock(&config.mutex);
  pthread_mutex_destroy(&config.mutex);
}

bool config_set(const char *param, const char *value) {
  bool result;
  if (!param || !value) return false;

  pthread_mutex_lock(&config.mutex);
  if (!config.is_init) {
    pthread_mutex_unlock(&config.mutex);
    return false;
  }

  result = false;

  if (strcasecmp(param, "maxmemory") == 0) {
    size_t bytes;
    if (parse_size_t(value, &bytes)) {
      config.max_memory_size_bytes = bytes;
      result = true;
    }
  } else if (strcasecmp(param, "loglevel") == 0) {
    config.log_level = logger_level_from_string(value);
    result = true;
  } else if (strcasecmp(param, "requirepass") == 0) {
    config_free_str(config.default_password);
    config.default_password = config_strdup(value);
    result = true;
  }

  pthread_mutex_unlock(&config.mutex);
  return result;
}

// Getters
int config_get_port() { 
  return config.port; 
}

char *config_get_param(const char *param) {
  char *result;
  if (!param)
    return NULL;

  pthread_mutex_lock(&config.mutex);

  if (!config.is_init) {
    pthread_mutex_unlock(&config.mutex);
    return NULL;
  }

  result = NULL;
  if (strcasecmp(param, "maxmemory") == 0) {
    result = config_asprintf("%zu", config.max_memory_size_bytes);
  } else if (strcasecmp(param, "loglevel") == 0) {
    if (config.log_level == DEBUG) {
      result = config_strdup("debug");
    } else if (config.log_level == WARNING) {
      result = config_strdup("warning");
    } else if (config.log_level == ERROR) {
      result = config_strdup("error");
    } else {
      result = config_strdup("notice");  // Redis default for INFO
    }
  } else if (strcasecmp(param, "requirepass") == 0) {
    if (config.default_password) {
      result = config_strdup(config.default_password);
    } else {
      result = config_strdup("");
    }
  } else if (strcasecmp(param, "port") == 0) {
    result = config_asprintf("%d", config.port);
  } else if (strcasecmp(param, "maxmemory-policy") == 0) {
    result = config_strdup("noeviction");
  } else if (strcasecmp(param, "tcp-keepalive") == 0) {
    result = config_strdup("0");
  }

  pthread_mutex_unlock(&config.mutex);
  return result;
}

size_t config_get_max_memory_bytes() { 
  return config.max_memory_size_bytes; 
}

int config_get_default_ttl_sec() { 
  return config.default_ttl_sec; 
}

int config_get_workers() { 
  return config.num_workers; 
}

logger_level config_get_log_level() { 
  return config.log_level; 
}

char *config_get_log_output() { 
  return config.log_output; 
}

char *config_get_default_user() { 
  return config.default_user; 
}

char *config_get_default_password() { 
  return config.default_password; 
}
