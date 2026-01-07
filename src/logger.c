#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "logger.h"

static struct {
    logger_level level;
    int fd;   // -1 - if output is stdout
    pthread_mutex_t file_mutex;
    bool is_init;
} logger_stat;

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

void logger_init(const logger_level level, const char *logger_file) {
  pthread_mutex_lock(&init_mutex);

  if (logger_stat.is_init) {
    pthread_mutex_unlock(&init_mutex);
    return;
  }

  logger_stat.level = level;
  if (logger_file && logger_file[0] != '\0') {
    int fd = open(logger_file, O_WRONLY | O_CREAT | O_APPEND, PERMISSIONS);
    if (fd == -1) {
      // error - use stderr
      logger_stat.fd = STDERR_FILENO;
      const char err_message[] = "[logger] Failed to open log file, using stderr\n";
      write(logger_stat.fd, err_message, sizeof(err_message) - 1);
    } else {
      logger_stat.fd = fd;
    }
  } else {
    logger_stat.fd = STDOUT_FILENO;
  }

  pthread_mutex_init(&logger_stat.file_mutex, NULL);
  logger_stat.is_init = true;
  pthread_mutex_unlock(&init_mutex);
}

void logger_destroy() {
  pthread_mutex_lock(&init_mutex);
  if (!logger_stat.is_init) {
    pthread_mutex_unlock(&init_mutex);
    return;
  }

  if (logger_stat.fd >= 0 && logger_stat.fd != STDOUT_FILENO && logger_stat.fd != STDERR_FILENO) {
      close(logger_stat.fd);
      pthread_mutex_unlock(&init_mutex);
    }

    logger_stat.is_init = false;
    logger_stat.fd = -1;
    logger_stat.level = INFO;

    pthread_mutex_unlock(&init_mutex);
  }

static const char *level_to_str(const logger_level level){
  switch (level){
    case DEBUG:
      return "DEBUG";
    case INFO:
      return "INFO";
    case WARNING:
      return "WARNING";
    case ERROR:
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

static void logger_write(const logger_level level, const char *format, va_list args) {
  if (!logger_stat.is_init) return;
  if (level < logger_stat.level) return;

  char *buffer = mmap(NULL, LOG_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) return;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  time_t now = ts.tv_sec;
  struct tm tm_info;
  localtime_r(&now, &tm_info);

  char time_str[LEN_TIME];
  strftime(time_str, LEN_TIME, "%d %b %H:%M:%S", &tm_info);
  int msec = (int)(ts.tv_nsec / MSEC_IN_NSEC);
  pid_t pid = getpid();

  int len = snprintf(buffer, LOG_BUFFER_SIZE, "[%d] %s.%03d # %s: ", (int)pid,
                     time_str, msec, level_to_str(level));

  if (len > 0 && len < LOG_BUFFER_SIZE - 1) {
    int msg_len = vsnprintf(buffer + len, LOG_BUFFER_SIZE - len, format, args);
    if (msg_len > 0) {
      len += msg_len;
    }
  }

  if (len < LOG_BUFFER_SIZE - 1) {
    buffer[len++] = '\n';
  }

  pthread_mutex_lock(&logger_stat.file_mutex);
  write(logger_stat.fd, buffer, len);
  pthread_mutex_unlock(&logger_stat.file_mutex);

  munmap(buffer, LOG_BUFFER_SIZE);
}

void logger_debug(const char *format, ...) {
  va_list args;
  va_start(args, format);
  logger_write(DEBUG, format, args);
  va_end(args);
}

void logger_info(const char *format, ...) {
  va_list args;
  va_start(args, format);
  logger_write(INFO, format, args);
  va_end(args);
}

void logger_warn(const char *format, ...) {
  va_list args;
  va_start(args, format);
  logger_write(WARNING, format, args);
  va_end(args);
}

void logger_error(const char *format, ...) {
  va_list args;
  va_start(args, format);
  logger_write(ERROR, format, args);
  va_end(args);
}

logger_level logger_level_from_string(const char *str) {
  if (!str) return INFO;
  if (strcasecmp(str, "debug") == 0) return DEBUG;
  if (strcasecmp(str, "verbose") == 0) return DEBUG;
  if (strcasecmp(str, "info") == 0) return INFO;
  if (strcasecmp(str, "notice") == 0) return INFO; 
  if (strcasecmp(str, "warning") == 0) return WARNING;
  if (strcasecmp(str, "error") == 0) return ERROR;
  return INFO;
}
