#ifndef INCLUDE_LOGGER_H
#define INCLUDE_LOGGER_H

#define LOG_BUFFER_SIZE 1024
#define LEN_TIME 32
#define MSEC_IN_NSEC 1000000
#define PERMISSIONS 0644

typedef enum {
  DEBUG,
  INFO,
  WARNING,
  ERROR,
} logger_level;

void logger_init(const logger_level level, const char *logger_file);
void logger_destroy();
void logger_debug(const char *format, ...);
void logger_info(const char *format, ...);
void logger_warn(const char *format, ...);
void logger_error(const char *format, ...);
logger_level logger_level_from_string(const char *str);

#endif
