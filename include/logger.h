#ifndef INCLUDE_LOGGER_H
#define INCLUDE_LOGGER_H

typedef enum {
  DEBUG,
  INFO,
  WARNING,
  ERROR,
} logger_level;

void logger_init(const logger_level level, const char *logger_file);
void logger_destroy(void);
void logger_debug(const char *format, ...);
void logger_info(const char *format, ...);
void logger_warn(const char *format, ...);
void logger_error(const char *format, ...);
logger_level logger_level_from_string(const char *str);

#endif
