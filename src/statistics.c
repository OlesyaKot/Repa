#include "statistics.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include "logger.h"
#include "storage.h"

#define SEC_IN_HOUR 3600
#define SEC_IN_MINUTE 60
#define LEN_NUM 40
#define LEN_BETWEEN_COMMAS 3
#define REPORT_BUFFER_SIZE (8 * 1024)
#define RES_BUF_SIZE 64
#define HUNDRED_PERSENT 100.0
#define TO_BYTES (1024.0 * 1024.0)

typedef struct {
  uint64_t total_commands;
  uint64_t cmd_get;
  uint64_t cmd_set;
  uint64_t cmd_del;
  uint64_t cmd_other;
  uint64_t cache_hits;
  uint64_t cache_misses;
  uint64_t current_connections;
  uint64_t total_connections;
  time_t start_time;
  pthread_mutex_t mutex;
} statistics;

static statistics stats;

// transfer numbers to format with comma (ex. 1,256,844)
static bool format_number(char* buffer, const size_t buf_size, const uint64_t number) {
  if (buf_size == 0) return false;

  char src[LEN_NUM] = {0};
  int len;
  char res[LEN_NUM] = {0};
  int res_len = 0;
  int digit_count = 0;
  
  if (number == 0) {
    if (snprintf(buffer, buf_size, "0") < 0) {
      return false;
    }
    return true;
  }

  len = snprintf(src, sizeof(src), "%" PRIu64, number);
  if (len <= 0 || len >= (int)sizeof(src)) {
    snprintf(buffer, buf_size, "0");
    return false;
  }

  for (int i = len - 1; i >= 0; i--) {
    if (digit_count > 0 && digit_count % LEN_BETWEEN_COMMAS == 0) {
      if (res_len >= (int)sizeof(res) - 1) return false;
      res[res_len++] = ',';
    }

    if (res_len >= (int)sizeof(res) - 1) return false;
    res[res_len++] = src[i];
    digit_count++;
  }

  for (int i = 0; i < res_len / 2; i++) {
    char tmp = res[i];
    res[i] = res[res_len - 1 - i];
    res[res_len - 1 - i] = tmp;
  }
  res[res_len] = '\0';

  if (snprintf(buffer, buf_size, "%s", res) < 0) return false;
  
  return true;
}

// transfer time to format Xh Ym Zs
static bool format_time(char* buffer, const size_t buf_size, const time_t seconds) {
  if (seconds == 0) {
    if (snprintf(buffer, buf_size, "0s") < 0) return false;
    return true;
  }

  const long hours = seconds / SEC_IN_HOUR;
  const long minutes = (seconds % SEC_IN_HOUR) / SEC_IN_MINUTE;
  const long secs = seconds % SEC_IN_MINUTE;

  int written;
  if (hours > 0) {
    written = snprintf(buffer, buf_size, "(%ldh %ldm %lds)", hours, minutes, secs);
  }
  else if (minutes > 0) {
    written = snprintf(buffer, buf_size, "(%ldm %lds)", minutes, secs);
  }
  else {
    written = snprintf(buffer, buf_size, "(%lds)", secs);
  }

  return written > 0 && (size_t)written < buf_size;
}

void stats_init(void) {
  memset(&stats, 0, sizeof(stats));
  stats.start_time = time(NULL);

  if (pthread_mutex_init(&stats.mutex, NULL) != 0) {
    logger_error("Failed to initialize statistics mutex");
    exit(1);
  }

  logger_info("Statistics initialized");
}

void stats_destroy(void) { 
  pthread_mutex_destroy(&stats.mutex);
}

void stats_inc_cmd_get(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_get++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_set(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_set++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_del(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_del++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_other(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_other++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_hit(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cache_hits++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_miss(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.cache_misses++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_connection(void) {
  pthread_mutex_lock(&stats.mutex);
  stats.current_connections++;
  stats.total_connections++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_dec_connection(void) {
  pthread_mutex_lock(&stats.mutex);
  if (stats.current_connections > 0) {
    stats.current_connections--;
  }
  pthread_mutex_unlock(&stats.mutex);
}

char* stats_get_report(void) {
  char* buffer = malloc(REPORT_BUFFER_SIZE);
  if (!buffer) {
    logger_error("Failed to allocate memory for stats report");
    return NULL;
  }

  pthread_mutex_lock(&stats.mutex);

  const uint64_t total_requests = stats.total_commands;
  const uint64_t total_cache = stats.cache_hits + stats.cache_misses;
  const double hit_ratio =
      (total_cache > 0) ? (stats.cache_hits * HUNDRED_PERSENT / total_cache) : 0.0;
  const time_t uptime = time(NULL) - stats.start_time;
  const size_t used_mem = storage_get_used_memory();
  const size_t max_mem = storage_get_max_memory();
  const size_t key_count = storage_get_key_count();

  char total_req_str[RES_BUF_SIZE], get_str[RES_BUF_SIZE],
      set_str[RES_BUF_SIZE], del_str[RES_BUF_SIZE], other_str[RES_BUF_SIZE];
  char hits_str[RES_BUF_SIZE], misses_str[RES_BUF_SIZE],
      used_mem_str[RES_BUF_SIZE], key_count_str[RES_BUF_SIZE];
  char curr_conn_str[RES_BUF_SIZE], total_conn_str[RES_BUF_SIZE];
  char uptime_str[RES_BUF_SIZE * 2];

  bool format_ok = true;
  format_ok = format_ok && format_number(total_req_str, sizeof(total_req_str), total_requests);
  format_ok = format_ok && format_number(get_str, sizeof(get_str), stats.cmd_get);
  format_ok = format_ok && format_number(set_str, sizeof(set_str), stats.cmd_set);
  format_ok = format_ok && format_number(del_str, sizeof(del_str), stats.cmd_del);
  format_ok = format_ok && format_number(other_str, sizeof(other_str), stats.cmd_other);
  format_ok = format_ok && format_number(hits_str, sizeof(hits_str), stats.cache_hits);
  format_ok = format_ok && format_number(misses_str, sizeof(misses_str), stats.cache_misses);
  format_ok = format_ok && format_number(used_mem_str, sizeof(used_mem_str), (uint64_t)used_mem);
  format_ok = format_ok && format_number(key_count_str, sizeof(key_count_str), (uint64_t)key_count);
  format_ok = format_ok && format_number(curr_conn_str, sizeof(curr_conn_str), stats.current_connections);
  format_ok = format_ok && format_number(total_conn_str, sizeof(total_conn_str), stats.total_connections);
  format_ok = format_ok && format_time(uptime_str, sizeof(uptime_str), uptime);

  if (!format_ok) {
    pthread_mutex_unlock(&stats.mutex);
    free(buffer);
    logger_error("Failed to format statistics");
    return NULL;
  }

  double used_mb = used_mem / TO_BYTES;
  double max_mb = max_mem / TO_BYTES;
  double pct = (max_mem > 0) ? (used_mb / max_mb * HUNDRED_PERSENT) : 0.0;

  const int len = snprintf(
      buffer, REPORT_BUFFER_SIZE,
      "STATS\n"
      "1. Requests\n"
      "  total_commands_processed      %14s\n"
      "  cmd_get                       %14s\n"
      "  cmd_set                       %14s\n"
      "  cmd_del                       %14s\n"
      "  cmd_other                     %14s\n"
      "\n"
      "2. Cache\n"
      "  cache_hits                    %14s\n"
      "  cache_misses                  %14s\n"
      "  hit_ratio                     %14.1f%%\n"
      "\n"
      "3. Memory\n"
      "  used_memory_bytes        %14s  (%.1f / %.1f MiB,  %.0f%%)\n"
      "  total_keys                %14s\n"
      "\n"
      "4. Connections / Uptime\n"
      "  current_connections           %14s\n"
      "  total_connections_received    %14s\n"
      "  uptime_s                      %14jd  %s\n",
      total_req_str, get_str, set_str, del_str, other_str, hits_str, misses_str,
      hit_ratio, used_mem_str, used_mb, max_mb, pct, key_count_str,
      curr_conn_str, total_conn_str, (intmax_t)uptime, uptime_str);

  pthread_mutex_unlock(&stats.mutex);

  if (len < 0 || len >= REPORT_BUFFER_SIZE) {
    free(buffer);
    logger_error("Stats report buffer overflow");
    return NULL;
  }
  return buffer;
}
