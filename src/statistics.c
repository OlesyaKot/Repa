#define _GNU_SOURCE

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>

#include "statistics.h"
#include "storage.h"

typedef struct {
    uint64_t total_commands;
    uint64_t cmd_get;
    uint64_t cmd_set;
    uint64_t cmd_del;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t current_connections;
    uint64_t total_connections;
    time_t start_time;
    pthread_mutex_t mutex;
} statistics;

static statistics stats;

// transfer numbers to format with comma (ex. 1,256,844)
static void format_number(char* buffer, const size_t buf_size, const uint64_t number) {
  char src[LEN_NUM];
  int len;
  char res[LEN_NUM];
  int res_len = 0;
  int digit_count = 0;
  
  if (buf_size == 0)
    return;
  
  if (number == 0) {
    snprintf(buffer, buf_size, "0");
    return;
  }

  len = snprintf(src, sizeof(src), "%llu", (unsigned long long)number);
  if (len <= 0 || len >= (int)sizeof(src)) {
    snprintf(buffer, buf_size, "0");
    return;
  }

  for (int i = len - 1; i >= 0; i--) {
    if (digit_count > 0 && digit_count % LEN_BETWEEN_COMMAS == 0) {
      res[res_len++] = ',';
    }
    res[res_len++] = src[i];
    digit_count++;
  }

  for (int i = 0; i < res_len / 2; i++) {
    char tmp = res[i];
    res[i] = res[res_len - 1 - i];
    res[res_len - 1 - i] = tmp;
  }
  res[res_len] = '\0';

  snprintf(buffer, buf_size, "%s", res);
}

// transfer time to format Xh Ym Zs
static void format_time(char* buffer, const size_t buf_size, const time_t seconds) {
  if (seconds == 0) {
    snprintf(buffer, buf_size, "0s");
    return;
  }

  const long hours = seconds / SEC_IN_HOUR;
  const long minutes = (seconds % SEC_IN_HOUR) / SEC_IN_MINUTE;
  const long secs = seconds % SEC_IN_MINUTE;

  if (hours > 0) {
    snprintf(buffer, buf_size, "(%ldh %ldm %lds)", hours, minutes, secs);
  } else if (minutes > 0) {
    snprintf(buffer, buf_size, "(%ldm %lds)", minutes, secs);
  } else {
    snprintf(buffer, buf_size, "(%lds)", secs);
  }
}

void stats_init() {
  stats.total_commands = 0;
  stats.cmd_get = 0;
  stats.cmd_set = 0;
  stats.cmd_del = 0;
  stats.cache_hits = 0;
  stats.cache_misses = 0;
  stats.current_connections = 0;
  stats.total_connections = 0;
  stats.start_time = time(NULL);
  pthread_mutex_init(&stats.mutex, NULL); 
}

void stats_destroy() { 
  pthread_mutex_destroy(&stats.mutex);
}

void stats_inc_cmd_get() {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_get++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_set() {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_set++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_del() {
  pthread_mutex_lock(&stats.mutex);
  stats.cmd_del++;
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_cmd_other() {
  pthread_mutex_lock(&stats.mutex);
  stats.total_commands++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_hit() {
  pthread_mutex_lock(&stats.mutex);
  stats.cache_hits++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_miss() {
  pthread_mutex_lock(&stats.mutex);
  stats.cache_misses++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_inc_connection() {
  pthread_mutex_lock(&stats.mutex);
  stats.current_connections++;
  stats.total_connections++;
  pthread_mutex_unlock(&stats.mutex);
}

void stats_dec_connection() {
  pthread_mutex_lock(&stats.mutex);
  if (stats.current_connections > 0) {
    stats.current_connections--;
  }
  pthread_mutex_unlock(&stats.mutex);
}

char* stats_get_report() {
  char* buffer = mmap(NULL, REPORT_BUFFER_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) {
    return NULL;
  }

  pthread_mutex_lock(&stats.mutex);

  const uint64_t total_requests = stats.total_commands;
  const uint64_t total_cache = stats.cache_hits + stats.cache_misses;
  const double hit_ratio =
      (total_cache > 0) ? (stats.cache_hits * HUNDRED_PERSENT / total_cache)
                        : 0.0;
  const time_t uptime = time(NULL) - stats.start_time;
  const size_t used_mem = storage_get_used_memory();
  const size_t max_mem = storage_get_max_memory();

  char total_req_str[RES_BUF_SIZE], get_str[RES_BUF_SIZE],
      set_str[RES_BUF_SIZE], del_str[RES_BUF_SIZE];
  char hits_str[RES_BUF_SIZE], misses_str[RES_BUF_SIZE],
      used_mem_str[RES_BUF_SIZE], max_mem_str[RES_BUF_SIZE],
      curr_conn_str[RES_BUF_SIZE], total_conn_str[RES_BUF_SIZE];
  char uptime_str[RES_BUF_SIZE * 2];

  format_number(total_req_str, sizeof(total_req_str), total_requests);
  format_number(get_str, sizeof(get_str), stats.cmd_get);
  format_number(set_str, sizeof(set_str), stats.cmd_set);
  format_number(del_str, sizeof(del_str), stats.cmd_del);
  format_number(hits_str, sizeof(hits_str), stats.cache_hits);
  format_number(misses_str, sizeof(misses_str), stats.cache_misses);
  format_number(used_mem_str, sizeof(used_mem_str), (uint64_t)used_mem);
  format_number(max_mem_str, sizeof(max_mem_str), (uint64_t)max_mem);

  format_number(curr_conn_str, sizeof(curr_conn_str), stats.current_connections);
  format_number(total_conn_str, sizeof(total_conn_str), stats.total_connections);

  format_time(uptime_str, sizeof(uptime_str), uptime);

  const int len = snprintf(
      buffer, REPORT_BUFFER_SIZE,
      "STATS\n"
      "1. Requests\n"
      "  total_commands_processed      %14s\n"
      "  cmd_get                       %14s\n"
      "  cmd_set                       %14s\n"
      "  cmd_del                       %14s\n"
      "\n"
      "2. Cache\n"
      "  cache_hits                    %14s\n"
      "  cache_misses                  %14s\n"
      "  hit_ratio                     %14.1f%%\n"
      "\n"
      "3. Memory\n"
      "  used_memory_bytes        %14s  (0.0 / 0.0 MiB,  %14s)\n"  
      "\n"
      "4. Connections / Uptime\n"
      "  current_connections           %14s\n"
      "  total_connections_received    %14s\n"
      "  uptime_s                      %14jd  %s\n",
      total_req_str, get_str, set_str, del_str, hits_str, misses_str, hit_ratio,
      used_mem_str, max_mem_str, curr_conn_str, total_conn_str,
      (intmax_t)uptime, uptime_str);

  pthread_mutex_unlock(&stats.mutex);

  if (len < 0 || len >= REPORT_BUFFER_SIZE) {
    munmap(buffer, REPORT_BUFFER_SIZE);
    return NULL;
  }

  return buffer;
}
