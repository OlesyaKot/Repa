#ifndef INCLUDE_STATISTICS_H
#define INCLUDE_STATISTICS_H

#define SEC_IN_HOUR 3600
#define SEC_IN_MINUTE 60
#define LEN_NUM 40
#define LEN_BETWEEN_COMMAS 3
#define REPORT_BUFFER_SIZE (8 * 1024)
#define RES_BUF_SIZE 32
#define HUNDRED_PERSENT 100.0

void stats_init();
void stats_destroy();
void stats_inc_cmd_get();
void stats_inc_cmd_set();
void stats_inc_cmd_del();
void stats_inc_cmd_other();
void stats_inc_hit();
void stats_inc_miss();
void stats_inc_connection();
void stats_dec_connection();
char *stats_get_report();

#endif
