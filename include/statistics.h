#ifndef INCLUDE_STATISTICS_H
#define INCLUDE_STATISTICS_H

void stats_init(void);
void stats_destroy(void);
void stats_inc_cmd_get(void);
void stats_inc_cmd_set(void);
void stats_inc_cmd_del(void);
void stats_inc_cmd_other(void);
void stats_inc_hit(void);
void stats_inc_miss(void);
void stats_inc_connection(void);
void stats_dec_connection(void);
char *stats_get_report(void);

#endif
