#ifndef INCLUDE_QUEUE_H
#define INCLUDE_QUEUE_H

void job_queue_init(void);
void job_queue_destroy(void);
void job_queue_push(void *data);
void *job_queue_pop(void);
void job_queue_stop_accepting(void);
void job_queue_free(void (*cleanup_func)(void *));

#endif
