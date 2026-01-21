#include "queue.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "logger.h"

typedef struct job_node {
  void *data;
  struct job_node *next;
} job_node;

static struct {
  job_node *head;
  job_node *tail;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  bool accepting_jobs;
  bool destroyed;
} queue;

void job_queue_init(void) {
  queue.head = NULL;
  queue.tail = NULL;
  queue.accepting_jobs = true;
  queue.destroyed = false;
  if (pthread_mutex_init(&queue.mutex, NULL) != 0) {
    logger_error("Failed to init queue mutex");
    return;
  }

  if (pthread_cond_init(&queue.cond, NULL) != 0) {
    logger_error("Failed to init queue cond var");
    pthread_mutex_destroy(&queue.mutex);
    return;
  }

  logger_debug("Job queue initialized");
}

void job_queue_destroy(void) {
  if (queue.destroyed)
    return;

  pthread_mutex_lock(&queue.mutex);

  queue.accepting_jobs = false;
  queue.destroyed = true;

  pthread_cond_broadcast(&queue.cond);

  job_node *node = queue.head;
  while (node) {
    job_node *next = node->next;
    free(node);
    node = next;
  }

  queue.head = NULL;
  queue.tail = NULL;

  pthread_mutex_unlock(&queue.mutex);

  pthread_mutex_destroy(&queue.mutex);
  pthread_cond_destroy(&queue.cond);

  logger_debug("Job queue destroyed");
}

void job_queue_push(void *data) {
  if (!data) return;

  pthread_mutex_lock(&queue.mutex);

  if (!queue.accepting_jobs || queue.destroyed) {
    pthread_mutex_unlock(&queue.mutex);
    logger_debug("Queue not accepting jobs, discarding data");
    return;
  }

  job_node *node = malloc(sizeof(job_node));
  if (!node) {
    pthread_mutex_unlock(&queue.mutex);
    logger_error("Failed to allocate job queue node");
    return;
  }

  node->data = data;
  node->next = NULL;

  if (queue.tail) {
    queue.tail->next = node;
  } else {
    queue.head = node;
  }
  queue.tail = node;

  pthread_cond_signal(&queue.cond);
  pthread_mutex_unlock(&queue.mutex);
}

void *job_queue_pop(void) {
  pthread_mutex_lock(&queue.mutex);

  while (queue.head == NULL && queue.accepting_jobs && !queue.destroyed) {
    pthread_cond_wait(&queue.cond, &queue.mutex);
  }

  if (queue.head == NULL) {
    pthread_mutex_unlock(&queue.mutex);
    return NULL;
  }

  job_node *node = queue.head;
  queue.head = node->next;
  if (!queue.head) {
    queue.tail = NULL;
  }

  void *data = node->data;
  free(node);

  pthread_mutex_unlock(&queue.mutex);
  return data;
}

void job_queue_stop_accepting(void) {
  pthread_mutex_lock(&queue.mutex);

  if (!queue.accepting_jobs) {
    pthread_mutex_unlock(&queue.mutex);
    return;
  }

  queue.accepting_jobs = false;

  pthread_cond_broadcast(&queue.cond);
  pthread_mutex_unlock(&queue.mutex);

  logger_debug("Job queue stopped accepting new jobs");
}

void job_queue_free(void (*cleanup_func)(void *)) {
  pthread_mutex_lock(&queue.mutex);

  while (queue.head) {
    job_node *node = queue.head;
    queue.head = node->next;
    if (!queue.head) {
      queue.tail = NULL;
    }

    if (cleanup_func) {
      cleanup_func(node->data);  
    }
    free(node);
  }

  pthread_mutex_unlock(&queue.mutex);
}
