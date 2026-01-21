#ifndef INCLUDE_LIST_H
#define INCLUDE_LIST_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct node {
  void *data;
  struct node *next;
  struct node *prev;
} list_node;

typedef struct {
  list_node *head;
  list_node *tail;
  size_t size;
} list;

list *list_create(void);
void list_destroy(list *list, void (*free_data)(void *));
bool list_push_front(list *list, void *data);
bool list_remove_node(list *list, list_node *node, void (*free_data)(void *));
list_node *list_get_tail(const list *list);
list_node *list_get_next(const list_node *node);
list_node *list_get_prev(const list_node *node);
void *list_get_data(const list_node *node);
size_t get_list_size(const list *list);
list_node *list_find(const list *list, bool (*predicate)(const void *data, const void *ctx),
                     const void *ctx);
#endif
