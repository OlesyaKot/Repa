#include "list.h"

list* list_create(void) {
  list *l = malloc(sizeof(list));
  if (!l)
    return NULL;
  l->head = NULL;
  l->tail = NULL;
  l->size = 0;
  return l;
}

void list_destroy(list * list, void (*free_data)(void*)){
  if (!list)
    return;

  list_node* node = list->head;
  while (node) {
    list_node* next = node->next;

    if (free_data && node->data) {
      free_data(node->data);
    }
    free(node);
    node = next;
  }
  free(list);
}

bool list_push_front(list* list, void* data) {
  if (!list)
    return false;

  list_node *node = malloc(sizeof(list_node));
  if (!node)
    return false;
  node->data = data;
  node->next = list->head;
  node->prev = NULL;

  if (list->head) {
    list->head->prev = node;
  } else {
    list->tail = node;
  }

  list->head = node;
  list->size++;
  return true;
}

bool list_remove_node(list* list, list_node* node, void (*free_data)(void*)) {
  if (!list || !node) return false;

  if (node->prev) {
    node->prev->next = node->next;
  } else {
    list->head = node->next;
  }

  if (node->next) {
    node->next->prev = node->prev;
  } else {
    list->tail = node->prev;
  }

  if (free_data && node->data) {
    free_data(node->data);
  }
  free(node);
  list->size--;
  return true;
}

list_node* list_get_tail(const list* list) {
  return list ? list->tail : NULL;
}

list_node* list_get_next(const list_node* node) {
  return node ? node->next : NULL;
}

list_node* list_get_prev(const list_node* node) {
   return node ? node->prev : NULL;
}

void* list_get_data(const list_node* node) {
  return node ? node->data : NULL;
}

size_t get_list_size(const list* list) { 
  return list ? list->size : 0; 
}

list_node* list_find(const list* list, bool (*predicate)(const void* data, const void* ctx), const void* ctx) {
  if (!list || !predicate) 
    return NULL;

  for (list_node* node = list->head; node; node = node->next) {
    if (predicate(node->data, ctx)) {
      return node;
    }
  }
  return NULL;
}
