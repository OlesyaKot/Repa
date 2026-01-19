#include "storage.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "list.h"
#include "logger.h"

#define DEFAULT_CAPACITY 16
#define HASH_VALUE 5381
#define HASH_SHIFT 5
#define LOAD_FACTOR 0.75
#define UNUSED(x) (void)(x)

// The storage uses two data structures in tandem:
// 1. A hash table (buckets array) for efficient key lookup.
// 2. A doubly-linked list (lru_list)  for efficient LRU (Least Recently Used)
// eviction when memory is full.
// They provide O(1) average-time lookup and O(1) LRU update/eviction

// Expiration (TTL):
// 1. Lazy cleanup: expired keys are removed on GET/TTL access.
// 2. Background GC: a dedicated thread removes all expired keys every second.
// Memory eviction (LRU): synchronously in storage_set when memory limit is reached.

typedef struct kv_node {
  char *key;
  char *value;
  size_t key_size;
  size_t value_size;
  time_t expire_at; // 0 = never
  time_t last_use;
  struct kv_node *hash_next;
} kv_node;

typedef struct {
  kv_node **buckets; // hash-table (array of lists's pointers)
  size_t capacity;
  size_t size;
  size_t used_mem; 
  size_t max_mem;
  list *lru_list;
  pthread_mutex_t mutex;
} kv_store;

static kv_store store;

static pthread_t gc_thread;
static volatile bool gc_running = false;
static const int gc_interval_sec = 1;

static uint32_t get_hash(const char *str, const size_t len) {
  uint32_t hash = HASH_VALUE;
  for (size_t i = 0; i < len; i++) {
    hash = ((hash << HASH_SHIFT) + hash) + (unsigned char)str[i];
  }
  return hash;
}

static bool find_node_by_ptr(const void *data, const void *target) {
  return data == target;
}

static void lru_delete(kv_node *node) {
  if (!node || !store.lru_list) return;

  list_node *list_node = list_find(store.lru_list, find_node_by_ptr, node);
  if (list_node) {
    list_remove_node(store.lru_list, list_node, NULL);
  }
}

static void delete_node(kv_node *node) {
  if (!node) return;
  
  lru_delete(node);

  uint32_t idx = get_hash(node->key, node->key_size) % store.capacity;
  kv_node **prev = &store.buckets[idx];
  while (*prev) {
    if (*prev == node) {
      *prev = node->hash_next;
      break;
    }
    prev = &(*prev)->hash_next;
  }

  store.used_mem -= sizeof(kv_node) + node->key_size + node->value_size;
  free(node->key);
  free(node->value);
  free(node);
  store.size--;
}

static size_t cleanup_expired_nodes_sync(void) {
  time_t now = time(NULL);
  size_t cleaned = 0;

  list_node *node = list_get_tail(store.lru_list);
  while (node) {
    kv_node *key_val_node = (kv_node *)list_get_data(node);
    list_node *prev = list_get_prev(node);

    if (key_val_node && key_val_node->expire_at != 0 &&
        key_val_node->expire_at <= now) {
      delete_node(key_val_node);
      cleaned++;
    }
    node = prev;
  }

  return cleaned;
}

static bool evict_lru(const size_t needed) {
  size_t freed = 0;
  while (freed < needed) {
    list_node *tail = list_get_tail(store.lru_list);
    if (!tail) break; 

    kv_node *node = (kv_node *)list_get_data(tail);
    size_t entry_size = sizeof(kv_node) + node->key_size + node->value_size;

    delete_node(node);
    freed += entry_size;
  }
  return freed >= needed;
}

static void update_lru_position(kv_node *node) {
  if (!node || !store.lru_list) return;

  lru_delete(node);
  if (!list_push_front(store.lru_list, node)) {
    logger_error("Failed to update LRU position for key");
  }
  node->last_use = time(NULL);
}

static bool expand_table(void) {
  if (store.size < store.capacity * LOAD_FACTOR) return true;

  size_t new_capacity = store.capacity * 2;
  if (new_capacity == 0) new_capacity = DEFAULT_CAPACITY;

  size_t current_table_mem = store.capacity * sizeof(kv_node *);
  size_t new_table_mem = new_capacity * sizeof(kv_node *);

  if (new_table_mem > current_table_mem) {
    size_t additional_memory = new_table_mem - current_table_mem;

    if (store.used_mem + additional_memory > store.max_mem) {
      if (!evict_lru(additional_memory)) {
        logger_warn("Cannot expand table: not enough memory even after eviction");
        return false;
      }
    }
  }

  kv_node **new_buckets = calloc(new_capacity, sizeof(kv_node *));
  if (!new_buckets) {
    logger_error("Failed to allocate memory for expanded table");
    return false;
  }

  // Rehash
  for (size_t i = 0; i < store.capacity; i++) {
    kv_node *node = store.buckets[i];
    while (node) {
      kv_node *next = node->hash_next;
      uint32_t new_idx = get_hash(node->key, node->key_size) % new_capacity;
      node->hash_next = new_buckets[new_idx];
      new_buckets[new_idx] = node;
      node = next;
    }
  }

  free(store.buckets);
  store.buckets = new_buckets;
  store.capacity = new_capacity;
  return true;
}

static void *gc_thread_func(void *arg) {
  UNUSED(arg);
  logger_info("GC thread started");

  while (gc_running) {
    sleep(gc_interval_sec);

    if (!gc_running) break;

    pthread_mutex_lock(&store.mutex);
    size_t cleaned = cleanup_expired_nodes_sync();
    pthread_mutex_unlock(&store.mutex);

    if (cleaned > 0) {
      logger_debug("GC cleaned %zu expired keys", cleaned);
    }
  }

  logger_info("GC thread stopped");
  return NULL;
}

static void storage_start_gc(void) {
  if (gc_running) {
    logger_warn("GC thread already running");
    return;
  }

  gc_running = true;
  if (pthread_create(&gc_thread, NULL, gc_thread_func, NULL) != 0) {
    logger_error("Failed to start GC thread");
    gc_running = false;
    return;
  }
}

static void storage_stop_gc(void) {
  if (!gc_running) {
    return;
  }

  gc_running = false;
  pthread_join(gc_thread, NULL);
}

bool storage_init(const size_t max_memory_bytes) {
  if (max_memory_bytes <= 0){
    logger_error("Storage size is 0");
    return false;
  }

  if (pthread_mutex_init(&store.mutex, NULL) != 0) {
    logger_error("Failed to initialize storage mutex");
    return false;
  }
  store.capacity = DEFAULT_CAPACITY;
  store.size = 0;
  store.used_mem = 0;
  store.max_mem = max_memory_bytes;

  store.lru_list = list_create();
  if (!store.lru_list) {
    logger_error("Lru_list create failed");
    pthread_mutex_destroy(&store.mutex);
    return false;
  }

  store.buckets = calloc(sizeof(kv_node *), store.capacity);
  if (!store.buckets) {
    logger_error("Hash create failed");
    list_destroy(store.lru_list, NULL);
    pthread_mutex_destroy(&store.mutex);
    return false;
  }

  gc_running = false;
  logger_info("Storage initialized with max memory: %zu bytes", max_memory_bytes);

  storage_start_gc();
  return true;
}

void storage_destroy(void) {
  storage_stop_gc();

  pthread_mutex_lock(&store.mutex);
  for (size_t i = 0; i < store.capacity; ++i) {
    kv_node* node = store.buckets[i];
    while (node) {
      kv_node* next = node->hash_next;
      free(node->key);
      free(node->value);
      free(node);
      node = next;
    }
  }

  free(store.buckets);
  store.buckets = NULL;

  if (store.lru_list) {
    list_destroy(store.lru_list, NULL);
    store.lru_list = NULL;
  }
  store.capacity = 0;
  store.size = 0;
  store.used_mem = 0;

  pthread_mutex_unlock(&store.mutex);
  pthread_mutex_destroy(&store.mutex);
}

bool storage_set(const char *key, const size_t key_size, const char *value,
                 const size_t value_size, const int ttl_sec) {
  if (!key || !value) return false;

  int final_ttl = ttl_sec;
  if (final_ttl == 0) {
    final_ttl = config_get_default_ttl_sec();
  }

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *node = store.buckets[idx];
  size_t new_node_size = sizeof(kv_node) + key_size + value_size;
  size_t old_node_size = 0;
  size_t needed_mem = 0;

  while (node) {
    if (node->key_size == key_size && memcmp(node->key, key, key_size) == 0) {
      break;
    }
    node = node->hash_next;
  }

  if (node) {
    old_node_size = sizeof(kv_node) + node->key_size + node->value_size;
    if (new_node_size > old_node_size) {
      needed_mem = new_node_size - old_node_size;
    } else {
      needed_mem = 0;
    }
  } else {
    needed_mem = new_node_size;
  }

  if (store.used_mem + needed_mem > store.max_mem) {
    if (!evict_lru(needed_mem)) {
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
  }
  if (!expand_table()) {
    pthread_mutex_unlock(&store.mutex);
    return false;
  }

  idx = get_hash(key, key_size) % store.capacity;

  if (node) {
    free(node->value);
    node->value = malloc(value_size);
    if (!node->value) {
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    memcpy(node->value, value, value_size);
    node->value_size = value_size;
    node->expire_at = (final_ttl > 0) ? time(NULL) + final_ttl : 0;
    update_lru_position(node);
    store.used_mem += needed_mem;
  } else {
    kv_node* new_node = malloc(sizeof(kv_node));
    if (!new_node) {
      pthread_mutex_unlock(&store.mutex);
      return false;
    }

    new_node->key = malloc(key_size);
    if (!new_node->key) {
      free(new_node);
      pthread_mutex_unlock(&store.mutex);
      return false;
    }

    new_node->value = malloc(value_size);
    if (!new_node->value) {
      free(new_node->key);
      free(new_node);
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    memcpy(new_node->key, key, key_size);
    memcpy(new_node->value, value, value_size);
    new_node->key_size = key_size;
    new_node->value_size = value_size;
    new_node->expire_at = (final_ttl > 0) ? time(NULL) + final_ttl : 0;
    new_node->last_use = time(NULL);
    new_node->hash_next = (store.capacity > 0) ? store.buckets[idx] : NULL;

    if (!list_push_front(store.lru_list, new_node)) {
      logger_error("Failed to add new key to LRU");
      free(new_node->value);
      free(new_node->key);
      free(new_node);
      pthread_mutex_unlock(&store.mutex);
      return false;
    }

    store.buckets[idx] = new_node;
    store.used_mem += new_node_size;
    store.size++;
  }
  pthread_mutex_unlock(&store.mutex);
  return true;
}

char* storage_get(const char* key, const size_t key_size, size_t* out_value_len) {
  if (!key || !out_value_len) return NULL;

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *node = store.buckets[idx];

  while(node) {
    if (node->key_size == key_size && memcmp(node->key, key, key_size) == 0) {
      time_t now = time(NULL);
      if (node->expire_at != 0 && node->expire_at <= now) {
        // key expired
        delete_node(node);
        pthread_mutex_unlock(&store.mutex);
        return NULL;
      }

      update_lru_position(node);

      char *result = malloc(node->value_size);
      if (!result) {
        logger_error("storage_get: out of memory");
        pthread_mutex_unlock(&store.mutex);
        return NULL;
      }
      memcpy(result, node->value, node->value_size);
      *out_value_len = node->value_size;
      pthread_mutex_unlock(&store.mutex);
      return result;
    }
    node = node->hash_next;
  }
  pthread_mutex_unlock(&store.mutex);
  return NULL;
}

bool storage_del(const char* key, const size_t key_size) {
  if (!key) return false;

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node **prev = &store.buckets[idx];
  while(*prev) {
    if ((*prev)->key_size == key_size && memcmp((*prev)->key, key, key_size) == 0) {
      kv_node* del = *prev;
      delete_node(del);

      pthread_mutex_unlock(&store.mutex);
      return true;
    }
    prev = &(*prev)->hash_next;
  }
  pthread_mutex_unlock(&store.mutex);
  return false;
}

bool storage_set_expire(const char* key, const size_t key_size, const int ttl_sec) { 
  if (!key)
    return false;

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *needed_node = store.buckets[idx];
  while (needed_node) {
    if (memcmp(needed_node->key, key, key_size) == 0) {
      needed_node->expire_at = (ttl_sec > 0) ? time(NULL) + ttl_sec : 0;
      pthread_mutex_unlock(&store.mutex);
      return true;
    }
    needed_node = needed_node->hash_next;
  }
  pthread_mutex_unlock(&store.mutex);
  return false;
}

int storage_ttl(const char *key, const size_t key_size) {
  if (!key)
    return -1;

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *needed_node = store.buckets[idx];
  while (needed_node) {
    if (memcmp(needed_node->key, key, key_size) == 0) {
      time_t now = time(NULL);
      if (needed_node->expire_at == 0) {
        pthread_mutex_unlock(&store.mutex);
        return -1;
      }
      if (needed_node->expire_at <= now) {
        // key expired
        delete_node(needed_node);
        pthread_mutex_unlock(&store.mutex);
        return -1;
      }
      int ttl = (int)(needed_node->expire_at - now);
      pthread_mutex_unlock(&store.mutex);
      return ttl;
    }
    needed_node = needed_node->hash_next;
  }
  pthread_mutex_unlock(&store.mutex);
  return -1;
}

size_t storage_get_used_memory(void) {
  return store.used_mem;
}

size_t storage_get_max_memory(void) {
  return store.max_mem;
}

size_t storage_get_key_count(void) {
  return store.size;
}
