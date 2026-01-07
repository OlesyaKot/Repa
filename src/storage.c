#define _GNU_SOURCE

#include <inttypes.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/mman.h>

#include "storage.h"
#include "logger.h"

// вытеснение по TTL - ленивое при GET/SET/DET - если ключ истек то удаляем
// вытеснение по памяти - синхронно при set - удаляем LRU

typedef struct kv_node {
  char *key;
  char *value;
  size_t key_size;
  size_t value_size;
  time_t expire_at; // 0 = never
  time_t last_use;
  struct kv_node *hash_next;
  struct kv_node *next;
  struct kv_node *prev;
} kv_node;

typedef struct {
  kv_node *head;     // most recently used 
  kv_node *tail;  
  kv_node **buckets; // hash-table (array of lists's pointers)
  size_t capacity;
  size_t size;
  size_t used_mem; 
  size_t max_mem; 
  pthread_mutex_t mutex;
} kv_store;

static kv_store store;

static uint32_t get_hash(const char *str, const size_t len) {
  uint32_t hash = HASH_VALUE;
  for (size_t i = 0; i < len; i++) {
    hash = ((hash << HASH_SHIFT) + hash) + str[i];
  }
  return hash;
}

static void *storage_alloc(const size_t size) {
  void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return (ptr == MAP_FAILED) ? NULL : ptr;
}

static void storage_free(void *ptr, const size_t len) {
  if (ptr && ptr != MAP_FAILED) {
    munmap(ptr, len);
  }
}

static void lru_delete(kv_node *node) {
  if (node->prev) {
    node->prev->next = node->next;
  } else {
    store.head = node->next;
  }
  if (node->next) {
    node->next->prev = node->prev;
  } else {
    store.tail = node->prev;
  }
  node->prev = node->next = NULL;
}

static void lru_add_to_head(kv_node *node) {
  node->prev = NULL;
  node->next = store.head;
  if (store.head) {
    store.head->prev = node;
  }
  store.head = node;
  if (!store.tail) {
    store.tail = node;
  }
}

static void delete_node(kv_node *node, const size_t size) {
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

  store.used_mem -= (size + node->key_size + node->value_size);
  storage_free(node->key, node->key_size);
  storage_free(node->value, node->value_size);
  storage_free(node, size);
  store.size--;
}

static bool evict_expire_nodes() {
  time_t now = time(NULL);
  bool evicted = false;
  kv_node* curr = store.tail;

  while (curr) {
    kv_node* prev = curr->prev;
    if (curr->expire_at != 0 && curr->expire_at <= now) {
      delete_node(curr, sizeof(kv_node));
      evicted = true;
    }
    curr = prev;
  }
  return evicted;
}

static bool evict_lru(const size_t needed) {
  size_t freed = 0;
  kv_node *curr = store.tail;

  while (curr && freed < needed) {
    kv_node *prev = curr->prev;
    if (curr->expire_at == 0 || curr->expire_at > time(NULL)) {
      size_t entry_size = sizeof(kv_node) + curr->key_size + curr->value_size;
      delete_node(curr, sizeof(kv_node));
      freed += entry_size;
    }
    curr = prev;
  }
  return freed >= needed;
}

static bool expand_table() {
  if (store.size < store.capacity * LOAD_FACTOR) return true;

  size_t new_capacity = store.capacity * 2;
  if (new_capacity == 0) new_capacity = DEFAULT_CAPACITY;

  kv_node **new_buckets = storage_alloc(new_capacity * sizeof(kv_node*));
  if (!new_buckets) return false;
  memset(new_buckets, 0, new_capacity * sizeof(kv_node *));

  // rehash
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

  storage_free(store.buckets, store.capacity * sizeof(kv_node *));
  store.buckets = new_buckets;
  store.capacity = new_capacity;
  return true;
}

bool storage_init(const size_t max_memory_bytes) {
  if (max_memory_bytes == 0)
    return false;

  pthread_mutex_init(&store.mutex, NULL);
  store.head = NULL;
  store.tail = NULL;
  store.capacity = DEFAULT_CAPACITY;
  store.size = 0;
  store.used_mem = 0;
  store.max_mem = max_memory_bytes;

  store.buckets = storage_alloc(store.capacity * sizeof(kv_node*));
  if (!store.buckets) {
    pthread_mutex_destroy(&store.mutex);
    return false;
  }
  memset(store.buckets, 0, store.capacity * sizeof(kv_node*));

  return true;
}

void storage_destroy() {
  pthread_mutex_lock(&store.mutex);
  for (size_t i = 0; i < store.capacity; ++i) {
    kv_node* node = store.buckets[i];
    while (node) {
      kv_node* next = node->hash_next;
      storage_free(node->key, node->key_size);
      storage_free(node->value, node->value_size);
      storage_free(node, sizeof(kv_node));
      node = next;
    }
  }
  if (store.buckets) {
    storage_free(store.buckets, store.capacity * sizeof(kv_node *));
  }
  pthread_mutex_unlock(&store.mutex);
  pthread_mutex_destroy(&store.mutex);
}

bool storage_set(const char* key, const size_t key_size, const char* value, const size_t value_size, const int ttl_sec) {
  if (!key || !value) return false;

  pthread_mutex_lock(&store.mutex);

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *node = NULL;
  size_t new_node_size = 0;
  size_t old_node_size = 0;
  size_t needed_mem = 0;
  kv_node *new_node;

  if (store.buckets) {
    node = store.buckets[idx];
    while(node) {
      if (node->key_size == key_size && memcmp(node->key, key, key_size) == 0) {
        break;
      }
      node = node->hash_next;
    }
  }

  new_node_size = sizeof(kv_node) + key_size + value_size;
  if (node) {
    old_node_size = sizeof(kv_node) + node->key_size + node->value_size;
  }

  needed_mem = (node) ? (new_node_size - old_node_size) : new_node_size;

  evict_expire_nodes();
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

  if (node) {
    storage_free(node->value, node->value_size);
    node->value = storage_alloc(value_size);
    if (!node->value) {
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    memcpy(node->value, value, value_size);
    node->value_size = value_size;
    node->expire_at = (ttl_sec > 0) ? time(NULL) + ttl_sec : 0;
    node->last_use = time(NULL);
    lru_delete(node);
    lru_add_to_head(node);
    store.used_mem += needed_mem;
  } else {
    new_node = storage_alloc(sizeof(kv_node));
    if (!new_node){
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    new_node->key = storage_alloc(key_size);
    if (!new_node->key) {
      storage_free(new_node, sizeof(kv_node));
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    new_node->value = storage_alloc(value_size);
    if (!new_node->value) {
      storage_free(new_node, sizeof(kv_node));
      storage_free(new_node->key, new_node->key_size);
      pthread_mutex_unlock(&store.mutex);
      return false;
    }
    memcpy(new_node->key, key, key_size);
    memcpy(new_node->value, value, value_size);
    new_node->key_size = key_size;
    new_node->value_size = value_size;
    new_node->expire_at = (ttl_sec > 0) ? time(NULL) + ttl_sec : 0;
    new_node->last_use = time(NULL);
    new_node->hash_next = (store.capacity > 0) ? store.buckets[idx] : NULL;
    new_node->next = new_node->prev = NULL;
    if (store.capacity > 0) {
      store.buckets[idx] = new_node;
    }
    lru_add_to_head(new_node);
    store.used_mem += new_node_size;
    store.size++;
  }
  pthread_mutex_unlock(&store.mutex);
  return true;
}

char* storage_get(const char* key, const size_t key_size, size_t* out_value_len) {
  if (!key || !out_value_len) return NULL;

  pthread_mutex_lock(&store.mutex);

  if (store.capacity == 0 || !store.buckets) {
    pthread_mutex_unlock(&store.mutex);
    return NULL;
  }

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node *node = store.buckets[idx];

  while(node) {
    if (node->key_size == key_size && memcmp(node->key, key, key_size) == 0) {
      time_t now = time(NULL);
      if (node->expire_at != 0 && node->expire_at <= now) {
        // key expired
        delete_node(node, sizeof(kv_node));
        pthread_mutex_unlock(&store.mutex);
        return NULL;
      }

      lru_delete(node);
      lru_add_to_head(node);
      node->last_use = now;

      const size_t node_vel_size = node->value_size;
      char *result = storage_alloc(node_vel_size);
      if (result) {
        memcpy(result, node->value, node_vel_size);
        *out_value_len = node_vel_size;
      }
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

  if (store.capacity == 0 || !store.buckets) {
    pthread_mutex_unlock(&store.mutex);
    return false;
  }

  uint32_t idx = get_hash(key, key_size) % store.capacity;
  kv_node **prev = &store.buckets[idx];
  while(*prev) {
    if ((*prev)->key_size == key_size && memcmp((*prev)->key, key, key_size) == 0) {
      kv_node* del = *prev;
      *prev = del->hash_next;
      lru_delete(del);
      store.used_mem -= (sizeof(kv_node) + del->key_size + del->value_size);
      storage_free(del->key, del->key_size);
      storage_free(del->value, del->value_size);
      storage_free(del, sizeof(kv_node));
      store.size--;
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

  if (store.capacity == 0 || !store.buckets) {
    pthread_mutex_unlock(&store.mutex);
    return false;
  }

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
  pthread_mutex_lock(&store.mutex);
  return false;
}

// return value: -1 = no expire; -2 = not found
int storage_ttl(const char *key, const size_t key_size) {
  if (!key)
    return -1;

  pthread_mutex_lock(&store.mutex);
  if (store.capacity == 0 || !store.buckets) {
    pthread_mutex_unlock(&store.mutex);
    return -1;
  }

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
        delete_node(needed_node, sizeof(kv_node));
        pthread_mutex_unlock(&store.mutex);
        return -2;
      }
      int ttl = (int)(needed_node->expire_at - now);
      pthread_mutex_unlock(&store.mutex);
      return ttl;
    }
    needed_node = needed_node->hash_next;
  }
  pthread_mutex_unlock(&store.mutex);
  return -2;
}

size_t storage_get_used_memory() {
  pthread_mutex_lock(&store.mutex);
  size_t memory = store.used_mem;
  pthread_mutex_unlock(&store.mutex);
  return memory;
}

size_t storage_get_max_memory() {
  pthread_mutex_lock(&store.mutex);
  size_t memory = store.max_mem;
  pthread_mutex_unlock(&store.mutex);
  return memory;
}

size_t storage_get_key_count() {
  pthread_mutex_lock(&store.mutex);
  size_t count = store.size;
  pthread_mutex_unlock(&store.mutex);
  return count;
}
