#ifndef INCLUDE_STORAGE_H
#define INCLUDE_STORAGE_H

#include <stdlib.h>
#include <stdbool.h>

#define DEFAULT_CAPACITY 16
#define HASH_VALUE 5381
#define HASH_SHIFT 5

bool storage_init(const size_t max_memory_bytes);
void storage_destroy();
bool storage_set(const char *key, const size_t key_size, const char *value,
     const size_t value_size, const int ttl_sec);
char *storage_get(const char *key, const size_t key_size, size_t *out_value_len);
bool storage_del(const char *key, const size_t key_size);
bool storage_set_expire(const char *key, const size_t key_size, const int ttl_sec);
int storage_ttl(const char *key, const size_t key_size);
size_t storage_get_used_memory();
size_t storage_get_max_memory();
size_t storage_get_key_count();

#endif
