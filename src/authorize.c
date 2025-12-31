#define _GNU_SOURCE

#include <pthread.h>
#include <stdbool.h>
#include <strings.h>
#include <string.h>
#include <sys/mman.h>

#include "config.h"
#include "authorize.h"

typedef struct {
  char* user;
  char* password;
  pthread_rwlock_t lock;
  bool is_initialized;
} authorization;

static authorization server_auth;

static bool safe_strcmp(const char* a, const char* b) {
  if (!a && !b) return true;
  if (!a || !b) return false;
  return strcmp(a, b) == 0;
}

static char* auth_strdup(const char* str) {
  if (!str) return NULL;
  size_t len = strlen(str) + 1;
  char* copy = mmap(NULL, len, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (copy == MAP_FAILED) return NULL;
  memcpy(copy, str, len);
  return copy;
}

static void free_str(char* str) {
  if (str && str != MAP_FAILED) {
    munmap(str, strlen(str) + 1);
  }
}

void authorize_init() {
  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    pthread_rwlock_unlock(&server_auth.lock);
    return;
  }

  const char* user = config_get_default_user();
  const char* password = config_get_default_password();

  server_auth.user = auth_strdup(user);
  server_auth.password = auth_strdup(password);
  server_auth.is_initialized = true;

  logger_info("Autorization initialized: user='%s", user);

  pthread_rwlock_unlock(&server_auth.lock);
}

void authorize_destroy() { 
  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    free_str(server_auth.user);
    free_str(server_auth.password);
    server_auth.is_initialized = false;
  }

  pthread_rwlock_unlock(&server_auth.lock);
}

void authorize_set_password(const char* new_password) {
  if (!new_password)
    return;

  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    free_str(server_auth.password);
    server_auth.password = auth_strdup(new_password);
    logger_info("Password updated via CONFIG SET");
  }

  pthread_rwlock_unlock(&server_auth.lock);
}

bool authorize_check_auth(const char* username, const char* password) {
  if (!username || !password)
    return false;

  pthread_rwlock_wrlock(&server_auth.lock);

  bool result = false;
  if (server_auth.is_initialized) {
    bool user_ok = (strcasecmp(username, server_auth.user) == 0);
    bool pass_ok = safe_strcmp(password, server_auth.password);
    result = user_ok && pass_ok;
  }

  pthread_rwlock_unlock(&server_auth.lock);
  return result;
}

bool authorize_is_command_allow_unauth(const char* cmd) {
  if (!cmd) return false;

  const char* allowed[] = {"HELLO", "AUTH", "PING", "QUIT", NULL};

  for (int i = 0; allowed[i] != NULL; i++) {
    if (strcasecmp(cmd, allowed[i]) == 0) {
      return true;
    }
  }
  return false;
}
