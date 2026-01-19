#define _GNU_SOURCE

#include "authorize.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "logger.h"

typedef struct {
  char* user;
  char* password;
  pthread_rwlock_t lock;
  bool is_initialized;
} authorization;

static authorization server_auth;

void authorize_init(void) {
  if (pthread_rwlock_init(&server_auth.lock, NULL) != 0) {
    logger_error("Failed to initialize auth rwlock");
    return;
  }

  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    pthread_rwlock_unlock(&server_auth.lock);
    return;
  }

  const char* user = config_get_default_user();
  const char* password = config_get_default_password();

  server_auth.user = strdup(user);
  if (!server_auth.user) {
    pthread_rwlock_unlock(&server_auth.lock);
    return;
  }
  server_auth.password = strdup(password);
  if (!server_auth.password) {
    free(server_auth.user);
    pthread_rwlock_unlock(&server_auth.lock);
    return;
  }
  server_auth.is_initialized = true;

  logger_info("Authorization initialized: user='%s'", user);

  pthread_rwlock_unlock(&server_auth.lock);
}

void authorize_destroy(void) { 
  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    free(server_auth.user);
    free(server_auth.password);
    server_auth.user = NULL;
    server_auth.password = NULL;
    server_auth.is_initialized = false;
  }

  pthread_rwlock_unlock(&server_auth.lock);
  pthread_rwlock_destroy(&server_auth.lock);
}

void authorize_set_password(const char* new_password) {
  if (!new_password)
    return;

  pthread_rwlock_wrlock(&server_auth.lock);

  if (server_auth.is_initialized) {
    char* new_pass_copy = strdup(new_password);
    if (!new_pass_copy) {
      logger_error("Failed to allocate memory for new password");
      pthread_rwlock_unlock(&server_auth.lock);
      return;
    }

    free(server_auth.password);
    server_auth.password = new_pass_copy;
    logger_info("Password updated via CONFIG SET");
  }

  pthread_rwlock_unlock(&server_auth.lock);
}

bool authorize_check_auth(const char* username, const char* password) {
  bool result;
  if (!username || !password)
    return false;

  pthread_rwlock_rdlock(&server_auth.lock);

  result = false;
  if (server_auth.is_initialized) {
    bool user_ok = (strcasecmp(username, server_auth.user) == 0);
    bool pass_ok = (strcmp(password, server_auth.password) == 0);
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
