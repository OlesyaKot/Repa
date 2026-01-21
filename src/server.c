#define _GNU_SOURCE

#include "server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "authorize.h"
#include "config.h"
#include "list.h"
#include "logger.h"
#include "queue.h"  // for sessions
#include "resp_command_parser.h"
#include "statistics.h"
#include "storage.h"

#define MAX_PORT 65535
#define QUEUE_LEN 128
#define BUFFER_SIZE (4 * 1024)
#define INPUT_BUFFER_INITIAL_SIZE (4 * 1024)
#define MAX_INPUT_BUFFER_SIZE (8 * 1024 * 1024)
#define ERROR_BUF_LEN 256
#define TIMEOUT 5
#define RADIX 10
#define UNUSED(x) (void)(x)

typedef struct {
  int fd;
  bool is_auth;
  char *input_buffer;
  size_t input_len;
  size_t input_capacity;
  char *output_buffer;
  size_t output_len;
  size_t output_capacity;
  bool should_close;
  pthread_mutex_t mutex;
  volatile int ref_count;
} client_session;

typedef struct {
  int listen_fd;
  list *sessions_list;  // consist all connected clients 
  size_t sessions_count;
  pthread_t *workers;
  size_t worker_count;
  bool running;
  pthread_mutex_t sessions_mutex;
  pthread_mutex_t listen_mutex;
} server_state;

static server_state server;

static client_session *session_acquire(client_session *session) {
  if (session) {
    __sync_fetch_and_add(&session->ref_count, 1);
  }
  return session;
}

static void session_release(client_session *session) {
  if (!session) return;
  if (__sync_sub_and_fetch(&session->ref_count, 1) == 0) {
    if (session->fd >= 0) {
      logger_debug("Releasing session, closing fd = %d", session->fd);
      close(session->fd);
    }
    free(session->input_buffer);
    free(session->output_buffer);
    pthread_mutex_destroy(&session->mutex);
    free(session);
  }
}

static bool find_session_by_ptr(const void *data, const void *target) {
  return data == target;
}

static bool expand_input_buf(client_session *session, const size_t needed) {
  size_t new_capacity;
  char *new_buffer;
  if (session->input_capacity >= needed) return true;
  if (needed > MAX_INPUT_BUFFER_SIZE) return false;

  new_capacity = session->input_capacity;
  if (new_capacity == 0) new_capacity = INPUT_BUFFER_INITIAL_SIZE;
  while (new_capacity < needed) {
    new_capacity *= 2;
  }
  if (new_capacity > MAX_INPUT_BUFFER_SIZE) {
    new_capacity = MAX_INPUT_BUFFER_SIZE;
  }

  new_buffer = malloc(new_capacity);
  if (!new_buffer) return false;

  if (session->input_buffer) {
    memcpy(new_buffer, session->input_buffer, session->input_len);
    free(session->input_buffer);
  }
  session->input_buffer = new_buffer;
  session->input_capacity = new_capacity;
  return true;
}

static bool send_all(int fd, const char *buf, size_t len) {
  while (len > 0) {
    ssize_t sent = send(fd, buf, len, 0);
    if (sent < 0) {
      if (errno == EINTR) {
        continue; 
      }
      return false;  
    }
    if (sent == 0) {
      logger_debug("Socket closed");
      return false;
    }
    buf += sent;
    len -= sent;
  }
  return true;
}

static void buffer_response(client_session *session, char *response) {
  if (!response) return;
  size_t len = strlen(response);

  if (session->output_len + len > session->output_capacity) {
    size_t new_cap = session->output_capacity ? session->output_capacity * 2 : BUFFER_SIZE;
    while (new_cap < session->output_len + len) {
      new_cap *= 2;
    }
    char *new_buf = realloc(session->output_buffer, new_cap);
    if (!new_buf) {
      free(response);
      return;
    }
    session->output_buffer = new_buf;
    session->output_capacity = new_cap;
  }

  memcpy(session->output_buffer + session->output_len, response, len);
  session->output_len += len;
  free(response); 
}

static void handle_command(client_session *session, resp_command *cmd) {
  char *cmd_upper = NULL;

  if (!cmd || !cmd->command) {
    buffer_response(session, resp_serialize_error("ERR invalid command"));
    goto CLEANUP;
  }

  cmd_upper = malloc(cmd->command_len + 1);
  if (!cmd_upper) {
    buffer_response(session, resp_serialize_error("ERR oom"));
    goto CLEANUP;
  }

  for (size_t i = 0; i < cmd->command_len; i++) {
    cmd_upper[i] = toupper((unsigned char)cmd->command[i]);
  }
  cmd_upper[cmd->command_len] = '\0';

  // Auth check
  if (!session->is_auth && !authorize_is_command_allow_unauth(cmd_upper)) {
    buffer_response(session, resp_serialize_error("NOAUTH Authentication required."));
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "QUIT") == 0) {
    buffer_response(session, resp_serialize_simple_string("OK"));
    session->should_close = true;
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "PING") == 0) {
    if (cmd->args_num == 0) {
      buffer_response(session, resp_serialize_simple_string("PONG"));
    } else if (cmd->args_num == 1) {
      buffer_response(session, resp_serialize_bulk_string(
                                       cmd->args[0], cmd->args_lens[0]));
    } else {
      buffer_response(session, resp_serialize_error(
                      "ERR wrong number of arguments for 'PING' command"));
    }
    stats_inc_cmd_other();
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "HELLO") == 0) {
    if (cmd->args_num >= 1 && strcmp(cmd->args[0], "2") == 0) {
      buffer_response(session, resp_serialize_simple_string("OK"));
    } else {
      buffer_response(session, resp_serialize_error("ERR unknown protocol version"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "AUTH") == 0) {
    if (cmd->args_num == 1) {
      if (authorize_check_auth("admin", cmd->args[0])) {
        session->is_auth = true;
        buffer_response(session, resp_serialize_simple_string("OK"));
        stats_inc_cmd_other();
      } else {
        buffer_response(session, resp_serialize_error("ERR invalid password"));
      }
    } else if (cmd->args_num == 2) {
      if (authorize_check_auth(cmd->args[0], cmd->args[1])) {
        session->is_auth = true;
        buffer_response(session, resp_serialize_simple_string("OK"));
        stats_inc_cmd_other();
      } else {
        buffer_response(session, resp_serialize_error(
                                       "ERR invalid username-password pair"));
      }
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'AUTH' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "GET") == 0) {
    if (cmd->args_num == 1) {
      size_t val_len;
      char *val = storage_get(cmd->args[0], cmd->args_lens[0], &val_len);
      if (val) {
        buffer_response(session, resp_serialize_bulk_string(val, val_len));
        free(val);
        stats_inc_hit();
      } else {
        buffer_response(session, resp_serialize_nil());
        stats_inc_miss();
      }
      stats_inc_cmd_get();
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'GET' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "SET") == 0) {
    if (cmd->args_num >= 2) {
      int ttl_sec = 0;
      if (cmd->args_num >= 4 && strcasecmp(cmd->args[2], "EX") == 0) {
        char *end;
        long ttl = strtol(cmd->args[3], &end, RADIX);
        if (*end == '\0' && ttl > 0) {
          ttl_sec = (int)ttl;
        }
      }
      if (storage_set(cmd->args[0], cmd->args_lens[0], cmd->args[1],
                      cmd->args_lens[1], ttl_sec)) {
        buffer_response(session, resp_serialize_simple_string("OK"));
        stats_inc_cmd_set();
      } else {
        buffer_response(session, resp_serialize_error("OOM"));
      }
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'SET' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "DEL") == 0) {
    if (cmd->args_num == 1) {
      if (storage_del(cmd->args[0], cmd->args_lens[0])) {
        buffer_response(session, resp_serialize_integer(1));
      } else {
        buffer_response(session, resp_serialize_integer(0));
      }
      stats_inc_cmd_del();
    } else {
      buffer_response(session, resp_serialize_error("ERR wrong number of arguments for 'DEL' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "EXPIRE") == 0) {
    if (cmd->args_num == 2) {
      char *end;
      long ttl = strtol(cmd->args[1], &end, RADIX);
      if (*end == '\0' && ttl > 0) {
        if (storage_set_expire(cmd->args[0], cmd->args_lens[0], (int)ttl)) {
          buffer_response(session, resp_serialize_integer(1));
        } else {
          buffer_response(session, resp_serialize_integer(0));
        }
      } else {
        buffer_response(session, resp_serialize_error("ERR invalid expire time"));
      }
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'EXPIRE' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "TTL") == 0) {
    if (cmd->args_num == 1) {
      int ttl = storage_ttl(cmd->args[0], cmd->args_lens[0]);
      buffer_response(session, resp_serialize_integer(ttl));
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'TTL' command"));
    }
    goto CLEANUP;
  }

  if (strcmp(cmd_upper, "CONFIG") == 0) {
    if (cmd->args_num >= 2) {
      if (strcasecmp(cmd->args[0], "GET") == 0) {
        if (!session->is_auth) {
          buffer_response(session, resp_serialize_error("NOAUTH Authentication required."));
          goto CLEANUP;
        }

        const char *param = cmd->args[1];
        char *value = config_get_param(param);

        if (value) {
          buffer_response(session, resp_serialize_bulk_string(value, strlen(value)));
          free(value);
        } else {
          buffer_response(session, resp_serialize_nil());
        }
        stats_inc_cmd_other();
        goto CLEANUP;

      } else if (strcasecmp(cmd->args[0], "SET") == 0) {
        if (!session->is_auth) {
          buffer_response(session, resp_serialize_error("NOAUTH Authentication required."));
          goto CLEANUP;
        }

        if (cmd->args_num >= 3) {
          if (config_set(cmd->args[1], cmd->args[2])) {
            if (strcasecmp(cmd->args[1], "requirepass") == 0) {
              authorize_set_password(cmd->args[2]);
            }
            buffer_response(session, resp_serialize_simple_string("OK"));
          } else {
            buffer_response(session, resp_serialize_error("ERR invalid config set parameter"));
          }
        } else {
          buffer_response(session, resp_serialize_error(
                           "ERR wrong number of arguments for 'CONFIG SET' command"));
        }
        stats_inc_cmd_other();
        goto CLEANUP;
      } else {
        buffer_response(session, resp_serialize_error( "ERR CONFIG subcommand must be GET or SET"));
        stats_inc_cmd_other();
        goto CLEANUP;
      }
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'CONFIG' command"));
      stats_inc_cmd_other();
      goto CLEANUP;
    }
  }

  if (strcmp(cmd_upper, "STATS") == 0) {
    if (cmd->args_num == 0) {
      char *report = stats_get_report();
      if (report) {
        buffer_response(session, resp_serialize_bulk_string(report, strlen(report)));
        free(report);
      } else {
        buffer_response(session,resp_serialize_error("ERR stats unavailable"));
      }
      stats_inc_cmd_other();
    } else {
      buffer_response(session, resp_serialize_error(
                        "ERR wrong number of arguments for 'STATS' command"));
    }
    goto CLEANUP;
  }

  {
    char error_msg[ERROR_BUF_LEN];
    snprintf(error_msg, sizeof(error_msg), "ERR unknown command '%.*s'",
             (int)cmd->command_len, cmd->command);
    buffer_response(session, resp_serialize_error(error_msg));
  }

CLEANUP:
  free(cmd_upper);
}


static void *worker_thread_func(void *args) {
  size_t worker_id = (size_t)args;
  logger_info("Worker %zu started", worker_id);

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

  while (server.running) {
    pthread_testcancel();

    client_session *session = (client_session *)job_queue_pop();
    if (!session) continue;

    pthread_mutex_lock(&server.sessions_mutex);
    list_node *node = list_find(server.sessions_list, find_session_by_ptr, session);
    if (!node) {
      pthread_mutex_unlock(&server.sessions_mutex);
      session_release(session);
      continue;
    }
    pthread_mutex_unlock(&server.sessions_mutex);

    if (pthread_mutex_lock(&session->mutex) != 0) {
      session_release(session);
      continue;
    }

    if (session->fd < 0 || session->should_close) {
      pthread_mutex_unlock(&session->mutex);
      session_release(session);
      continue;
    }

    char read_buf[BUFFER_SIZE];
    ssize_t bytes_read = read(session->fd, read_buf, sizeof(read_buf));
    bool should_close = false;

    if (bytes_read > 0) {
      if (!expand_input_buf(session, session->input_len + bytes_read)) {
        logger_error("Input buffer too large, closing connection");
        should_close = true;
      } else {
        memcpy(session->input_buffer + session->input_len, read_buf, bytes_read);
        session->input_len += bytes_read;

        size_t total_consumed = 0;
        while (server.running && !should_close && session->input_len > 0) {
          size_t consumed = 0;
          resp_list_commands *cmds = resp_parse(session->input_buffer + total_consumed, 
                                  session->input_len - total_consumed, &consumed);
          if (cmds) {
            for (size_t j = 0; j < cmds->num_commands; j++) {
              handle_command(session, &cmds->commands[j]);
              if (session->should_close) {
                should_close = true;
                break;
              }
            }
            resp_free_command_list(cmds);
            total_consumed += consumed;
          } else {
            if (consumed == 0 && session->input_len >= MAX_INPUT_BUFFER_SIZE) {
              logger_error("Invalid RESP data, closing connection");
              should_close = true;
            }
            break;
          }
        }

        if (total_consumed > 0 && total_consumed < session->input_len) {
          memmove(session->input_buffer, session->input_buffer + total_consumed,
                session->input_len - total_consumed);
          session->input_len -= total_consumed;
        } else if (total_consumed >= session->input_len) {
          session->input_len = 0;
        }
      }
    } else if (bytes_read == 0) {
      logger_info("Client closed connection (fd %d)", session->fd);
      should_close = true;
    } else {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        logger_error("Read error on fd %d: %s", session->fd, strerror(errno));
        should_close = true;
      }
    }

    if (session->output_len > 0) {
      send_all(session->fd, session->output_buffer, session->output_len);
      session->output_len = 0;
    }

    if (should_close) {
      session->should_close = true;
      stats_dec_connection();
    }
    pthread_mutex_unlock(&session->mutex);

    bool keep_alive = false;
    if (server.running && session->fd >= 0 && !session->should_close) {
      keep_alive = true;
    }

    if (keep_alive) {
      job_queue_push(session_acquire(session));
    }

    session_release(session);
  }

  logger_info("Worker %zu stopped", worker_id);
  return NULL;
}

static void *accept_thread_func(void *args) {
  UNUSED(args);
  logger_info("Accept thread started");

  while (server.running) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    pthread_mutex_lock(&server.listen_mutex);
    if (server.listen_fd < 0) {
      pthread_mutex_unlock(&server.listen_mutex);
      break;
    }
    int client_fd = accept(server.listen_fd, (struct sockaddr *)&client_addr, &client_len);
    pthread_mutex_unlock(&server.listen_mutex);

    if (client_fd >= 0) {
      // Make client socket non-blocking because read() is a blocking system
      // call. Otherwise, a worker thread would block indefinitely in read() if
      // the client (repactl) stays connected but sends no data, preventing graceful shutdown.      
      int flags = fcntl(client_fd, F_GETFL, 0);
      if (flags == -1 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        logger_warn("Failed to set client fd %d to non-blocking", client_fd);
      }

      client_session *session = malloc(sizeof(client_session));
      if (!session) {
        close(client_fd);
        continue;
      }

      session->fd = client_fd;
      session->is_auth = false;
      session->input_buffer = NULL;
      session->input_len = 0;
      session->input_capacity = 0;
      session->output_buffer = NULL;
      session->output_len = 0;
      session->output_capacity = 0;
      session->should_close = false;
      session->ref_count = 1;
      pthread_mutex_init(&session->mutex, NULL);

      pthread_mutex_lock(&server.sessions_mutex);
      if (list_push_front(server.sessions_list, session)) {
        server.sessions_count++;
        pthread_mutex_unlock(&server.sessions_mutex);
        stats_inc_connection();
        logger_info("Client connected from %s:%d", inet_ntoa(client_addr.sin_addr),
                    ntohs(client_addr.sin_port));
        job_queue_push(session);
      } else {
        pthread_mutex_unlock(&server.sessions_mutex);
        close(client_fd);
        session_release(session);
      }
    } else {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
      } else if (errno == EINTR) {
        continue;
      } else {
        logger_error("Accept error: %s", strerror(errno));
        break;
      }
    }
  }

  logger_info("Accept thread stopped");
  return NULL;
}

bool server_start(const int port, const size_t worker_count) {
  if (port <= 0 || port > MAX_PORT || worker_count == 0) return false;

  server.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server.listen_fd < 0) {
    logger_error("Failed to create socket");
    return false;
  }

  // Make listen socket non-blocking because accept() is a blocking system call.
  // Otherwise, the accept thread would block indefinitely in accept() when no
  // clients are connecting, preventing it from exiting during graceful shutdown.
  int flags = fcntl(server.listen_fd, F_GETFL, 0); 
  if (flags == -1 || fcntl(server.listen_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    logger_error("Failed to set listen_fd to non-blocking");
    close(server.listen_fd);
    return false;
  }

  setsockopt(server.listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);

  if (bind(server.listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    logger_error("Failed to bind to port %d", port);
    close(server.listen_fd);
    return false;
  }

  if (listen(server.listen_fd, QUEUE_LEN) < 0) {
    logger_error("Failed to listen");
    close(server.listen_fd);
    return false;
  }

  server.running = true;
  server.worker_count = worker_count;
  server.sessions_count = 0;

  server.sessions_list = list_create();
  if (!server.sessions_list) {
    logger_error("Failed to create sessions list");
    close(server.listen_fd);
    return false;
  }

  pthread_mutex_init(&server.listen_mutex, NULL);
  pthread_mutex_init(&server.sessions_mutex, NULL);

  job_queue_init();

  server.workers = malloc(worker_count * sizeof(pthread_t));
  if (!server.workers) {
    logger_error("Failed to allocate workers");
    close(server.listen_fd);
    list_destroy(server.sessions_list, NULL);
    job_queue_destroy();
    return false;
  }

  for (size_t i = 0; i < worker_count; ++i) {
    if (pthread_create(&server.workers[i], NULL, worker_thread_func, (void *)i) != 0) {
      logger_error("Failed to create worker %zu", i);
      server.running = false;
      job_queue_stop_accepting();
      for (size_t j = 0; j < i; ++j) {
        pthread_join(server.workers[j], NULL);
      }
      close(server.listen_fd);
      list_destroy(server.sessions_list, NULL);
      job_queue_destroy();
      free(server.workers);
      return false;
    }
  }

  pthread_t accept_thread;
  if (pthread_create(&accept_thread, NULL, accept_thread_func, NULL) != 0) {
    logger_error("Failed to create accept thread");
    server.running = false;
    job_queue_stop_accepting();

    for (size_t i = 0; i < worker_count; ++i) {
      pthread_join(server.workers[i], NULL);
    }

    close(server.listen_fd);
    list_destroy(server.sessions_list, NULL);
    job_queue_destroy();
    free(server.workers);
    return false;
  }

  pthread_detach(accept_thread);
  logger_info("Server started on port %d with %zu workers", port, worker_count);
  return true;
}

void server_stop(void) {
  logger_info("SERVER_STOP called - starting graceful shutdown");

  server.running = false;

  pthread_mutex_lock(&server.listen_mutex);
  if (server.listen_fd >= 0) {
    logger_info("SERVER_STOP: closing listen_fd = %d", server.listen_fd);
    close(server.listen_fd);
    server.listen_fd = -1;
  }
  pthread_mutex_unlock(&server.listen_mutex);

  job_queue_stop_accepting();

  logger_info("SERVER_STOP: waiting up to 5 seconds for workers to finish...");

  struct timespec timeout;
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += TIMEOUT;

  for (size_t i = 0; i < server.worker_count; i++) {
    if (pthread_timedjoin_np(server.workers[i], NULL, &timeout) != 0) {
      logger_warn("Worker %zu not responding, cancelling", i);
      pthread_cancel(server.workers[i]);
      pthread_join(server.workers[i], NULL);
    }
  }

  free(server.workers);
  server.workers = NULL;

  job_queue_free((void (*)(void *))session_release);

  pthread_mutex_lock(&server.sessions_mutex);
  list_destroy(server.sessions_list, NULL);
  server.sessions_list = NULL;
  pthread_mutex_unlock(&server.sessions_mutex);

  job_queue_destroy();

  pthread_mutex_destroy(&server.sessions_mutex);
  pthread_mutex_destroy(&server.listen_mutex);

  logger_info("Server stopped gracefully");
}
