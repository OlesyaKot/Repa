#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "authorize.h"
#include "config.h"
#include "logger.h"
#include "resp_command_parser.h"
#include "server.h"
#include "statistics.h"
#include "storage.h"

typedef struct {
  int fd;
  bool is_auth;
  char *input_buffer;
  size_t input_len;
  size_t input_capacity;
  bool should_close;
  pthread_mutex_t mutex;
} client_session;

typedef struct {
  client_session *session;
  int worker_id;
} worker_task;

typedef struct {
  int listen_fd;
  client_session *sessions;
  size_t sessions_capacity;
  size_t sessions_count;
  pthread_t *workers;
  size_t worker_count;
  bool running;
  bool shutting_down;
  pthread_mutex_t sessions_mutex;
  pthread_mutex_t listen_mutex;
} server_state;

static server_state server;

static void free_session(client_session *session) {
  if (session->fd >= 0) {
    close(session->fd);
    session->fd = -1;
  }
  if (session->input_buffer) {
    munmap(session->input_buffer, session->input_capacity);
    session->input_buffer = NULL;
  }
  session->input_len = 0;
  session->input_capacity = 0;
  session->is_auth = false;
}

static bool expand_input_buf(client_session *session, const size_t needed) {
  if (session->input_capacity >= needed) return true;

  if (needed > MAX_INPUT_BUFFER_SIZE) return false;

  size_t new_capacity = session->input_capacity;
  if (new_capacity == 0) new_capacity = INPUT_BUFFER_INITIAL_SIZE;
  while (new_capacity < needed) {
    new_capacity *= 2;
  }
  if (new_capacity > MAX_INPUT_BUFFER_SIZE) {
    new_capacity = MAX_INPUT_BUFFER_SIZE;
  }

  char *new_buffer = mmap(NULL, new_capacity, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (new_buffer == MAP_FAILED) return false;

  if (session->input_buffer) {
    memcpy(new_buffer, session->input_buffer, session->input_len);
    munmap(session->input_buffer, session->input_capacity);
  }
  session->input_buffer = new_buffer;
  session->input_capacity = new_capacity;
  return true;
}

static void send_response(const int client_fd, char *response) {
  if (!response) return;
  size_t len = strlen(response);
  send(client_fd, response, len, 0);
  resp_free_serialized(response);
}

static void handle_command(client_session* session, resp_command* cmd) {
  if (!cmd || !cmd->command) {
    send_response(session->fd, resp_serialize_error("ERR invalid command"));
    return;
  }

  char *cmd_upper = mmap(NULL, cmd->command_len + 1, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (!cmd_upper) {
    send_response(session->fd, resp_serialize_error("ERR oom"));
    return;
  }

  for (size_t i = 0; i < cmd->command_len; i++) {
    cmd_upper[i] = (cmd->command[i] >= 'a' && cmd->command[i] <= 'z')
                       ? cmd->command[i] - 'a' + 'A' : cmd->command[i];
  }
  cmd_upper[cmd->command_len] = '\0';

  //check auth
  if (!session->is_auth && !authorize_is_command_allow_unauth(cmd_upper)) {
    munmap(cmd_upper, cmd->command_len + 1);
    send_response(session->fd, resp_serialize_error("NOAUTH Authentication required."));
    return;
  }

  // command parse
  if (strcmp(cmd_upper, "QUIT") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    send_response(session->fd, resp_serialize_simple_string("OK"));
    session->should_close = true; 
    return;
  }

  if (strcmp(cmd_upper, "PING") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    send_response(session->fd, resp_serialize_simple_string("PONG"));
    return;
  }

  if (strcmp(cmd_upper, "HELLO") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num >= 1 && strcmp(cmd->args[0], "2") == 0) {
      send_response(session->fd, resp_serialize_simple_string("OK"));
    } else {
      send_response(session->fd, resp_serialize_error("ERR unknown protocol version"));
    }
    return;
  }

  if (strcmp(cmd_upper, "AUTH") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);

    if (cmd->args_num == 1) {
      // AUTH <password> - old format Redis (without username)
      if (authorize_check_auth("admin", cmd->args[0])) {
        session->is_auth = true;
        send_response(session->fd, resp_serialize_simple_string("OK"));
        stats_inc_cmd_other();
      } else {
        send_response(session->fd,
                      resp_serialize_error("ERR invalid password"));
      }
    } else if (cmd->args_num == 2) {
      // AUTH <username> <password> - new format
      if (authorize_check_auth(cmd->args[0], cmd->args[1])) {
        session->is_auth = true;
        send_response(session->fd, resp_serialize_simple_string("OK"));
        stats_inc_cmd_other();
      } else {
        send_response(session->fd, resp_serialize_error("ERR invalid username-password pair"));
      }
    } else {
      send_response(session->fd, resp_serialize_error("ERR wrong number of arguments for 'AUTH' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "GET") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num == 1) {
      size_t val_len;
      char *val = storage_get(cmd->args[0], cmd->args_lens[0], &val_len);
      if (val) {
        send_response(session->fd, resp_serialize_bulk_string(val, val_len));
        munmap(val, val_len);
        stats_inc_cmd_get();
        stats_inc_hit();
      } else {
        send_response(session->fd, resp_serialize_nil());
        stats_inc_cmd_get();
        stats_inc_miss();
      }
    } else {
      send_response(session->fd, resp_serialize_error("ERR wrong number of arguments for 'GET' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "SET") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num >= 2) {
      int ttl_sec = 0;
      if (cmd->args_num >= 4) {
        // SET key value EX ttl
        if (strcasecmp(cmd->args[2], "EX") == 0) {
          char *end;
          long ttl = strtol(cmd->args[3], &end, 10);
          if (*end == '\0' && ttl > 0) {
            ttl_sec = (int)ttl;
          }
        }
      }
      if (storage_set(cmd->args[0], cmd->args_lens[0], cmd->args[1],
                      cmd->args_lens[1], ttl_sec)) {
        send_response(session->fd, resp_serialize_simple_string("OK"));
        stats_inc_cmd_set();
      } else {
        send_response(session->fd, resp_serialize_error("OOM"));
      }
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'SET' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "DEL") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num == 1) {
      if (storage_del(cmd->args[0], cmd->args_lens[0])) {
        send_response(session->fd, resp_serialize_integer(1));
        stats_inc_cmd_del();
      } else {
        send_response(session->fd, resp_serialize_integer(0));
        stats_inc_cmd_del();
      }
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'DEL' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "EXPIRE") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num == 2) {
      char *end;
      long ttl = strtol(cmd->args[1], &end, 10);
      if (*end == '\0' && ttl > 0) {
        if (storage_set_expire(cmd->args[0], cmd->args_lens[0], (int)ttl)) {
          send_response(session->fd, resp_serialize_integer(1));
        } else {
          send_response(session->fd, resp_serialize_integer(0));
        }
      } else {
        send_response(session->fd,
                      resp_serialize_error("ERR invalid expire time"));
      }
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'EXPIRE' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "TTL") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num == 1) {
      int ttl = storage_ttl(cmd->args[0], cmd->args_lens[0]);
      send_response(session->fd, resp_serialize_integer(ttl));
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'TTL' command"));
    }
    return;
  }

  if (strcmp(cmd_upper, "CONFIG") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);

    if (cmd->args_num >= 2) {
      if (strcasecmp(cmd->args[0], "GET") == 0) {
        char *value = config_get_param(cmd->args[1]);
        if (value) {
          size_t value_len = strlen(value);
          send_response(session->fd,
                        resp_serialize_bulk_string(value, value_len));
          munmap(value, strlen(value) + 1);  
          stats_inc_cmd_other();
        } else {
          send_response(session->fd, resp_serialize_nil());
          stats_inc_cmd_other();
        }
      } else if (strcasecmp(cmd->args[0], "SET") == 0) {
        if (cmd->args_num >= 3) {
          if (config_set(cmd->args[1], cmd->args[2])) {
            if (strcasecmp(cmd->args[1], "requirepass") == 0) {
              authorize_set_password(cmd->args[2]);
            }
            send_response(session->fd, resp_serialize_simple_string("OK"));
            stats_inc_cmd_other();
          } else {
            send_response(session->fd, resp_serialize_error(
                                           "ERR invalid config set parameter"));
            stats_inc_cmd_other();
          }
        } else {
          send_response(session->fd,
              resp_serialize_error("ERR wrong number of arguments for 'CONFIG SET' command"));
          stats_inc_cmd_other();
        }
      } else {
        send_response(session->fd,
            resp_serialize_error("ERR CONFIG subcommand must be GET or SET"));
        stats_inc_cmd_other();
      }
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'CONFIG' command"));
      stats_inc_cmd_other();
    }
    return;
  }

  if (strcmp(cmd_upper, "STATS") == 0) {
    munmap(cmd_upper, cmd->command_len + 1);
    if (cmd->args_num == 0) {
      char *report = stats_get_report();
      if (report) {
        send_response(session->fd, resp_serialize_bulk_string(report, strlen(report)));
        munmap(report, REPORT_BUFFER_SIZE);
      } else {
        send_response(session->fd,
                      resp_serialize_error("ERR stats unavailable"));
      }
      stats_inc_cmd_other();
    } else {
      send_response(session->fd,
                    resp_serialize_error("ERR wrong number of arguments for 'STATS' command"));
    }
    return;
  }

  // unknown command
  munmap(cmd_upper, cmd->command_len + 1);
  char error_msg[ERROR_BUF_LEN];
  snprintf(error_msg, sizeof(error_msg), "ERR unknown command '%.*s'", (int)cmd->command_len, cmd->command);
  send_response(session->fd, resp_serialize_error(error_msg));
}

static void* worker_thread_func(void* args) {
  size_t worker_id = *(size_t *)args;
  logger_info("Worker %zu started", worker_id);

  while (server.running) {
    pthread_mutex_lock(&server.sessions_mutex);

    bool found = false;
    for (size_t i = 0; i < server.sessions_count; ++i) {
      client_session* session = &server.sessions[i];
      if (session->fd >= 0) {
        if (pthread_mutex_trylock(&session->mutex) == 0) {
          pthread_mutex_unlock(&server.sessions_mutex);

          char read_buf[CLIENT_BUFFER_SIZE];
          ssize_t bytes_read = read(session->fd, read_buf, CLIENT_BUFFER_SIZE);
          if (bytes_read > 0) {
            logger_debug("Received %zd bytes: '%.*s'", bytes_read,
                         (int)bytes_read, read_buf);
            if (!expand_input_buf(session, session->input_len + bytes_read)) {
              logger_error("Input buffer too large, closing connection");
              free_session(session);
              pthread_mutex_unlock(&session->mutex);
              break;
            }

            // add data to buff
            memcpy(session->input_buffer + session->input_len, read_buf, bytes_read);
            session->input_len += bytes_read;

            size_t consumed = 0;
            resp_list_commands *cmds = resp_parse(session->input_buffer, session->input_len, &consumed);

            if (cmds) {
              for (size_t j = 0; j < cmds->num_commands; j++) {
                handle_command(session, &cmds->commands[j]);
              }
              resp_free_command_list(cmds);

              // delete finished data
              if (session->should_close) {
                free_session(session);
              } else if (consumed > 0) {
                memmove(session->input_buffer, session->input_buffer + consumed, session->input_len - consumed);
                session->input_len -= consumed;
              }
            } else if (consumed == 0 && session->input_len >= MAX_INPUT_BUFFER_SIZE) {
              logger_error("Invalid RESP data, closing connection");
              free_session(session);
            }
          } else if (bytes_read == 0) {
            logger_debug("Client closed connection");
            free_session(session);
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // no data
            } else {
              logger_error("Read error: %s", strerror(errno));
              free_session(session);
            }
          }

          pthread_mutex_unlock(&session->mutex);
          found = true;
          break;
        }
      }
    }
    if (!found) {
        pthread_mutex_unlock(&server.sessions_mutex);
    }
  }

  logger_info("Worker %zu stopped", worker_id);
  return NULL;
}

static void *accept_thread_func(void *args) {
  (void)args;
  logger_info("Accept thread started");

  while (server.running && !server.shutting_down) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    pthread_mutex_lock(&server.listen_mutex);
    int client_fd = -1;
    if (server.listen_fd >= 0) {
      client_fd = accept(server.listen_fd, (struct sockaddr *)&client_addr, &client_len);
    }
    pthread_mutex_unlock(&server.listen_mutex);

    if (client_fd >= 0) {
      int flags = fcntl(client_fd, F_GETFL, 0);
      fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

      // add session
      pthread_mutex_lock(&server.sessions_mutex);

      if (server.sessions_count >= server.sessions_capacity) {
        size_t new_capacity = server.sessions_capacity
                                  ? server.sessions_capacity * 2 : DEFAULT_SESSION_CAP;
        client_session *new_sessions = mmap(NULL, new_capacity * sizeof(client_session),
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_sessions == MAP_FAILED) {
          close(client_fd);
          pthread_mutex_unlock(&server.sessions_mutex);
          continue;
        }

        if (server.sessions) {
          memcpy(new_sessions, server.sessions, server.sessions_count * sizeof(client_session));
          munmap(server.sessions, server.sessions_capacity * sizeof(client_session));
        }

        server.sessions = new_sessions;
        server.sessions_capacity = new_capacity;
      }

      client_session *session = &server.sessions[server.sessions_count];
      session->fd = client_fd;
      session->is_auth = false;
      session->input_buffer = NULL;
      session->input_len = 0;
      session->input_capacity = 0;
      session->should_close = false;
      pthread_mutex_init(&session->mutex, NULL);
      server.sessions_count++;

      stats_inc_connection();
      logger_info("Client connected from %s:%d",
                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

      pthread_mutex_unlock(&server.sessions_mutex);
    } else {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      } else if (errno != EINTR) {
        logger_error("Accept error: %s", strerror(errno));
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

  const int reuse = 1;
  setsockopt(server.listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);

  if (bind(server.listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    logger_error("Failed to bind to port %d", port);
    close(server.listen_fd);
    return false;
  }

  if (listen(server.listen_fd, QUEUE_LEN) < 0) {
    logger_error("Failed to listen");
    close(server.listen_fd);
    return false;
  }

  int flags = fcntl(server.listen_fd, F_GETFL, 0);
  fcntl(server.listen_fd, F_SETFL, flags | O_NONBLOCK);

  server.running = true;
  server.worker_count = worker_count;
  server.sessions = NULL;
  server.sessions_capacity = 0;
  server.sessions_count = 0;
  pthread_mutex_init(&server.listen_mutex, NULL);
  pthread_mutex_init(&server.sessions_mutex, NULL);

  server.workers = mmap(NULL, worker_count * sizeof(pthread_t),
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (server.workers == MAP_FAILED) {
    logger_error("Failed to allocate workers");
    close(server.listen_fd);
    return false;
  }

  for (size_t i = 0; i < worker_count; ++i) {
    size_t *worker_id = mmap(NULL, sizeof(size_t), PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (worker_id == MAP_FAILED) {
      logger_error("Failed to allocate worker_id");
      server.running = false;
      close(server.listen_fd); 
      return false;
    }

    *worker_id = i;
    if (pthread_create(&server.workers[i], NULL, worker_thread_func, worker_id) != 0) {
      logger_error("Failed to create worker %zu", i);
      server.running = false;
      close(server.listen_fd);
      return false;
    }
  }

  pthread_t accept_thread;
  if (pthread_create(&accept_thread, NULL, accept_thread_func, NULL) != 0) {
    logger_error("Failed to create accept thread");
    server.running = false;
    close(server.listen_fd);
    return false;
  }

  pthread_detach(accept_thread);

  logger_info("Server started on port %d with %zu workers", port, worker_count);
  return true;
}

void server_stop() {
  logger_info("Initiating graceful shutdown...");

  pthread_mutex_lock(&server.listen_mutex);
  if (server.listen_fd >= 0) {
    close(server.listen_fd);
    server.listen_fd = -1;
  }
  pthread_mutex_unlock(&server.listen_mutex);

  server.shutting_down = true;

  time_t start_time = time(NULL);
  bool sessions_active = true;

  while (sessions_active) {
    pthread_mutex_lock(&server.sessions_mutex);
    sessions_active = (server.sessions_count > 0);
    pthread_mutex_unlock(&server.sessions_mutex);

    if (!sessions_active) {
      logger_info("All client sessions closed");
      break;
    }

    if (time(NULL) - start_time >= MAX_WAIT_SEC) {
      logger_info("Graceful shutdown timeout (%d sec), forcing close", MAX_WAIT_SEC);
      break;
    }
  }

  server.running = false;
  for (size_t i = 0; i < server.worker_count; i++) {
    pthread_join(server.workers[i], NULL);
  }

  munmap(server.workers, server.worker_count * sizeof(pthread_t));

  pthread_mutex_lock(&server.sessions_mutex);
  for (size_t i = 0; i < server.sessions_count; i++) {
    free_session(&server.sessions[i]);
    pthread_mutex_destroy(&server.sessions[i].mutex);
  }
  if (server.sessions) {
    munmap(server.sessions, server.sessions_capacity * sizeof(client_session));
  }
  pthread_mutex_unlock(&server.sessions_mutex);

  pthread_mutex_destroy(&server.sessions_mutex);
  pthread_mutex_destroy(&server.listen_mutex);

  logger_info("Server stopped gracefully");
}
