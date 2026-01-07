#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define DEFAULT_IP_ADDR "127.0.0.1"
#define DEFAULT_PORT 6379
#define RESPONSE_BUFF_LEN 8192
#define COMMAND_CAPACITY 64
#define RADIX 10
#define MAX_NUM_LEN 16

static int sockfd = -1;

static void signal_handler(int sig) {
  (void)sig;
  rl_cleanup_after_signal(); 
  if (sockfd >= 0) {
    close(sockfd);
  }
  exit(0);
}

static char *serialize_command(const int argc, char *argv[], size_t *out_len) {
  size_t total_len = 0;
  char *buffer;
  int offset;
  if (argc == 0) return NULL;

  for (int i = 0; i < argc; i++) {
    total_len += MAX_NUM_LEN + strlen(argv[i]) + 2;
  }
  total_len += MAX_NUM_LEN;

  buffer = malloc(total_len);
  if (!buffer) return NULL;

  offset = snprintf(buffer, total_len, "*%d\r\n", argc);

  for (int i = 0; i < argc; i++) {
    size_t arg_len = strlen(argv[i]);
    offset += snprintf(buffer + offset, total_len - offset, "$%zu\r\n", arg_len);
    memcpy(buffer + offset, argv[i], arg_len);
    offset += arg_len;
    memcpy(buffer + offset, "\r\n", 2);
    offset += 2;
  }

  if (out_len) *out_len = offset;
  return buffer;
}

static void parse_and_print_response(const char *response, const size_t len) {
  if (len == 0) {
    printf("(no response)\n");
    return;
  }

  const char *newline = memchr(response, '\n', len);
  if (!newline) {
    printf("%.*s\n", (int)len, response);
    return;
  }

  size_t first_line_len = newline - response;
  if (first_line_len > 0 && response[first_line_len - 1] == '\r') {
    first_line_len--;
  }

  switch (response[0]) {
    case '+':  // Simple String
      printf("%.*s\n", (int)first_line_len - 1, response + 1);
      break;

    case '-':  // Error
      printf("%.*s\n", (int)first_line_len - 1, response + 1);
      break;

    case ':':  // Integer
      printf("%.*s\n", (int)first_line_len - 1, response + 1);
      break;

    case '$':  // Bulk String
      if (first_line_len == 3 && memcmp(response, "$-1", 3) == 0) {
        printf("(nil)\n");
      } else {
        const char *num_start = response + 1;
        long long data_len = strtoll(num_start, NULL, RADIX);

        if (data_len < 0) {
          printf("(nil)\n");
        } else {
          const char *data_start = newline + 1;
          size_t available = len - (data_start - response);

          if (available >= (size_t)data_len) {
            printf("\"%.*s\"\n", (int)data_len, data_start);
          } else {
            printf("(incomplete response)\n");
          }
        }
      }
      break;

    default:
      printf("%.*s\n", (int)len, response);
      break;
  }
}

static char *get_password_secure() {
  struct termios old_term, new_term;
  char *password = NULL;
  size_t len = 0;
  size_t capacity = COMMAND_CAPACITY;

  password = malloc(capacity);
  if (!password) return NULL;

  printf("Password: ");
  fflush(stdout);

  if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term);
  }

  int c;
  while ((c = getchar()) != '\n' && c != EOF) {
    if (len >= capacity - 1) {
      capacity *= 2;
      char *new_pass = realloc(password, capacity);
      if (!new_pass) {
        free(password);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        printf("\n");
        return NULL;
      }
      password = new_pass;
    }
    password[len++] = (char)c;
  }
  password[len] = '\0';

  tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
  printf("\n");

  return password;
}

static bool send_command(const int argc, char *argv[]) {
  size_t request_len;
  char *request;
  ssize_t sent;
  char response[RESPONSE_BUFF_LEN] = {0};
  ssize_t bytes_read;

  if (sockfd < 0) {
    printf("(not connected)\n");
    return false;
  }

  request = serialize_command(argc, argv, &request_len);
  if (!request) {
    printf("Error: Failed to serialize command\n");
    return false;
  }

  sent = send(sockfd, request, request_len, 0);
  free(request); 

  if (sent < 0) {
    printf("Error: Failed to send command\n");
    sockfd = -1;
    return false;
  }

  bytes_read = recv(sockfd, response, sizeof(response) - 1, 0);
  if (bytes_read <= 0) {
    printf("(connection closed)\n");
    sockfd = -1;
    return false;
  }

  response[bytes_read] = '\0';
  parse_and_print_response(response, bytes_read); 
  return true;
}

static int command_handler(char *line) {
  int argc = 0;
  char **args;
  char *token;

  if (!line || !*line) return 0;

  add_history(line);

  args = malloc(COMMAND_CAPACITY * sizeof(char *));
  if (!args) {
    printf("Error: Out of memory\n");
    return 0;
  }

  token = strtok(line, " \t");
  while (token && argc < COMMAND_CAPACITY) {
    args[argc++] = token;
    token = strtok(NULL, " \t");
  }

  if (argc > 0) {
    if (strcasecmp(args[0], "QUIT") == 0) {
      char *quit_cmd[] = {"QUIT"};
      send_command(1, quit_cmd);
      free(args);
      return 1; 
    }
    send_command(argc, args);
  }

  free(args);
  return 0;
}

static int connect_to_server(const char *addr, const int port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) return -1;

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
    close(sockfd);
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    close(sockfd);
    return -1;
  }

  return sockfd;
}

static void print_help(const char *program_name) {
  printf("Usage: %s [OPTIONS]\n", program_name);
  printf("\n");
  printf("Options:\n");
  printf("  --port <num>     Port number (default: 6379)\n");
  printf("  --addr <address> Server address (default: 127.0.0.1)\n");
  printf("  --user <name>    Username for authentication\n");
  printf("\n");
  printf("Interactive mode supports:\n");
  printf("  - Command history (arrow up/down)\n");
  printf("  - Line editing (arrow left/right)\n");
  printf("  - Password masking\n");
}

int main(int argc, char *argv[]) {
  const char *addr = DEFAULT_IP_ADDR;
  int port = DEFAULT_PORT;
  const char *username = NULL;
  char *auth_user = NULL;
  char *auth_pass = NULL;

  int command_start = -1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--addr") == 0 && i + 1 < argc) {
      addr = argv[++i];
    } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
      username = argv[++i];
    } else if (strcmp(argv[i], "--help") == 0) {
      print_help(argv[0]);
      return 0;
    } else {
      command_start = i; 
      break;
    }
  }

  sockfd = connect_to_server(addr, port);
  if (sockfd < 0) {
    fprintf(stderr, "Error: Could not connect to %s:%d\n", addr, port);
    return 1;
  }
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  if (username) {
    auth_user = strdup(username);
  } else {
    if (command_start != -1) {
      auth_user = strdup("admin");
    } else {
      auth_user = readline("Username: ");
      if (!auth_user || !*auth_user) {
        free(auth_user);
        close(sockfd);
        return 1;
      }
    }
  }

  if (command_start != -1) {
    auth_pass = strdup("admin");  
  } else {
    auth_pass = get_password_secure();
    if (!auth_pass) {
      free(auth_user);
      close(sockfd);
      return 1;
    }
  }

  {
    char *auth_args[] = {"AUTH", auth_user, auth_pass};
    if (!send_command(3, auth_args)) {
      fprintf(stderr, "Authentication failed\n");
      free(auth_user);
      free(auth_pass);
      close(sockfd);
      return 1;
    }
  }

  free(auth_user);
  free(auth_pass);

  if (command_start != -1) {
    // NON-INTERACTIVE MODE
    int cmd_argc = argc - command_start;
    char **cmd_argv = &argv[command_start];
    send_command(cmd_argc, cmd_argv);
  } else {
    // INTERACTIVE MODE
    printf("Connected to Repa server at %s:%d\n", addr, port);
    printf("Type 'QUIT' to exit.\n");

    char *line;
    while ((line = readline("> ")) != NULL) {
      if (command_handler(line)) {
        free(line);
        break;
      }
      free(line);
    }
  }

  close(sockfd);
  rl_cleanup_after_signal();
  return 0;
}
