#ifndef INCLUDE_SERVER_H
#define INCLUDE_SERVER_H

#include <stdlib.h>

#define MAX_PORT 65535
#define QUEUE_LEN 128
#define DEFAULT_SESSION_CAP 16
#define CLIENT_BUFFER_SIZE 1024
#define REPORT_BUFFER_SIZE (8 * 1024)
#define INPUT_BUFFER_INITIAL_SIZE (4 * 1024)
#define MAX_INPUT_BUFFER_SIZE (8 * 1024 * 1024)
#define ERROR_BUF_LEN 256

bool server_start(const int port, const size_t worker_count);
void server_stop();

#endif
