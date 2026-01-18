#ifndef INCLUDE_SERVER_H
#define INCLUDE_SERVER_H

#include <stdlib.h>
#include <stdbool.h>

bool server_start(const int port, const size_t worker_count);
void server_stop(void);

#endif
