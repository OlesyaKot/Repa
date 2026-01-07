#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "resp_command_parser.h" 
#include "server.h"
#include "config.h"
#include "storage.h"
#include "statistics.h"
#include "authorize.h"

int main(int argc, char *argv[]) {
  config_init(argc, argv);
  logger_init(DEBUG, config_get_log_output());
  stats_init();
  authorize_init();
  storage_init(config_get_max_memory_bytes());

  if (!server_start(config_get_port(), config_get_workers())) {
    logger_error("Failed to start server");
    return 1;
  }

  pause();

  server_stop();
  storage_destroy();
  authorize_destroy();
  stats_destroy();
  logger_destroy();
  config_destroy();
  return 0;
}
