#include <signal.h>
#include <unistd.h>

#include "authorize.h"
#include "config.h"
#include "logger.h"
#include "server.h"
#include "statistics.h"
#include "storage.h"

#define UNUSED(x) (void)(x)

static volatile sig_atomic_t shutdown_requested = 0;

void signal_handler(int sig) {
  UNUSED(sig);
  shutdown_requested = 1;
}

int main(int argc, char *argv[]) {
  logger_info("MAIN: starting server initialization");
  config_init(argc, argv);
  logger_init(config_get_log_level(), config_get_log_output());
  stats_init();
  authorize_init();

  if (!storage_init(config_get_max_memory_bytes())) {
    logger_error("Failed to initialize storage");
    goto CLEANUP;
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGPIPE, SIG_IGN);

  if (!server_start(config_get_port(), config_get_workers())) {
    logger_error("Failed to start server");
    goto CLEANUP;
  }

  logger_info("Repa server is running and ready to accept connections");

  while (!shutdown_requested) {
    pause();  
  }

  logger_info("Received shutdown signal");

  server_stop();

CLEANUP:
  storage_destroy();
  authorize_destroy();
  stats_destroy();
  logger_destroy();
  config_destroy();
  logger_info("Repa finished");
  logger_info("MAIN: about to exit normally");
  return 0;
}
