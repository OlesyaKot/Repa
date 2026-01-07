#ifndef INCLUDE_AUTHORIZE_H
#define INCLUDE_AUTHORIZE_H

void authorize_init();
void authorize_destroy();
void authorize_set_password(const char *new_password);
bool authorize_check_auth(const char *username, const char *password);
bool authorize_is_command_allow_unauth(const char *cmd);

#endif
