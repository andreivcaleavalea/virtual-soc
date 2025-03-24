#pragma once
#include <stdlib.h>

#define PORT 2729
#define MAX_USERS 100
#define MAX_BUFFER_SIZE 4096
#define MAX_LENGTH_USER_NAME 50

void error_message(const char* message) {
    perror(message);
    exit(EXIT_FAILURE);
}
