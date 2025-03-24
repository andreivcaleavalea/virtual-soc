#pragma once
#include <stdlib.h>
#include <time.h>

char* get_current_time() {
    time_t t;
    char* buff = (char*)malloc(26);

    time(&t);
    struct tm *info = localtime(&t);

    if (strftime(buff, 26, "%H:%M:%S", info) == 0) {
        error_message("Eroare la parsarea orei curente.\n");
    }
    return buff;
}

char* get_current_date() {
    time_t t;
    char* buff = (char*)malloc(26);

    time(&t);
    struct tm *info = localtime(&t);

    if (strftime(buff, 26, "%Y-%m-%d", info) == 0) {
        error_message("Eroare la parsarea datei curente.\n");
    }
    return buff;
}