#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "headers/Globals.h"

int main() {
    printf("Un client a fost pornit.\n");

    int socket_fd;
    struct sockaddr_in server;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        error_message("[client] Eroare la crearea socket-ului.\n");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(PORT);

    if (connect(socket_fd, (struct sockaddr*)&server,
                sizeof(struct sockaddr)) == -1) {
        error_message("[client] Eroare la connect.\n");
    }

    int fiu = fork();

    if (fiu == -1) {
        error_message("[client] Eroare la fork.\n");
    }

    if (fiu == 0) {
        // Procesul fiu
        char msg[MAX_BUFFER_SIZE];
        int bytes;
        while (1) {
            bzero(msg, sizeof(msg));
            bytes = 0;
            if ((bytes = read(socket_fd, msg, sizeof(msg))) < 0) {
                error_message("[client] Eroare la read in fork.\n");
            }
            if (bytes > 0) {
                msg[strlen(msg)] = '\0';
                printf("%s\n", msg);

            } else if (bytes == 0) {
                printf("Serverul s-a inchis!\n");
                close(socket_fd);
                exit(EXIT_SUCCESS);
            }
        }
    } else {
        // Procesul tată
        char send[MAX_BUFFER_SIZE];
        int bytes;
        while (1) {
            bzero(send, MAX_BUFFER_SIZE);
            bytes = 0;
            if ((bytes = read(0, send, sizeof(send))) < 0) {
                error_message("Eroare la read de la stdin.\n");
            }
            if (bytes > 0) {
                if (write(socket_fd, send, sizeof(send)) < 0) {
                    error_message("Eroare la write in socket_fd.\n");
                }
            }
        }
    }
    return 0;
}
