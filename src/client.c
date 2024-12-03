#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 2728
extern int errno;

void error_message(char* resp);

int main() {
    printf("Un client a fost pornit.\n");

    int socket_fd;
    struct sockaddr_in server;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        error_message("[client] Eroare la crearea socket-ului.\n");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("0");
    server.sin_port = htons(PORT);

    if (connect(socket_fd, (struct sockaddr*)&server,
                sizeof(struct sockaddr)) == -1) {
        error_message("[client] Eroare la connect.\n");
    }

    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        error_message("[client] Eroare la crearea pipe-ului.\n");
        return errno;
    }

    int fiu = fork();

    if (fiu == -1) {
        error_message("[client] Eroare la fork.\n");
    }

    if (fiu == 0) {
        char msg[100];
        int bytes;
        while (1) {
            bzero(msg, sizeof(msg));
            bytes = 0;
            if ((bytes = read(socket_fd, msg, sizeof(msg))) < 0) {
                error_message("[client] Eroare la read in fork.\n");
            }
            if (bytes > 0) {
                printf("%s\n", msg);
            } else if (bytes == 0) {
                printf("Serverul s-a inchis!\n");
                close(socket_fd);
                return 0;
            }
        }

    } else {
        char send[100];
        int bytes;
        while (1) {
            bzero(send, 100);
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

void error_message(char* resp) {
    perror(resp);
    exit errno;
}