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

    char msg[100];
    char msgresp[100];

    int fiu = fork();

    if (fiu == -1) {
        error_message("[client] Eroare la fork.\n");
    }
    if (fiu == 0) {
        char msg[100];

        while (1) {
            bzero(msg, 100);
            int bytes;
            if ((bytes = read(socket_fd, msg, 100)) < 0) {
                error_message("[client] Eroare la read in fork.\n");
            }
            if (bytes > 0) {
                printf("Mesaj de la alt client: %s\n", msg);
            }
        }
    } else {
        while (1) {
            bzero(msg, sizeof(msg));
            bzero(msgresp, sizeof(msgresp));
            int bytes;
            bytes = read(0, msg, 100);
            if (bytes < 0) {
                error_message("[client] Eroare la read din stdin.\n");
            }

            if (write(socket_fd, msg, 100) < 0) {
                error_message("[client] Eroare la write catre server.\n");
            }

            bytes = read(socket_fd, msgresp, sizeof(msgresp));
            if (bytes > 0) {
                msgresp[bytes] = '\0';
                // printf("[client] Răspuns primit de la server: %s\n",
                // msgresp);
            } else if (bytes == 0) {
                printf("[client] Serverul a închis conexiunea.\n");
            } else {
                perror("[client] Eroare la read().\n");
            }
        }
    }
    return 0;
}

void error_message(char* resp) {
    perror(resp);
    exit errno;
}