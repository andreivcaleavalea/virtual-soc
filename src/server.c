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
#define MAX_CONNECTIONS 100
extern int errno;

void error_message(char* resp);
char* conv_addr(struct sockaddr_in address);

int main() {
    printf("Serverul a fost pornit.\n");

    struct sockaddr_in server;
    struct sockaddr_in from;

    fd_set read_fds;
    fd_set active_fds;

    struct timeval tv;
    int maxim_fd;
    int socket_fd;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        error_message("[server] Eroare la crearea socket-ului.\n");
    }

    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const void*)1, 1);

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if (bind(socket_fd, (struct sockaddr*)&server, sizeof(struct sockaddr)) ==
        -1) {
        error_message("[server] eroare la bind.\n");
    }
    if (listen(socket_fd, MAX_CONNECTIONS) == -1) {
        error_message("[server] Eroare la listen.\n");
    }

    FD_ZERO(&active_fds);
    FD_SET(socket_fd, &active_fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    maxim_fd = socket_fd;

    printf("Asteptam la portul %i\n", PORT);
    fflush(stdout);

    while (1) {
        bcopy((char*)&active_fds, (char*)&read_fds, sizeof(read_fds));

        if (select(maxim_fd + 1, &read_fds, NULL, NULL, &tv) < 0) {
            error_message("[server] Eroare la select.\n");
        }

        if (FD_ISSET(socket_fd, &read_fds)) {
            int len = sizeof(from);
            bzero(&from, len);

            int client = accept(socket_fd, (struct sockaddr*)&from, &len);

            if (client < 0) {
                error_message("[server] Eroare la accept.\n");
            }

            if (maxim_fd < client) {
                maxim_fd = client;
            }

            FD_SET(client, &active_fds);
            printf("S-a conectat clientul cu fd=%i, de la adresa %s.\n", client,
                   conv_addr(from));
            fflush(stdout);
        }

        for (int fd = 0; fd <= maxim_fd; fd++) {
            if (fd != socket_fd && FD_ISSET(fd, &read_fds)) {
                char msg[100], msgresp[100], buffer[100];
                bzero(msg, sizeof(msg));
                bzero(msgresp, sizeof(msgresp));
                bzero(buffer, sizeof(buffer));

                int bytes = read(fd, msg, sizeof(buffer));
                if (bytes < 0) {
                    error_message("[server] Eroare la read de la client.\n");
                } else if (bytes == 0) {
                    printf("Clientul s-a terminat? \n");
                    return 0;
                }

                strcpy(msgresp, "Hello ");
                strcat(msgresp, msg);
                printf("[server] Trimitem raspunsul inapoi ...%s\n", msgresp);

                char temp[100];
                strcpy(temp, msg);
                char* p = strtok(temp, " ");
                int c = atoi(p);

                if (write(c, msg, 100) < 0) {
                    error_message("[server] Eroare la write in alt client.");
                }

                if (write(fd, msgresp, 100) < 0) {
                    error_message("[server] Eroare la write catre client.\n");
                }
                // close(fd);
                // FD_CLR(fd, &active_fds);
            }
        }
    }

    return 0;
}

void error_message(char* resp) {
    perror(resp);
    exit errno;
}
char* conv_addr(struct sockaddr_in address) {
    static char str[25];
    char port[7];
    strcpy(str, inet_ntoa(address.sin_addr));
    bzero(port, 7);
    sprintf(port, ":%d", ntohs(address.sin_port));
    strcat(str, port);
    return (str);
}