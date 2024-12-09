#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "headers/Globals.h"
#include "headers/UsersManager.h"

char* conv_addr(struct sockaddr_in address);
void initialize_server();
void run_command(struct UsersManager* manager, int fd);

fd_set read_fds;
fd_set active_fds;

int maxim_fd;
int socket_fd;

struct sockaddr_in server;
struct sockaddr_in from;
struct timeval tv;

struct user {
    int fd;
    char name[100];
};
struct user users[100];
int nr_users = 0;
int main() {
    printf("Serverul a fost pornit.\n");

    initialize_server();

    struct UsersManager manager = get_users_manager();

    while (1) {
        bcopy((char*)&active_fds, (char*)&read_fds, sizeof(read_fds));

        if (select(maxim_fd + 1, &read_fds, NULL, NULL, &tv) < 0) {
            error_message("[server] Eroare la select.\n");
        }

        if (FD_ISSET(socket_fd, &read_fds)) {
            int len = sizeof(from);
            bzero(&from, len);

            int client =
                accept(socket_fd, (struct sockaddr*)&from, (socklen_t*)&len);

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
                run_command(&manager, fd);
            }
        }
    }

    return 0;
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

void initialize_server() {
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        error_message("[server] Eroare la crearea socket-ului.\n");
    }
    int optval = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if (bind(socket_fd, (struct sockaddr*)&server, sizeof(struct sockaddr)) ==
        -1) {
        error_message("[server] eroare la bind.\n");
    }
    if (listen(socket_fd, MAX_USERS) == -1) {
        error_message("[server] Eroare la listen.\n");
    }

    FD_ZERO(&active_fds);
    FD_SET(socket_fd, &active_fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    maxim_fd = socket_fd;

    printf("Asteptam la portul %i\n", PORT);
    fflush(stdout);
}

void run_command(struct UsersManager* manager, int fd) {
    char recv[MAX_BUFFER_SIZE], send[MAX_BUFFER_SIZE], temp[MAX_BUFFER_SIZE];
    bzero(recv, sizeof(recv));
    bzero(send, sizeof(send));

    int bytes = read(fd, recv, sizeof(recv));
    recv[strlen(recv) - 1] = '\0';

    if (bytes < 0) {
        perror("Eroare la read din fd_client!\n");
        return;
    } else if (bytes == 0) {
        printf("Clientul %i a inchis conexiunea.\n", fd);
        close(fd);
        int ok = logout_user(manager, fd, send);
        FD_CLR(fd, &active_fds);
        return;
    }
    printf("From client: %s\n", recv);
    strcpy(temp, recv);
    char* command = strtok(temp, " ");

    if (strcmp(command, "login") == 0) {
        char user[MAX_LENGTH_USER_NAME] = "";
        command = strtok(NULL, " ");
        if (command != NULL) {
            strcpy(user, command);
        }

        char password[100] = "";
        command = strtok(NULL, " ");
        if (command != NULL) {
            strcpy(password, command);
        }
        if (strcmp(user, "") == 0 || strcmp(password, "") == 0) {
            sprintf(send, "Sintaxa: login <user> <password>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }
        int ok = login(manager, user, password, fd, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "add-user") == 0) {
        char user[MAX_LENGTH_USER_NAME] = "";
        command = strtok(NULL, " ");
        if (command != NULL) {
            strcpy(user, command);
        }

        char password[100] = "";
        command = strtok(NULL, " ");
        if (command != NULL) {
            strcpy(password, command);
        }

        if (strcmp(user, "") == 0 || strcmp(password, "") == 0) {
            sprintf(send, "Sintaxa: add-user <user> <password>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }

        int ok = add_user(manager, user, password, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "send") == 0) {
        char receiver[MAX_LENGTH_USER_NAME] = "";
        char* p = strtok(NULL, " ");
        if (p != NULL) {
            strcpy(receiver, p);
        }

        char message[MAX_BUFFER_SIZE] = "";
        p = strtok(NULL, "");
        if (p != NULL) {
            strcpy(message, p);
        }

        if (strcmp(message, "") == 0 || strcmp(receiver, "") == 0) {
            sprintf(send, "Sintaxa: send <user> <content>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }

        int ok = send_to_user(manager, fd, receiver, message, send);

        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "get-online-users") == 0) {
        int ok = get_online_users(manager, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "logout") == 0) {
        int ok = logout_user(manager, fd, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "get-messages") == 0) {
        char* user = strtok(NULL, " ");

        if (user == NULL) {
            sprintf(send, "Sintaxa: get-messages <user>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }

        int ok = get_messages(manager, fd, user, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "get-posts") == 0) {
        int ok = get_posts(manager, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else {
        strcpy(send, "Comanda nu a fost gasita!");
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    }
}