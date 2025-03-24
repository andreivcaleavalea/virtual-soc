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
    if (command == NULL) {
        strcpy(send, "Comanda nu a fost gasita!");
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
        return;
    }
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
        int ok = get_online_users(fd, manager, send);
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
        int ok = get_posts(manager, fd, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "add-to-friends") == 0) {
        char* user = strtok(NULL, " ");
        if (user == NULL) {
            sprintf(send, "Sintaxa: add-to-friends <user>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }
        int ok = add_friend(manager, fd, user, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "get-friends") == 0) {
        int ok = get_friends(manager, fd, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "add-to-close-friends") == 0) {
        char* user = strtok(NULL, " ");
        if (user == NULL) {
            sprintf(send, "Sintaxa: add-to-close-friends <user>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }
        int ok = add_close_friend(manager, fd, user, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "get-close-friends") == 0) {
        int ok = get_close_friends(manager, fd, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "create-post") == 0) {
        char type[MAX_LENGTH_USER_NAME] = "";
        char content[MAX_BUFFER_SIZE] = "";

        char* p = strtok(NULL, " ");
        if (p != NULL) {
            strcpy(type, p);
        }
        p = strtok(NULL, "");
        if (p != NULL) {
            strcpy(content, p);
        }
        if (strcmp(type, "") == 0 || strcmp(content, "") == 0) {
            sprintf(send,
                    "Sintaxa: create-post <public/friends/close_friends> "
                    "<content>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }
        int type_int = -1;
        if (strcmp(type, "public") == 0) {
            type_int = 0;
        } else if (strcmp(type, "friends") == 0) {
            type_int = 1;
        } else if (strcmp(type, "close_friends") == 0) {
            type_int = 2;
        }
        if (type_int == -1) {
            sprintf(send,
                    "temp: Sintaxa: create-post <public/friends/close_friends> "
                    "<content>");
            if (write(fd, send, sizeof(send)) < 0) {
                perror("Eroare la write!");
                return;
            }
            return;
        }
        int ok = create_post(manager, fd, type_int, content, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "change-to-private-profile") == 0) {
        int ok = change_profile(manager, fd, 1, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "change-to-public-profile") == 0) {
        int ok = change_profile(manager, fd, 0, send);
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "help") == 0) {
        sprintf(send,
                "Aveti la dispozitie urmatoarele comenzi:\n"
                "login <user> <password>\n"
                "logout\n"
                "add-user <user> <password>\n"
                "send <user> <message>\n"
                "get-messages <user>\n"
                "get-online-users\n"
                "get-posts\n"
                "change-to-private-profile\n"
                "change-to-public-profile\n"
                "create-post <public/friends/close_friends> <content>\n"
                "add_to_friends\n"
                "add_to_close_friends\n"
                "create-group\n"
                "add-to-group\n"
                "send-group\n"
                "get-group-messages\n"
                "quit\n");
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    } else if (strcmp(command, "create-group") == 0) {
        char group_name[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(group_name, command);
        }

        if (strcmp(group_name, "") == 0) {
            sprintf(send, "Sintaxa: create-group <group_name>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = create_group(manager, group_name, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "add-to-group") == 0) {
        char group_name[100], user_name[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(group_name, command);
        }
        command = strtok(NULL, " ");
        if (command) {
            strcpy(user_name, command);
        }

        if (strcmp(group_name, "") == 0 || strcmp(user_name, "") == 0) {
            sprintf(send, "Sintaxa: add-to-group <group_name> <user_name>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = add_user_to_group(manager, group_name, user_name, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "send-group") == 0) {
        char group_name[100], message[MAX_BUFFER_SIZE];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(group_name, command);
        }
        command = strtok(NULL, "");
        if (command) {
            strcpy(message, command);
        }

        if (strcmp(group_name, "") == 0 || strcmp(message, "") == 0) {
            sprintf(send, "Sintaxa: send-group <group_name> <message>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = send_message_to_group(
            manager, group_name, get_name_from_fd(manager, fd), message, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "get-group-messages") == 0) {
        char group_name[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(group_name, command);
        }

        if (strcmp(group_name, "") == 0) {
            sprintf(send, "Sintaxa: get-group-messages <group_name>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = get_group_messages(manager, group_name, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "delete-user") == 0) {
        if (!is_admin(manager, fd)) {
            sprintf(send, "Nu aveți privilegii pentru această comandă!");
            write(fd, send, sizeof(send));
            return;
        }

        char username[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(username, command);
        }

        if (strcmp(username, "") == 0) {
            sprintf(send, "Sintaxa: delete-user <username>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = admin_delete_user(manager, username, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "delete-post") == 0) {
        if (!is_admin(manager, fd)) {
            sprintf(send, "Nu aveți privilegii pentru această comandă!");
            write(fd, send, sizeof(send));
            return;
        }

        int post_id = atoi(strtok(NULL, " "));
        if (post_id <= 0) {
            sprintf(send, "Sintaxa: delete-post <post_id>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = admin_delete_post(manager, post_id, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "delete-messages-of-user") == 0) {
        if (!is_admin(manager, fd)) {
            sprintf(send, "Nu aveți privilegii pentru această comandă!");
            write(fd, send, sizeof(send));
            return;
        }

        char username[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(username, command);
        }

        if (strcmp(username, "") == 0) {
            sprintf(send, "Sintaxa: delete-messages-of-user <username>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = admin_delete_messages_of_user(manager, username, send);
        write(fd, send, sizeof(send));
    } else if (strcmp(command, "delete-posts-of-user") == 0) {
        if (!is_admin(manager, fd)) {
            sprintf(send, "Nu aveți privilegii pentru această comandă!");
            write(fd, send, sizeof(send));
            return;
        }

        char username[100];
        command = strtok(NULL, " ");
        if (command) {
            strcpy(username, command);
        }

        if (strcmp(username, "") == 0) {
            sprintf(send, "Sintaxa: delete-posts-of-user <username>");
            write(fd, send, sizeof(send));
            return;
        }

        int ok = admin_delete_posts_of_user(manager, username, send);
        write(fd, send, sizeof(send));
    } else {
        strcpy(send, "Comanda nu a fost gasita!");
        if (write(fd, send, sizeof(send)) < 0) {
            perror("Eroare la write!");
            return;
        }
    }
}