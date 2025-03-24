#pragma once
#include <netinet/in.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "DatabaseManager.h"
#include "GetTime.h"
#include "Globals.h"

struct User {
    char* name;
    int fd;
};

struct UsersManager {
    struct User* users;
    struct Database* database;
    int nr_users;
};

int create_group(struct UsersManager* manager, char* group_name,
                 char* response) {
    if (create_group_in_db(manager->database, group_name, response) == -1) {
        return -1;
    }
    sprintf(response, "Grupul %s a fost creat cu succes!", group_name);
    return 0;
}

int add_user_to_group(struct UsersManager* manager, char* group_name,
                      char* user_name, char* response) {
    if (check_user_db(manager->database, user_name) == -1) {
        sprintf(response, "Utilizatorul %s nu există!", user_name);
        return -1;
    }

    if (add_user_to_group_in_db(manager->database, group_name, user_name,
                                response) == -1) {
        return -1;
    }

    sprintf(response, "Utilizatorul %s a fost adăugat în grupul %s!", user_name,
            group_name);
    return 0;
}

int send_message_to_group(struct UsersManager* manager, char* group_name,
                          char* sender_name, char* message, char* response) {
    if (send_message_to_group_in_db(manager->database, group_name, sender_name,
                                    message, response) == -1) {
        return -1;
    }

    char msg[MAX_BUFFER_SIZE];
    sprintf(msg, "[%s->%s]: %s", sender_name, group_name, message);

    sqlite3_stmt* stmt;
    const char* query =
        "SELECT u.id, u.username FROM group_members gm "
        "JOIN users u ON gm.id_user = u.id "
        "WHERE gm.id_group = (SELECT id FROM groups WHERE name = ?)";

    if (prepare(manager->database, query, &stmt) == -1) {
        sprintf(response, "Eroare la obținerea membrilor grupului %s!",
                group_name);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int user_id = sqlite3_column_int(stmt, 0);
        char* username = (char*)sqlite3_column_text(stmt, 1);

        for (int i = 0; i < manager->nr_users; ++i) {
            if (strcmp(manager->users[i].name, username) == 0) {
                if (write(manager->users[i].fd, msg, MAX_BUFFER_SIZE) < 0) {
                    sprintf(response,
                            "Eroare la trimiterea mesajului din grup către %s!",
                            username);
                    sqlite3_finalize(stmt);
                    return -1;
                }
            }
        }
    }

    sqlite3_finalize(stmt);
    sprintf(response, "Mesajul a fost trimis către grupul %s!", group_name);
    return 0;
}

int get_group_messages(struct UsersManager* manager, char* group_name,
                       char* response) {
    return get_group_messages_in_db(manager->database, group_name, response);
}

struct UsersManager get_users_manager() {
    struct UsersManager manager;
    manager.users = (struct User*)malloc(MAX_USERS * sizeof(struct User));

    if (manager.users == NULL) {
        error_message("Eroare la alocarea spatiului pentru useri.");
    }
    manager.nr_users = 0;

    manager.database = get_database();

    return manager;
}

char* get_name_from_fd(struct UsersManager* manager, int fd) {
    char* name;
    for (int i = 0; i < manager->nr_users; i++) {
        if (manager->users[i].fd == fd) {
            name = (char*)malloc(MAX_LENGTH_USER_NAME);
            strcpy(name, manager->users[i].name);
            return name;
        }
    }
    return NULL;
}

int login(struct UsersManager* manager, char* user, char* password, int fd,
          char* response) {
    printf("Attempted login: <%s>:<%s>\n", user, password);

    char* temp = get_name_from_fd(manager, fd);
    if (temp != NULL) {
        sprintf(response, "Utilizatorul %s este deja logat!", user);
        free(temp);
        return -1;
    }

    for (int i = 0; i < manager->nr_users; ++i) {
        if (strcmp(manager->users[i].name, user) == 0) {
            sprintf(response, "Utilizatorul %s este deja logat!", user);
            return -1;
        }
    }

    int ok = login_from_db(manager->database, user, password);

    if (ok == 0) {
        struct User _user;
        _user.fd = fd;
        _user.name = (char*)malloc(MAX_LENGTH_USER_NAME * sizeof(char));
        strcpy(_user.name, user);
        manager->users[manager->nr_users] = _user;
        manager->nr_users++;

        sprintf(response, "Utilizatorul %s a fost logat cu succes!", user);
        return 0;
    } else if (ok == -1) {
        sprintf(response, "Utilizatorul %s nu reusit sa se logheze!", user);
        return -1;
    }
    return -1;
}

int add_user(struct UsersManager* manager, char* user, char* password,
             char* response) {
    if (strlen(user) > MAX_LENGTH_USER_NAME) {
        sprintf(response,
                "Numele utilizatorului nu trebuie sa depaseasca %i caractere!",
                MAX_LENGTH_USER_NAME);
        return -1;
    }
    if (check_user_db(manager->database, user) == 0) {
        sprintf(response, "Utilizatorul %s se afla deja in baza de date!",
                user);
        return -1;
    }

    if (add_user_to_db(manager->database, user, password) == -1) {
        sprintf(response, "A fost o eroare la adaugarea lui %s in baza de date",
                user);
        return -1;
    }
    sprintf(response, "Utilizatorul %s a fost adaugat cu succes!", user);
    return 0;
}

int send_to_user(struct UsersManager* manager, int sender_fd, char* receiver,
                 char* message, char* response) {
    char* sender = get_name_from_fd(manager, sender_fd);
    if (sender == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }
    printf("[%s->%s] %s\n", sender, receiver, message);

    char* hour = get_current_time();
    char* date = get_current_date();
    int ok =
        add_message(manager->database, sender, receiver, message, hour, date);
    if (ok == -1) {
        sprintf(response, "A fost o eroare la trimiterea mesajului catre %s.",
                receiver);
        return -1;
    }

    char to_send[MAX_BUFFER_SIZE];

    sprintf(to_send, "[%s][%s %s]%s", sender, date, hour, message);
    for (int i = 0; i < manager->nr_users; ++i) {
        if (strcmp(manager->users[i].name, receiver) == 0) {
            if (write(manager->users[i].fd, to_send, MAX_BUFFER_SIZE) < 0) {
                sprintf(response,
                        "A fost o eroare la trimiterea mesajului catre %s.(in "
                        "baza de date: succes)",
                        receiver);
                return -1;
            } else {
                sprintf(response, "Mesajul a fost trimis cu succes catre %s!",
                        receiver);
                return 0;
            }
        }
    }
    sprintf(
        response,
        "Utilizatorul %s nu este online, va primi mesajul cand se va conecta!",
        receiver);
    return 0;
}

int logout_user(struct UsersManager* manager, int fd_user, char* response) {
    char temp[MAX_LENGTH_USER_NAME];

    for (int i = 0; i < manager->nr_users; ++i) {
        if (manager->users[i].fd == fd_user) {
            strcpy(temp, manager->users[i].name);
            for (int j = i; j < manager->nr_users - 1; ++j) {
                manager->users[j].fd = manager->users[j + 1].fd;
                strcpy(manager->users[j].name, manager->users[j + 1].name);
            }
            manager->nr_users--;

            sprintf(response, "Utilizatorul %s a fost delogat cu succes", temp);

            return 0;
        }
    }
    sprintf(response, "Nu sunteti logat!");
    return -1;
}

int get_online_users(int fd, struct UsersManager* manager, char* response) {
    if (get_name_from_fd(manager, fd) == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }

    int nr = manager->nr_users;
    sprintf(response, "Useri online(%i): ", nr);

    for (int i = 0; i < nr; ++i) {
        strcat(response, manager->users[i].name);
        strcat(response, " ,");
    }

    return 0;
}

int get_messages(struct UsersManager* manager, int user1_fd, char* user2,
                 char* response) {
    char* user1 = get_name_from_fd(manager, user1_fd);
    if (user1 == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }
    if (get_messages_from_db(manager->database, user1, user2, response) == -1) {
        strcpy(response, "Nu am putut prelua mesajele din baza de date!");
        return -1;
    }
    return 0;
}

int add_friend(struct UsersManager* manager, int fd, char* friend,
               char* response) {
    char* sender = get_name_from_fd(manager, fd);
    if (sender == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }
    printf("Incercam sa adaugam lui %s prietenul %s\n", sender, friend);
    int ok = add_friend_to_db(manager->database, sender, friend, response);
    if (ok == 0) {
        sprintf(
            response,
            "Utilizatorul %s a fost adaugat cu succes la lista ta de prieteni!",
            friend);
        return 0;
    }
    sprintf(response, "Eroare la adaugarea lui %s in lista ta de prieteni!",
            friend);
    return -1;
}

int get_posts(struct UsersManager* manager, int fd, char* response) {
    char* name = get_name_from_fd(manager, fd);
    if (name == NULL) {
        name = malloc(MAX_LENGTH_USER_NAME);
        strcpy(name, "none");
    }

    int ok = get_posts_from_db(manager->database, name, response);
    if (ok == 0) {
        return 0;
    }
    sprintf(response, "Eroare la preluarea postarilor din baza de date!");
    return -1;
}

int get_friends(struct UsersManager* manager, int fd, char* response) {
    char* user = get_name_from_fd(manager, fd);
    if (user == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }

    int ok = get_friends_from_db(manager->database, user, response);
    if (ok == 0) {
        return 0;
    }

    sprintf(response, "A fost o eroare la preluarea listei de prieteni!");
    return -1;
}

int add_close_friend(struct UsersManager* manager, int fd, char* friend,
                     char* response) {
    char* sender = get_name_from_fd(manager, fd);
    if (sender == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }
    printf("Incercam sa adaugam lui %s prietenul  apropriat %s\n", sender,
           friend);
    int ok =
        add_close_friend_to_db(manager->database, sender, friend, response);
    if (ok == 0) {
        sprintf(response,
                "Utilizatorul %s a fost adaugat cu succes la lista ta de "
                "prieteni apropriati!",
                friend);
        return 0;
    }
    sprintf(response,
            "Eroare la adaugarea lui %s in lista ta de prieteni apropriati!",
            friend);
    return -1;
}

int get_close_friends(struct UsersManager* manager, int fd, char* response) {
    char* user = get_name_from_fd(manager, fd);
    if (user == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }

    int ok = get_close_friends_from_db(manager->database, user, response);
    if (ok == 0) {
        return 0;
    }

    sprintf(response,
            "A fost o eroare la preluarea listei de prieteni apropriati!");
    return -1;
}

int create_post(struct UsersManager* manager, int fd, int type, char* content,
                char* response) {
    char* sender = get_name_from_fd(manager, fd);
    if (sender == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a executa aceasta comanda!");
        return -1;
    }

    int ok = create_post_db(manager->database, sender, type, content);

    if (ok == 0) {
        sprintf(response, "Stirea a fost publicata cu succes!");
        return 0;
    }
    sprintf(response, "Stirea nu a fost publicata cu succes!");
    return -1;
}

int is_admin(struct UsersManager* manager, int fd) {
    char* username = get_name_from_fd(manager, fd);
    if (!username) {
        return 0;
    }

    sqlite3_stmt* stmt;
    const char* query = "SELECT isAdmin FROM users WHERE username = ?;";

    if (prepare(manager->database, query, &stmt) == -1) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int is_admin = 0;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        is_admin = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return is_admin;
}

int admin_delete_user(struct UsersManager* manager, char* username,
                      char* response) {
    return delete_user_from_db(manager->database, username, response);
}
int admin_delete_post(struct UsersManager* manager, int post_id,
                      char* response) {
    return delete_post_from_db(manager->database, post_id, response);
}
int admin_delete_messages_of_user(struct UsersManager* manager, char* username,
                                  char* response) {
    return delete_messages_of_user(manager->database, username, response);
}
int admin_delete_posts_of_user(struct UsersManager* manager, char* username,
                               char* response) {
    return delete_posts_of_user(manager->database, username, response);
}

int change_profile(struct UsersManager* manager, int fd, int isPrivate,
                   char* response) {
    char* username = get_name_from_fd(manager, fd);

    if (username == NULL) {
        sprintf(response,
                "Trebuie sa fiti logati pentru a rula aceasta comanda!");
    }

    return change_profile_db(manager->database, username, isPrivate, response);
}