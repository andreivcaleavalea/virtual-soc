#include <sqlite3.h>
#include <string.h>

#include "GetTime.h"
#include "UsersManager.h"

struct Database {
    sqlite3* db;
};

struct Database* get_database() {
    struct Database* database =
        (struct Database*)malloc(sizeof(struct Database));
    if (sqlite3_open("database.db", &database->db) != SQLITE_OK) {
        error_message("Eroare la deschiderea bazei de date!");
        return (struct Database*)NULL;
    }

    const char* create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL UNIQUE, "
        "password TEXT NOT NULL, "
        "private_account BOOLEAN DEFAULT FALSE, "
        "isAdmin BOOLEAN DEFAULT FALSE);";

    const char* create_posts_table =
        "CREATE TABLE IF NOT EXISTS posts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "id_author INTEGER NOT NULL, "
        "content TEXT NOT NULL, "
        "send_date TEXT NOT NULL, "
        "send_time TEXT NOT NULL, "
        "target_group INTEGER NOT NULL DEFAULT 0, "
        "FOREIGN KEY(id_author) REFERENCES users(id));";

    const char* create_messages_table =
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "id_sender INTEGER NOT NULL, "
        "id_receiver INTEGER NOT NULL, "
        "content TEXT NOT NULL, "
        "send_date TEXT NOT NULL, "
        "send_time TEXT NOT NULL, "
        "FOREIGN KEY(id_sender) REFERENCES users(id), "
        "FOREIGN KEY(id_receiver) REFERENCES users(id));";

    const char* create_groups_table =
        "CREATE TABLE IF NOT EXISTS groups ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL UNIQUE);";

    const char* create_group_messages_table =
        "CREATE TABLE IF NOT EXISTS group_messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "id_group INTEGER NOT NULL, "
        "id_sender INTEGER NOT NULL, "
        "content TEXT NOT NULL, "
        "send_date TEXT NOT NULL, "
        "send_time TEXT NOT NULL, "
        "FOREIGN KEY(id_group) REFERENCES groups(id), "
        "FOREIGN KEY(id_sender) REFERENCES users(id));";

    const char* create_group_members_table =
        "CREATE TABLE IF NOT EXISTS group_members ("
        "id_group INTEGER NOT NULL, "
        "id_user INTEGER NOT NULL, "
        "PRIMARY KEY(id_group, id_user), "
        "FOREIGN KEY(id_group) REFERENCES groups(id), "
        "FOREIGN KEY(id_user) REFERENCES users(id));";

    const char* create_friends_table =
        "CREATE TABLE IF NOT EXISTS friends ("
        "id_user1 INTEGER NOT NULL, "
        "id_user2 INTEGER NOT NULL, "
        "PRIMARY KEY(id_user1, id_user2), "
        "FOREIGN KEY(id_user1) REFERENCES users(id), "
        "FOREIGN KEY(id_user2) REFERENCES users(id));";

    const char* create_close_friends_table =
        "CREATE TABLE IF NOT EXISTS close_friends ("
        "id_user1 INTEGER NOT NULL, "
        "id_user2 INTEGER NOT NULL, "
        "PRIMARY KEY(id_user1, id_user2), "
        "FOREIGN KEY(id_user1) REFERENCES users(id), "
        "FOREIGN KEY(id_user2) REFERENCES users(id));";

    char* err = NULL;

    sqlite3_exec(database->db, create_users_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_posts_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_messages_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_groups_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_group_messages_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_group_members_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_friends_table, NULL, NULL, &err);
    sqlite3_exec(database->db, create_close_friends_table, NULL, NULL, &err);

    if (err != NULL) {
        error_message("Eroare la crearea tabelelor!");
        sqlite3_free(err);
    }

    return database;
}

int prepare(struct Database* database, const char* query, sqlite3_stmt** stmt) {
    if (sqlite3_prepare_v2(database->db, query, -1, stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    return 0;
}

int login_from_db(struct Database* database, char* user, char* password) {
    sqlite3_stmt* stmt;
    char* query = "SELECT password FROM users WHERE username = ?";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        char* pass = (char*)sqlite3_column_text(stmt, 0);
        if (pass && strcmp(pass, password) == 0) {
            return 0;
        }
    }
    sqlite3_finalize(stmt);
    return -1;
}

int add_user_to_db(struct Database* database, char* user, char* password) {
    sqlite3_stmt* stmt;
    const char* query = "INSERT INTO users (username, password) VALUES (?, ?)";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int check_user_db(struct Database* database, char* user) {
    sqlite3_stmt* stmt;
    const char* query = "SELECT COUNT(*) FROM users WHERE username = ?;";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int nr = sqlite3_column_int(stmt, 0);
        if (nr == 1) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    sqlite3_finalize(stmt);
    return -1;
}

int add_message(struct Database* database, char* sender, char* receiver,
                char* msg, char* hour, char* date) {
    sqlite3_stmt* stmt;
    int s = -1, r = -1;
    char* query = "SELECT id FROM users WHERE username = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        s = sqlite3_column_int(stmt, 0);
    }
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, receiver, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        r = sqlite3_column_int(stmt, 0);
    }
    if (s == -1 || r == -1) {
        return -1;
    }
    char* query_insert =
        "INSERT INTO messages (id_sender, id_receiver, content, send_date "
        ",send_time) VALUES (?, ?, ?, ?, ?);";
    if (prepare(database, query_insert, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, s);
    sqlite3_bind_int(stmt, 2, r);
    sqlite3_bind_text(stmt, 3, msg, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, hour, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        return -1;
    } else {
        return 0;
    }
}

int get_messages_from_db(struct Database* database, char* sender,
                         char* receiver, char* response) {
    sqlite3_stmt* stmt;
    int s = -1, r = -1;
    char* query = "SELECT id FROM users WHERE username = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        s = sqlite3_column_int(stmt, 0);
    }
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, receiver, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        r = sqlite3_column_int(stmt, 0);
    }
    if (s == -1 || r == -1) {
        return -1;
    }
    char* query1 =
        "SELECT u1.username AS sender, u2.username AS receiver, "
        "m.send_date, m.send_time, m.content "
        "FROM messages m "
        "JOIN users u1 ON m.id_sender = u1.id "
        "JOIN users u2 ON m.id_receiver = u2.id "
        "WHERE (m.id_sender = ? AND m.id_receiver = ?) "
        "   OR (m.id_sender = ? AND m.id_receiver = ?) "
        "ORDER BY m.send_date ASC, m.send_time ASC;";
    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, s);
    sqlite3_bind_int(stmt, 2, r);
    sqlite3_bind_int(stmt, 3, r);
    sqlite3_bind_int(stmt, 4, s);

    bzero(response, sizeof(response));
    char line[MAX_BUFFER_SIZE];
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        bzero(line, sizeof(line));
        char* db_sender = (char*)sqlite3_column_text(stmt, 0);
        char* db_receiver = (char*)sqlite3_column_text(stmt, 1);
        char* db_send_date = (char*)sqlite3_column_text(stmt, 2);
        char* db_send_time = (char*)sqlite3_column_text(stmt, 3);
        char* db_content = (char*)sqlite3_column_text(stmt, 4);
        sprintf(line, "[%s->%s][%s %s] %s\n", db_sender, db_receiver,
                db_send_date, db_send_time, db_content);
        strcat(response, line);
    }
    sqlite3_finalize(stmt);

    if (strlen(response) == 0) {
        sprintf(response, "Nu există mesaje");
    }

    return 0;
}

char* get_name_from_id(struct Database* database, int id) {
    char* user = malloc(MAX_LENGTH_USER_NAME);
    sqlite3_stmt* stmt;
    char* query = "SELECT username from users where id = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return NULL;
    }
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        strcpy(user, (char*)sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return user;
    }
    sqlite3_finalize(stmt);
    return NULL;
}

int get_id_from_name(struct Database* database, char* name) {
    int id;
    sqlite3_stmt* stmt;
    char* query = "SELECT id from users where username = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return id;
    }
    sqlite3_finalize(stmt);
    return -1;
}

int is_friend(struct Database* database, int user1, int user2) {
    if (user1 == user2) {
        return 1;
    }
    sqlite3_stmt* stmt;
    char* query =
        "SELECT count(id_user1) from friends where id_user1 = ? and id_user2 = "
        "? or id_user1 = ? and id_user2 = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return 0;
    }
    sqlite3_bind_int(stmt, 1, user1);
    sqlite3_bind_int(stmt, 2, user2);
    sqlite3_bind_int(stmt, 3, user2);
    sqlite3_bind_int(stmt, 4, user1);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int nr = sqlite3_column_int(stmt, 0);
        if (nr > 0) {
            return 1;
        }
    }
    return 0;
}

int is_close_friend(struct Database* database, int user1, int user2) {
    if (user1 == user2) {
        return 1;
    }
    sqlite3_stmt* stmt;
    char* query =
        "SELECT count(id_user1) from close_friends where id_user1 = ? and "
        "id_user2 = ? or id_user1 = ? and id_user2 = ?;";
    if (prepare(database, query, &stmt) == -1) {
        return 0;
    }
    sqlite3_bind_int(stmt, 1, user1);
    sqlite3_bind_int(stmt, 2, user2);
    sqlite3_bind_int(stmt, 3, user2);
    sqlite3_bind_int(stmt, 4, user1);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int nr = sqlite3_column_int(stmt, 0);
        if (nr > 0) {
            return 1;
        }
    }
    return 0;
}

int get_posts_from_db(struct Database* database, char* name, char* response) {
    int id = get_id_from_name(database, name);

    strcpy(response, "");

    sqlite3_stmt* stmt;
    char* query =
        "SELECT id, id_author, content, send_date, send_time from posts where "
        "target_group = 0";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    char line[MAX_BUFFER_SIZE];
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        bzero(line, sizeof(line));
        int id_post = (int)sqlite3_column_int(stmt, 0);
        int db_author = (int)sqlite3_column_int(stmt, 1);
        char* db_content = (char*)sqlite3_column_text(stmt, 2);
        char* db_send_date = (char*)sqlite3_column_text(stmt, 3);
        char* db_send_time = (char*)sqlite3_column_text(stmt, 4);

        char* author = get_name_from_id(database, db_author);

        sprintf(line, "[Post: %i][Autor: %s]\n[%s %s]\n%s\n\n", id_post, author,
                db_send_date, db_send_time, db_content);
        strcat(response, line);
    }
    if (strcmp(name, "none") != 0) {
        char* query1 =
            "SELECT id, id_author, content, send_date, send_time from posts "
            "where "
            "target_group = 1";
        if (prepare(database, query1, &stmt) == -1) {
            return -1;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            bzero(line, sizeof(line));
            int id_post = (int)sqlite3_column_int(stmt, 0);
            int db_author = (int)sqlite3_column_int(stmt, 1);
            char* db_content = (char*)sqlite3_column_text(stmt, 2);
            char* db_send_date = (char*)sqlite3_column_text(stmt, 3);
            char* db_send_time = (char*)sqlite3_column_text(stmt, 4);

            char* author = get_name_from_id(database, db_author);
            if (is_friend(database, db_author, id) == 1) {
                sprintf(line, "[Post: %i][Autor: %s]\n[%s %s]\n%s\n\n", id_post,
                        author, db_send_date, db_send_time, db_content);
                strcat(response, line);
            }
        }
        char* query2 =
            "SELECT id, id_author, content, send_date, send_time from posts "
            "where "
            "target_group = 2";
        if (prepare(database, query2, &stmt) == -1) {
            return -1;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            bzero(line, sizeof(line));
            int id_post = (int)sqlite3_column_int(stmt, 0);
            int db_author = (int)sqlite3_column_int(stmt, 1);
            char* db_content = (char*)sqlite3_column_text(stmt, 2);
            char* db_send_date = (char*)sqlite3_column_text(stmt, 3);
            char* db_send_time = (char*)sqlite3_column_text(stmt, 4);

            char* author = get_name_from_id(database, db_author);
            if (is_close_friend(database, db_author, id) == 1) {
                sprintf(line, "[Post: %i][Autor: %s]\n[%s %s]\n%s\n\n", id_post,
                        author, db_send_date, db_send_time, db_content);
                strcat(response, line);
            }
        }
    }
    return 0;
}

int add_friend_to_db(struct Database* database, char* sender, char* friend,
                     char* response) {
    if (check_user_db(database, friend) == -1) {
        return -1;
    }
    int id1 = -1, id2 = -1;
    sqlite3_stmt* stmt;
    const char* query = "SELECT id FROM users WHERE username = ?";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id1 = sqlite3_column_int(stmt, 0);
    }

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, friend, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id2 = sqlite3_column_int(stmt, 0);
    }
    if (id1 == -1 || id2 == -1) {
        sqlite3_finalize(stmt);
        return -1;
    }
    const char* query1 =
        "SELECT COUNT(*) FROM friends WHERE id_user1 = ? and id_user2 = ? or "
        "id_user1 = ? and id_user2 = ?;";

    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id1);
    sqlite3_bind_int(stmt, 2, id2);
    sqlite3_bind_int(stmt, 3, id2);
    sqlite3_bind_int(stmt, 4, id1);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int nr = sqlite3_column_int(stmt, 0);
        if (nr > 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
    }
    const char* query2 =
        "INSERT INTO friends (id_user1, id_user2) VALUES (?, ?)";

    if (prepare(database, query2, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id1);
    sqlite3_bind_int(stmt, 2, id2);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int get_friends_from_db(struct Database* database, char* user, char* response) {
    int id = -1;

    sqlite3_stmt* stmt;
    const char* query = "SELECT id FROM users WHERE username = ?";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }

    int ids[MAX_USERS];
    int nr_ids = 0;
    const char* query1 =
        "SELECT id_user1, id_user2 from friends where id_user1 = ? or id_user2 "
        "= ?;";
    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_int(stmt, 2, id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id1 = sqlite3_column_int(stmt, 0);
        int id2 = sqlite3_column_int(stmt, 1);
        if (id1 == id) {
            ids[nr_ids++] = id2;
        } else {
            ids[nr_ids++] = id1;
        }
    }
    strcpy(response, "Lista ta de prieteni: \n");
    for (int i = 0; i < nr_ids; i++) {
        const char* q = "select username from users where id = ?;";
        if (prepare(database, q, &stmt) == -1) {
            return -1;
        }
        sqlite3_bind_int(stmt, 1, ids[i]);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            char* name = (char*)sqlite3_column_text(stmt, 0);
            strcat(response, name);
            strcat(response, "\n");
        }
    }
    sqlite3_finalize(stmt);
    return 0;
}

int add_close_friend_to_db(struct Database* database, char* sender,
                           char* friend, char* response) {
    if (check_user_db(database, friend) == -1) {
        return -1;
    }
    int id1 = -1, id2 = -1;
    sqlite3_stmt* stmt;
    const char* query = "SELECT id FROM users WHERE username = ?";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id1 = sqlite3_column_int(stmt, 0);
    }

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, friend, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id2 = sqlite3_column_int(stmt, 0);
    }
    if (id1 == -1 || id2 == -1) {
        sqlite3_finalize(stmt);
        return -1;
    }
    const char* query1 =
        "SELECT COUNT(*) FROM close_friends WHERE id_user1 = ? and id_user2 = "
        "? or id_user1 = ? and id_user2 = ?;";

    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id1);
    sqlite3_bind_int(stmt, 2, id2);
    sqlite3_bind_int(stmt, 3, id2);
    sqlite3_bind_int(stmt, 4, id1);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int nr = sqlite3_column_int(stmt, 0);
        if (nr > 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
    }
    const char* query2 =
        "INSERT INTO close_friends (id_user1, id_user2) VALUES (?, ?)";

    if (prepare(database, query2, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id1);
    sqlite3_bind_int(stmt, 2, id2);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int get_close_friends_from_db(struct Database* database, char* user,
                              char* response) {
    int id = -1;

    sqlite3_stmt* stmt;
    const char* query = "SELECT id FROM users WHERE username = ?";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }

    int ids[MAX_USERS];
    int nr_ids = 0;
    const char* query1 =
        "SELECT id_user1, id_user2 from close_friends where id_user1 = ? or "
        "id_user2 = ?;";
    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_int(stmt, 2, id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id1 = sqlite3_column_int(stmt, 0);
        int id2 = sqlite3_column_int(stmt, 1);
        if (id1 == id) {
            ids[nr_ids++] = id2;
        } else {
            ids[nr_ids++] = id1;
        }
    }
    strcpy(response, "Lista ta de prieteni apropriati: \n");
    for (int i = 0; i < nr_ids; i++) {
        const char* q = "select username from users where id = ?;";
        if (prepare(database, q, &stmt) == -1) {
            return -1;
        }
        sqlite3_bind_int(stmt, 1, ids[i]);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            char* name = (char*)sqlite3_column_text(stmt, 0);
            strcat(response, name);
            strcat(response, "\n");
        }
    }
    sqlite3_finalize(stmt);
    return 0;
}

int create_post_db(struct Database* database, char* sender, int type,
                   char* content) {
    int author_id = get_id_from_name(database, sender);
    printf("POST: [%i, %s, %i] %s\n", author_id, sender, type, content);
    if (author_id == -1) {
        return -1;
    }
    sqlite3_stmt* stmt;
    const char* query =
        "INSERT into posts (id, id_author, content, send_date, send_time, "
        "target_group) VALUES(?,?,?,?,?,?);";
    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }
    char* date = get_current_date();
    char* time = get_current_time();
    sqlite3_bind_int(stmt, 2, author_id);
    sqlite3_bind_text(stmt, 3, content, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, time, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, type);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int create_group_in_db(struct Database* database, char* group_name,
                       char* response) {
    sqlite3_stmt* stmt;
    const char* query = "INSERT INTO groups (name) VALUES (?);";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Grupul %s există deja!", group_name);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int add_user_to_group_in_db(struct Database* database, char* group_name,
                            char* user_name, char* response) {
    sqlite3_stmt* stmt;
    const char* query =
        "INSERT INTO group_members (id_group, id_user) "
        "VALUES ((SELECT id FROM groups WHERE name = ?), "
        "(SELECT id FROM users WHERE username = ?));";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_name, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response,
                "Utilizatorul %s este deja membru al grupului %s sau grupul nu "
                "există!",
                user_name, group_name);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int send_message_to_group_in_db(struct Database* database, char* group_name,
                                char* sender_name, char* message,
                                char* response) {
    sqlite3_stmt* stmt;
    const char* query =
        "INSERT INTO group_messages (id_group, id_sender, content, send_date, "
        "send_time) "
        "VALUES ((SELECT id FROM groups WHERE name = ?), "
        "(SELECT id FROM users WHERE username = ?), ?, ?, ?);";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    char* date = get_current_date();
    char* time = get_current_time();

    sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sender_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, message, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, time, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Eroare la trimiterea mesajului către grupul %s!",
                group_name);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int get_group_messages_in_db(struct Database* database, char* group_name,
                             char* response) {
    sqlite3_stmt* stmt;

    const char* query =
        "SELECT u.username, gm.content, gm.send_date, gm.send_time "
        "FROM group_messages gm "
        "JOIN users u ON gm.id_sender = u.id "
        "WHERE gm.id_group = (SELECT id FROM groups WHERE name = ?) "
        "ORDER BY gm.send_date ASC, gm.send_time ASC;";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_STATIC);

    bzero(response, MAX_BUFFER_SIZE);
    char line[MAX_BUFFER_SIZE];
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        bzero(line, sizeof(line));

        char* sender = (char*)sqlite3_column_text(stmt, 0);
        char* content = (char*)sqlite3_column_text(stmt, 1);
        char* date = (char*)sqlite3_column_text(stmt, 2);
        char* time = (char*)sqlite3_column_text(stmt, 3);

        sprintf(line, "[%s][%s %s]: %s\n", sender, date, time, content);
        strcat(response, line);
    }

    sqlite3_finalize(stmt);

    if (strlen(response) == 0) {
        sprintf(response, "Nu există mesaje în grupul %s!", group_name);
    }

    return 0;
}

int delete_user_from_db(struct Database* database, char* username,
                        char* response) {
    sqlite3_stmt* stmt;

    const char* query1 =
        "DELETE FROM messages WHERE id_sender = (SELECT id FROM users WHERE "
        "username = ?) OR id_receiver = (SELECT id FROM users WHERE username = "
        "?);";

    if (prepare(database, query1, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const char* query2 =
        "DELETE FROM posts WHERE id_author = (SELECT id FROM users WHERE "
        "username = ?);";
    if (prepare(database, query2, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const char* query3 = "DELETE FROM users WHERE username = ?;";
    if (prepare(database, query3, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Eroare la ștergerea utilizatorului %s!", username);
        return -1;
    }

    sqlite3_finalize(stmt);
    sprintf(
        response,
        "Utilizatorul %s și toate datele asociate au fost șterse cu succes!",
        username);
    return 0;
}

int delete_post_from_db(struct Database* database, int post_id,
                        char* response) {
    sqlite3_stmt* stmt;
    const char* query = "DELETE FROM posts WHERE id = ?;";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, post_id);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Eroare la ștergerea postării!");
        return -1;
    }

    sqlite3_finalize(stmt);
    sprintf(response, "Postarea cu ID %d a fost ștearsă cu succes!", post_id);
    return 0;
}

int delete_messages_of_user(struct Database* database, char* username,
                            char* response) {
    sqlite3_stmt* stmt;
    const char* query =
        "DELETE FROM messages WHERE id_sender = (SELECT id FROM users WHERE "
        "username = ?) OR id_receiver = (SELECT id FROM users WHERE username = "
        "?);";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Eroare la ștergerea mesajelor utilizatorului %s!",
                username);
        return -1;
    }

    sqlite3_finalize(stmt);
    sprintf(response,
            "Toate mesajele utilizatorului %s au fost șterse cu succes!",
            username);
    return 0;
}

int delete_posts_of_user(struct Database* database, char* username,
                         char* response) {
    sqlite3_stmt* stmt;
    const char* query =
        "DELETE FROM posts WHERE id_author = (SELECT id FROM users WHERE "
        "username = ?);";

    if (prepare(database, query, &stmt) == -1) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sprintf(response, "Eroare la ștergerea postărilor utilizatorului %s!",
                username);
        return -1;
    }

    sqlite3_finalize(stmt);
    sprintf(response,
            "Toate postările utilizatorului %s au fost șterse cu succes!",
            username);
    return 0;
}

int change_profile_db(struct Database* database, char* username, int isPrivate,
                      char* response) {
    if (check_user_db(database, username) == -1) {
        sprintf(response, "User-ul %s nu a fost gasit in baza de date\n",
                username);
        return -1;
    }

    sqlite3_stmt* stmt;
    const char* query =
        "UPDATE users SET private_account = ? where username = ?;";

    if (prepare(database, query, &stmt) == -1) {
        sprintf(response, "Eroare la prepare!");
        return -1;
    }
    sqlite3_bind_int(stmt, 1, isPrivate);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);

        sprintf(response, "Eroare la setarea profilului %s", username);
        return -1;
    }

    sqlite3_finalize(stmt);

    if (isPrivate) {
        const char* query_update_posts =
            "UPDATE posts "
            "SET target_group = 1 "
            "WHERE id_author = (SELECT id FROM users WHERE username = ?) AND "
            "target_group = 0;";

        if (prepare(database, query_update_posts, &stmt) == -1) {
            return -1;
        }

        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sprintf(response,
                    "Eroare la actualizarea postărilor utilizatorului %s!",
                    username);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    sprintf(response,
            "Profilul utilizatorului %s a fost schimbat la %s și postările au "
            "fost actualizate!",
            username, isPrivate ? "privat" : "public");

    return 0;
}