#include <stdio.h>
#include <stdlib.h>   // free
#include <string.h>

#include "user_db.h"

static int run_db_check(void) {
    user_db_t *db = NULL;

    if (user_db_open(&db, "db/users.db") != UDB_OK) {
        fprintf(stderr, "DB CHECK: failed to open database\n");
        return 1;
    }

    const char *user = "db_check_user";
    const char *value = "display=DBCheck;status=ok";

    if (user_db_put(db, user, value, strlen(value), true) != UDB_OK) {
        fprintf(stderr, "DB CHECK: failed to write\n");
        user_db_close(db);
        return 1;
    }

    void *out = NULL;
    size_t outlen = 0;

    if (user_db_get(db, user, &out, &outlen) != UDB_OK) {
        fprintf(stderr, "DB CHECK: failed to read\n");
        user_db_close(db);
        return 1;
    }

    printf("DB CHECK OK: %.*s\n", (int)outlen, (char *)out);
    free(out);

    user_db_close(db);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--db-check") == 0) {
        return run_db_check();
    }

    printf("Server starting...\n");

    user_db_t *db = NULL;
    if (user_db_open(&db, "db/users.db") != UDB_OK) {
        fprintf(stderr, "Fatal: could not open user DB\n");
        return 1;
    }

    printf("User DB opened successfully\n");



    user_db_close(db);
    return 0;
}
