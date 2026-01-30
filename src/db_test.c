#include "user_db.h"
#include <stdio.h>

int main(void) {
    user_db_t *db = user_db_open("db/users");
    if (!db) {
        puts("failed to open db");
        return 1;
    }

    if (!user_db_put(db, "alice", "display=Alice;status=active", false)) {
        puts("insert alice failed (maybe already exists)");
    }

    char buf[256];
    if (user_db_get(db, "alice", buf, sizeof(buf))) {
        printf("alice => %s\n", buf);
    } else {
        puts("alice not found");
    }

    user_db_close(db);
    return 0;
}
