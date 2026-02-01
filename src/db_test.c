#include "user_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dump(const char *username, const void *value, size_t len, void *ctx) {
    (void)ctx;
    printf("user=%s len=%zu ", username, len);
    if (value && len) {
        printf("value=");
        fwrite(value, 1, len, stdout);
    }
    printf("\n");
}

int main(void) {
    user_db_t *db = NULL;

    if (user_db_open(&db, "db/users.db") != UDB_OK) {
        fprintf(stderr, "open failed\n");
        return 1;
    }

    const char *u = "alice";
    const char *v = "example_password_hash_or_blob";

    udb_status_t st = user_db_put(db, u, v, strlen(v), true);
    if (st != UDB_OK) {
        fprintf(stderr, "put failed (%d)\n", st);
        user_db_close(db);
        return 1;
    }

    void *out = NULL;
    size_t outlen = 0;
    if (user_db_get(db, u, &out, &outlen) == UDB_OK) {
        printf("get: %.*s\n", (int)outlen, (char *)out);
        free(out);
    } else {
        printf("get: not found\n");
    }

    printf("iterate:\n");
    user_db_iterate(db, dump, NULL);

    user_db_close(db);
    return 0;
}
