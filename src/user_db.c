#define _POSIX_C_SOURCE 200809L
#include "user_db.h"

#include <ndbm.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct user_db {
    DBM *h;
};

static datum mk_datum(const char *s) {
    datum d;
    d.dptr = (char *)s;
    d.dsize = (int)strlen(s);
    return d;
}

user_db_t *user_db_open(const char *path_prefix) {
    if (!path_prefix) return NULL;

    user_db_t *db = calloc(1, sizeof(*db));
    if (!db) return NULL;

    db->h = dbm_open(path_prefix, O_RDWR | O_CREAT, 0644);
    if (!db->h) {
        perror("dbm_open");
        free(db);
        return NULL;
    }
    return db;
}

void user_db_close(user_db_t *db) {
    if (!db) return;
    if (db->h) dbm_close(db->h);
    free(db);
}

bool user_db_put(user_db_t *db, const char *username, const char *record, bool replace) {
    if (!db || !db->h || !username || !record) return false;

    datum k = mk_datum(username);
    datum v = mk_datum(record);

    int flags = replace ? DBM_REPLACE : DBM_INSERT;

    errno = 0;
    int rc = dbm_store(db->h, k, v, flags);
    if (rc != 0) {
        /* With DBM_INSERT, duplicate key causes failure; errno may or may not be set depending on impl. */
        return false;
    }
    return true;
}

bool user_db_get(user_db_t *db, const char *username, char *out, size_t outsz) {
    if (!db || !db->h || !username || !out || outsz == 0) return false;

    datum k = mk_datum(username);

    datum got = dbm_fetch(db->h, k);
    if (!got.dptr || got.dsize <= 0) return false;

    size_t n = (size_t)got.dsize;
    if (n >= outsz) n = outsz - 1;

    memcpy(out, got.dptr, n);
    out[n] = '\0';
    return true;
}

bool user_db_exists(user_db_t *db, const char *username) {
    if (!db || !db->h || !username) return false;
    datum k = mk_datum(username);
    datum got = dbm_fetch(db->h, k);
    return got.dptr != NULL;
}
