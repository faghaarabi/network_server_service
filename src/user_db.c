#define _POSIX_C_SOURCE 200809L

#include "user_db.h"

#include <ndbm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

struct user_db {
    DBM *dbm;
};

static udb_status_t validate_username(const char *u) {
    if (!u) return UDB_ERR_INVALID;
    size_t n = strlen(u);
    if (n == 0) return UDB_ERR_INVALID;

    // Keep it simple and safe for now: forbid whitespace/control chars
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)u[i];
        if (c <= 32 || c == 127) return UDB_ERR_INVALID; // spaces + control
    }
    return UDB_OK;
}
static datum make_key(const char *username) {
    datum k;
    k.dptr = (char *)username;
    k.dsize = (int)strlen(username);
    return k;
}

udb_status_t user_db_open(user_db_t **out, const char *path) {
    if (!out || !path || path[0] == '\0') return UDB_ERR_INVALID;

    user_db_t *db = (user_db_t *)calloc(1, sizeof(*db));
    if (!db) return UDB_ERR_IO;

    db->dbm = dbm_open(path, O_RDWR | O_CREAT, 0644);
    if (!db->dbm) {
        free(db);
        return UDB_ERR_OPEN;
    }

    *out = db;
    return UDB_OK;
}
udb_status_t user_db_exists(user_db_t *db, const char *username, bool *out_exists) {
    if (!db || !db->dbm || !out_exists) return UDB_ERR_INVALID;

    udb_status_t vu = validate_username(username);
    if (vu != UDB_OK) return vu;

    datum k = make_key(username);
    datum v = dbm_fetch(db->dbm, k);

    *out_exists = (v.dptr != NULL);
    return UDB_OK;
}


udb_status_t user_db_close(user_db_t *db) {
    if (!db) return UDB_ERR_INVALID;
    if (db->dbm) {
        dbm_close(db->dbm);
        db->dbm = NULL;
    }
    free(db);
    return UDB_OK;
}
