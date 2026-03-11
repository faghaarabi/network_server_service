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

    db->dbm = dbm_open((char *)path, O_RDWR | O_CREAT, 0644);
    if (!db->dbm) {
        free(db);
        return UDB_ERR_OPEN;
    }

    *out = db;
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

udb_status_t user_db_exists(user_db_t *db, const char *username, bool *out_exists) {
    if (!db || !db->dbm || !out_exists) return UDB_ERR_INVALID;

    udb_status_t vu = validate_username(username);
    if (vu != UDB_OK) return vu;

    datum k = make_key(username);
    datum v = dbm_fetch(db->dbm, k);

    *out_exists = (v.dptr != NULL);
    return UDB_OK;
}

udb_status_t user_db_put(user_db_t *db,
                         const char *username,
                         const void *value,
                         size_t value_len,
                         bool overwrite) {
    if (!db || !db->dbm || !value || value_len == 0) return UDB_ERR_INVALID;

    udb_status_t vu = validate_username(username);
    if (vu != UDB_OK) return vu;

    datum k = make_key(username);

    datum v;
    v.dptr = (char *)value;
    v.dsize = (int)value_len;

    int flags = overwrite ? DBM_REPLACE : DBM_INSERT;

    // rc: 0 success, 1 means "exists" when DBM_INSERT, -1 error
    int rc = dbm_store(db->dbm, k, v, flags);

    if (rc == 0) return UDB_OK;
    if (rc == 1) return UDB_ERR_EXISTS;
    return UDB_ERR_IO;
}

udb_status_t user_db_get(user_db_t *db,
                         const char *username,
                         void **out_value,
                         size_t *out_len) {
    if (!db || !db->dbm || !out_value || !out_len) return UDB_ERR_INVALID;

    udb_status_t vu = validate_username(username);
    if (vu != UDB_OK) return vu;

    datum k = make_key(username);
    datum v = dbm_fetch(db->dbm, k);

    if (!v.dptr) return UDB_ERR_NOTFOUND;

    void *copy = malloc((size_t)v.dsize);
    if (!copy) return UDB_ERR_IO;

    memcpy(copy, v.dptr, (size_t)v.dsize);
    *out_value = copy;
    *out_len = (size_t)v.dsize;

    return UDB_OK;
}

udb_status_t user_db_del(user_db_t *db, const char *username) {
    if (!db || !db->dbm) return UDB_ERR_INVALID;

    udb_status_t vu = validate_username(username);
    if (vu != UDB_OK) return vu;

    datum k = make_key(username);

    int rc = dbm_delete(db->dbm, k);
    if (rc == 0) return UDB_OK;

    // Some implementations return -1 if key doesn't exist
    return UDB_ERR_NOTFOUND;
}

udb_status_t user_db_iterate(user_db_t *db, user_db_iter_cb cb, void *ctx) {
    if (!db || !db->dbm || !cb) return UDB_ERR_INVALID;

    for (datum k = dbm_firstkey(db->dbm); k.dptr != NULL; k = dbm_nextkey(db->dbm)) {
        // Make key NUL-terminated for callback
        char *uname = (char *)malloc((size_t)k.dsize + 1);
        if (!uname) return UDB_ERR_IO;

        memcpy(uname, k.dptr, (size_t)k.dsize);
        uname[k.dsize] = '\0';

        datum v = dbm_fetch(db->dbm, k);

        cb(uname, v.dptr, (size_t)((v.dptr) ? v.dsize : 0), ctx);

        free(uname);
    }

    return UDB_OK;
}
