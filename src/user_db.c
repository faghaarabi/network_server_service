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