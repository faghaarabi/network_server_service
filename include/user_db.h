#ifndef USER_DB_H
#define USER_DB_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct user_db user_db_t;

    typedef enum {
        UDB_OK = 0,
        UDB_ERR_INVALID = -1,
        UDB_ERR_OPEN = -2,
        UDB_ERR_IO = -3,
        UDB_ERR_NOTFOUND = -4,
        UDB_ERR_EXISTS = -5
    } udb_status_t;

    /**
 * Open/create the user DB.
 * path example: "db/users.db"
 */
    udb_status_t user_db_open(user_db_t **out, const char *path);

    /** Close DB and free resources */
    udb_status_t user_db_close(user_db_t *db);

    /** Return true if username exists */
    udb_status_t user_db_exists(user_db_t *db, const char *username, bool *out_exists);
