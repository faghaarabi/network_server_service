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