#ifndef USER_DB_H
#define USER_DB_H

#include <stddef.h>
#include <stdbool.h>

typedef struct user_db user_db_t;

/* Open (or create) DB at path prefix, e.g. "db/users" */
user_db_t *user_db_open(const char *path_prefix);

/* Close DB */
void user_db_close(user_db_t *db);

/* Insert or replace a user record.
   - if replace=false, duplicate usernames fail (DBM_INSERT)
   - if replace=true, overwrites existing (DBM_REPLACE)
   returns true on success
*/
bool user_db_put(user_db_t *db,
                 const char *username,
                 const char *record,
                 bool replace);

/* Fetch record into out buffer (null-terminated if fits).
   returns true if found.
*/
bool user_db_get(user_db_t *db,
                 const char *username,
                 char *out,
                 size_t outsz);

/* Check existence */
bool user_db_exists(user_db_t *db, const char *username);

#endif
