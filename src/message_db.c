//
// Created by Fereshteh on 4/2/26.
//

#include "message_db.h"

#include <ndbm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

struct message_db {
    DBM *dbm;
};

#pragma pack(push, 1)
typedef struct {
    uint8_t channel_id;
    uint64_t timestamp;
    uint8_t sender_id;
} message_key_t;

typedef struct {
    uint8_t sender_username16[16];
    uint16_t msg_len;
} message_value_prefix_t;
#pragma pack(pop)

static void make_key(message_key_t *k,
                     uint8_t channel_id,
                     uint64_t timestamp,
                     uint8_t sender_id) {
    k->channel_id = channel_id;
    k->timestamp = timestamp;
    k->sender_id = sender_id;
}

static mdb_status_t ensure_parent_dir(const char *path) {
    if (!path) return MDB_ERR_INVALID;

    char *tmp = strdup(path);
    if (!tmp) return MDB_ERR_IO;

    char *slash = strrchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        if (tmp[0] != '\0') {
            mkdir(tmp, 0777);
        }
    }

    free(tmp);
    return MDB_OK;
}

mdb_status_t message_db_open(message_db_t **out, const char *path) {
    if (!out || !path) return MDB_ERR_INVALID;
    *out = NULL;

    if (ensure_parent_dir(path) != MDB_OK) return MDB_ERR_IO;

    message_db_t *db = (message_db_t *)calloc(1, sizeof(*db));
    if (!db) return MDB_ERR_IO;

    db->dbm = dbm_open(path, O_RDWR | O_CREAT, 0666);
    if (!db->dbm) {
        free(db);
        return MDB_ERR_OPEN;
    }

    *out = db;
    return MDB_OK;
}

mdb_status_t message_db_close(message_db_t *db) {
    if (!db) return MDB_ERR_INVALID;
    if (db->dbm) dbm_close(db->dbm);
    free(db);
    return MDB_OK;
}

mdb_status_t message_db_put(message_db_t *db,
                            uint8_t channel_id,
                            uint64_t timestamp,
                            uint8_t sender_id,
                            const uint8_t sender_username16[16],
                            const uint8_t *msg,
                            uint16_t msg_len,
                            bool overwrite) {
    if (!db || !db->dbm || !sender_username16) return MDB_ERR_INVALID;
    if (msg_len > 0 && !msg) return MDB_ERR_INVALID;

    message_key_t key_struct;
    make_key(&key_struct, channel_id, timestamp, sender_id);

    datum key;
    key.dptr = (char *)&key_struct;
    key.dsize = sizeof(key_struct);

    size_t value_len = sizeof(message_value_prefix_t) + msg_len;
    uint8_t *buf = (uint8_t *)malloc(value_len);
    if (!buf) return MDB_ERR_IO;

    message_value_prefix_t *prefix = (message_value_prefix_t *)buf;
    memcpy(prefix->sender_username16, sender_username16, 16);
    prefix->msg_len = msg_len;

    if (msg_len > 0) {
        memcpy(buf + sizeof(message_value_prefix_t), msg, msg_len);
    }

    datum value;
    value.dptr = (char *)buf;
    value.dsize = (int)value_len;

    int flags = overwrite ? DBM_REPLACE : DBM_INSERT;
    int rc = dbm_store(db->dbm, key, value, flags);

    free(buf);

    if (rc != 0) {
        if (!overwrite) return MDB_ERR_EXISTS;
        return MDB_ERR_IO;
    }

    return MDB_OK;
}

mdb_status_t message_db_get(message_db_t *db,
                            uint8_t channel_id,
                            uint64_t timestamp,
                            uint8_t sender_id,
                            uint8_t out_sender_username16[16],
                            uint8_t **out_msg,
                            uint16_t *out_msg_len) {
    if (!db || !db->dbm || !out_sender_username16 || !out_msg || !out_msg_len) {
        return MDB_ERR_INVALID;
    }

    *out_msg = NULL;
    *out_msg_len = 0;

    message_key_t key_struct;
    make_key(&key_struct, channel_id, timestamp, sender_id);

    datum key;
    key.dptr = (char *)&key_struct;
    key.dsize = sizeof(key_struct);

    datum value = dbm_fetch(db->dbm, key);
    if (!value.dptr || value.dsize < (int)sizeof(message_value_prefix_t)) {
        return MDB_ERR_NOTFOUND;
    }

    message_value_prefix_t prefix;
    memcpy(&prefix, value.dptr, sizeof(prefix));

    if ((size_t)value.dsize != sizeof(message_value_prefix_t) + prefix.msg_len) {
        return MDB_ERR_IO;
    }

    memcpy(out_sender_username16, prefix.sender_username16, 16);

    if (prefix.msg_len > 0) {
        *out_msg = (uint8_t *)malloc(prefix.msg_len);
        if (!*out_msg) return MDB_ERR_IO;
        memcpy(*out_msg,
               (uint8_t *)value.dptr + sizeof(message_value_prefix_t),
               prefix.msg_len);
    }

    *out_msg_len = prefix.msg_len;
    return MDB_OK;
}

mdb_status_t message_db_del(message_db_t *db,
                            uint8_t channel_id,
                            uint64_t timestamp,
                            uint8_t sender_id) {
    if (!db || !db->dbm) return MDB_ERR_INVALID;

    message_key_t key_struct;
    make_key(&key_struct, channel_id, timestamp, sender_id);

    datum key;
    key.dptr = (char *)&key_struct;
    key.dsize = sizeof(key_struct);

    datum value = dbm_fetch(db->dbm, key);
    if (!value.dptr) {
        return MDB_ERR_NOTFOUND;
    }

    int rc = dbm_delete(db->dbm, key);
    if (rc != 0) {
        return MDB_ERR_IO;
    }

    return MDB_OK;
}

mdb_status_t message_db_load_channel(message_db_t *db,
                                     uint8_t channel_id,
                                     message_record_t **out_items,
                                     size_t *out_count) {
    if (!db || !db->dbm || !out_items || !out_count) return MDB_ERR_INVALID;

    *out_items = NULL;
    *out_count = 0;

    size_t cap = 0;
    size_t count = 0;
    message_record_t *items = NULL;

    for (datum key = dbm_firstkey(db->dbm); key.dptr != NULL; key = dbm_nextkey(db->dbm)) {
        if (key.dsize != (int)sizeof(message_key_t)) continue;

        message_key_t k;
        memcpy(&k, key.dptr, sizeof(k));

        if (k.channel_id != channel_id) continue;

        datum value = dbm_fetch(db->dbm, key);
        if (!value.dptr || value.dsize < (int)sizeof(message_value_prefix_t)) continue;

        message_value_prefix_t prefix;
        memcpy(&prefix, value.dptr, sizeof(prefix));

        if ((size_t)value.dsize != sizeof(message_value_prefix_t) + prefix.msg_len) continue;

        if (count == cap) {
            size_t new_cap = (cap == 0) ? 8 : cap * 2;
            message_record_t *tmp =
                (message_record_t *)realloc(items, new_cap * sizeof(message_record_t));
            if (!tmp) {
                message_db_free_records(items, count);
                return MDB_ERR_IO;
            }
            items = tmp;
            cap = new_cap;
        }

        items[count].timestamp = k.timestamp;
        items[count].sender_id = k.sender_id;
        memcpy(items[count].sender_username16, prefix.sender_username16, 16);
        items[count].msg_len = prefix.msg_len;
        items[count].msg = NULL;

        if (prefix.msg_len > 0) {
            items[count].msg = (uint8_t *)malloc(prefix.msg_len);
            if (!items[count].msg) {
                message_db_free_records(items, count);
                return MDB_ERR_IO;
            }
            memcpy(items[count].msg,
                   (uint8_t *)value.dptr + sizeof(message_value_prefix_t),
                   prefix.msg_len);
        }

        count++;
    }

    *out_items = items;
    *out_count = count;
    return MDB_OK;
}

void message_db_free_records(message_record_t *items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) {
        free(items[i].msg);
    }
    free(items);
}