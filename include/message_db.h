#ifndef MESSAGE_DB_H
#define MESSAGE_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct message_db message_db_t;

    typedef enum {
        MDB_OK = 0,
        MDB_ERR_INVALID = -1,
        MDB_ERR_OPEN = -2,
        MDB_ERR_IO = -3,
        MDB_ERR_NOTFOUND = -4,
        MDB_ERR_EXISTS = -5
    } mdb_status_t;

    typedef struct {
        uint64_t timestamp;
        uint8_t sender_id;
        uint8_t sender_username16[16];
        uint16_t msg_len;
        uint8_t *msg;
    } message_record_t;

    mdb_status_t message_db_open(message_db_t **out, const char *path);
    mdb_status_t message_db_close(message_db_t *db);

    mdb_status_t message_db_put(message_db_t *db,
                                uint8_t channel_id,
                                uint64_t timestamp,
                                uint8_t sender_id,
                                const uint8_t sender_username16[16],
                                const uint8_t *msg,
                                uint16_t msg_len,
                                bool overwrite);

    mdb_status_t message_db_get(message_db_t *db,
                                uint8_t channel_id,
                                uint64_t timestamp,
                                uint8_t sender_id,
                                uint8_t out_sender_username16[16],
                                uint8_t **out_msg,
                                uint16_t *out_msg_len);

    mdb_status_t message_db_load_channel(message_db_t *db,
                                         uint8_t channel_id,
                                         message_record_t **out_items,
                                         size_t *out_count);

    void message_db_free_records(message_record_t *items, size_t count);

#ifdef __cplusplus
}
#endif

#endif