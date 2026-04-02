//
// Created by Fereshteh on 4/2/26.
//#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "include/message_db.h"
#include <stdio.h>

int main() {
    message_db_t *db = NULL;

    if (message_db_open(&db, "db/messages.db") != MDB_OK) {
        printf("Failed to open DB\n");
        return 1;
    }

    uint8_t username[16] = "Fereshteh";
    uint8_t msg[] = "Hello world!";
    uint64_t ts = 123456789;

    // write
    if (message_db_put(db, 1, ts, 1, username, msg, sizeof(msg), false) != MDB_OK) {
        printf("PUT failed\n");
    } else {
        printf("PUT success\n");
    }

    // read
    uint8_t out_username[16];
    uint8_t *out_msg = NULL;
    uint16_t out_len = 0;

    if (message_db_get(db, 1, ts, 1, out_username, &out_msg, &out_len) != MDB_OK) {
        printf("GET failed\n");
    } else {
        printf("GET success\n");
        printf("username: %.16s\n", out_username);
        printf("message: %.*s\n", out_len, out_msg);
    }

    free(out_msg);
    message_db_close(db);

    return 0;
}