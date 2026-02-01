#include "user_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dump(const char *username, const void *value, size_t len, void *ctx) {
    (void)ctx;
    printf("user=%s len=%zu ", username, len);
    if (value && len) {
        printf("value=");
        fwrite(value, 1, len, stdout);
    }
    printf("\n");
}