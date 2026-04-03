// protocol.c - BIG v0.2 RFC + Refactored for response/body alignment
// Fully compatible with macOS ARM64 and Linux

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>


#include "user_db.h"
#include "message_db.h"

static pthread_mutex_t g_db_mu = PTHREAD_MUTEX_INITIALIZER;



enum { PROTO_V2 = 0x02 };

/* Status codes (1 byte) */
enum {
    ST_OK                 = 0x00,
    ST_InvalidVersion     = 0x40,
    ST_InvalidType        = 0x41,
    ST_InvalidSize        = 0x42,
    ST_MalformedRequest   = 0x43,
    ST_InvalidCreds       = 0x44,
    ST_NotFound           = 0x45,
    ST_AlreadyExists      = 0x46,
    ST_NotRegistered      = 0x47,
    ST_Forbidden          = 0x48,
    ST_NotChannelMember   = 0x49,
    ST_InternalError      = 0x80,
    ST_ServiceUnavailable = 0x81,
    ST_ResourceExhausted  = 0x82,
    ST_MessageTooLarge    = 0x83,
    ST_Timeout            = 0x84
};

/* Type encoding */
enum {
    RES_SERVER          = 0x00,
    RES_ACTIVATEDSERVER = 0x01,
    RES_USER            = 0x02,
    RES_LOG             = 0x03,
    RES_CHANNEL         = 0x04,
    RES_CHANNELS        = 0x05,
    RES_MESSAGE         = 0x06
};

enum { CRUD_CREATE = 0x00, CRUD_READ = 0x01, CRUD_UPDATE = 0x02, CRUD_DELETE = 0x03 };

/* Message types */
enum MsgType {
    MSG_SERVER_REG_REQ      = 0x00, MSG_SERVER_REG_RES      = 0x01,
    MSG_SERVER_HC_REQ       = 0x04, MSG_SERVER_HC_RES       = 0x05,
    MSG_ACTIVATE_REQ        = 0x08, MSG_ACTIVATE_RES        = 0x09,
    MSG_GET_ACTIVE_REQ      = 0x0A, MSG_GET_ACTIVE_RES      = 0x0B,
    MSG_DEACTIVATE_REQ      = 0x0E, MSG_DEACTIVATE_RES      = 0x0F,
    MSG_USER_CREATE_REQ     = 0x10, MSG_USER_CREATE_RES     = 0x11,
    MSG_USER_READ_REQ       = 0x12, MSG_USER_READ_RES       = 0x13,
    MSG_USER_UPDATE_REQ     = 0x14, MSG_USER_UPDATE_RES     = 0x15,
    MSG_LOG_CREATE_REQ      = 0x18, MSG_LOG_CREATE_RES      = 0x19,
    MSG_CHANNEL_CREATE_REQ  = 0x20, MSG_CHANNEL_CREATE_RES  = 0x21,
    MSG_CHANNEL_READ_REQ    = 0x22, MSG_CHANNEL_READ_RES    = 0x23,
    MSG_CHANNELS_READ_REQ   = 0x2A, MSG_CHANNELS_READ_RES   = 0x2B,
    MSG_MESSAGE_CREATE_REQ  = 0x30, MSG_MESSAGE_CREATE_RES  = 0x31,
    MSG_MESSAGE_READ_REQ    = 0x32, MSG_MESSAGE_READ_RES    = 0x33
};

/* Compatibility aliases */
enum {
    MSG_OLD_SERVER_GET_REQ      = 0x02,
    MSG_OLD_SERVER_GET_RES      = 0x03,
    MSG_OLD_SERVER_ACTIVATE_REQ = 0x04,
    MSG_OLD_SERVER_ACTIVATE_RES = 0x05
};

enum { BIG_MAX_BODY = 65579 };

#pragma pack(push, 1)

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  reserved;
    uint32_t size_be;
} WireHeader;

typedef struct {
    uint8_t ipv4[4];
    uint8_t id;
} Body5;

typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t user_id;
} BodyUserCreate;

typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t ipv4[4];
    uint8_t user_status;
} BodyUserUpdate;

/* Request + response layout reused:
 * auth_username16 + auth_password16 + username16 + target_user_id
 */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t username16[16];
    uint8_t target_user_id;
} BodyUserRead;



typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_name16[16];
    uint8_t channel_id;
} BodyChannelCreate;

/* Channel Read req/ack prefix:
 * username(16) + password(16) + channel_name(16) + channel_id(1) + user_id_len(1) + user_ids[]
 */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_name16[16];
    uint8_t channel_id;
    uint8_t user_id_len;
} BodyChannelReadPrefix;

/* Channels Read req/ack prefix:
 * username(16) + password(16) + channel_list_len(1) + channel_list[]
 */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_id_len;
} BodyChannelsReadPrefix;

/* Message Create req:
 * username(16) + password(16) + timestamp(8) + msg_len(2) + channel_id(1) + message[]
 */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint64_t timestamp;
    uint16_t message_len;
    uint8_t channel_id;
} BodyMessageCreateReqPrefix;

/* Message Read req/ack:
 * username(16) + password(16) + timestamp(8) + msg_len(2) + channel_id(1) + sender_id(1) + message[]
 */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint64_t timestamp;
    uint16_t message_len;
    uint8_t channel_id;
    uint8_t sender_id;
} BodyMessageReadPrefix;

#pragma pack(pop)

/* Portable 64-bit endian helpers */
static uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8)  & 0xFF00FF00FF00FF00ULL) | ((val >> 8)  & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

static uint64_t my_htonll(uint64_t val) {
    uint32_t test = 1;
    if (*((uint8_t *)&test) == 1) return swap_uint64(val);
    return val;
}

static uint64_t my_ntohll(uint64_t val) {
    return my_htonll(val);
}

#define MAX_CHANNELS 32
#define MAX_CHANNEL_MEMBERS 255
#define MAX_HISTORY 256
#define MAX_STORED_MESSAGE 1024

typedef struct {
    bool in_use;
    uint8_t channel_id;
    uint8_t channel_name16[16];
    uint8_t member_count;
    uint8_t member_ids[MAX_CHANNEL_MEMBERS];
    uint8_t owner_user_id;
} Channel;

typedef struct {
    uint64_t timestamp;
    uint16_t msg_len;
    uint8_t channel_id;
    uint8_t sender_id;
    uint8_t sender_username16[16];
    uint8_t sender_password16[16];
    uint8_t msg[MAX_STORED_MESSAGE];
} HistoricalMsg;

static pthread_mutex_t g_channels_mu = PTHREAD_MUTEX_INITIALIZER;
static Channel g_channels[MAX_CHANNELS];
static uint8_t g_next_channel_id = 1;
static pthread_once_t g_channels_once = PTHREAD_ONCE_INIT;

/* Client connection registry for broadcasting messages */
static int g_client_fds[256];
static pthread_mutex_t g_clients_mu = PTHREAD_MUTEX_INITIALIZER;

/* Message history */
static HistoricalMsg g_msg_history[MAX_HISTORY];
static int g_msg_hist_head = -1;
static pthread_mutex_t g_msg_hist_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---------- UID allocator + UID->Username mapping ---------- */
static pthread_mutex_t g_uid_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_next_uid = 1;

static pthread_mutex_t g_uidmap_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_uid_present[256];
static uint8_t g_uid_username16[256][16];

/* ---------- Activated server state ---------- */
static pthread_mutex_t g_active_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_active_set = false;
static Body5 g_active_server;

/* ---------- Helpers ---------- */
static void client_set_fd(uint8_t uid, int fd) {
    pthread_mutex_lock(&g_clients_mu);
    if (uid > 0) g_client_fds[uid] = fd;
    pthread_mutex_unlock(&g_clients_mu);
}

static int client_get_fd(uint8_t uid) {
    int fd = -1;
    pthread_mutex_lock(&g_clients_mu);
    if (uid > 0) fd = g_client_fds[uid];
    pthread_mutex_unlock(&g_clients_mu);
    return fd;
}

static void client_remove_fd(int fd) {
    pthread_mutex_lock(&g_clients_mu);
    for (int i = 0; i < 256; i++) {
        if (g_client_fds[i] == fd) g_client_fds[i] = -1;
    }
    pthread_mutex_unlock(&g_clients_mu);
}

static uint8_t alloc_uid(void) {
    pthread_mutex_lock(&g_uid_mu);
    uint8_t id = g_next_uid++;
    if (g_next_uid == 0) g_next_uid = 1;
    pthread_mutex_unlock(&g_uid_mu);
    return id;
}

static void uidmap_set(uint8_t uid, const uint8_t username16[16]) {
    if (uid == 0) return;
    pthread_mutex_lock(&g_uidmap_mu);
    memcpy(g_uid_username16[uid], username16, 16);
    g_uid_present[uid] = true;
    pthread_mutex_unlock(&g_uidmap_mu);
}

static bool uidmap_get(uint8_t uid, uint8_t out_username16[16]) {
    if (uid == 0) return false;
    pthread_mutex_lock(&g_uidmap_mu);
    bool ok = g_uid_present[uid];
    if (ok) memcpy(out_username16, g_uid_username16[uid], 16);
    pthread_mutex_unlock(&g_uidmap_mu);
    return ok;
}


static bool uidmap_find_by_username(const uint8_t username16[16], uint8_t *out_uid) {
    pthread_mutex_lock(&g_uidmap_mu);
    for (int i = 1; i < 256; i++) {
        if (g_uid_present[i] && memcmp(g_uid_username16[i], username16, 16) == 0) {
            if (out_uid) *out_uid = (uint8_t)i;
            pthread_mutex_unlock(&g_uidmap_mu);
            return true;
        }
    }
    pthread_mutex_unlock(&g_uidmap_mu);
    return false;
}

static void active_set(const Body5 *s) {
    pthread_mutex_lock(&g_active_mu);
    g_active_server = *s;
    g_active_set = true;
    pthread_mutex_unlock(&g_active_mu);
}

static bool active_get(Body5 *out) {
    pthread_mutex_lock(&g_active_mu);
    bool ok = g_active_set;
    if (ok && out) *out = g_active_server;
    pthread_mutex_unlock(&g_active_mu);
    return ok;
}

static void channels_init_once(void) {
    memset(g_channels, 0, sizeof(g_channels));
    memset(g_msg_history, 0, sizeof(g_msg_history));
    memset(g_uid_present, 0, sizeof(g_uid_present));
    memset(g_uid_username16, 0, sizeof(g_uid_username16));
    for (int i = 0; i < 256; i++) g_client_fds[i] = -1;

    g_channels[0].in_use = true;
    g_channels[0].channel_id = 1;
    memcpy(g_channels[0].channel_name16, "milestone2\0\0\0\0\0\0", 16);
    g_channels[0].member_count = 0;
    g_channels[0].owner_user_id = 0;

    g_channels[1].in_use = true;
    g_channels[1].channel_id = 2;
    memcpy(g_channels[1].channel_name16, "general\0\0\0\0\0\0\0\0\0", 16);
    g_channels[1].member_count = 0;
    g_channels[1].owner_user_id = 0;

    g_channels[2].in_use = true;
    g_channels[2].channel_id = 3;
    memcpy(g_channels[2].channel_name16, "random\0\0\0\0\0\0\0\0\0\0", 16);
    g_channels[2].member_count = 0;
    g_channels[2].owner_user_id = 0;

    g_next_channel_id = 4;
    g_msg_hist_head = -1;
}

static void ensure_channels_initialized(void) {
    pthread_once(&g_channels_once, channels_init_once);
}

static bool channel_has_member_locked(const Channel *ch, uint8_t user_id) {
    if (!ch || user_id == 0) return false;
    for (uint8_t i = 0; i < ch->member_count; i++) {
        if (ch->member_ids[i] == user_id) return true;
    }
    return false;
}

static bool channel_add_member_locked(Channel *ch, uint8_t user_id) {
    if (!ch || user_id == 0) return false;
    if (channel_has_member_locked(ch, user_id)) return true;
    if (ch->member_count >= MAX_CHANNEL_MEMBERS) return false;
    ch->member_ids[ch->member_count++] = user_id;
    return true;
}

static uint8_t channels_collect_ids(uint8_t out_ids[255]) {
    uint8_t count = 0;
    ensure_channels_initialized();
    pthread_mutex_lock(&g_channels_mu);
    for (int i = 0; i < MAX_CHANNELS && count < 255; i++) {
        if (g_channels[i].in_use) out_ids[count++] = g_channels[i].channel_id;
    }
    pthread_mutex_unlock(&g_channels_mu);
    return count;
}

static int read_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r == 0) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 1;
}

static int write_exact(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static inline uint8_t type_direction(uint8_t type) { return type & 0x01; }
static inline uint8_t type_crud(uint8_t type)      { return (type >> 1) & 0x03; }
static inline uint8_t type_resource(uint8_t type)  { return (type >> 3) & 0x1F; }
static inline uint8_t make_resp_type(uint8_t req_type) { return (uint8_t)((req_type & 0xFE) | 0x01); }

static bool is_valid_type_combo(uint8_t type) {
    uint8_t r = type_resource(type), a = type_crud(type);
    if (type == MSG_OLD_SERVER_GET_REQ || type == MSG_OLD_SERVER_ACTIVATE_REQ) return true;

    switch (r) {
        case RES_SERVER:
            return (a == CRUD_CREATE) || (a == CRUD_UPDATE);
        case RES_ACTIVATEDSERVER:
            return (a == CRUD_CREATE) || (a == CRUD_READ) || (a == CRUD_DELETE);
        case RES_USER:
            return (a == CRUD_CREATE) || (a == CRUD_READ) || (a == CRUD_UPDATE);
        case RES_LOG:
            return (a == CRUD_CREATE);
        case RES_CHANNEL:
            return (a == CRUD_CREATE) || (a == CRUD_READ);
        case RES_CHANNELS:
            return (a == CRUD_READ);
        case RES_MESSAGE:
            return (a == CRUD_CREATE) || (a == CRUD_READ);
        default:
            return false;
    }
}

static void username16_to_key(const uint8_t in[16], char out[17]) {
    memcpy(out, in, 16);
    out[16] = '\0';
}

static bool udb_is_exists(udb_status_t st) {
    return st == UDB_ERR_EXISTS;
}

static bool auth_ok16(user_db_t *db, const uint8_t username16[16], const uint8_t password16[16]) {
    char key[17];
    username16_to_key(username16, key);

    void *stored = NULL;
    size_t stored_len = 0;

    pthread_mutex_lock(&g_db_mu);
    udb_status_t st = user_db_get(db, key, &stored, &stored_len);
    pthread_mutex_unlock(&g_db_mu);

    if (st != UDB_OK || !stored) {
        free(stored);
        return false;
    }

    bool ok = (stored_len >= 16) && (memcmp(stored, password16, 16) == 0);
    free(stored);
    return ok;
}

static int send_response_raw(int fd, uint8_t type, uint8_t status, const void *body, uint32_t body_len) {
    WireHeader h = { PROTO_V2, type, status, 0, htonl(body_len) };
    if (write_exact(fd, &h, sizeof(h)) < 0) return -1;
    if (body_len > 0 && body) {
        if (write_exact(fd, body, body_len) < 0) return -1;
    }
    return 0;
}

static int send_response_keepalive(int fd, uint8_t type, uint8_t status, const void *body, uint32_t body_len) {
    return (send_response_raw(fd, type, status, body, body_len) < 0) ? -1 : 1;
}

static uint8_t *build_message_read_body(const uint8_t username16[16],
                                        const uint8_t password16[16],
                                        uint64_t timestamp_host,
                                        uint16_t msg_len_host,
                                        uint8_t channel_id,
                                        uint8_t sender_id,
                                        const uint8_t *msg,
                                        uint32_t *out_len) {
    uint32_t total = (uint32_t)sizeof(BodyMessageReadPrefix) + msg_len_host;
    uint8_t *buf = (uint8_t *)calloc(1, total);
    if (!buf) return NULL;

    BodyMessageReadPrefix *p = (BodyMessageReadPrefix *)buf;
    memcpy(p->auth_username16, username16, 16);
    memcpy(p->auth_password16, password16, 16);
    p->timestamp = my_htonll(timestamp_host);
    p->message_len = htons(msg_len_host);
    p->channel_id = channel_id;
    p->sender_id = sender_id;

    if (msg_len_host > 0 && msg) {
        memcpy(buf + sizeof(BodyMessageReadPrefix), msg, msg_len_host);
    }

    if (out_len) *out_len = total;
    printf("DEBUG BUILD:\n");
    printf("  total size = %u\n", total);
    printf("  timestamp = %llu\n", (unsigned long long)timestamp_host);
    printf("  msg_len = %u\n", msg_len_host);
    printf("  channel_id = %u\n", channel_id);
    printf("  sender_id = %u\n", sender_id);
    fflush(stdout);
    return buf;
}

int protocol_handle_one(int client_fd, user_db_t *db, message_db_t *msg_db)  {
    (void)msg_db;
    WireHeader h;
    int rr = read_exact(client_fd, &h, sizeof(h));
    if (rr <= 0) return rr;

    uint8_t resp_type = make_resp_type(h.type);

    if (h.version != PROTO_V2) {
        return send_response_keepalive(client_fd, resp_type, ST_InvalidVersion, NULL, 0) - 2;
    }

    if (type_direction(h.type) != 0 || !is_valid_type_combo(h.type)) {
        return send_response_keepalive(client_fd, resp_type, ST_InvalidType, NULL, 0) - 2;
    }

    uint32_t body_len = ntohl(h.size_be);
    uint8_t *body = NULL;

    if (body_len > BIG_MAX_BODY) {
        return send_response_keepalive(client_fd, resp_type, ST_MessageTooLarge, NULL, 0) - 2;
    }

    if (body_len > 0) {
        body = (uint8_t *)malloc(body_len);
        if (!body) {
            return send_response_keepalive(client_fd, resp_type, ST_ResourceExhausted, NULL, 0) - 2;
        }
        if (read_exact(client_fd, body, body_len) <= 0) {
            free(body);
            return -1;
        }
    }

    ensure_channels_initialized();

    /* ================= SERVER REGISTER ================= */
    if (h.type == MSG_SERVER_REG_REQ) {
        if (body_len != sizeof(Body5)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_SERVER_REG_RES, ST_InvalidSize, NULL, 0);
        }
        int ret = send_response_keepalive(client_fd, MSG_SERVER_REG_RES, ST_OK, body, body_len);
        free(body);
        return ret;
    }

    /* ================= ACTIVATE SERVER ================= */
    if (h.type == MSG_ACTIVATE_REQ || h.type == MSG_OLD_SERVER_ACTIVATE_REQ) {
        uint8_t t = (h.type == MSG_OLD_SERVER_ACTIVATE_REQ) ? MSG_OLD_SERVER_ACTIVATE_RES : MSG_ACTIVATE_RES;
        if (body_len != sizeof(Body5)) {
            free(body);
            return send_response_keepalive(client_fd, t, ST_InvalidSize, NULL, 0);
        }
        active_set((Body5 *)body);
        int ret = send_response_keepalive(client_fd, t, ST_OK, body, body_len);
        free(body);
        return ret;
    }

    /* ================= GET ACTIVE SERVER ================= */
    if (h.type == MSG_GET_ACTIVE_REQ || h.type == MSG_OLD_SERVER_GET_REQ) {
        uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;
        free(body);

        Body5 res;
        memset(&res, 0, sizeof(res));
        if (!active_get(&res)) {
            return send_response_keepalive(client_fd, t, ST_NotRegistered, NULL, 0);
        }
        return send_response_keepalive(client_fd, t, ST_OK, &res, sizeof(res));
    }

    /* ================= USER CREATE ================= */
    if (h.type == MSG_USER_CREATE_REQ) {
        if (body_len != sizeof(BodyUserCreate)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyUserCreate req;
        memcpy(&req, body, sizeof(req));
        free(body);

        char key[17];
        username16_to_key(req.username16, key);

        pthread_mutex_lock(&g_db_mu);
        udb_status_t st = user_db_put(db, key, req.password16, 16, false);
        pthread_mutex_unlock(&g_db_mu);

        if (st == UDB_OK) {
            req.user_id = alloc_uid();
            uidmap_set(req.user_id, req.username16);

            pthread_mutex_lock(&g_channels_mu);
            channel_add_member_locked(&g_channels[0], req.user_id);
            pthread_mutex_unlock(&g_channels_mu);

            return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_OK, &req, sizeof(req));
        }

        return send_response_keepalive(
            client_fd,
            MSG_USER_CREATE_RES,
            udb_is_exists(st) ? ST_AlreadyExists : ST_InternalError,
            NULL,
            0
        );
    }

    /* ================= USER UPDATE (Login/Logout) ================= */
    if (h.type == MSG_USER_UPDATE_REQ) {
        if (body_len != sizeof(BodyUserUpdate)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyUserUpdate req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.username16, req.password16)) {
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidCreds, NULL, 0);
        }

        if (req.user_status > 1) {
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_MalformedRequest, NULL, 0);
        }

        uint8_t uid = 0;
        if (!uidmap_find_by_username(req.username16, &uid)) {
            uid = alloc_uid();
            uidmap_set(uid, req.username16);
        }

        if (req.user_status == 1) {
            client_set_fd(uid, client_fd);
            printf("LOGIN username=%.16s uid=%u fd=%d\n", req.username16, uid, client_fd);
            fflush(stdout);

            pthread_mutex_lock(&g_channels_mu);
            channel_add_member_locked(&g_channels[0], uid);
            pthread_mutex_unlock(&g_channels_mu);
        } else {
            client_remove_fd(client_fd);
        }

        return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_OK, &req, sizeof(req));
    }

    /* ================= USER READ ================= */
    if (h.type == MSG_USER_READ_REQ) {
        if (body_len != sizeof(BodyUserRead)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyUserRead req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        uint8_t uname16[16];
        if (!uidmap_get(req.target_user_id, uname16)) {
            return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_NotFound, NULL, 0);
        }

        BodyUserRead res;
        memset(&res, 0, sizeof(res));
        memcpy(res.auth_username16, req.auth_username16, 16);
        memcpy(res.auth_password16, req.auth_password16, 16);
        memcpy(res.username16, uname16, 16);
        res.target_user_id = req.target_user_id;

        return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_OK, &res, sizeof(res));
    }

    /* ================= CHANNEL CREATE ================= */
    if (h.type == MSG_CHANNEL_CREATE_REQ) {
        free(body);
        return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_Forbidden, NULL, 0);
    }

    /* ================= CHANNEL READ ================= */
    if (h.type == MSG_CHANNEL_READ_REQ) {
        if (body_len < sizeof(BodyChannelReadPrefix)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyChannelReadPrefix req;
        memcpy(&req, body, sizeof(req));

        if (body_len != (uint32_t)sizeof(BodyChannelReadPrefix) + req.user_id_len) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidSize, NULL, 0);
        }

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        uint8_t uid = 0;
        if (!uidmap_find_by_username(req.auth_username16, &uid)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InternalError, NULL, 0);
        }

        pthread_mutex_lock(&g_channels_mu);

        int ch_idx = -1;

        if (req.channel_id != 0) {
            for (int i = 0; i < MAX_CHANNELS; i++) {
                if (g_channels[i].in_use && g_channels[i].channel_id == req.channel_id) {
                    ch_idx = i;
                    break;
                }
            }
        }

        if (ch_idx < 0) {
            for (int i = 0; i < MAX_CHANNELS; i++) {
                if (g_channels[i].in_use &&
                    memcmp(g_channels[i].channel_name16, req.channel_name16, 16) == 0) {
                    ch_idx = i;
                    break;
                }
            }
        }

        if (ch_idx < 0) {
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_NotFound, NULL, 0);
        }

        if (!channel_has_member_locked(&g_channels[ch_idx], uid)) {
            if (!channel_add_member_locked(&g_channels[ch_idx], uid)) {
                pthread_mutex_unlock(&g_channels_mu);
                free(body);
                return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_ResourceExhausted, NULL, 0);
            }

            printf("JOIN: uid=%u -> channel=%u\n", uid, g_channels[ch_idx].channel_id);
            fflush(stdout);
        }

        Channel ch = g_channels[ch_idx];
        pthread_mutex_unlock(&g_channels_mu);
        free(body);

        uint32_t resp_len = (uint32_t)sizeof(BodyChannelReadPrefix) + ch.member_count;
        uint8_t *resp = (uint8_t *)calloc(1, resp_len);
        if (!resp) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_ResourceExhausted, NULL, 0);
        }

        BodyChannelReadPrefix *prefix = (BodyChannelReadPrefix *)resp;
        memcpy(prefix->auth_username16, req.auth_username16, 16);
        memcpy(prefix->auth_password16, req.auth_password16, 16);
        memcpy(prefix->channel_name16, ch.channel_name16, 16);
        prefix->channel_id = ch.channel_id;
        prefix->user_id_len = ch.member_count;

        if (ch.member_count > 0) {
            memcpy(resp + sizeof(BodyChannelReadPrefix), ch.member_ids, ch.member_count);
        }

        int ret = send_response_raw(client_fd, MSG_CHANNEL_READ_RES, ST_OK, resp, resp_len);
        free(resp);
        return ret < 0 ? -1 : 1;
    }

    /* ================= CHANNELS READ ================= */
    if (h.type == MSG_CHANNELS_READ_REQ) {
        if (body_len < sizeof(BodyChannelsReadPrefix)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyChannelsReadPrefix req;
        memcpy(&req, body, sizeof(req));

        if (body_len != (uint32_t)sizeof(BodyChannelsReadPrefix) + req.channel_id_len) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
        }

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        free(body);

        uint8_t ids[255];
        uint8_t count = channels_collect_ids(ids);

        uint32_t resp_len = (uint32_t)sizeof(BodyChannelsReadPrefix) + count;
        uint8_t *resp = (uint8_t *)calloc(1, resp_len);
        if (!resp) {
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_ResourceExhausted, NULL, 0);
        }

        BodyChannelsReadPrefix *prefix = (BodyChannelsReadPrefix *)resp;
        memcpy(prefix->auth_username16, req.auth_username16, 16);
        memcpy(prefix->auth_password16, req.auth_password16, 16);
        prefix->channel_id_len = count;
        if (count > 0) memcpy(resp + sizeof(BodyChannelsReadPrefix), ids, count);

        int ret = send_response_raw(client_fd, MSG_CHANNELS_READ_RES, ST_OK, resp, resp_len);
        free(resp);
        return ret < 0 ? -1 : 1;
    }

    /* ================= MESSAGE CREATE ================= */
    if (h.type == MSG_MESSAGE_CREATE_REQ) {
        if (body_len < sizeof(BodyMessageCreateReqPrefix)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyMessageCreateReqPrefix req;
        memcpy(&req, body, sizeof(req));

        uint16_t msg_len = ntohs(req.message_len);
        if (body_len != (uint32_t)sizeof(BodyMessageCreateReqPrefix) + msg_len) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_InvalidSize, NULL, 0);
        }

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_InvalidCreds, NULL, 0);
        }

        uint8_t sender_uid = 0;
        if (!uidmap_find_by_username(req.auth_username16, &sender_uid)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_InternalError, NULL, 0);
        }

        pthread_mutex_lock(&g_channels_mu);

        int ch_idx = -1;
        for (int i = 0; i < MAX_CHANNELS; i++) {
            if (g_channels[i].in_use && g_channels[i].channel_id == req.channel_id) {
                ch_idx = i;
                break;
            }
        }

        if (ch_idx < 0) {
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_NotFound, NULL, 0);
        }

        if (!channel_has_member_locked(&g_channels[ch_idx], sender_uid)) {
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_NotChannelMember, NULL, 0);
        }

        uint64_t ts = my_ntohll(req.timestamp);
        const uint8_t *msg_ptr = body + sizeof(BodyMessageCreateReqPrefix);
        uint16_t stored_len = (msg_len > MAX_STORED_MESSAGE) ? MAX_STORED_MESSAGE : msg_len;

        pthread_mutex_lock(&g_msg_hist_mu);
        for (int i = 0; i < MAX_HISTORY; i++) {
            if (g_msg_history[i].channel_id == req.channel_id &&
                g_msg_history[i].sender_id == sender_uid &&
                g_msg_history[i].timestamp == ts) {
                pthread_mutex_unlock(&g_msg_hist_mu);
                pthread_mutex_unlock(&g_channels_mu);
                free(body);
                return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_AlreadyExists, NULL, 0);
            }
        }

        g_msg_hist_head = (g_msg_hist_head + 1) % MAX_HISTORY;
        g_msg_history[g_msg_hist_head].channel_id = req.channel_id;
        g_msg_history[g_msg_hist_head].sender_id = sender_uid;
        g_msg_history[g_msg_hist_head].timestamp = ts;
        g_msg_history[g_msg_hist_head].msg_len = stored_len;
        memcpy(g_msg_history[g_msg_hist_head].sender_username16, req.auth_username16, 16);
        memcpy(g_msg_history[g_msg_hist_head].sender_password16, req.auth_password16, 16);
        memcpy(g_msg_history[g_msg_hist_head].msg, msg_ptr, stored_len);
        pthread_mutex_unlock(&g_msg_hist_mu);

        int ack_ret = send_response_raw(client_fd, MSG_MESSAGE_CREATE_RES, ST_OK, body, body_len);

        uint32_t read_len = 0;
        uint8_t *read_body = build_message_read_body(req.auth_username16,
                                                     req.auth_password16,
                                                     ts,
                                                     msg_len,
                                                     req.channel_id,
                                                     sender_uid,
                                                     msg_ptr,
                                                     &read_len);

        if (!read_body) {
            printf("DEBUG: build_message_read_body FAILED\n");
            fflush(stdout);
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return ack_ret < 0 ? -1 : 1;
        }

        printf("DEBUG: build_message_read_body done\n");
        printf("DEBUG: read_len = %u\n", read_len);
        printf("DEBUG: msg_len = %u\n", msg_len);
        printf("DEBUG: sender_uid = %u\n", sender_uid);
        printf("DEBUG: channel_id = %u\n", req.channel_id);
        fflush(stdout);

        printf("Broadcast from uid=%u to channel=%u member_count=%u\n",
               sender_uid, req.channel_id, g_channels[ch_idx].member_count);
        printf("DEBUG: broadcasting to %u members\n", g_channels[ch_idx].member_count);

        for (int i = 0; i < g_channels[ch_idx].member_count; i++) {
            uint8_t muid = g_channels[ch_idx].member_ids[i];
            int mfd = client_get_fd(muid);
            printf(" -> uid=%u fd=%d\n", muid, mfd);
        }
        fflush(stdout);

        for (int i = 0; i < g_channels[ch_idx].member_count; i++) {
            uint8_t muid = g_channels[ch_idx].member_ids[i];
            int mem_fd = client_get_fd(muid);
            if (mem_fd >= 0) {
                printf("DEBUG: actually sending to uid=%u fd=%d\n", muid, mem_fd);
                int sret = send_response_raw(mem_fd, MSG_MESSAGE_READ_RES, ST_OK, read_body, read_len);
                printf("DEBUG: send_response_raw to fd=%d returned %d\n", mem_fd, sret);
            }
        }
        fflush(stdout);


        free(read_body);
        pthread_mutex_unlock(&g_channels_mu);
        free(body);
        return ack_ret < 0 ? -1 : 1;
    }

    /* ================= MESSAGE READ ================= */
    if (h.type == MSG_MESSAGE_READ_REQ) {
        if (body_len < sizeof(BodyMessageReadPrefix)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyMessageReadPrefix req;
        memcpy(&req, body, sizeof(req));

        uint16_t msg_len = ntohs(req.message_len);
        if (body_len != (uint32_t)sizeof(BodyMessageReadPrefix) + msg_len) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_InvalidSize, NULL, 0);
        }

        free(body);

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        uint64_t target_ts = my_ntohll(req.timestamp);

        pthread_mutex_lock(&g_msg_hist_mu);
        bool found = false;
        HistoricalMsg m;
        memset(&m, 0, sizeof(m));

        for (int i = 0; i < MAX_HISTORY; i++) {
            if (g_msg_history[i].channel_id == req.channel_id &&
                g_msg_history[i].timestamp == target_ts) {
                m = g_msg_history[i];
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&g_msg_hist_mu);

        if (!found) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_NotFound, NULL, 0);
        }

        uint32_t rlen = 0;
        uint8_t *rbody = build_message_read_body(m.sender_username16,
                                                 m.sender_password16,
                                                 m.timestamp,
                                                 m.msg_len,
                                                 m.channel_id,
                                                 m.sender_id,
                                                 m.msg,
                                                 &rlen);
        if (!rbody) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_ResourceExhausted, NULL, 0);
        }

        int ret = send_response_raw(client_fd, MSG_MESSAGE_READ_RES, ST_OK, rbody, rlen);
        free(rbody);
        return ret < 0 ? -1 : 1;
    }

    free(body);
    return send_response_keepalive(client_fd, resp_type, ST_InvalidType, NULL, 0);
}

void protocol_handle_client(int client_fd, user_db_t *db, message_db_t *msg_db) {
    while (1) {
        int rc = protocol_handle_one(client_fd, db, msg_db);
        if (rc <= 0) break;
    }
    client_remove_fd(client_fd);
    close(client_fd);
    printf("SIZE CHECK:\n");
    printf("sizeof(BodyMessageReadPrefix) = %lu\n", sizeof(BodyMessageReadPrefix));
}
