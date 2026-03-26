// protocol.c - BIG v0.2 RFC + Milestone 2 Hardcoded Channel
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

/* CHANNEL_READ now uses channel_id, not channel_name */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_id;
} BodyChannelReadReq;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
} BodyAuth32;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_id_len;
} BodyChannelsReadReq33;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint64_t timestamp;
    uint16_t message_len;
    uint8_t channel_id;
} BodyMessageCreateReq;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint64_t timestamp;
    uint16_t message_len;
    uint8_t channel_id;
    uint8_t sender_id;
} BodyMessageReadRes;

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

typedef struct {
    bool in_use;
    uint8_t channel_id;
    uint8_t channel_name16[16];
    uint8_t member_count;
    uint8_t member_ids[MAX_CHANNEL_MEMBERS];
    uint8_t owner_user_id;
} Channel;

static pthread_mutex_t g_channels_mu = PTHREAD_MUTEX_INITIALIZER;
static Channel g_channels[MAX_CHANNELS];
static uint8_t g_next_channel_id = 1;
static pthread_once_t g_channels_once = PTHREAD_ONCE_INIT;

/* Client connection registry for broadcasting messages */
static int g_client_fds[256];
static pthread_mutex_t g_clients_mu = PTHREAD_MUTEX_INITIALIZER;

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

/* Message history */
#define MAX_HISTORY 256
typedef struct {
    uint64_t timestamp;
    uint16_t msg_len;
    uint8_t channel_id;
    uint8_t sender_id;
    uint8_t msg[1024];
} HistoricalMsg;

static HistoricalMsg g_msg_history[MAX_HISTORY];
static int g_msg_hist_head = 0;
static pthread_mutex_t g_msg_hist_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---------- UID allocator + UID->Username mapping ---------- */
static pthread_mutex_t g_uid_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_next_uid = 1;

static pthread_mutex_t g_uidmap_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_uid_present[256];
static uint8_t g_uid_username16[256][16];

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

/* ---------- Activated server state ---------- */
static pthread_mutex_t g_active_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_active_set = false;
static Body5 g_active_server;

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

/* ---------- Channel storage ---------- */
static void channels_init_once(void) {
    memset(g_channels, 0, sizeof(g_channels));
    for (int i = 0; i < 256; i++) g_client_fds[i] = -1;

    g_channels[0].in_use = true;
    g_channels[0].channel_id = 1;
    memcpy(g_channels[0].channel_name16, "milestone2\0\0\0\0\0\0", 16);
    g_channels[0].member_count = 0;
    g_channels[0].owner_user_id = 0;

    g_next_channel_id = 2;
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

/* ---------- I/O helpers ---------- */
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

int protocol_handle_one(int client_fd, user_db_t *db) {
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

            pthread_mutex_lock(&g_channels_mu);
            channel_add_member_locked(&g_channels[0], uid);
            pthread_mutex_unlock(&g_channels_mu);
        } else {
            client_remove_fd(client_fd);
        }

        memset(req.password16, 0, 16);
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

        memset(&req, 0, sizeof(req));
        memcpy(req.username16, uname16, 16);
        return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_OK, &req, sizeof(req));
    }

    /* ================= CHANNEL CREATE ================= */
    if (h.type == MSG_CHANNEL_CREATE_REQ) {
        free(body);
        return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_Forbidden, NULL, 0);
    }

    /* ================= CHANNEL READ ================= */
    if (h.type == MSG_CHANNEL_READ_REQ) {
        if (body_len != sizeof(BodyChannelReadReq)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyChannelReadReq req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidCreds, NULL, 0);
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
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_NotFound, NULL, 0);
        }

        Channel ch = g_channels[ch_idx];
        pthread_mutex_unlock(&g_channels_mu);

        uint32_t resp_len = 32 + 16 + 1 + 1 + ch.member_count;
        uint8_t *resp = (uint8_t *)calloc(1, resp_len);
        if (!resp) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_ResourceExhausted, NULL, 0);
        }

        /* first 32 bytes: zeroed auth area */
        memcpy(resp + 32, ch.channel_name16, 16);
        resp[48] = ch.channel_id;
        resp[49] = ch.member_count;
        memcpy(resp + 50, ch.member_ids, ch.member_count);

        int ret = send_response_raw(client_fd, MSG_CHANNEL_READ_RES, ST_OK, resp, resp_len);
        free(resp);
        return ret < 0 ? -1 : 1;
    }

    /* ================= CHANNELS READ ================= */
    if (h.type == MSG_CHANNELS_READ_REQ) {
        if (body_len < sizeof(BodyAuth32)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyAuth32 auth;
        memcpy(&auth, body, sizeof(auth));
        free(body);

        if (!auth_ok16(db, auth.auth_username16, auth.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        uint8_t out[32 + 1 + 255];
        memset(out, 0, 32);
        out[32] = channels_collect_ids(&out[33]);

        return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_OK, out, 33 + out[32]);
    }

    /* ================= MESSAGE CREATE ================= */
    if (h.type == MSG_MESSAGE_CREATE_REQ) {
        if (body_len < sizeof(BodyMessageCreateReq)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyMessageCreateReq req;
        memcpy(&req, body, sizeof(req));

        uint16_t msg_len = ntohs(req.message_len);
        if (body_len != sizeof(req) + msg_len) {
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

        int h_idx = g_msg_hist_head = (g_msg_hist_head + 1) % MAX_HISTORY;
        g_msg_history[h_idx].channel_id = req.channel_id;
        g_msg_history[h_idx].sender_id = sender_uid;
        g_msg_history[h_idx].timestamp = ts;
        g_msg_history[h_idx].msg_len = (msg_len > 1024) ? 1024 : msg_len;
        memcpy(g_msg_history[h_idx].msg, body + sizeof(req), g_msg_history[h_idx].msg_len);
        pthread_mutex_unlock(&g_msg_hist_mu);

        uint8_t *resp_body = (uint8_t *)malloc(body_len);
        if (!resp_body) {
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_CREATE_RES, ST_ResourceExhausted, NULL, 0);
        }

        memcpy(resp_body, body, body_len);
        memset(resp_body, 0, 32);

        int ret = send_response_raw(client_fd, MSG_MESSAGE_CREATE_RES, ST_OK, resp_body, body_len);
        free(resp_body);

        uint32_t read_len = 44 + msg_len;
        uint8_t *read_body = (uint8_t *)calloc(1, read_len);
        if (!read_body) {
            pthread_mutex_unlock(&g_channels_mu);
            free(body);
            return ret < 0 ? -1 : 1;
        }

        memcpy(read_body + 32, body + 32, 8);
        memcpy(read_body + 40, body + 40, 2);
        read_body[42] = req.channel_id;
        read_body[43] = sender_uid;
        memcpy(read_body + 44, body + 43, msg_len);

        for (int i = 0; i < g_channels[ch_idx].member_count; i++) {
            int mem_fd = client_get_fd(g_channels[ch_idx].member_ids[i]);
            if (mem_fd >= 0) {
                send_response_raw(mem_fd, MSG_MESSAGE_READ_RES, ST_OK, read_body, read_len);
            }
        }

        free(read_body);
        pthread_mutex_unlock(&g_channels_mu);
        free(body);
        return ret < 0 ? -1 : 1;
    }

    /* ================= MESSAGE READ ================= */
    if (h.type == MSG_MESSAGE_READ_REQ) {
        if (body_len < sizeof(BodyMessageReadRes)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyMessageReadRes req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        pthread_mutex_lock(&g_msg_hist_mu);
        bool found = false;
        HistoricalMsg m;
        for (int i = 0; i < MAX_HISTORY; i++) {
            if (g_msg_history[i].channel_id == req.channel_id &&
                g_msg_history[i].timestamp == my_ntohll(req.timestamp)) {
                m = g_msg_history[i];
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&g_msg_hist_mu);

        if (!found) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_NotFound, NULL, 0);
        }

        uint32_t rlen = sizeof(BodyMessageReadRes) + m.msg_len;
        uint8_t *rbody = (uint8_t *)calloc(1, rlen);
        if (!rbody) {
            return send_response_keepalive(client_fd, MSG_MESSAGE_READ_RES, ST_ResourceExhausted, NULL, 0);
        }

        uint64_t net_ts = my_htonll(m.timestamp);
        memcpy(rbody + 32, &net_ts, 8);

        uint16_t net_len = htons(m.msg_len);
        memcpy(rbody + 40, &net_len, 2);

        rbody[42] = m.channel_id;
        rbody[43] = m.sender_id;
        memcpy(rbody + 44, m.msg, m.msg_len);

        int ret = send_response_raw(client_fd, MSG_MESSAGE_READ_RES, ST_OK, rbody, rlen);
        free(rbody);
        return ret < 0 ? -1 : 1;
    }

    free(body);
    return send_response_keepalive(client_fd, resp_type, ST_InvalidType, NULL, 0);
}

void protocol_handle_client(int client_fd, user_db_t *db) {
    while (1) {
        int rc = protocol_handle_one(client_fd, db);
        if (rc <= 0) break;
    }
    client_remove_fd(client_fd);
    close(client_fd);
}