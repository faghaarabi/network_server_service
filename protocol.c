// protocol.c - BIG v0.2 RFC + Spreadsheet aligned (safe/compat mode)
//
// Implements (client-facing):
//   - Server: Register(Create)              0x00/0x01  (5 bytes)
//   - ActivatedServer: Activate(Create)     0x08/0x09  (5 bytes)  [RFC]
//   - ActivatedServer: GetActive(Read)      0x0A/0x0B  (5 bytes)  [RFC]
//   - User: Create                          0x10/0x11  (33 bytes)
//   - User: Read                            0x12/0x13  (49 bytes)
//   - User: Update (Login/Logout)           0x14/0x15  (37 bytes)
//
// Implements (channel milestone: one pre-defined channel):
//   - Channel: Read (Get Channel Info)      0x22/0x23  (48 req, 50+N res) [RFC]
//   - Channels: Read (List Channels)        0x2A/0x2B  (32 or 33 req, 33+N res) [RFC + tolerant]
//
// Compatibility / DO NOT BREAK existing tests:
//   - Keeps accepting your old "activate/get" types (0x04/0x05 and 0x02/0x03) as aliases,
//     so if your current binaries still use them, they will continue to work.
//   - Keeps UserStatus mapping tolerant: accepts BOTH conventions:
//       * Spreadsheet legacy: login=0, logout=1
//       * RFC: online=1, offline=0
//     (We do NOT reject either; we just validate it's 0 or 1.)
//
// Key RFC/Spreadsheet compliance:
//   - Header = 8 bytes: version,type,status,reserved,size_be
//   - Type = (Resource<<3) | (CRUD<<1) | Direction
//   - Auth fields are fixed 16 bytes; password compare uses memcmp(16)
//   - Server bodies are 5 bytes: IPv4(4) + ID(1)

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

/* Type encoding:
   Type = (Resource << 3) | (Action << 1) | Direction
*/
enum {
    RES_SERVER          = 0x00, /* RFC: Server */
    RES_ACTIVATEDSERVER = 0x01, /* RFC: ActivatedServer */
    RES_USER            = 0x02, /* RFC: User */
    RES_LOG             = 0x03, /* RFC: Log */
    RES_CHANNEL         = 0x04, /* RFC: Channel */
    RES_CHANNELS        = 0x05, /* RFC: Channels */
    RES_MESSAGE         = 0x06  /* RFC: Message */
};

enum { CRUD_CREATE = 0x00, CRUD_READ = 0x01, CRUD_UPDATE = 0x02, CRUD_DELETE = 0x03 };

/* Message types (RFC) */
enum MsgType {
    /* Server */
    MSG_SERVER_REG_REQ      = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 0, /* 0x00 */
    MSG_SERVER_REG_RES      = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 1, /* 0x01 */
    MSG_SERVER_HC_REQ       = (RES_SERVER << 3) | (CRUD_UPDATE << 1) | 0, /* 0x04 */
    MSG_SERVER_HC_RES       = (RES_SERVER << 3) | (CRUD_UPDATE << 1) | 1, /* 0x05 */

    /* ActivatedServer */
    MSG_ACTIVATE_REQ        = (RES_ACTIVATEDSERVER << 3) | (CRUD_CREATE << 1) | 0, /* 0x08 */
    MSG_ACTIVATE_RES        = (RES_ACTIVATEDSERVER << 3) | (CRUD_CREATE << 1) | 1, /* 0x09 */
    MSG_GET_ACTIVE_REQ      = (RES_ACTIVATEDSERVER << 3) | (CRUD_READ   << 1) | 0, /* 0x0A */
    MSG_GET_ACTIVE_RES      = (RES_ACTIVATEDSERVER << 3) | (CRUD_READ   << 1) | 1, /* 0x0B */
    MSG_DEACTIVATE_REQ      = (RES_ACTIVATEDSERVER << 3) | (CRUD_DELETE << 1) | 0, /* 0x0E */
    MSG_DEACTIVATE_RES      = (RES_ACTIVATEDSERVER << 3) | (CRUD_DELETE << 1) | 1, /* 0x0F */

    /* User */
    MSG_USER_CREATE_REQ     = (RES_USER   << 3) | (CRUD_CREATE << 1) | 0, /* 0x10 */
    MSG_USER_CREATE_RES     = (RES_USER   << 3) | (CRUD_CREATE << 1) | 1, /* 0x11 */
    MSG_USER_READ_REQ       = (RES_USER   << 3) | (CRUD_READ   << 1) | 0, /* 0x12 */
    MSG_USER_READ_RES       = (RES_USER   << 3) | (CRUD_READ   << 1) | 1, /* 0x13 */
    MSG_USER_UPDATE_REQ     = (RES_USER   << 3) | (CRUD_UPDATE << 1) | 0, /* 0x14 */
    MSG_USER_UPDATE_RES     = (RES_USER   << 3) | (CRUD_UPDATE << 1) | 1, /* 0x15 */

    /* Log */
    MSG_LOG_CREATE_REQ      = (RES_LOG    << 3) | (CRUD_CREATE << 1) | 0, /* 0x18 */
    MSG_LOG_CREATE_RES      = (RES_LOG    << 3) | (CRUD_CREATE << 1) | 1, /* 0x19 */

    /* Channel / Channels */
    MSG_CHANNEL_READ_REQ    = (RES_CHANNEL  << 3) | (CRUD_READ << 1) | 0, /* 0x22 */
    MSG_CHANNEL_READ_RES    = (RES_CHANNEL  << 3) | (CRUD_READ << 1) | 1, /* 0x23 */
    MSG_CHANNELS_READ_REQ   = (RES_CHANNELS << 3) | (CRUD_READ << 1) | 0, /* 0x2A */
    MSG_CHANNELS_READ_RES   = (RES_CHANNELS << 3) | (CRUD_READ << 1) | 1  /* 0x2B */
};

/* ---- Compatibility aliases (keep old tests working) ----
   Your previous draft used:
     - "Activate server" as 0x04/0x05
     - "Get active server" as 0x02/0x03 (non-RFC)
   We accept those too, without changing responses.
*/
enum {
    MSG_OLD_SERVER_GET_REQ      = 0x02,
    MSG_OLD_SERVER_GET_RES      = 0x03,
    MSG_OLD_SERVER_ACTIVATE_REQ = 0x04,
    MSG_OLD_SERVER_ACTIVATE_RES = 0x05
};

/* Largest body from RFC: Message Read max 65579; your earlier guard was 65539 (logs max).
   Keep a safe cap that covers RFC 0.2 messaging too.
*/
enum { BIG_MAX_BODY = 65579 };

#pragma pack(push, 1)

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  reserved;
    uint32_t size_be;
} WireHeader;

/* 5-byte bodies used for Server/ActivatedServer */
typedef struct {
    uint8_t ipv4[4];
    uint8_t id; /* ServerId for Server; ServerId for ActivatedServer */
} Body5;

/* User Create: 33 bytes */
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t user_id; /* client sets 0; server assigns */
} BodyUserCreate;

/* User Update (Login/Logout): 37 bytes */
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t ipv4[4];
    uint8_t user_status; /* ACCEPT 0/1 (tolerant: RFC and spreadsheet) */
} BodyUserUpdate;

/* User Read: 49 bytes */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t username16[16];
    uint8_t target_user_id;
} BodyUserRead;

/* Channel Read request: 48 bytes (Auth + ChannelName) */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_name16[16];
} BodyChannelReadReq;

/* Channel Read response fixed prefix: 50 bytes (Auth(32) + Name(16) + ChannelId + UserIdLen) */
typedef struct {
    uint8_t auth_username16[16]; /* MUST be zero unless otherwise specified */
    uint8_t auth_password16[16]; /* MUST be zero unless otherwise specified */
    uint8_t channel_name16[16];
    uint8_t channel_id;
    uint8_t user_id_len; /* number of user ids following */
    /* followed by user ids (user_id_len bytes) */
} BodyChannelReadRes50;

/* Channels Read request variants:
   - RFC text implies Auth only (32 bytes)
   - Appendix C shows min body 33 (Auth + ChannelIdLen)
   - Your sheet includes that len byte = 0 in request.
*/
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
} BodyAuth32;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_id_len; /* request often 0; server ignores */
    /* followed by channel ids (usually none in request) */
} BodyChannelsReadReq33;

#pragma pack(pop)

/* ---------- UID allocator + UID->Username mapping ---------- */
static pthread_mutex_t g_uid_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_next_uid = 1;

static pthread_mutex_t g_uidmap_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_uid_present[256];
static uint8_t g_uid_username16[256][16];

static uint8_t alloc_uid(void) {
    pthread_mutex_lock(&g_uid_mu);
    uint8_t id = g_next_uid++;
    if (g_next_uid == 0) g_next_uid = 1; /* skip 0 */
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

/* ---------- One pre-defined channel state (milestone) ---------- */
static pthread_mutex_t g_chan_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_chan_set = true; /* pre-created */
static uint8_t g_chan_id = 1;
static uint8_t g_chan_name16[16] = {
    'g','e','n','e','r','a','l',0,0,0,0,0,0,0,0,0
};
/* For now, no members tracked (UserIds list empty) */

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

/* ---------- Type decode ---------- */
static inline uint8_t type_direction(uint8_t type) { return type & 0x01; }
static inline uint8_t type_crud(uint8_t type)      { return (type >> 1) & 0x03; }
static inline uint8_t type_resource(uint8_t type)  { return (type >> 3) & 0x1F; }
static inline uint8_t make_resp_type(uint8_t req_type) { return (uint8_t)((req_type & 0xFE) | 0x01); }

/* Validate resource/action combinations per RFC (strict), but allow our old aliases too. */
static bool is_valid_type_combo(uint8_t type) {
    uint8_t r = type_resource(type);
    uint8_t a = type_crud(type);
    uint8_t d = type_direction(type);

    (void)d; /* direction checked elsewhere */

    /* Allow old non-RFC types we used previously (compat) */
    if (type == MSG_OLD_SERVER_GET_REQ || type == MSG_OLD_SERVER_ACTIVATE_REQ) return true;

    switch (r) {
        case RES_SERVER:          return (a == CRUD_CREATE) || (a == CRUD_UPDATE);
        case RES_ACTIVATEDSERVER: return (a == CRUD_CREATE) || (a == CRUD_READ) || (a == CRUD_DELETE);
        case RES_USER:            return (a == CRUD_CREATE) || (a == CRUD_READ) || (a == CRUD_UPDATE);
        case RES_LOG:             return (a == CRUD_CREATE);
        case RES_CHANNEL:         return (a == CRUD_READ);
        case RES_CHANNELS:        return (a == CRUD_READ);
        case RES_MESSAGE:         return (a == CRUD_CREATE) || (a == CRUD_READ);
        default:                  return false;
    }
}

/* ---------- DB helpers ---------- */
static void username16_to_key(const uint8_t in[16], char out[17]) {
    memcpy(out, in, 16);
    out[16] = '\0';
}

static bool udb_is_exists(udb_status_t st) {
#if defined(UDB_ERR_EXISTS)
    return st == UDB_ERR_EXISTS;
#elif defined(UDB_EXISTS)
    return st == UDB_EXISTS;
#elif defined(UDB_ALREADY_EXISTS)
    return st == UDB_ALREADY_EXISTS;
#else
    (void)st;
    return false;
#endif
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

/* ---------- sending ---------- */
static int send_response_raw(int fd, uint8_t type, uint8_t status,
                             const void *body, uint32_t body_len)
{
    WireHeader h;
    h.version  = PROTO_V2;
    h.type     = type;
    h.status   = status;
    h.reserved = 0;
    h.size_be  = htonl(body_len);

    if (write_exact(fd, &h, sizeof(h)) < 0) return -1;
    if (body_len > 0 && body) {
        if (write_exact(fd, body, body_len) < 0) return -1;
    }
    return 0;
}

static int send_response_keepalive(int fd, uint8_t type, uint8_t status,
                                   const void *body, uint32_t body_len)
{
    return (send_response_raw(fd, type, status, body, body_len) < 0) ? -1 : 1;
}

static void zero16(uint8_t a[16]) { memset(a, 0, 16); }

/* ---------- main handler ---------- */
int protocol_handle_one(int client_fd, user_db_t *db)
{
    WireHeader h;
    int rr = read_exact(client_fd, &h, sizeof(h));
    if (rr <= 0) return rr;

    uint8_t resp_type = make_resp_type(h.type);

    if (h.version != PROTO_V2) {
        (void)send_response_raw(client_fd, resp_type, ST_InvalidVersion, NULL, 0);
        return -1;
    }

    /* basic request validation: Direction must be 0 for requests */
    if (type_direction(h.type) != 0) {
        (void)send_response_raw(client_fd, resp_type, ST_InvalidType, NULL, 0);
        return -1;
    }

    /* validate resource/action */
    if (!is_valid_type_combo(h.type)) {
        (void)send_response_raw(client_fd, resp_type, ST_InvalidType, NULL, 0);
        return -1;
    }

    uint32_t body_len = ntohl(h.size_be);
    if (body_len > BIG_MAX_BODY) {
        (void)send_response_raw(client_fd, resp_type, ST_MessageTooLarge, NULL, 0);
        return -1;
    }

    uint8_t *body = NULL;
    if (body_len > 0) {
        body = (uint8_t *)malloc(body_len);
        if (!body) {
            (void)send_response_raw(client_fd, resp_type, ST_ResourceExhausted, NULL, 0);
            return -1;
        }
        if (read_exact(client_fd, body, body_len) <= 0) {
            free(body);
            return -1;
        }
    }

    /* ================= SERVER REGISTER (5 bytes) ================= */
    if (h.type == MSG_SERVER_REG_REQ) {
        if (body_len != (uint32_t)sizeof(Body5)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_SERVER_REG_RES, ST_InvalidSize, NULL, 0);
        }
        Body5 req;
        memcpy(&req, body, sizeof(req));
        free(body);

        /* Minimal: accept and echo back */
        return send_response_keepalive(client_fd, MSG_SERVER_REG_RES, ST_OK,
                                       &req, (uint32_t)sizeof(req));
    }

    /* ================= ActivatedServer Activate (RFC 0x08) ================= */
    if (h.type == MSG_ACTIVATE_REQ || h.type == MSG_OLD_SERVER_ACTIVATE_REQ) {
        if (body_len != (uint32_t)sizeof(Body5)) {
            free(body);
            uint8_t t = (h.type == MSG_OLD_SERVER_ACTIVATE_REQ) ? MSG_OLD_SERVER_ACTIVATE_RES : MSG_ACTIVATE_RES;
            return send_response_keepalive(client_fd, t, ST_InvalidSize, NULL, 0);
        }
        Body5 req;
        memcpy(&req, body, sizeof(req));
        free(body);

        active_set(&req);

        uint8_t t = (h.type == MSG_OLD_SERVER_ACTIVATE_REQ) ? MSG_OLD_SERVER_ACTIVATE_RES : MSG_ACTIVATE_RES;
        return send_response_keepalive(client_fd, t, ST_OK, &req, (uint32_t)sizeof(req));
    }

    /* ================= ActivatedServer GetActive (RFC 0x0A) ================= */
    if (h.type == MSG_GET_ACTIVE_REQ || h.type == MSG_OLD_SERVER_GET_REQ) {
        /* RFC says request body is 5 bytes (ignored). Old draft also used 5.
           Be tolerant: allow 0 or 5; if 5, ignore contents. */
        if (!(body_len == 0 || body_len == (uint32_t)sizeof(Body5))) {
            free(body);
            uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;
            return send_response_keepalive(client_fd, t, ST_InvalidSize, NULL, 0);
        }
        free(body);

        Body5 res;
        memset(&res, 0, sizeof(res));

        if (!active_get(&res)) {
            uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;
            return send_response_keepalive(client_fd, t, ST_NotRegistered, NULL, 0);
        }

        uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;
        return send_response_keepalive(client_fd, t, ST_OK, &res, (uint32_t)sizeof(res));
    }

    /* ================= USER CREATE (33 bytes) ================= */
    if (h.type == MSG_USER_CREATE_REQ) {
        if (body_len != (uint32_t)sizeof(BodyUserCreate)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyUserCreate req;
        memcpy(&req, body, sizeof(req));
        free(body);

        char key[17];
        username16_to_key(req.username16, key);

        /* store password as EXACTLY 16 bytes */
        pthread_mutex_lock(&g_db_mu);
        udb_status_t st = user_db_put(db, key, req.password16, 16, false);
        pthread_mutex_unlock(&g_db_mu);

        if (st == UDB_OK) {
            req.user_id = alloc_uid();
            uidmap_set(req.user_id, req.username16);
            return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_OK,
                                           &req, (uint32_t)sizeof(req));
        }

        if (udb_is_exists(st)) {
            return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_AlreadyExists, NULL, 0);
        }

        return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_InternalError, NULL, 0);
    }

    /* ================= USER UPDATE (Login/Logout) (37 bytes) ================= */
    if (h.type == MSG_USER_UPDATE_REQ) {
        if (body_len != (uint32_t)sizeof(BodyUserUpdate)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidSize, NULL, 0);
        }

        BodyUserUpdate req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.username16, req.password16)) {
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidCreds, NULL, 0);
        }

        /* Tolerant: accept only 0 or 1 (do not enforce meaning to avoid breaking existing clients) */
        if (!(req.user_status == 0 || req.user_status == 1)) {
            return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_MalformedRequest, NULL, 0);
        }

        return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_OK,
                                       &req, (uint32_t)sizeof(req));
    }

    /* ================= USER READ (49 bytes) ================= */
    if (h.type == MSG_USER_READ_REQ) {
        if (body_len != (uint32_t)sizeof(BodyUserRead)) {
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

        BodyUserRead resbody;
        memset(&resbody, 0, sizeof(resbody));
        memcpy(resbody.auth_username16, req.auth_username16, 16);
        memcpy(resbody.auth_password16, req.auth_password16, 16);
        memcpy(resbody.username16, uname16, 16);
        resbody.target_user_id = req.target_user_id;

        return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_OK,
                                       &resbody, (uint32_t)sizeof(resbody));
    }

    /* ================= CHANNELS READ (List All Channels) ================= */
    if (h.type == MSG_CHANNELS_READ_REQ) {
        /* Accept both request bodies:
           - 32 bytes (Auth only)
           - 33+ bytes (Auth + channel_id_len + optional ids), as in your sheet
        */
        if (!(body_len == (uint32_t)sizeof(BodyAuth32) || body_len >= (uint32_t)sizeof(BodyChannelsReadReq33))) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
        }

        if (body_len < (uint32_t)sizeof(BodyAuth32)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyAuth32 auth;
        memcpy(&auth, body, sizeof(auth));

        if (!auth_ok16(db, auth.auth_username16, auth.auth_password16)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        free(body);

        /* Response: Auth fields SHOULD be zero unless otherwise specified */
        uint8_t out[32 + 1 + 255];
        size_t off = 0;

        memset(out, 0, 32);
        off += 32;

        pthread_mutex_lock(&g_chan_mu);
        bool has = g_chan_set;
        uint8_t cid = g_chan_id;
        pthread_mutex_unlock(&g_chan_mu);

        out[off++] = has ? 1 : 0; /* ChannelIdLen */
        if (has) out[off++] = cid;

        return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_OK, out, (uint32_t)off);
    }

    /* ================= CHANNEL READ (Get Channel Info) ================= */
    if (h.type == MSG_CHANNEL_READ_REQ) {
        if (body_len != (uint32_t)sizeof(BodyChannelReadReq)) {
            free(body);
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidSize, NULL, 0);
        }

        BodyChannelReadReq req;
        memcpy(&req, body, sizeof(req));
        free(body);

        if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidCreds, NULL, 0);
        }

        pthread_mutex_lock(&g_chan_mu);
        bool has = g_chan_set;
        uint8_t cid = g_chan_id;
        uint8_t cname16[16];
        memcpy(cname16, g_chan_name16, 16);
        pthread_mutex_unlock(&g_chan_mu);

        if (!has) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_NotFound, NULL, 0);
        }

        /* Require matching channel name (simple) */
        if (memcmp(req.channel_name16, cname16, 16) != 0) {
            return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_NotFound, NULL, 0);
        }

        /* Response fixed part: 50 bytes, no users for now */
        BodyChannelReadRes50 res;
        memset(&res, 0, sizeof(res));
        /* Auth in response MUST be zero unless otherwise specified */
        zero16(res.auth_username16);
        zero16(res.auth_password16);
        memcpy(res.channel_name16, cname16, 16);
        res.channel_id = cid;
        res.user_id_len = 0;

        return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_OK, &res, (uint32_t)sizeof(res));
    }

    /* Unknown type (for now) */
    free(body);
    return send_response_keepalive(client_fd, resp_type, ST_InvalidType, NULL, 0);
}

void protocol_handle_client(int client_fd, user_db_t *db)
{
    while (1) {
        int rc = protocol_handle_one(client_fd, db);
        if (rc <= 0) break;
    }
    close(client_fd);
}