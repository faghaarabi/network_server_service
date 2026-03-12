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
// Implements (channel layer):
//   - Channel: Create                       0x20/0x21  (49 bytes) [project extension]
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

/* Message types (RFC + project extension for Channel.Create) */
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
    MSG_CHANNEL_CREATE_REQ  = (RES_CHANNEL  << 3) | (CRUD_CREATE << 1) | 0, /* 0x20 */
    MSG_CHANNEL_CREATE_RES  = (RES_CHANNEL  << 3) | (CRUD_CREATE << 1) | 1, /* 0x21 */
    MSG_CHANNEL_READ_REQ    = (RES_CHANNEL  << 3) | (CRUD_READ   << 1) | 0, /* 0x22 */
    MSG_CHANNEL_READ_RES    = (RES_CHANNEL  << 3) | (CRUD_READ   << 1) | 1, /* 0x23 */
    MSG_CHANNELS_READ_REQ   = (RES_CHANNELS << 3) | (CRUD_READ   << 1) | 0, /* 0x2A */
    MSG_CHANNELS_READ_RES   = (RES_CHANNELS << 3) | (CRUD_READ   << 1) | 1  /* 0x2B */
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

/* Largest body from RFC: Message Read max 65579 */
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

/* Channel Create: 49 bytes */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_name16[16];
    uint8_t channel_id; /* request sets 0; response assigns */
} BodyChannelCreate;

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

#define MAX_CHANNELS 32
#define MAX_CHANNEL_MEMBERS 64

typedef struct {
    bool in_use;
    uint8_t channel_id;
    uint8_t channel_name16[16];
    uint8_t member_count;
    uint8_t member_ids[MAX_CHANNEL_MEMBERS];
    uint8_t owner_user_id;
} Channel;

typedef struct {
    bool found;
    uint8_t channel_id;
    uint8_t channel_name16[16];
    uint8_t member_count;
    uint8_t member_ids[MAX_CHANNEL_MEMBERS];
    uint8_t owner_user_id;
} ChannelSnapshot;

static pthread_mutex_t g_channels_mu = PTHREAD_MUTEX_INITIALIZER;
static Channel g_channels[MAX_CHANNELS];
static uint8_t g_next_channel_id = 1;
static pthread_once_t g_channels_once = PTHREAD_ONCE_INIT;

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

static bool uidmap_find_by_username(const uint8_t username16[16], uint8_t *out_uid) {
    int i;
    pthread_mutex_lock(&g_uidmap_mu);
    for (i = 1; i < 256; i++) {
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

    /* Keep a default channel for compatibility with earlier tests */
    g_channels[0].in_use = true;
    g_channels[0].channel_id = 1;
    memset(g_channels[0].channel_name16, 0, 16);
    memcpy(g_channels[0].channel_name16, "general", 7);
    g_channels[0].member_count = 0;
    g_channels[0].owner_user_id = 0;

    g_next_channel_id = 2;
}

static void ensure_channels_initialized(void) {
    pthread_once(&g_channels_once, channels_init_once);
}

static uint8_t alloc_channel_id_locked(void) {
    uint8_t start = g_next_channel_id;
    uint8_t id = start;

    if (id == 0) id = 1;

    do {
        bool used = false;
        int i;

        for (i = 0; i < MAX_CHANNELS; i++) {
            if (g_channels[i].in_use && g_channels[i].channel_id == id) {
                used = true;
                break;
            }
        }

        if (!used) {
            g_next_channel_id = (uint8_t)(id + 1);
            if (g_next_channel_id == 0) g_next_channel_id = 1;
            return id;
        }

        id = (uint8_t)(id + 1);
        if (id == 0) id = 1;
    } while (id != start);

    return 0;
}

static int channel_find_index_by_name_locked(const uint8_t name16[16]) {
    int i;
    for (i = 0; i < MAX_CHANNELS; i++) {
        if (g_channels[i].in_use && memcmp(g_channels[i].channel_name16, name16, 16) == 0) {
            return i;
        }
    }
    return -1;
}

static int channel_find_index_by_id_locked(uint8_t channel_id) {
    int i;
    for (i = 0; i < MAX_CHANNELS; i++) {
        if (g_channels[i].in_use && g_channels[i].channel_id == channel_id) {
            return i;
        }
    }
    return -1;
}

static bool channel_has_member_locked(const Channel *ch, uint8_t user_id) {
    uint8_t i;
    if (!ch || user_id == 0) return false;
    for (i = 0; i < ch->member_count; i++) {
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

static bool channel_create_with_owner(const uint8_t name16[16], uint8_t owner_user_id, uint8_t *out_channel_id) {
    int slot = -1;
    int i;

    ensure_channels_initialized();

    pthread_mutex_lock(&g_channels_mu);

    if (channel_find_index_by_name_locked(name16) >= 0) {
        pthread_mutex_unlock(&g_channels_mu);
        return false;
    }

    for (i = 0; i < MAX_CHANNELS; i++) {
        if (!g_channels[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_channels_mu);
        return false;
    }

    memset(&g_channels[slot], 0, sizeof(g_channels[slot]));
    g_channels[slot].in_use = true;
    g_channels[slot].channel_id = alloc_channel_id_locked();
    memcpy(g_channels[slot].channel_name16, name16, 16);
    g_channels[slot].owner_user_id = owner_user_id;

    if (owner_user_id != 0) {
        if (!channel_add_member_locked(&g_channels[slot], owner_user_id)) {
            g_channels[slot].in_use = false;
            pthread_mutex_unlock(&g_channels_mu);
            return false;
        }
    }

    if (out_channel_id) *out_channel_id = g_channels[slot].channel_id;

    pthread_mutex_unlock(&g_channels_mu);
    return true;
}

static bool channel_snapshot_by_name(const uint8_t name16[16], ChannelSnapshot *out) {
    int idx;

    ensure_channels_initialized();

    if (!out) return false;

    pthread_mutex_lock(&g_channels_mu);
    idx = channel_find_index_by_name_locked(name16);
    if (idx < 0) {
        pthread_mutex_unlock(&g_channels_mu);
        memset(out, 0, sizeof(*out));
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->found = true;
    out->channel_id = g_channels[idx].channel_id;
    memcpy(out->channel_name16, g_channels[idx].channel_name16, 16);
    out->member_count = g_channels[idx].member_count;
    memcpy(out->member_ids, g_channels[idx].member_ids, g_channels[idx].member_count);
    out->owner_user_id = g_channels[idx].owner_user_id;

    pthread_mutex_unlock(&g_channels_mu);
    return true;
}

static uint8_t channels_collect_ids(uint8_t out_ids[255]) {
    uint8_t count = 0;
    int i;

    ensure_channels_initialized();

    pthread_mutex_lock(&g_channels_mu);
    for (i = 0; i < MAX_CHANNELS && count < 255; i++) {
        if (g_channels[i].in_use) {
            out_ids[count++] = g_channels[i].channel_id;
        }
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

/* ---------- Type decode ---------- */
static inline uint8_t type_direction(uint8_t type) { return type & 0x01; }
static inline uint8_t type_crud(uint8_t type)      { return (type >> 1) & 0x03; }
static inline uint8_t type_resource(uint8_t type)  { return (type >> 3) & 0x1F; }
static inline uint8_t make_resp_type(uint8_t req_type) { return (uint8_t)((req_type & 0xFE) | 0x01); }

/* Validate resource/action combinations per RFC, plus Channel.Create extension,
   and allow our old aliases too. */
static bool is_valid_type_combo(uint8_t type) {
    uint8_t r = type_resource(type);
    uint8_t a = type_crud(type);
    uint8_t d = type_direction(type);

    (void)d; /* direction checked elsewhere */

    /* Allow old non-RFC types we used previously (compat) */
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
            return (a == CRUD_CREATE) || (a == CRUD_READ); /* project extension */

        case RES_CHANNELS:
            return (a == CRUD_READ);

        case RES_MESSAGE:
            return (a == CRUD_CREATE) || (a == CRUD_READ);

        default:
            return false;
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

    {
        bool ok = (stored_len >= 16) && (memcmp(stored, password16, 16) == 0);
        free(stored);
        return ok;
    }
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

static bool all_zero16(const uint8_t a[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != 0) return false;
    }
    return true;
}

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

    {
        uint32_t body_len = ntohl(h.size_be);
        uint8_t *body = NULL;

        if (body_len > BIG_MAX_BODY) {
            (void)send_response_raw(client_fd, resp_type, ST_MessageTooLarge, NULL, 0);
            return -1;
        }

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

            {
                Body5 req;
                memcpy(&req, body, sizeof(req));
                free(body);

                /* Minimal: accept and echo back */
                return send_response_keepalive(client_fd, MSG_SERVER_REG_RES, ST_OK,
                                               &req, (uint32_t)sizeof(req));
            }
        }

        /* ================= ActivatedServer Activate (RFC 0x08) ================= */
        if (h.type == MSG_ACTIVATE_REQ || h.type == MSG_OLD_SERVER_ACTIVATE_REQ) {
            if (body_len != (uint32_t)sizeof(Body5)) {
                uint8_t t = (h.type == MSG_OLD_SERVER_ACTIVATE_REQ) ? MSG_OLD_SERVER_ACTIVATE_RES : MSG_ACTIVATE_RES;
                free(body);
                return send_response_keepalive(client_fd, t, ST_InvalidSize, NULL, 0);
            }

            {
                Body5 req;
                uint8_t t = (h.type == MSG_OLD_SERVER_ACTIVATE_REQ) ? MSG_OLD_SERVER_ACTIVATE_RES : MSG_ACTIVATE_RES;

                memcpy(&req, body, sizeof(req));
                free(body);

                active_set(&req);
                return send_response_keepalive(client_fd, t, ST_OK, &req, (uint32_t)sizeof(req));
            }
        }

        /* ================= ActivatedServer GetActive (RFC 0x0A) ================= */
        if (h.type == MSG_GET_ACTIVE_REQ || h.type == MSG_OLD_SERVER_GET_REQ) {
            /* Be tolerant: allow 0 or 5; if 5, ignore contents. */
            if (!(body_len == 0 || body_len == (uint32_t)sizeof(Body5))) {
                uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;
                free(body);
                return send_response_keepalive(client_fd, t, ST_InvalidSize, NULL, 0);
            }

            free(body);

            {
                Body5 res;
                uint8_t t = (h.type == MSG_OLD_SERVER_GET_REQ) ? MSG_OLD_SERVER_GET_RES : MSG_GET_ACTIVE_RES;

                memset(&res, 0, sizeof(res));
                if (!active_get(&res)) {
                    return send_response_keepalive(client_fd, t, ST_NotRegistered, NULL, 0);
                }

                return send_response_keepalive(client_fd, t, ST_OK, &res, (uint32_t)sizeof(res));
            }
        }

        /* ================= USER CREATE (33 bytes) ================= */
        if (h.type == MSG_USER_CREATE_REQ) {
            if (body_len != (uint32_t)sizeof(BodyUserCreate)) {
                free(body);
                return send_response_keepalive(client_fd, MSG_USER_CREATE_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyUserCreate req;
                char key[17];

                memcpy(&req, body, sizeof(req));
                free(body);

                username16_to_key(req.username16, key);

                pthread_mutex_lock(&g_db_mu);
                {
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
            }
        }

        /* ================= USER UPDATE (Login/Logout) (37 bytes) ================= */
        if (h.type == MSG_USER_UPDATE_REQ) {
            if (body_len != (uint32_t)sizeof(BodyUserUpdate)) {
                free(body);
                return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyUserUpdate req;
                memcpy(&req, body, sizeof(req));
                free(body);

                if (!auth_ok16(db, req.username16, req.password16)) {
                    return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_InvalidCreds, NULL, 0);
                }

                /* Tolerant: accept only 0 or 1 */
                if (!(req.user_status == 0 || req.user_status == 1)) {
                    return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_MalformedRequest, NULL, 0);
                }

                return send_response_keepalive(client_fd, MSG_USER_UPDATE_RES, ST_OK,
                                               &req, (uint32_t)sizeof(req));
            }
        }

        /* ================= USER READ (49 bytes) ================= */
        if (h.type == MSG_USER_READ_REQ) {
            if (body_len != (uint32_t)sizeof(BodyUserRead)) {
                free(body);
                return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyUserRead req;
                uint8_t uname16[16];
                BodyUserRead resbody;

                memcpy(&req, body, sizeof(req));
                free(body);

                if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
                    return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_InvalidCreds, NULL, 0);
                }

                if (!uidmap_get(req.target_user_id, uname16)) {
                    return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_NotFound, NULL, 0);
                }

                memset(&resbody, 0, sizeof(resbody));
                memcpy(resbody.auth_username16, req.auth_username16, 16);
                memcpy(resbody.auth_password16, req.auth_password16, 16);
                memcpy(resbody.username16, uname16, 16);
                resbody.target_user_id = req.target_user_id;

                return send_response_keepalive(client_fd, MSG_USER_READ_RES, ST_OK,
                                               &resbody, (uint32_t)sizeof(resbody));
            }
        }

        /* ================= CHANNEL CREATE (49 bytes) ================= */
        if (h.type == MSG_CHANNEL_CREATE_REQ) {
            if (body_len != (uint32_t)sizeof(BodyChannelCreate)) {
                free(body);
                return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyChannelCreate req;
                uint8_t owner_uid = 0;
                uint8_t new_channel_id = 0;

                memcpy(&req, body, sizeof(req));
                free(body);

                if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
                    return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_InvalidCreds, NULL, 0);
                }

                if (all_zero16(req.channel_name16)) {
                    return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_MalformedRequest, NULL, 0);
                }

                if (!uidmap_find_by_username(req.auth_username16, &owner_uid)) {
                    return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_NotRegistered, NULL, 0);
                }

                if (!channel_create_with_owner(req.channel_name16, owner_uid, &new_channel_id)) {
                    ChannelSnapshot snap;
                    if (channel_snapshot_by_name(req.channel_name16, &snap)) {
                        return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_AlreadyExists, NULL, 0);
                    }
                    return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_ResourceExhausted, NULL, 0);
                }

                req.channel_id = new_channel_id;
                return send_response_keepalive(client_fd, MSG_CHANNEL_CREATE_RES, ST_OK,
                                               &req, (uint32_t)sizeof(req));
            }
        }

        /* ================= CHANNELS READ (List All Channels) ================= */
        if (h.type == MSG_CHANNELS_READ_REQ) {
            if (!(body_len == (uint32_t)sizeof(BodyAuth32) ||
                  body_len >= (uint32_t)sizeof(BodyChannelsReadReq33))) {
                free(body);
                return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyAuth32 auth;
                uint8_t ids[255];
                uint8_t count;
                uint8_t out[32 + 1 + 255];
                size_t off = 0;

                if (body_len < (uint32_t)sizeof(BodyAuth32)) {
                    free(body);
                    return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidSize, NULL, 0);
                }

                memcpy(&auth, body, sizeof(auth));
                free(body);

                if (!auth_ok16(db, auth.auth_username16, auth.auth_password16)) {
                    return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_InvalidCreds, NULL, 0);
                }

                count = channels_collect_ids(ids);

                memset(out, 0, 32);
                off += 32;
                out[off++] = count;
                if (count > 0) {
                    memcpy(&out[off], ids, count);
                    off += count;
                }

                return send_response_keepalive(client_fd, MSG_CHANNELS_READ_RES, ST_OK, out, (uint32_t)off);
            }
        }

        /* ================= CHANNEL READ (Get Channel Info) ================= */
        if (h.type == MSG_CHANNEL_READ_REQ) {
            if (body_len != (uint32_t)sizeof(BodyChannelReadReq)) {
                free(body);
                return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidSize, NULL, 0);
            }

            {
                BodyChannelReadReq req;
                ChannelSnapshot snap;
                uint8_t out[50 + MAX_CHANNEL_MEMBERS];
                size_t off = 0;

                memcpy(&req, body, sizeof(req));
                free(body);

                if (!auth_ok16(db, req.auth_username16, req.auth_password16)) {
                    return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_InvalidCreds, NULL, 0);
                }

                if (!channel_snapshot_by_name(req.channel_name16, &snap)) {
                    return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_NotFound, NULL, 0);
                }

                memset(out, 0, 32);
                off += 32;
                memcpy(&out[off], snap.channel_name16, 16);
                off += 16;
                out[off++] = snap.channel_id;
                out[off++] = snap.member_count;
                if (snap.member_count > 0) {
                    memcpy(&out[off], snap.member_ids, snap.member_count);
                    off += snap.member_count;
                }

                return send_response_keepalive(client_fd, MSG_CHANNEL_READ_RES, ST_OK, out, (uint32_t)off);
            }
        }

        /* Unknown type (for now) */
        free(body);
        return send_response_keepalive(client_fd, resp_type, ST_InvalidType, NULL, 0);
    }
}

void protocol_handle_client(int client_fd, user_db_t *db)
{
    while (1) {
        int rc = protocol_handle_one(client_fd, db);
        if (rc <= 0) break;
    }
    close(client_fd);
}