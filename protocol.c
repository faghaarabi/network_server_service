/*
 *I added the protocol skeleton that maps the ASN.1 spec to packed C structs
 *and enums. This defines the exact on-wire layout for headers and request bodies,
 *so we can safely read/write messages without padding or endian issues. It doesn’t handle
 *logic yet — it just sets up the foundation for parsing messages and wiring them into the
 *server and DB layer
 *the protocol is its own layer. main.c handles sockets and flow control,
 *while the protocol file handles how
 *messages are encoded and decoded. Separating them keeps things cleaner and easier to extend.
 */


/*
./server_app \
  --listen-ip 192.168.0.123 \
  --listen-port 5001 \
  --mgr-ip 192.168.0.131 \
  --mgr-port 42069 \
  --server-id 0 \
  --db db/users.db

 */


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>   // ntohl/htonl

#include "user_db.h"
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>

// ---- constants (match your ASN.1 / hexpat numeric values) ----
enum { PROTO_V1 = 0x01 };

enum MsgType {
    MSG_SERVER_REG_REQ   = 0x00,
    MSG_SERVER_REG_RES   = 0x01,

    MSG_HEALTH_REQ       = 0x04,
    MSG_HEALTH_RES       = 0x05,

    MSG_ACCT_REG_REQ     = 0x10,
    MSG_ACCT_REG_RES     = 0x11,

    MSG_LOGIN_LOGOUT_REQ = 0x14,
    MSG_LOGIN_LOGOUT_RES = 0x15,

    MSG_LOG_REQ          = 0x18,
    MSG_LOG_RES          = 0x19
};

enum Status {
    ST_OK = 0,
    ST_SENDER_ERR = 1,
    ST_RECEIVER_ERR = 2
};

/* ---- compatibility: "BigHeader" bitfield message type used by example client ----
 * type byte layout: [res:5 bits][crud:2 bits][ack:1 bit]
 *   res  = (type >> 3) & 0x1F
 *   crud = (type >> 1) & 0x03
 *   ack  =  type       & 0x01   (0=request, 1=response; client treats 1 as ACK)
 */
enum {
    RES_SERVER     = 0x00,
    RES_ACTIVATION = 0x01,
    RES_ACCOUNT    = 0x02,
    RES_LOG        = 0x03
};

enum {
    CRUD_CREATE = 0x00,
    CRUD_READ   = 0x01,
    CRUD_UPDATE = 0x02,
    CRUD_DELETE = 0x03
};

static inline uint8_t type_res(uint8_t t)  { return (uint8_t)((t >> 3) & 0x1F); }
static inline uint8_t type_crud(uint8_t t) { return (uint8_t)((t >> 1) & 0x03); }
static inline uint8_t type_ack(uint8_t t)  { return (uint8_t)(t & 0x01); }

static inline uint8_t make_type(uint8_t res, uint8_t crud, uint8_t ack) {
    return (uint8_t)(((res & 0x1F) << 3) | ((crud & 0x03) << 1) | (ack & 0x01));
}


#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  padding;
    uint32_t size_be;   // body length, big-endian
} WireHeader;

#pragma pack(push, 1)
// ...
typedef struct {
    uint8_t account_id;
} BodyAccountRegRes;
#pragma pack(pop)


typedef struct {
    uint8_t ip[4];
    uint8_t server_id;
} BodyServerReg; // also used for health check

typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t id;
} BodyAccountReg;

/* Example client sends 34-byte account body:
 * username16 + password16 + server_id + status_flag
 * status_flag: 1=online/login, 0=offline/logout (client uses CRUD_UPDATE for this)
 */
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t server_id;
    uint8_t status_flag;
} BodyAccount34;

// commited
typedef struct {
    uint8_t password16[16];
    uint8_t account_id;
    uint8_t account_status;
    uint8_t ip[4];
} BodyLoginLogout;
#pragma pack(pop)

//small IO helpers
static int read_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t*)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r == 0) return 0;               // peer closed
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 1;
}

static int write_exact(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t*)buf;
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

static int send_response(int fd, uint8_t type, uint8_t status,
                         const void *body, uint32_t body_len) {
    WireHeader h;
    h.version  = PROTO_V1;
    h.type     = type;
    h.status   = status;
    h.padding  = 0;
    h.size_be  = htonl(body_len);

    if (write_exact(fd, &h, sizeof(h)) < 0) return -1;
    if (body_len > 0 && body != NULL) {
        if (write_exact(fd, body, body_len) < 0) return -1;
    }
    return 0;
}

// Make 16-byte fixed fields safe to use as C strings (adds '\0').
static void to_cstr_16(const uint8_t in[16], char out[17]) {
    memcpy(out, in, 16);
    out[16] = '\0';
}

// public API: handle one message
// return: 1 keep going, 0 client closed, -1 fatal read/write error
int protocol_handle_one(int client_fd, user_db_t *db) {
    WireHeader h;

    int rr = read_exact(client_fd, &h, sizeof(h));
    if (rr == 0) return 0;
    if (rr < 0) return -1;

    if (h.version != PROTO_V1) {
        // wrong version -> sender error, empty body
        (void)send_response(client_fd, h.type, ST_SENDER_ERR, NULL, 0);
        return 1;
    }

    uint32_t body_len = ntohl(h.size_be);

    // simple safety cap: avoid huge alloc (adjust if your spec needs bigger)
    if (body_len > 4096) {
        (void)send_response(client_fd, h.type, ST_SENDER_ERR, NULL, 0);
        return 1;
    }

    uint8_t *body = NULL;
    if (body_len > 0) {
        body = (uint8_t*)malloc(body_len);
        if (!body) {
            (void)send_response(client_fd, h.type, ST_RECEIVER_ERR, NULL, 0);
            return 1;
        }
        if (read_exact(client_fd, body, body_len) <= 0) {
            free(body);
            return -1;
        }
    }

    switch (h.type) {

        case MSG_SERVER_REG_REQ: {
            if (body_len != sizeof(BodyServerReg)) {
                (void)send_response(client_fd, MSG_SERVER_REG_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }
            BodyServerReg req;
            memcpy(&req, body, sizeof(req));

            (void)send_response(client_fd, MSG_SERVER_REG_RES, ST_OK, &req, sizeof(req));
            break;
        }

        case MSG_HEALTH_REQ: {
            if (body_len != sizeof(BodyServerReg)) {
                (void)send_response(client_fd, MSG_HEALTH_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }
            BodyServerReg req;
            memcpy(&req, body, sizeof(req));

            // TODO: update "alive" timestamp for server_id
            (void)send_response(client_fd, MSG_HEALTH_RES, ST_OK, &req, sizeof(req));
            break;
        }

        case MSG_ACCT_REG_REQ: {
            if (body_len != sizeof(BodyAccountReg)) {
                (void)send_response(client_fd, MSG_ACCT_REG_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }
            BodyAccountReg req;
            memcpy(&req, body, sizeof(req));

            char username[17];
            to_cstr_16(req.username16, username);

            // Store password as raw 16 bytes (matches fixed-size protocol field)
            udb_status_t st = user_db_put(db, username, req.password16, 16, /*overwrite=*/false);
            printf("[DB] storing username='%s' result=%d\n", username, (int)st);
            fflush(stdout);

            uint8_t status = ST_OK;
            if (st == UDB_ERR_EXISTS || st == UDB_ERR_INVALID) status = ST_SENDER_ERR;
            else if (st != UDB_OK) status = ST_RECEIVER_ERR;

            // If your ASN.1 requires a response body, add it later. Keep empty for now.
            (void)send_response(client_fd, MSG_ACCT_REG_RES, status, NULL, 0);
            break;
        }

        case MSG_LOGIN_LOGOUT_REQ: {
            if (body_len != sizeof(BodyLoginLogout)) {
                (void)send_response(client_fd, MSG_LOGIN_LOGOUT_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }
            BodyLoginLogout req;
            memcpy(&req, body, sizeof(req));

            // TODO: implement your actual login/logout logic.
            // Spec uses account_id; your DB currently keys by username, so you’ll need a mapping
            // (or change key strategy). For now just ack OK.
            (void)req;
            (void)send_response(client_fd, MSG_LOGIN_LOGOUT_RES, ST_OK, NULL, 0);
            break;
        }

        case MSG_LOG_REQ: {
            // body: serverId(1), pad(1), msgLen(2), msg(msgLen)
            if (body_len < 4) {
                (void)send_response(client_fd, MSG_LOG_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }
            uint8_t server_id = body[0];

            // Assume big-endian length (adjust if your spec says otherwise)
            uint16_t msg_len = (uint16_t)body[2] << 8 | (uint16_t)body[3];
            if ((uint32_t)(4 + msg_len) != body_len) {
                (void)send_response(client_fd, MSG_LOG_RES, ST_SENDER_ERR, NULL, 0);
                break;
            }

            // message bytes are body+4, length msg_len (NOT null-terminated)
            (void)server_id;
            //

            (void)send_response(client_fd, MSG_LOG_RES, ST_OK, NULL, 0);
            break;
        }

        /* ---- example client compatibility: RES_ACCOUNT ---- */
        default: {
            /* If it's not one of our fixed MsgType values, it might be BigHeader-style. */
            uint8_t res  = type_res(h.type);
            uint8_t crud = type_crud(h.type);

            if (res == RES_ACCOUNT) {
                /* Create account */
                if (crud == CRUD_CREATE) {
                    if (body_len != sizeof(BodyAccount34)) {
                        /* NACK: respond with ack=0 so client treats as SERVER_NACK */
                        (void)send_response(client_fd, make_type(RES_ACCOUNT, CRUD_CREATE, 0), ST_SENDER_ERR, NULL, 0);
                        break;
                    }
                    BodyAccount34 req;
                    memcpy(&req, body, sizeof(req));

                    char username[17];
                    to_cstr_16(req.username16, username);

                    udb_status_t st = user_db_put(db, username, req.password16, 16, /*overwrite=*/false);

                    uint8_t status = ST_OK;
                    if (st == UDB_ERR_EXISTS || st == UDB_ERR_INVALID) status = ST_SENDER_ERR;
                    else if (st != UDB_OK) status = ST_RECEIVER_ERR;

                    uint8_t ack_bit = (status == ST_OK) ? 1 : 0; /* client checks LSB */
                    (void)send_response(client_fd, make_type(RES_ACCOUNT, CRUD_CREATE, ack_bit), status, NULL, 0);
                    break;
                }

                /* Login / logout update (client uses CRUD_UPDATE and status_flag) */
                if (crud == CRUD_UPDATE) {
                    if (body_len != sizeof(BodyAccount34)) {
                        (void)send_response(client_fd, make_type(RES_ACCOUNT, CRUD_UPDATE, 0), ST_SENDER_ERR, NULL, 0);
                        break;
                    }
                    /* For now we ACK; DB credential verification can be added once user_db_get is available. */
                    (void)send_response(client_fd, make_type(RES_ACCOUNT, CRUD_UPDATE, 1), ST_OK, NULL, 0);
                    break;
                }

                /* Unsupported CRUD on account */
                (void)send_response(client_fd, make_type(RES_ACCOUNT, crud, 0), ST_SENDER_ERR, NULL, 0);
                break;
            }

            /* fall back: unknown type */
            (void)send_response(client_fd, h.type, ST_SENDER_ERR, NULL, 0);
            break;
        }

    }

    free(body);
    return 1;
}

// public API: handle a whole connection
void protocol_handle_client(int client_fd, user_db_t *db) {
    while (1) {
        int rc = protocol_handle_one(client_fd, db);
        if (rc <= 0) break;
    }
    close(client_fd);
}
