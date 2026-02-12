#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "user_db.h"

/* Protocol Constants per Protocol.txt */
enum { PROTO_V1 = 0x01 };

enum MsgType {
    MSG_SERVER_REG_REQ   = 0x00, 
    MSG_SERVER_REG_RES   = 0x01, 
    MSG_HEALTH_REQ       = 0x08, 
    MSG_HEALTH_RES       = 0x09, 
    MSG_ACCT_REG_REQ     = 0x10, 
    MSG_ACCT_REG_RES     = 0x11, 
    MSG_LOGIN_LOGOUT_REQ = 0x14, 
    MSG_LOGIN_LOGOUT_RES = 0x15, 
    MSG_LOG_REQ          = 0x18, 
    MSG_LOG_RES          = 0x19  
};

#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  padding;
    uint32_t size_be;
} WireHeader;

// Server Register: 4 byte IP + 1 byte ID
typedef struct {
    uint8_t ip[4];
    uint8_t server_id;
} BodyServerReg;

// Create Account & Login: 16 user + 16 pass + 1 id + 1 status = 34 bytes
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t client_id;
    uint8_t status;    
} BodyAuth; // Used for Acct Reg and Login/Logout

// Forward Logs: 1 byte ID + 2 byte len + data
typedef struct {
    uint8_t server_id;
    uint16_t log_len_be;
    // Log data follows
} BodyLogHeader;
#pragma pack(pop)

/* --- IO Helpers --- */

static int read_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t*)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r == 0) return 0; // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 1; // Success
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
    return 0; // Success
}

/* Updated: 'status' is now hardcoded to 0 internally */
static int send_response(int fd, uint8_t type, 
                         const void *body, uint32_t body_len) {
    WireHeader h;
    h.version  = PROTO_V1;
    h.type     = type;
    h.status   = 0;
    h.padding  = 0;
    h.size_be  = htonl(body_len);

    if (write_exact(fd, &h, sizeof(h)) < 0) return -1;
    if (body_len > 0 && body != NULL) {
        if (write_exact(fd, body, body_len) < 0) return -1;
    }
    return 0;
}

static void to_cstr_16(const uint8_t in[16], char out[17]) {
    memcpy(out, in, 16);
    out[16] = '\0';
}

/* --- Main Protocol Handler --- */
/* Returns: 1 to keep connection open, 0/negative to close */
int protocol_handle_one(int client_fd, user_db_t *db) {
    WireHeader h;

    // 1. Read Header
    int rr = read_exact(client_fd, &h, sizeof(h));
    if (rr == 0) return 0; // EOF (Client closed cleanly)
    if (rr < 0) return -1; // Error

    if (h.version != PROTO_V1) {
        // Protocol mismatch
        send_response(client_fd, h.type, NULL, 0);
        return -1; 
    }

    uint32_t body_len = ntohl(h.size_be);
    
    // Safety check for huge payloads
    if (body_len > 65536 + 100) { 
        send_response(client_fd, h.type, NULL, 0);
        return -1;
    }

    uint8_t *body = NULL;
    if (body_len > 0) {
        body = (uint8_t*)malloc(body_len);
        if (!body) {
            send_response(client_fd, h.type, NULL, 0);
            return 1;
        }
        if (read_exact(client_fd, body, body_len) <= 0) {
            free(body);
            return -1;
        }
    }

    // 2. Dispatch
    switch (h.type) {

        case MSG_SERVER_REG_REQ: { // 0x00
            send_response(client_fd, MSG_SERVER_REG_RES, body, body_len);
            break;
        }

        case MSG_HEALTH_REQ: { // 0x08
            send_response(client_fd, MSG_HEALTH_RES, body, body_len);
            break;
        }

        case MSG_ACCT_REG_REQ: { // 0x10
            if (body_len != sizeof(BodyAuth)) {
                send_response(client_fd, MSG_ACCT_REG_RES, NULL, 0);
                break;
            }
            BodyAuth req;
            memcpy(&req, body, sizeof(req));

            char username[17];
            to_cstr_16(req.username16, username);

            udb_status_t st = user_db_put(db, username, req.password16, 16, false);
            printf("[DB] Create User '%s': %d\n", username, st);

            if (st == UDB_OK) {
                req.status = 1; // Success body status (distinct from header status)
                send_response(client_fd, MSG_ACCT_REG_RES, &req, sizeof(req));
            } else {
                 send_response(client_fd, MSG_ACCT_REG_RES, NULL, 0);
            }
            break;
        }

        case MSG_LOGIN_LOGOUT_REQ: { // 0x14
            if (body_len != sizeof(BodyAuth)) {
                send_response(client_fd, MSG_LOGIN_LOGOUT_RES, NULL, 0);
                break;
            }
            BodyAuth req;
            memcpy(&req, body, sizeof(req));

            char username[17];
            to_cstr_16(req.username16, username);

            // Check body status for Login(1) vs Logout(0)
            if (req.status == 1) { // LOGIN
                void *stored_pw = NULL;
                size_t stored_len = 0;
                udb_status_t st = user_db_get(db, username, &stored_pw, &stored_len);

                bool success = false;
                if (st == UDB_OK && stored_len == 16) {
                    if (memcmp(stored_pw, req.password16, 16) == 0) {
                        success = true;
                    }
                    free(stored_pw);
                }

                if (success) {
                    printf("[DB] Login Success: %s\n", username);
                    send_response(client_fd, MSG_LOGIN_LOGOUT_RES, &req, sizeof(req));
                } else {
                    printf("[DB] Login Failed: %s\n", username);
                    send_response(client_fd, MSG_LOGIN_LOGOUT_RES, NULL, 0);
                }
            } 
            else { // LOGOUT
                printf("[DB] Logout: %s\n", username);
                send_response(client_fd, MSG_LOGIN_LOGOUT_RES, &req, sizeof(req));
            }
            break;
        }

        case MSG_LOG_REQ: { // 0x18
            if (body_len < 3) {
                 send_response(client_fd, MSG_LOG_RES, NULL, 0);
                 break;
            }
            BodyLogHeader log_h;
            memcpy(&log_h, body, 3);
            uint16_t actual_log_len = ntohs(log_h.log_len_be);
            
            printf("[LOG] Recv %d bytes from Server ID %d\n", actual_log_len, log_h.server_id);
            send_response(client_fd, MSG_LOG_RES, NULL, 0);
            break;
        }

        default:
            send_response(client_fd, h.type, NULL, 0);
            break;
    }

    free(body);
    return 1; // Keep connection open
}

void protocol_handle_client(int client_fd, user_db_t *db) {
    while (1) {
        int rc = protocol_handle_one(client_fd, db);
        if (rc <= 0) break;
    }
    close(client_fd);
}
