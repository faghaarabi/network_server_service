#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>   // ntohl/htonl

#include "user_db.h"

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

#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  padding;
    uint32_t size_be;   // body length, big-endian
} WireHeader;

typedef struct {
    uint8_t ip[4];
    uint8_t server_id;
} BodyServerReg; // also used for health check

typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t id;
} BodyAccountReg;