#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { PROTO_V2 = 0x02 };

enum {
    ST_OK            = 0x00,
    ST_AlreadyExists = 0x46,
    ST_Forbidden     = 0x48
};

enum MsgType {
    MSG_USER_CREATE_REQ    = 0x10,
    MSG_USER_CREATE_RES    = 0x11,
    MSG_USER_UPDATE_REQ    = 0x14,
    MSG_USER_UPDATE_RES    = 0x15,
    MSG_CHANNEL_CREATE_REQ = 0x20,
    MSG_CHANNEL_CREATE_RES = 0x21,
    MSG_CHANNEL_READ_REQ   = 0x22,
    MSG_CHANNEL_READ_RES   = 0x23,
    MSG_CHANNELS_READ_REQ  = 0x2A,
    MSG_CHANNELS_READ_RES  = 0x2B
};

#pragma pack(push, 1)

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  reserved;
    uint32_t size_be;
} WireHeader;

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
    uint8_t channel_name16[16];
    uint8_t channel_id;
} BodyChannelCreate;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
} BodyAuth32;

typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t channel_id;
} BodyChannelReadReq;

#pragma pack(pop)

static int read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;

    while (off < n) {
        ssize_t r = read(fd, (uint8_t *)buf + off, n - off);
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
    size_t off = 0;

    while (off < n) {
        ssize_t w = write(fd, (const uint8_t *)buf + off, n - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }

    return 0;
}

static void fill16(uint8_t out[16], const char *s) {
    memset(out, 0, 16);
    strncpy((char *)out, s, 15);
}

static void copy_name16_to_cstr(const uint8_t in[16], char out[17]) {
    memcpy(out, in, 16);
    out[16] = '\0';
}

static void print_name16(const uint8_t in[16]) {
    char s[17];
    copy_name16_to_cstr(in, s);
    printf("%s", s);
}

static int connect_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static int send_pdu(int fd, uint8_t type, const void *body, uint32_t body_len) {
    WireHeader h;

    h.version = PROTO_V2;
    h.type = type;
    h.status = 0;
    h.reserved = 0;
    h.size_be = htonl(body_len);

    if (write_exact(fd, &h, sizeof(h)) != 0) return -1;
    if (body_len > 0 && body != NULL) {
        if (write_exact(fd, body, body_len) != 0) return -1;
    }

    return 0;
}

static int recv_pdu(int fd, WireHeader *out_h, uint8_t **out_body) {
    WireHeader h;
    int rr = read_exact(fd, &h, sizeof(h));
    if (rr <= 0) return rr;

    uint32_t blen = ntohl(h.size_be);
    uint8_t *body = NULL;

    if (blen > 0) {
        body = (uint8_t *)malloc(blen);
        if (!body) return -1;

        if (read_exact(fd, body, blen) <= 0) {
            free(body);
            return -1;
        }
    }

    *out_h = h;
    *out_body = body;
    return 1;
}

static void print_header(const WireHeader *h) {
    printf("RESP: ver=0x%02x type=0x%02x status=0x%02x body_len=%u\n",
           h->version, h->type, h->status, ntohl(h->size_be));
}

/* New protocol.c returns:
   body[0..31]  = zeroed auth area
   body[32]     = count
   body[33..]   = channel IDs only
*/
static uint8_t read_channels_list_and_pick_id(const uint8_t *body, uint32_t blen) {
    if (body == NULL || blen < 33) return 0;

    uint8_t count = body[32];
    uint8_t chosen_id = 0;

    printf("Channels.Read OK: count=%u\n", count);

    for (uint8_t i = 0; i < count; i++) {
        uint32_t idx = 33u + i;
        if (idx >= blen) {
            printf("Truncated channel ID at index %u\n", i);
            break;
        }

        uint8_t channel_id = body[idx];
        printf("  Channel[%u]: id=%u\n", i, channel_id);

        if (chosen_id == 0) {
            chosen_id = channel_id;
        }
    }

    return chosen_id;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr,
                "Usage: %s <server_ip> <port> <username> <password> <channel_name>\n",
                argv[0]);
        return 2;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *username = argv[3];
    const char *password = argv[4];
    const char *channel_name = argv[5];

    int fd = connect_tcp(server_ip, port);
    if (fd < 0) return 1;

    uint8_t created_user_id = 0;
    uint8_t chosen_channel_id = 0;

    /* --------------------------------------------------
       1) User.Create
       -------------------------------------------------- */
    {
        BodyUserCreate req;
        memset(&req, 0, sizeof(req));
        fill16(req.username16, username);
        fill16(req.password16, password);
        req.user_id = 0;

        printf("SEND User.Create (0x10)\n");
        if (send_pdu(fd, MSG_USER_CREATE_REQ, &req, (uint32_t)sizeof(req)) != 0) {
            perror("send User.Create");
            close(fd);
            return 1;
        }

        WireHeader h;
        uint8_t *body = NULL;
        if (recv_pdu(fd, &h, &body) <= 0) {
            fprintf(stderr, "failed to recv User.Create response\n");
            close(fd);
            return 1;
        }

        print_header(&h);

        if (h.type == MSG_USER_CREATE_RES &&
            h.status == ST_OK &&
            ntohl(h.size_be) == sizeof(BodyUserCreate)) {
            BodyUserCreate res;
            memcpy(&res, body, sizeof(res));
            created_user_id = res.user_id;

            printf("User.Create OK: username=");
            print_name16(res.username16);
            printf(" user_id=%u\n", created_user_id);
        } else if (h.type == MSG_USER_CREATE_RES && h.status == ST_AlreadyExists) {
            printf("User already exists. Continuing with login test.\n");
        } else {
            printf("Unexpected User.Create response.\n");
        }

        free(body);
    }

    /* --------------------------------------------------
       2) Login
       -------------------------------------------------- */
    {
        BodyUserUpdate req;
        memset(&req, 0, sizeof(req));
        fill16(req.username16, username);
        fill16(req.password16, password);
        req.ipv4[0] = 127;
        req.ipv4[1] = 0;
        req.ipv4[2] = 0;
        req.ipv4[3] = 1;
        req.user_status = 1;

        printf("\nSEND User.Update LOGIN (0x14)\n");
        if (send_pdu(fd, MSG_USER_UPDATE_REQ, &req, (uint32_t)sizeof(req)) != 0) {
            perror("send Login");
            close(fd);
            return 1;
        }

        WireHeader h;
        uint8_t *body = NULL;
        if (recv_pdu(fd, &h, &body) <= 0) {
            fprintf(stderr, "failed to recv Login response\n");
            close(fd);
            return 1;
        }

        print_header(&h);

        if (h.type == MSG_USER_UPDATE_RES &&
            h.status == ST_OK &&
            ntohl(h.size_be) == sizeof(BodyUserUpdate)) {
            printf("Login OK\n");
        } else {
            printf("Unexpected Login response.\n");
        }

        free(body);
    }

    /* --------------------------------------------------
       3) Channel.Create
       New server returns ST_Forbidden
       -------------------------------------------------- */
    {
        BodyChannelCreate req;
        memset(&req, 0, sizeof(req));
        fill16(req.auth_username16, username);
        fill16(req.auth_password16, password);
        fill16(req.channel_name16, channel_name);
        req.channel_id = 0;

        printf("\nSEND Channel.Create (0x20)\n");
        if (send_pdu(fd, MSG_CHANNEL_CREATE_REQ, &req, (uint32_t)sizeof(req)) != 0) {
            perror("send Channel.Create");
            close(fd);
            return 1;
        }

        WireHeader h;
        uint8_t *body = NULL;
        if (recv_pdu(fd, &h, &body) <= 0) {
            fprintf(stderr, "failed to recv Channel.Create response\n");
            close(fd);
            return 1;
        }

        print_header(&h);

        if (h.type == MSG_CHANNEL_CREATE_RES &&
            h.status == ST_OK &&
            ntohl(h.size_be) == sizeof(BodyChannelCreate)) {
            BodyChannelCreate res;
            memcpy(&res, body, sizeof(res));

            printf("Channel.Create OK: channel_name=");
            print_name16(res.channel_name16);
            printf(" channel_id=%u\n", res.channel_id);
        } else if (h.type == MSG_CHANNEL_CREATE_RES && h.status == ST_AlreadyExists) {
            printf("Channel already exists.\n");
        } else if (h.type == MSG_CHANNEL_CREATE_RES && h.status == ST_Forbidden) {
            printf("Channel.Create forbidden by server. Continuing with existing/default channels.\n");
        } else {
            printf("Unexpected Channel.Create response.\n");
        }

        free(body);
    }

    /* --------------------------------------------------
       4) Channels.Read
       -------------------------------------------------- */
    {
        BodyAuth32 req;
        memset(&req, 0, sizeof(req));
        fill16(req.auth_username16, username);
        fill16(req.auth_password16, password);

        printf("\nSEND Channels.Read (0x2A)\n");
        if (send_pdu(fd, MSG_CHANNELS_READ_REQ, &req, (uint32_t)sizeof(req)) != 0) {
            perror("send Channels.Read");
            close(fd);
            return 1;
        }

        WireHeader h;
        uint8_t *body = NULL;
        if (recv_pdu(fd, &h, &body) <= 0) {
            fprintf(stderr, "failed to recv Channels.Read response\n");
            close(fd);
            return 1;
        }

        print_header(&h);

        if (h.type == MSG_CHANNELS_READ_RES &&
            h.status == ST_OK &&
            ntohl(h.size_be) >= 33) {
            uint32_t blen = ntohl(h.size_be);
            chosen_channel_id = read_channels_list_and_pick_id(body, blen);
        } else {
            printf("Unexpected Channels.Read response.\n");
        }

        free(body);
    }

    if (chosen_channel_id == 0) {
        printf("\nNo channel id available to read.\n");
        close(fd);
        return 1;
    }

    /* --------------------------------------------------
       5) Channel.Read
       -------------------------------------------------- */
    {
        BodyChannelReadReq req;
        memset(&req, 0, sizeof(req));
        fill16(req.auth_username16, username);
        fill16(req.auth_password16, password);
        req.channel_id = chosen_channel_id;

        printf("\nSEND Channel.Read (0x22) for channel_id=%u\n", req.channel_id);
        if (send_pdu(fd, MSG_CHANNEL_READ_REQ, &req, (uint32_t)sizeof(req)) != 0) {
            perror("send Channel.Read");
            close(fd);
            return 1;
        }

        WireHeader h;
        uint8_t *body = NULL;
        if (recv_pdu(fd, &h, &body) <= 0) {
            fprintf(stderr, "failed to recv Channel.Read response\n");
            close(fd);
            return 1;
        }

        print_header(&h);

        if (h.type == MSG_CHANNEL_READ_RES &&
            h.status == ST_OK &&
            ntohl(h.size_be) >= 50) {
            uint32_t blen = ntohl(h.size_be);
            char chname[17];
            uint8_t channel_id;
            uint8_t member_count;

            memcpy(chname, &body[32], 16);
            chname[16] = '\0';
            channel_id = body[48];
            member_count = body[49];

            printf("Channel.Read OK:\n");
            printf("  name=%s\n", chname);
            printf("  channel_id=%u\n", channel_id);
            printf("  member_count=%u\n", member_count);
            printf("  member_ids: ");

            for (uint8_t i = 0; i < member_count && (50u + i) < blen; i++) {
                printf("%u ", body[50 + i]);
            }
            printf("\n");

            if (created_user_id != 0) {
                int found = 0;
                for (uint8_t i = 0; i < member_count && (50u + i) < blen; i++) {
                    if (body[50 + i] == created_user_id) {
                        found = 1;
                        break;
                    }
                }
                printf("Creator membership check: %s\n", found ? "PASS" : "NOT FOUND");
            }
        } else {
            printf("Unexpected Channel.Read response.\n");
        }

        free(body);
    }

    close(fd);
    return 0;
}