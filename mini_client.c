// mini_client.c - BIG v0.2 minimal test client (home-friendly)
// Tests:
//  1) SERVER_REG_REQ (0x00)  body=5
//  2) USER_CREATE_REQ (0x10) body=33
//  3) USER_UPDATE_REQ (0x14) body=37  (login/logout)
//  4) USER_READ_REQ   (0x12) body=49
//
// Build (macOS/Linux):
//   clang -Wall -Wextra -O2 mini_client.c -o mini_client
// Run:
//   ./mini_client 127.0.0.1 5555 alice pass
//   ./mini_client 127.0.0.1 5555 alice pass --logout
//   ./mini_client 127.0.0.1 5555 alice pass --read 1
//
// Notes:
//  - Username/password are fixed 16 bytes (NUL-padded).
//  - Auth compare in your server uses memcmp(16), so we send full 16 bytes.
//
// This client prints response header + body bytes (hex) for easy checking.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { PROTO_V2 = 0x02 };

/* Type encoding: (Resource<<3)|(CRUD<<1)|ACK */
enum { RES_SERVER = 0x00, RES_USER = 0x02 };
enum { CRUD_CREATE = 0x00, CRUD_READ = 0x01, CRUD_UPDATE = 0x02 };

enum MsgType {
    /* Server */
    MSG_SERVER_REG_REQ      = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 0, /* 0x00 */
    MSG_SERVER_REG_RES      = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 1, /* 0x01 */

    /* User */
    MSG_USER_CREATE_REQ     = (RES_USER   << 3) | (CRUD_CREATE << 1) | 0, /* 0x10 */
    MSG_USER_CREATE_RES     = (RES_USER   << 3) | (CRUD_CREATE << 1) | 1, /* 0x11 */
    MSG_USER_READ_REQ       = (RES_USER   << 3) | (CRUD_READ   << 1) | 0, /* 0x12 */
    MSG_USER_READ_RES       = (RES_USER   << 3) | (CRUD_READ   << 1) | 1, /* 0x13 */
    MSG_USER_UPDATE_REQ     = (RES_USER   << 3) | (CRUD_UPDATE << 1) | 0, /* 0x14 */
    MSG_USER_UPDATE_RES     = (RES_USER   << 3) | (CRUD_UPDATE << 1) | 1, /* 0x15 */
};

#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  status;
    uint8_t  reserved;
    uint32_t size_be;
} WireHeader;

/* 5 bytes */
typedef struct {
    uint8_t ipv4[4];
    uint8_t server_id;
} BodyServer5;

/* 33 bytes */
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t user_id;
} BodyUserCreate;

/* 37 bytes */
typedef struct {
    uint8_t username16[16];
    uint8_t password16[16];
    uint8_t ipv4[4];
    uint8_t user_status; /* 0=Online(Login), 1=Offline(Logout) */
} BodyUserUpdate;

/* 49 bytes */
typedef struct {
    uint8_t auth_username16[16];
    uint8_t auth_password16[16];
    uint8_t username16[16]; /* ignored in request; filled in response */
    uint8_t target_user_id;
} BodyUserRead;
#pragma pack(pop)

static int read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (uint8_t*)buf + off, n - off);
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
        ssize_t w = write(fd, (const uint8_t*)buf + off, n - off);
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
    if (!s) return;
    size_t n = strlen(s);
    if (n > 16) n = 16;
    memcpy(out, s, n);
}

static void hexdump(const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t*)buf;
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
        if (i + 1 != n) printf(" ");
    }
    printf("\n");
}

static int connect_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
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

    if (write_exact(fd, &h, sizeof(h)) < 0) return -1;
    if (body_len && body) {
        if (write_exact(fd, body, body_len) < 0) return -1;
    }
    return 0;
}

static int recv_pdu(int fd, WireHeader *out_h, uint8_t **out_body) {
    *out_body = NULL;
    int rr = read_exact(fd, out_h, sizeof(*out_h));
    if (rr <= 0) return rr;

    uint32_t blen = ntohl(out_h->size_be);
    if (blen > 0) {
        uint8_t *b = (uint8_t*)malloc(blen);
        if (!b) return -1;
        int br = read_exact(fd, b, blen);
        if (br <= 0) { free(b); return -1; }
        *out_body = b;
    }
    return 1;
}

static void print_resp(const char *label, const WireHeader *h, const uint8_t *body) {
    uint32_t blen = ntohl(h->size_be);
    printf("RESP %s: ver=0x%02x type=0x%02x status=0x%02x body_len=%u\n",
           label, h->version, h->type, h->status, blen);
    if (blen) {
        printf("RESP body hex: ");
        hexdump(body, blen);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s <server_ip> <server_port> <username> <password> [--logout] [--read <uid>] [--no-reg]\n"
        "\n"
        "Defaults:\n"
        "  - Does SERVER_REG (id=1, ip=127.0.0.1)\n"
        "  - Does USER_CREATE\n"
        "  - Does USER_UPDATE login (status=0)\n"
        "  - Optionally does USER_UPDATE logout (status=1)\n"
        "  - Optionally does USER_READ for uid\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc < 5) { usage(argv[0]); return 2; }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    const char *user = argv[3];
    const char *pass = argv[4];

    bool do_logout = false;
    bool do_reg = true;
    bool do_read = false;
    int read_uid = 0;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--logout") == 0) {
            do_logout = true;
        } else if (strcmp(argv[i], "--no-reg") == 0) {
            do_reg = false;
        } else if (strcmp(argv[i], "--read") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            do_read = true;
            read_uid = atoi(argv[++i]);
            if (read_uid < 0) read_uid = 0;
            if (read_uid > 255) read_uid = 255;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    int fd = connect_tcp(ip, port);
    if (fd < 0) return 1;

    printf("Connected to %s:%d\n", ip, port);

    /* 1) Optional: SERVER_REG_REQ (0x00) body=5 */
    if (do_reg) {
        BodyServer5 s;
        memset(&s, 0, sizeof(s));
        /* For home testing, pretend our server IP is 127.0.0.1 */
        s.ipv4[0] = 127; s.ipv4[1] = 0; s.ipv4[2] = 0; s.ipv4[3] = 1;
        s.server_id = 1;

        printf("SEND SERVER_REG_REQ (0x%02x) body_len=%zu\n", MSG_SERVER_REG_REQ, sizeof(s));
        if (send_pdu(fd, MSG_SERVER_REG_REQ, &s, (uint32_t)sizeof(s)) < 0) {
            perror("send SERVER_REG_REQ");
            close(fd);
            return 1;
        }

        WireHeader rh;
        uint8_t *rb = NULL;
        if (recv_pdu(fd, &rh, &rb) <= 0) {
            fprintf(stderr, "recv SERVER_REG_RES failed\n");
            close(fd);
            return 1;
        }
        print_resp("SERVER_REG_RES", &rh, rb);
        free(rb);
    }

    /* 2) USER_CREATE_REQ (0x10) body=33 */
    BodyUserCreate cu;
    memset(&cu, 0, sizeof(cu));
    fill16(cu.username16, user);
    fill16(cu.password16, pass);
    cu.user_id = 0;

    printf("SEND USER_CREATE_REQ (0x%02x) body_len=%zu\n", MSG_USER_CREATE_REQ, sizeof(cu));
    if (send_pdu(fd, MSG_USER_CREATE_REQ, &cu, (uint32_t)sizeof(cu)) < 0) {
        perror("send USER_CREATE_REQ");
        close(fd);
        return 1;
    }

    WireHeader rh;
    uint8_t *rb = NULL;
    int rc = recv_pdu(fd, &rh, &rb);
    if (rc <= 0) { fprintf(stderr, "recv USER_CREATE_RES failed\n"); close(fd); return 1; }
    print_resp("USER_CREATE_RES", &rh, rb);

    uint8_t created_uid = 0;
    if (ntohl(rh.size_be) == sizeof(BodyUserCreate) && rb) {
        BodyUserCreate tmp;
        memcpy(&tmp, rb, sizeof(tmp));
        created_uid = tmp.user_id;
        printf("Parsed created user_id=%u\n", created_uid);
    }
    free(rb);

    /* 3) USER_UPDATE_REQ login (0x14) body=37 */
    BodyUserUpdate uu;
    memset(&uu, 0, sizeof(uu));
    fill16(uu.username16, user);
    fill16(uu.password16, pass);

    /* Put a fake client IP: 10.0.0.2 */
    uu.ipv4[0] = 10; uu.ipv4[1] = 0; uu.ipv4[2] = 0; uu.ipv4[3] = 2;
    uu.user_status = 0; /* login */

    printf("SEND USER_UPDATE_REQ login (0x%02x) body_len=%zu\n", MSG_USER_UPDATE_REQ, sizeof(uu));
    if (send_pdu(fd, MSG_USER_UPDATE_REQ, &uu, (uint32_t)sizeof(uu)) < 0) {
        perror("send USER_UPDATE_REQ(login)");
        close(fd);
        return 1;
    }

    rb = NULL;
    rc = recv_pdu(fd, &rh, &rb);
    if (rc <= 0) { fprintf(stderr, "recv USER_UPDATE_RES(login) failed\n"); close(fd); return 1; }
    print_resp("USER_UPDATE_RES(login)", &rh, rb);
    free(rb);

    /* 4) Optional: USER_READ_REQ (0x12) body=49 */
    if (do_read) {
        BodyUserRead ur;
        memset(&ur, 0, sizeof(ur));
        fill16(ur.auth_username16, user);
        fill16(ur.auth_password16, pass);
        memset(ur.username16, 0, 16); /* request ignores this */
        ur.target_user_id = (uint8_t)read_uid;

        printf("SEND USER_READ_REQ (0x%02x) body_len=%zu target_uid=%d\n",
               MSG_USER_READ_REQ, sizeof(ur), read_uid);
        if (send_pdu(fd, MSG_USER_READ_REQ, &ur, (uint32_t)sizeof(ur)) < 0) {
            perror("send USER_READ_REQ");
            close(fd);
            return 1;
        }

        rb = NULL;
        rc = recv_pdu(fd, &rh, &rb);
        if (rc <= 0) { fprintf(stderr, "recv USER_READ_RES failed\n"); close(fd); return 1; }
        print_resp("USER_READ_RES", &rh, rb);

        if (ntohl(rh.size_be) == sizeof(BodyUserRead) && rb) {
            BodyUserRead tmp;
            memcpy(&tmp, rb, sizeof(tmp));
            char uname[17];
            memcpy(uname, tmp.username16, 16);
            uname[16] = '\0';
            printf("Parsed USER_READ username16='%s' target_uid=%u\n", uname, tmp.target_user_id);
        }
        free(rb);
    } else if (created_uid != 0) {
        /* Handy hint */
        printf("Tip: try reading the created uid:\n");
        printf("  %s %s %d %s %s --read %u\n", argv[0], ip, port, user, pass, created_uid);
    }

    /* 5) Optional: USER_UPDATE_REQ logout */
    if (do_logout) {
        uu.user_status = 1; /* logout */
        printf("SEND USER_UPDATE_REQ logout (0x%02x) body_len=%zu\n", MSG_USER_UPDATE_REQ, sizeof(uu));
        if (send_pdu(fd, MSG_USER_UPDATE_REQ, &uu, (uint32_t)sizeof(uu)) < 0) {
            perror("send USER_UPDATE_REQ(logout)");
            close(fd);
            return 1;
        }

        rb = NULL;
        rc = recv_pdu(fd, &rh, &rb);
        if (rc <= 0) { fprintf(stderr, "recv USER_UPDATE_RES(logout) failed\n"); close(fd); return 1; }
        print_resp("USER_UPDATE_RES(logout)", &rh, rb);
        free(rb);
    }

    close(fd);
    return 0;
}//
// Created by Fereshteh on 3/3/26.
//