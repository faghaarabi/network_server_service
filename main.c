/*
 * Demo run:
 * ./server_app --listen-ip 192.168.0.121 --listen-port 42096 \
 *              --mgr-ip 192.168.0.131 --mgr-port 42069 \
 *              --server-id 1 --db db/users.db
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "user_db.h"


void protocol_handle_client(int client_fd, user_db_t *db);

/* protocol basics */
enum { PROTO_V1 = 0x01 };

enum MsgType {
    MSG_SERVER_REG_REQ = 0x00,
    MSG_SERVER_REG_RES = 0x01
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
    uint32_t size_be;
} WireHeader;

typedef struct {
    uint8_t ip[4];
    uint8_t server_id;
} BodyServerReg;
#pragma pack(pop)



static int read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (uint8_t*)buf + off, n - off);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const uint8_t*)buf + off, n - off);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}

static int connect_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        return -1;
    }
    return fd;
}

static int listen_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return -1;
    }
    if (listen(fd, 16) < 0) {
        perror("listen");
        return -1;
    }
    return fd;
}



static void send_server_reg(int mgr_fd, uint8_t ip[4], uint8_t id) {
    WireHeader h = {
        PROTO_V1,
        MSG_SERVER_REG_REQ,
        0,
        0,
        htonl(sizeof(BodyServerReg))
    };
    BodyServerReg b;
    memcpy(b.ip, ip, 4);
    b.server_id = id;

    write_exact(mgr_fd, &h, sizeof(h));
    write_exact(mgr_fd, &b, sizeof(b));
}

static void send_mgr_ack(int mgr_fd, uint8_t type, uint8_t *body, uint32_t blen) {
    WireHeader h = {
        PROTO_V1,
        type,       /* ACK type */
        ST_OK,
        0,
        htonl(blen)
    };
    write_exact(mgr_fd, &h, sizeof(h));
    if (blen > 0) {
        write_exact(mgr_fd, body, blen);
    }
}


static void *mgr_reader_thread(void *arg) {
    int mgr_fd = *(int *)arg;

    for (;;) {
        WireHeader h;
        if (read_exact(mgr_fd, &h, sizeof(h)) != 0) {
            printf("[MANAGER] connection closed\n");
            break;
        }

        uint32_t blen = ntohl(h.size_be);
        printf("[MANAGER] msg: type=0x%02x status=%u body_len=%u\n",
               h.type, h.status, blen);

        uint8_t *body = NULL;
        if (blen > 0) {
            body = malloc(blen);
            if (!body) break;
            if (read_exact(mgr_fd, body, blen) != 0) {
                free(body);
                break;
            }

            if (blen == 5) {
                printf("[MANAGER] body: ip=%u.%u.%u.%u id=%u\n",
                       body[0], body[1], body[2], body[3], body[4]);
            }
        }

        if (h.type == 0x08) {
            send_mgr_ack(mgr_fd, 0x09, body, blen);
            printf("[MANAGER] ACK sent (type=0x09)\n");
        }

        free(body);
    }

    return NULL;
}


int main() {
    const char *MY_IP  = "192.168.0.121";
    const int   MY_PORT = 42096;
    const char *MGR_IP = "192.168.0.131";
    const int   MGR_PORT = 42069;

    uint8_t ip[4];
    inet_pton(AF_INET, MY_IP, ip);

    user_db_t *db;
    user_db_open(&db, "db/users.db");

    int mgr_fd = connect_tcp(MGR_IP, MGR_PORT);
    printf("Connected to manager\n");

    send_server_reg(mgr_fd, ip, 1);
    printf("Sent SERVER_REG_REQ to manager\n");

    pthread_t tid;
    pthread_create(&tid, NULL, mgr_reader_thread, &mgr_fd);
    pthread_detach(tid);

    int listen_fd = listen_tcp(MY_IP, MY_PORT);
    printf("Listening for clients...\n");

    for (;;) {
        int c = accept(listen_fd, NULL, NULL);
        if (c < 0) continue;
        protocol_handle_client(c, db);
    }
}
