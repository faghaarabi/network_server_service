/*
 * Demo run:
 * ./server_app --listen-ip 0.0.0.0 --listen-port 42096 \
 * --mgr-ip 192.168.0.131 --mgr-port 42069 \
 * --server-id 1 --db db/users.db --reg-ip 192.168.0.121
 *
 * Notes:
 * - Handles networking/flow: connect to manager, listen for clients.
 * - Spawns a thread per client to prevent blocking.
 * - Removed "WELCOME" message to fix binary protocol mismatch.
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

/* Thread arguments wrapper */
typedef struct {
    int client_fd;
    user_db_t *db;
} client_thread_args_t;

static int read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (uint8_t*)buf + off, n - off);
        if (r == 0) return -1; // peer closed
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
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

static int connect_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed for mgr ip: %s\n", ip);
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

static int listen_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);

    /* Listen on all interfaces if ip is NULL or "0.0.0.0" */
    if (ip == NULL || strcmp(ip, "0.0.0.0") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            fprintf(stderr, "inet_pton failed for listen ip: %s\n", ip);
            close(fd);
            return -1;
        }
    }

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static void send_server_reg(int mgr_fd, uint8_t ip[4], uint8_t id) {
    WireHeader h;
    h.version = PROTO_V1;
    h.type = MSG_SERVER_REG_REQ;
    h.status = 0;
    h.padding = 0;
    h.size_be = htonl((uint32_t)sizeof(BodyServerReg));

    BodyServerReg b;
    memcpy(b.ip, ip, 4);
    b.server_id = id;

    if (write_exact(mgr_fd, &h, sizeof(h)) != 0) perror("write header");
    if (write_exact(mgr_fd, &b, sizeof(b)) != 0) perror("write body");
}

static void send_mgr_ack(int mgr_fd, uint8_t type, uint8_t *body, uint32_t blen) {
    WireHeader h;
    h.version = PROTO_V1;
    h.type = type;
    h.status = ST_OK;
    h.padding = 0;
    h.size_be = htonl(blen);

    if (write_exact(mgr_fd, &h, sizeof(h)) != 0) perror("write ack header");
    if (blen > 0 && body) {
        if (write_exact(mgr_fd, body, blen) != 0) perror("write ack body");
    }
}

static void *mgr_reader_thread(void *arg) {
    int mgr_fd = *(int *)arg;

    for (;;) {
        WireHeader h;
        if (read_exact(mgr_fd, &h, sizeof(h)) != 0) {
            printf("[MANAGER] connection closed\n");
            fflush(stdout);
            break;
        }

        uint32_t blen = ntohl(h.size_be);
        printf("[MANAGER] msg: type=0x%02x status=%u body_len=%u\n",
               h.type, h.status, blen);
        fflush(stdout);

        uint8_t *body = NULL;
        if (blen > 0) {
            body = (uint8_t*)malloc(blen);
            if (!body) break;
            if (read_exact(mgr_fd, body, blen) != 0) {
                free(body);
                break;
            }
            if (blen == 5) {
                printf("[MANAGER] body: ip=%u.%u.%u.%u id=%u\n",
                       body[0], body[1], body[2], body[3], body[4]);
                fflush(stdout);
            }
        }

        /* Heartbeat request type 0x08 => ack 0x09 */
        if (h.type == 0x08) {
            send_mgr_ack(mgr_fd, 0x09, body, blen);
            printf("[MANAGER] ACK sent (type=0x09)\n");
            fflush(stdout);
        }

        free(body);
    }

    return NULL;
}

static const char *get_arg(int argc, char **argv, const char *key) {
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], key) == 0) return argv[i + 1];
    }
    return NULL;
}

static int get_int_arg(int argc, char **argv, const char *key, int def) {
    const char *v = get_arg(argc, argv, key);
    return v ? atoi(v) : def;
}

/* Worker thread for client handling */
static void *client_worker(void *arg) {
    client_thread_args_t *args = (client_thread_args_t *)arg;
    protocol_handle_client(args->client_fd, args->db);
    // protocol_handle_client handles closing the fd
    free(args);
    return NULL;
}

int main(int argc, char **argv) {
    // Force immediate output flushing for clearer logs
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *LISTEN_IP = get_arg(argc, argv, "--listen-ip");
    if (!LISTEN_IP) LISTEN_IP = "0.0.0.0";
    int LISTEN_PORT = get_int_arg(argc, argv, "--listen-port", 42096);

    const char *MGR_IP = get_arg(argc, argv, "--mgr-ip");
    if (!MGR_IP) MGR_IP = "192.168.0.50";
    int MGR_PORT = get_int_arg(argc, argv, "--mgr-port", 42069);

    int server_id_int = get_int_arg(argc, argv, "--server-id", 1);
    if (server_id_int < 0) server_id_int = 1;
    if (server_id_int > 255) server_id_int = 255;
    uint8_t server_id = (uint8_t)server_id_int;

    const char *DB_PATH = get_arg(argc, argv, "--db");
    if (!DB_PATH) DB_PATH = "db/users.db";

    user_db_t *db = NULL;
    if (user_db_open(&db, DB_PATH) != 0) {
        fprintf(stderr, "Failed to open DB: %s\n", DB_PATH);
        return 1;
    }

    int mgr_fd = connect_tcp(MGR_IP, MGR_PORT);
    if (mgr_fd < 0) {
        fprintf(stderr, "Failed to connect to manager %s:%d\n", MGR_IP, MGR_PORT);
        return 1;
    }
    printf("Connected to manager %s:%d\n", MGR_IP, MGR_PORT);

    /* Register the reachable IP with the manager (NOT 0.0.0.0). */
    uint8_t reg_ip[4] = {0};
    const char *REG_IP = get_arg(argc, argv, "--reg-ip");
    if (!REG_IP) {
        REG_IP = (strcmp(LISTEN_IP, "0.0.0.0") == 0) ? "127.0.0.1" : LISTEN_IP;
    }
    if (inet_pton(AF_INET, REG_IP, reg_ip) != 1) {
        fprintf(stderr, "Bad --reg-ip / listen-ip for registration: %s\n", REG_IP);
        return 1;
    }

    send_server_reg(mgr_fd, reg_ip, server_id);
    printf("Sent SERVER_REG_REQ to manager (reg_ip=%s id=%u)\n", REG_IP, server_id);

    pthread_t mgr_tid;
    if (pthread_create(&mgr_tid, NULL, mgr_reader_thread, &mgr_fd) == 0) {
        pthread_detach(mgr_tid);
    } else {
        perror("pthread_create (manager)");
    }

    int listen_fd = listen_tcp(LISTEN_IP, LISTEN_PORT);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to listen on %s:%d\n", LISTEN_IP, LISTEN_PORT);
        return 1;
    }
    printf("Listening for clients on %s:%d\n", LISTEN_IP, LISTEN_PORT);

    /* Accept loop (Multi-threaded) */
    for (;;) {
        printf("[SERVER] waiting in accept()...\n");

        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int c = accept(listen_fd, (struct sockaddr*)&peer, &peerlen);
        if (c < 0) {
            perror("accept");
            continue;
        }

        char peer_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[CLIENT] accepted %s:%u (fd=%d)\n", peer_ip, ntohs(peer.sin_port), c);

        /* * FIX: Do NOT send "WELCOME" string. 
         * The protocol is strictly binary (header first). 
         * Sending text here causes immediate disconnects.
         */

        // Allocate thread args
        client_thread_args_t *args = malloc(sizeof(client_thread_args_t));
        if (!args) {
            perror("malloc");
            close(c);
            continue;
        }
        args->client_fd = c;
        args->db = db;

        pthread_t client_tid;
        if (pthread_create(&client_tid, NULL, client_worker, args) == 0) {
            pthread_detach(client_tid);
        } else {
            perror("pthread_create (client)");
            free(args);
            close(c);
        }
    }

    return 0;
}
