/*
 * server_app.c
 *
 * Demo run:
 * ./server_app --listen-ip 0.0.0.0 --listen-port 42069 \
 *   --mgr-ip 192.168.0.131 --mgr-port 42069 \
 *   --server-id 1 --db /db/users.db --reg-ip 192.168.0.121
 *
 * Updates (RFC v0.2 + compat-safe):
 * - Uses RFC manager heartbeat: Server.Update 0x04 -> 0x05 (5-byte body).
 * - Accepts BOTH manager heartbeat styles and ACKs them:
 *     * Old: 0x08 -> 0x09 (ActivatedServer.Create)
 *     * RFC: 0x04 -> 0x05 (Server.Update)
 * - If manager responds to registration with a ServerId, we store it and use it for heartbeats.
 * - DOES NOT change client accept/thread behavior (so login/logout and client protocol stays working).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "user_db.h"

/* Provided elsewhere (e.g., protocol.c). Must close(client_fd) inside. */
void protocol_handle_client(int client_fd, user_db_t *db);

/* BIG v0.2 */
enum { PROTO_V2 = 0x02 };

/* Type encoding:
   Type = (Resource << 3) | (Action << 1) | Direction
*/
enum { RES_SERVER = 0x00, RES_ACTIVATEDSERVER = 0x01 };
enum { CRUD_CREATE = 0x00, CRUD_READ = 0x01, CRUD_UPDATE = 0x02, CRUD_DELETE = 0x03 };

/* Server MsgTypes (RFC) */
enum MsgType {
    MSG_SERVER_REG_REQ = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 0, /* 0x00 */
    MSG_SERVER_REG_RES = (RES_SERVER << 3) | (CRUD_CREATE << 1) | 1, /* 0x01 */

    /* RFC heartbeat: Server.Update */
    MSG_SERVER_HC_REQ  = (RES_SERVER << 3) | (CRUD_UPDATE << 1) | 0, /* 0x04 */
    MSG_SERVER_HC_RES  = (RES_SERVER << 3) | (CRUD_UPDATE << 1) | 1  /* 0x05 */
};

/* Old heartbeat style some managers used */
enum {
    MSG_OLD_HB_REQ = 0x08,
    MSG_OLD_HB_RES = 0x09
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
    uint8_t ip[4];
    uint8_t server_id;
} BodyServer5;
#pragma pack(pop)

/* Thread arguments wrapper */
typedef struct {
    int client_fd;
    user_db_t *db;
    uint64_t client_id;
} client_thread_args_t;

/* ---- Globals for manager connection state ---- */
static pthread_mutex_t g_mgr_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_registered_server_id = 0; /* updated if manager assigns us one */
static uint8_t g_reg_ip[4] = {0};          /* our registered IP (4 bytes) */

/* Return convention:
   1 = success
   0 = peer closed cleanly
  -1 = error
*/
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
        fprintf(stderr, "inet_pton failed for mgr ip: %s\n", ip);
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

static int listen_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

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

    if (ip == NULL || strcmp(ip, "0.0.0.0") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            fprintf(stderr, "inet_pton failed for listen ip: %s\n", ip);
            close(fd);
            return -1;
        }
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 128) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int send_pdu(int fd, uint8_t type, uint8_t status, const void *body, uint32_t blen) {
    WireHeader h;
    h.version = PROTO_V2;
    h.type = type;
    h.status = status;
    h.reserved = 0;
    h.size_be = htonl(blen);

    if (write_exact(fd, &h, sizeof(h)) != 0) return -1;
    if (blen > 0 && body) {
        if (write_exact(fd, body, blen) != 0) return -1;
    }
    return 0;
}

static void send_server_reg(int mgr_fd, const uint8_t ip[4], uint8_t id) {
    BodyServer5 b;
    memcpy(b.ip, ip, 4);
    b.server_id = id; /* client suggests; manager may ignore + assign */

    if (send_pdu(mgr_fd, MSG_SERVER_REG_REQ, 0, &b, (uint32_t)sizeof(b)) != 0) {
        perror("send SERVER_REG_REQ");
    }
}

static void send_mgr_ack(int mgr_fd, uint8_t type, const uint8_t *body, uint32_t blen) {
    if (send_pdu(mgr_fd, type, 0, body, blen) != 0) {
        perror("send manager ack");
    }
}

/* RFC heartbeat sender (optional but good): 0x04 with 5-byte body */
static void send_server_hb(int mgr_fd) {
    BodyServer5 b;
    pthread_mutex_lock(&g_mgr_mu);
    memcpy(b.ip, g_reg_ip, 4);
    b.server_id = g_registered_server_id;
    pthread_mutex_unlock(&g_mgr_mu);

    /* If we still don't have an assigned id, send whatever we have (0 or initial). */
    (void)send_pdu(mgr_fd, MSG_SERVER_HC_REQ, 0, &b, (uint32_t)sizeof(b));
}

static void *mgr_heartbeat_thread(void *arg) {
    int mgr_fd = *(int *)arg;

    /* Send RFC heartbeat every 5 seconds (as RFC says <= 5). */
    for (;;) {
        sleep(5);
        /* If socket is dead, write will fail; we just let reader print close eventually. */
        send_server_hb(mgr_fd);
        /* no spam prints */
    }
    return NULL;
}

static void *mgr_reader_thread(void *arg) {
    int mgr_fd = *(int *)arg;

    for (;;) {
        WireHeader h;
        int hr = read_exact(mgr_fd, &h, sizeof(h));
        if (hr <= 0) {
            printf("[MANAGER] connection closed\n");
            fflush(stdout);
            break;
        }

        uint32_t blen = ntohl(h.size_be);
        printf("[MANAGER] msg: ver=0x%02x type=0x%02x status=%u body_len=%u\n",
               h.version, h.type, h.status, blen);
        fflush(stdout);

        uint8_t *body = NULL;
        if (blen > 0) {
            body = (uint8_t *)malloc(blen);
            if (!body) break;

            int br = read_exact(mgr_fd, body, blen);
            if (br <= 0) {
                free(body);
                break;
            }

            if (blen == (uint32_t)sizeof(BodyServer5)) {
                printf("[MANAGER] body: ip=%u.%u.%u.%u id=%u\n",
                       body[0], body[1], body[2], body[3], body[4]);
                fflush(stdout);
            }
        }

        /* If this is registration response, store assigned server id (if present). */
        if (h.type == MSG_SERVER_REG_RES && blen == (uint32_t)sizeof(BodyServer5) && body) {
            pthread_mutex_lock(&g_mgr_mu);
            g_registered_server_id = body[4];
            pthread_mutex_unlock(&g_mgr_mu);

            printf("[MANAGER] assigned server_id=%u\n", (unsigned)g_registered_server_id);
            fflush(stdout);
        }

        /* Heartbeat requests that we might need to ACK (keep old behavior too) */
        if (h.type == MSG_OLD_HB_REQ) {
            send_mgr_ack(mgr_fd, MSG_OLD_HB_RES, body, blen);
            printf("[MANAGER] ACK sent (type=0x%02x)\n", MSG_OLD_HB_RES);
            fflush(stdout);
        } else if (h.type == MSG_SERVER_HC_REQ) {
            /* Some managers might ping us with Server.Update instead */
            send_mgr_ack(mgr_fd, MSG_SERVER_HC_RES, body, blen);
            printf("[MANAGER] ACK sent (type=0x%02x)\n", MSG_SERVER_HC_RES);
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

static void *client_worker(void *arg) {
    client_thread_args_t *args = (client_thread_args_t *)arg;

    printf("[CLIENT %" PRIu64 "] handler started (fd=%d)\n", args->client_id, args->client_fd);

    /* protocol_handle_client() must close(client_fd) */
    protocol_handle_client(args->client_fd, args->db);

    printf("[CLIENT %" PRIu64 "] handler finished (fd=%d)\n", args->client_id, args->client_fd);

    free(args);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *LISTEN_IP = get_arg(argc, argv, "--listen-ip");
    if (!LISTEN_IP) LISTEN_IP = "0.0.0.0";
    int LISTEN_PORT = get_int_arg(argc, argv, "--listen-port", 8080);

    const char *MGR_IP = get_arg(argc, argv, "--mgr-ip");
    if (!MGR_IP) MGR_IP = "192.168.0.34";
    int MGR_PORT = get_int_arg(argc, argv, "--mgr-port", 8080);

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

    /* 1) Connect to Manager */
    int mgr_fd = connect_tcp(MGR_IP, MGR_PORT);
    if (mgr_fd < 0) {
        fprintf(stderr, "Failed to connect to manager %s:%d\n", MGR_IP, MGR_PORT);
        return 1;
    }
    printf("Connected to manager %s:%d\n", MGR_IP, MGR_PORT);

    /* 2) Register Server */
    uint8_t reg_ip[4] = {0};
    const char *REG_IP = get_arg(argc, argv, "--reg-ip");
    if (!REG_IP) {
        REG_IP = (strcmp(LISTEN_IP, "0.0.0.0") == 0) ? "127.0.0.1" : LISTEN_IP;
    }
    if (inet_pton(AF_INET, REG_IP, reg_ip) != 1) {
        fprintf(stderr, "Bad --reg-ip / listen-ip for registration: %s\n", REG_IP);
        return 1;
    }

    /* store reg ip and (initial) server id for heartbeat */
    pthread_mutex_lock(&g_mgr_mu);
    memcpy(g_reg_ip, reg_ip, 4);
    g_registered_server_id = server_id; /* manager may overwrite after REG_RES */
    pthread_mutex_unlock(&g_mgr_mu);

    send_server_reg(mgr_fd, reg_ip, server_id);
    printf("Sent SERVER_REG_REQ to manager (ver=0x%02x reg_ip=%s id=%u)\n", PROTO_V2, REG_IP, server_id);

    /* 3) Start Manager reader thread */
    pthread_t mgr_tid;
    if (pthread_create(&mgr_tid, NULL, mgr_reader_thread, &mgr_fd) == 0) {
        pthread_detach(mgr_tid);
    } else {
        perror("pthread_create (manager reader)");
    }

    /* 3.1) Start optional heartbeat sender thread (RFC) */
    pthread_t hb_tid;
    if (pthread_create(&hb_tid, NULL, mgr_heartbeat_thread, &mgr_fd) == 0) {
        pthread_detach(hb_tid);
    } else {
        perror("pthread_create (manager heartbeat)");
    }

    /* 4) Listen for clients */
    printf("DEBUG: Attempting to bind and listen on %s:%d\n", LISTEN_IP, LISTEN_PORT);
    int listen_fd = listen_tcp(LISTEN_IP, LISTEN_PORT);
    if (listen_fd < 0) {
        fprintf(stderr, "FATAL: listen_tcp failed for %s:%d: %s\n",
                LISTEN_IP, LISTEN_PORT, strerror(errno));
        return 1;
    }
    printf("SUCCESS: Listening for clients on %s:%d. (Run 'lsof -iTCP:%d -sTCP:LISTEN' to verify)\n",
           LISTEN_IP, LISTEN_PORT, LISTEN_PORT);

    pthread_mutex_t id_mu = PTHREAD_MUTEX_INITIALIZER;
    uint64_t next_client_id = 0;

    /* 5) Accept loop */
    for (;;) {
        printf("[SERVER] waiting in accept()...\n");

        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int c = accept(listen_fd, (struct sockaddr *)&peer, &peerlen);

        if (c < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char peer_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));

        uint64_t my_id;
        pthread_mutex_lock(&id_mu);
        my_id = ++next_client_id;
        pthread_mutex_unlock(&id_mu);

        printf("[CLIENT %" PRIu64 "] accepted %s:%u (fd=%d)\n",
               my_id, peer_ip, ntohs(peer.sin_port), c);

        client_thread_args_t *args = (client_thread_args_t *)malloc(sizeof(*args));
        if (!args) {
            perror("malloc");
            close(c);
            continue;
        }
        args->client_fd = c;
        args->db = db;
        args->client_id = my_id;

        pthread_t client_tid;
        if (pthread_create(&client_tid, NULL, client_worker, args) == 0) {
            pthread_detach(client_tid);
        } else {
            perror("pthread_create (client)");
            free(args);
            close(c);
        }
    }

    /* unreachable in current design */
    return 0;
}