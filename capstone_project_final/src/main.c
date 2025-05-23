#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BACKLOG 10
#define MAX_MSG_SIZE 2048

#define OPCODE_DELETE_REMOTE_FILE 0x02

#define RETURN_SUCCESS 0x01
#define RETURN_SESSION_ERROR 0x02
#define RETURN_PERMISSION_ERROR 0x03
#define RETURN_FAILURE 0xFF

typedef enum { PERM_READ, PERM_RW, PERM_ADMIN } Permission;

typedef struct {
    char username[64];
    char password[64];
    Permission perm;
    uint32_t session_id;
} User;

User users[100];
int user_count = 0;
pthread_mutex_t user_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t generate_session_id() {
    return rand() ^ (rand() << 16);
}

User* find_user_by_session(uint32_t session_id) {
    for (int i = 0; i < user_count; ++i)
        if (users[i].session_id == session_id)
            return &users[i];
    return NULL;
}

int add_user(const char* username, const char* password, Permission perm) {
    if (user_count >= 100) return RETURN_FAILURE;
    strncpy(users[user_count].username, username, 63);
    strncpy(users[user_count].password, password, 63);
    users[user_count].perm = perm;
    users[user_count].session_id = 0;
    user_count++;
    return RETURN_SUCCESS;
}

void send_status(int client_fd, uint8_t code) {
    uint8_t response[1] = { code };
    send(client_fd, response, 1, 0);
}

void handle_delete(int client_fd, uint8_t* buffer) {
    uint16_t name_len = ntohs(*(uint16_t*)&buffer[2]);
    uint32_t session_id = ntohl(*(uint32_t*)&buffer[4]);
    char* name = (char*)&buffer[8];

    pthread_mutex_lock(&user_lock);
    User* u = find_user_by_session(session_id);
    if (!u || u->perm < PERM_ADMIN) {
        send_status(client_fd, u ? RETURN_PERMISSION_ERROR : RETURN_SESSION_ERROR);
        pthread_mutex_unlock(&user_lock);
        return;
    }

    char path[256] = "./server_root/";
    strncat(path, name, name_len);
    int result = remove(path);
    send_status(client_fd, result == 0 ? RETURN_SUCCESS : RETURN_FAILURE);
    pthread_mutex_unlock(&user_lock);
}

void* handle_client(void* arg) {
    int client_fd = *((int*)arg);
    free(arg);

    uint8_t buffer[MAX_MSG_SIZE];
    ssize_t bytes = recv(client_fd, buffer, sizeof(buffer), 0);
    if (bytes < 1) {
        close(client_fd);
        return NULL;
    }

    uint8_t opcode = buffer[0];
    if (opcode == OPCODE_DELETE_REMOTE_FILE) {
        handle_delete(client_fd, buffer);
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    add_user("admin", "password", PERM_ADMIN);

    int port = 9090;
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        if (opt == 'p') port = atoi(optarg);
    }

    mkdir("./server_root", 0755);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, BACKLOG);
    printf("Server running on port %d\n", port);

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int* fd = malloc(sizeof(int));
        *fd = accept(sock, (struct sockaddr*)&client, &len);
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, fd);
        pthread_detach(tid);
    }

    close(sock);
    return 0;
}
