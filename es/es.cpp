#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#ifdef WIN32
#include <ws2tcpip.h>
#endif
#include <iostream>
#include <thread>
#include <set>
#include <mutex>

#ifdef WIN32
void myerror(const char* msg) { fprintf(stderr, "%s %lu\n", msg, GetLastError()); }
#else
void myerror(const char* msg) { fprintf(stderr, "%s %s %d\n", msg, strerror(errno), errno); }
#endif

void usage() {
    printf("syntax : echo-server <port> [-e[-b]]\n");
    printf("sample : echo-server 1234 -e -b\n");
}

bool echo_mode = false;
bool broadcast_mode = false;
std::set<int> clients;
std::mutex mtx;

void broadcastToOthers(int sender, const char* buf, ssize_t len) {
    std::lock_guard<std::mutex> lock(mtx);
    for (int c : clients) {
        if (c != sender) {
            ssize_t sent = send(c, buf, len, 0);
            if (sent == -1) {
                fprintf(stderr, "broadcast send to fd %d failed: %s (%d)\n", c, strerror(errno), errno);
            } else {
                printf("broadcasted to fd %d\n", c);
            }
        }
    }
}

void recvThread(int sd) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        clients.insert(sd);
    }

    printf("connected: fd %d\n", sd);
    fflush(stdout);

    const int BUFSIZE = 65536;
    char buf[BUFSIZE];

    while (true) {
        ssize_t res = recv(sd, buf, BUFSIZE - 1, 0);
        if (res <= 0) {
            fprintf(stderr, "recv return %zd\n", res);
            myerror("recv");
            break;
        }

        buf[res] = '\0';
        printf("[client %d] %s", sd, buf);
        fflush(stdout);

        if (echo_mode) {
            send(sd, buf, res, 0);
        }

        if (broadcast_mode) {
            broadcastToOthers(sd, buf, res);
        }
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        clients.erase(sd);
    }

    close(sd);
    printf("disconnected: fd %d\n", sd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage();
        return -1;
    }

    int port = atoi(argv[1]);
    if (argc >= 3) {
        for (int i = 2; i < argc; i++) {
            if (strchr(argv[i], 'e')) echo_mode = true;
            if (strchr(argv[i], 'b')) broadcast_mode = true;
        }
        if (broadcast_mode == true) printf("broadcast mode\n");
    }

#ifdef WIN32
    WSAData wsaData;
    WSAStartup(0x0202, &wsaData);
#endif

    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) {
        myerror("socket");
        return -1;
    }

#ifdef __linux__
    int optval = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        myerror("setsockopt");
        return -1;
    }
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        myerror("bind");
        return -1;
    }

    if (listen(sd, 5) == -1) {
        myerror("listen");
        return -1;
    }

    printf("Server listening on port %d\n", port);

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int newsd = accept(sd, (struct sockaddr*)&client_addr, &len);
        if (newsd == -1) {
            myerror("accept");
            continue;
        }

        std::thread(recvThread, newsd).detach();
    }

    close(sd);
    return 0;
}
