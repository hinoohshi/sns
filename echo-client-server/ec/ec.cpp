#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#ifdef WIN32
#include <ws2tcpip.h>
#endif
#include <iostream>
#include <thread>

#ifdef WIN32
void myerror(const char* msg) { fprintf(stderr, "%s %lu\n", msg, GetLastError()); }
#else
void myerror(const char* msg) { fprintf(stderr, "%s %s %d\n", msg, strerror(errno), errno); }
#endif

void usage() {
    printf("syntax : echo-client <ip> <port>\n");
    printf("sample : echo-client 127.0.0.1 1234\n");
}

struct Param {
    char* ip{nullptr};
    char* port{nullptr};

    bool parse(int argc, char* argv[]) {
        if (argc != 3) return false;
        ip = argv[1];
        port = argv[2];
        return true;
    }
} param;

void recvThread(int sd) {
    printf("connected\n");
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
        printf("[recv] %s", buf);
        fflush(stdout);
    }
    printf("disconnected\n");
    close(sd);
    exit(0);
}

int main(int argc, char* argv[]) {
    if (!param.parse(argc, argv)) {
        usage();
        return -1;
    }

#ifdef WIN32
    WSAData wsaData;
    WSAStartup(0x0202, &wsaData);
#endif

    struct addrinfo aiInput{}, *aiOutput;
    aiInput.ai_family = AF_INET;
    aiInput.ai_socktype = SOCK_STREAM;

    int res = getaddrinfo(param.ip, param.port, &aiInput, &aiOutput);
    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        return -1;
    }

    int sd = -1;
    for (auto ai = aiOutput; ai != nullptr; ai = ai->ai_next) {
        sd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sd != -1) {
            if (connect(sd, ai->ai_addr, ai->ai_addrlen) != -1) break;
            close(sd);
            sd = -1;
        }
    }

    if (sd == -1) {
        myerror("connect");
        return -1;
    }

    std::thread(recvThread, sd).detach();

    while (true) {
        std::string s;
        if (!std::getline(std::cin, s)) break;
        s += "\r\n";
        ssize_t res = send(sd, s.data(), s.size(), 0);
        if (res <= 0) {
            fprintf(stderr, "send return %zd\n", res);
            myerror("send");
            break;
        }
    }

    close(sd);
    return 0;
}
