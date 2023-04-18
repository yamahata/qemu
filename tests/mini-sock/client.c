/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * dummy qemu mini sock client to test qemu mini sock server
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <stdbool.h>
#include <limits.h>
#include <err.h>
#include <getopt.h>

#define SERVER_PATH     "/tmp/msock/server"
#define CLIENT_PATH     "/tmp/msock/client/%d"

static void usage(const char *prog)
{
    printf("Usage: %s [--client=<path>] [--server=<path>]\n"
           "Options:\n"
           "--help, -h: print this help\n"
           "--datagram, -d: datagram mode\n"
           "--stream, -s: datagram mode\n"
           "--client-path <path>, -P <path>: client path of unix domain socket to bind\n"
           "--server-path <path>, -p <path>: server path of unix domain socket to connect\n"
           "--sleep, -S: sleep 1 sec before next round\n",
           prog);
}

int main(int argc, char **argv)
{
    const struct option options[] = {
        { "datagram", no_argument, NULL, 'd'},
        { "stream", no_argument, NULL, 's'},

        { "client-path", required_argument, NULL, 'P' },
        { "server-path", required_argument, NULL, 'p' },
        { "sleep", no_argument, NULL, 'S' },
        { "help", no_argument, NULL, 'h' },
    };
    bool do_sleep = false;
    int sock_type = SOCK_DGRAM;
    struct sockaddr_un client;
    struct sockaddr_un server;
    const char *server_path = SERVER_PATH;
    const char *client_path = CLIENT_PATH;
    int sockfd;
    int optval;
    int c;

    while ((c = getopt_long(argc, argv, "dsP:p:Sh", options, NULL)) != -1) {
        switch (c) {
        case 'd':
            sock_type = SOCK_DGRAM;
            break;
        case 's':
            sock_type = SOCK_STREAM;
            break;

        case 'P':
            client_path = optarg;
            break;
        case 'p':
            server_path = optarg;
            break;
        case 'S':
            do_sleep = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    sockfd = socket(AF_UNIX, sock_type, 0);
    if (sockfd < 0) {
        err(EXIT_FAILURE, "failed to create unix domain socket");
    }

    optval = true;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval))) {
        err(EXIT_FAILURE, "setsockopt(SOL_SOCKET, SO_PASSCRED, true) failed");
    }

    memset(&client, 0, sizeof(client));
    client.sun_family = AF_UNIX;
    snprintf(client.sun_path, sizeof(client.sun_path), client_path, getpid());
    remove(client.sun_path);
    if (bind(sockfd, (struct sockaddr*)&client, sizeof(client))) {
        err(EXIT_FAILURE, "bind to \"%s\" failed\n", client.sun_path);
    }
    printf("bound socket to \"%s\"\n", client.sun_path);

    memset(&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    snprintf(server.sun_path, sizeof(server.sun_path), "%s", server_path);
    if (connect(sockfd, &server, sizeof(server))) {
        err(EXIT_FAILURE, "connect\n");
    }
    printf("connected socket to \"%s\"\n", server.sun_path);

    int count = 0;
    while (true) {
        char buffer[1024];
        int len;
        ssize_t ret;
        struct sockaddr_un tmp;

        memset(buffer, 0, sizeof(buffer));
        len = snprintf(buffer, sizeof(buffer),
                       "Hello from client %s pid %d to server %s count %d",
                       client.sun_path, getpid(), server.sun_path, count++);
        len++;
        printf("sending msg\n");
        ret = send(sockfd, buffer, len, 0);
        if (ret < 0) {
            err(EXIT_FAILURE, "sendto failed\n");
        }
        if (ret < len) {
            err(EXIT_FAILURE, "sendto partial write\n");
        }

        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };

        union {
            char buf[CMSG_SPACE(sizeof(struct ucred))];
            struct cmsghdr align;
        } msg_control;

        struct msghdr msghdr = {
            .msg_name = &tmp,
            .msg_namelen = sizeof(tmp),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = &msg_control,
            .msg_controllen = sizeof(msg_control),
            .msg_flags = 0,
        };

        memset(buffer, 0, sizeof(buffer));
        memset(&msg_control, 0, sizeof(msg_control));
        printf("recving msg\n");
        ret = recvmsg(sockfd, &msghdr, 0);
        if (ret == -1) {
            err(EXIT_FAILURE, "rescvmsg failed\n");
        }
        buffer[sizeof(buffer) - 1] = '\0';
        printf("from %s \"%s\"\n", tmp.sun_path, buffer);

        struct ucred *ucred = NULL;
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg;
             cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(*ucred))) {
                printf("bad cmsg header");
                continue;
            } else if (cmsg->cmsg_level != SOL_SOCKET) {
                printf("unknown cmsg_level %d\n", cmsg->cmsg_level);
                continue;
            } else if (cmsg->cmsg_type != SCM_CREDENTIALS) {
                printf("unknown cmsg_type %d\n", cmsg->cmsg_type);
                continue;
            }

            ucred = (struct ucred *)CMSG_DATA(cmsg);
            break;
        }
        if (ucred) {
            printf("ucred pid %d uid %d gid %d\n",
                   ucred->pid, ucred->uid, ucred->gid);
        } else {
            printf("no ucred\n");
        }

        if (do_sleep)
            sleep(1);
    }
    return 0;
}
