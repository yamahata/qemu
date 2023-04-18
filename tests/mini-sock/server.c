/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * dummy qemu mini sock server to test qemu mini sock client
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
#include <errno.h>

#define SERVER_PATH_DEFAULT     "/tmp/msock/server"
static bool do_sleep;

static void server_dgram(int sockfd, const char *server_path)
{
    int count = 0;

    while (true) {
        char buffer[1024];
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };

        union {
            char buf[CMSG_SPACE(sizeof(struct ucred))];
            struct cmsghdr align;
        } msg_control;

        struct sockaddr_un client;
        struct msghdr msghdr = {
            .msg_name = &client,
            .msg_namelen = sizeof(client),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = &msg_control,
            .msg_controllen = sizeof(msg_control),
            .msg_flags = 0,
        };

        memset(buffer, 0, sizeof(buffer));
        memset(&msg_control, 0, sizeof(msg_control));
        printf("recving msg\n");
        ssize_t ret = recvmsg(sockfd, &msghdr, 0);
        if (ret == -1) {
            err(EXIT_FAILURE, "rescvmsg failed\n");
        }
        printf("from %s \"%s\"\n", client.sun_path, buffer);

        struct ucred *ucred = NULL;
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg;
             cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(*ucred))) {
                printf("bad cmsg header\n");
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
            printf("ucred pid %d uid %d gid %d\n", ucred->pid,
                   ucred->uid, ucred->gid);
        } else {
            printf("no ucred\n");
        }

        if (do_sleep)
            sleep(1);

        memset(buffer, 0, sizeof(buffer));
        int len = snprintf(buffer, sizeof(buffer),
                 "Hello server %s count %d client %s pid %d",
                 server_path, count, client.sun_path,
                 ucred ? ucred->pid : 0);
        len++;  /* Include trailing NUL. */
        printf("sending msg\n");
        ret = sendto(sockfd, buffer, len, 0,
                     (struct sockaddr *)&client, msghdr.msg_namelen);
        if (ret < 0) {
            err(EXIT_FAILURE, "sendto failed errno %d\n", errno);
        }
        if(ret < len) {
            err(EXIT_FAILURE, "sendto too short ret 0x%zx len 0x%x\n", ret, len);
        }
        printf("Response: len %d \"%s\"\n", len, buffer);

        count++;
    }
}

static void server_stream_worker(int sockfd, struct sockaddr_un *client,
                                 const char *server_path,
                                 int accept_count)
{
    int count = 0;

    while (true) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        printf("recving msg\n");
        ssize_t ret = recv(sockfd, buffer, sizeof(buffer), 0);
        if (ret == -1) {
            err(EXIT_FAILURE, "rescvmsg failed\n");
        }
        printf("from %s \"%s\"\n", client->sun_path, buffer);

        if (do_sleep)
            sleep(1);

        memset(buffer, 0, sizeof(buffer));
        int len = snprintf(buffer, sizeof(buffer),
                           "Hello server %s accept %d count %d client %s",
                           server_path, accept_count, count, client->sun_path);
        len++;  /* Include trailing NUL. */
        printf("sending msg\n");
        ret = send(sockfd, buffer, len, 0);
        if (ret < 0) {
            err(EXIT_FAILURE, "sendto failed errno %d\n", errno);
        }
        if(ret < len) {
            err(EXIT_FAILURE, "sendto too short ret 0x%zx len 0x%x\n", ret, len);
        }
        printf("Response: len %d \"%s\"\n", len, buffer);

#define WORKER_LOOP     10
        count++;
        if (count >= WORKER_LOOP) {
            break;
        }
    }
}

static void server_stream(int sockfd, const char *server_path)
{
    int accept_count = 0;

    if (listen(sockfd, 1) < 0) {
        err(EXIT_FAILURE, "listen failed\n");
    }

    while (true) {
        struct sockaddr_un client;
        socklen_t len = sizeof(client);

        int fd = accept(sockfd, (struct sockaddr *)&client, &len);
        if (fd < 0) {
            err(EXIT_FAILURE, "accept failed\n");
        }

        printf("connected from \"%s\"\n", client.sun_path);
        server_stream_worker(fd, &client, server_path, accept_count);

        close(fd);
        accept_count++;
    }
}

static void usage(const char *prog)
{
    printf("Usage: %s [--path=<path>]\n"
           "Options:\n"
           "--help, -h: print this help\n"
           "--datagram, -d: datagram mode\n"
           "--stream, -s: datagram mode\n"
           "--path <path>, -p <path>: server path of unix domain socket to bind. "
           "default "SERVER_PATH_DEFAULT"\n"
           "--sleep, -S: sleep 1 sec before response\n",
           prog);
}

int main(int argc, char **argv)
{
    const char *server_path = SERVER_PATH_DEFAULT;
    int sock_type = SOCK_DGRAM;
    const struct option options[] = {
        { "datagram", no_argument, NULL, 'd'},
        { "stream", no_argument, NULL, 's'},

        { "sleep", no_argument, NULL, 'S' },
        { "path", required_argument, NULL, 'p' },
        { "help", no_argument, NULL, 'h' },
    };
    int c;

    while ((c = getopt_long(argc, argv, "dsp:Sh", options, NULL)) != -1) {
        switch (c) {
        case 'd':
            sock_type = SOCK_DGRAM;
            break;
        case 's':
            sock_type = SOCK_STREAM;
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

    int sockfd = socket(AF_UNIX, sock_type, 0);
    if (sockfd < 0) {
        err(EXIT_FAILURE, "failed to create unix domain socket");
    }

    int optval = true;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval))) {
        err(EXIT_FAILURE, "setsockopt(SOL_SOCKET, SO_PASSCRED, true) failed");
    }

    struct sockaddr_un server;
    memset(&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    snprintf(server.sun_path, sizeof(server.sun_path), "%s", server_path);
    remove(server.sun_path);
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server))) {
        err(EXIT_FAILURE, "bind to \"%s\" failed\n", server.sun_path);
    }
    printf("bound socket to \"%s\"\n", server.sun_path);

    if (sock_type == SOCK_DGRAM) {
        server_dgram(sockfd, server.sun_path);
    } else {
        server_stream(sockfd, server.sun_path);
    }

    return EXIT_SUCCESS;
}
