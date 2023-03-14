/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mini sock device
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qom/object_interfaces.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/virtio/mini-sock.h"
#include "sysemu/kvm.h"
#include "trace.h"

/* TODO: define enough value for MTU and queue max */
#define MINI_SOCK_MTU_DEFAULT           (4 * 1024 * 1024)
#define MINI_SOCK_QUEUE_MAX             64
#define UNIX_PATH_CLIENT_DEFAULT        "/run/qemu/client"
#define MINI_SOCK_PORT_MIN              1024
#define MINI_SOCK_PORT_MAX              ((uint32_t)-4096)
#define MINI_SOCK_CID_MIN               1024
#define MINI_SOCK_CID_MAX               ((uint64_t)-4096)

static void mini_sock_hdr_set(struct mini_sock_hdr *hdr,
                              int32_t ret_code, int32_t state_code)
{
    hdr->ret = cpu_to_le32(ret_code);
    hdr->state = cpu_to_le32(state_code);
}

static void mini_sock_handle_config(MiniSockState *msock, uint64_t gpa,
                                    struct mini_sock_hdr *hdr, bool get)
{
    struct mini_sock_config_data config;
    uint64_t len;
    uint64_t offset;
    uint64_t tmp;
    void *data;

    if (address_space_read(&address_space_memory, gpa + sizeof(*hdr),
                           MEMTXATTRS_UNSPECIFIED, &config,
                           sizeof(config)) != MEMTX_OK) {
        mini_sock_hdr_set(hdr, -EFAULT, MINI_SOCK_STATE_ERROR);
        return;
    }

    offset = sizeof(*hdr) + sizeof(config);
    len = 0;
    data = NULL;
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    switch(le64_to_cpu(config.key)) {
    case MINI_SOCK_CONFIG_CID:
        if (get) {
            len = sizeof(msock->mtu);
            tmp = cpu_to_le64(msock->guest_cid);
            data = &tmp;
        } else {
            mini_sock_hdr_set(hdr, -EINVAL, MINI_SOCK_STATE_ERROR);
        }
        break;
    case MINI_SOCK_CONFIG_MTU:
        if (get) {
            len = sizeof(msock->mtu);
            tmp = cpu_to_le64(msock->mtu);
            data = &tmp;
        } else {
            mini_sock_hdr_set(hdr, -EINVAL, MINI_SOCK_STATE_ERROR);
        }
        break;
    case MINI_SOCK_CONFIG_MSI:
        len = sizeof(msock->msi);
        data = &msock->msi;
        break;
    default:
        mini_sock_hdr_set(hdr, -EINVAL, MINI_SOCK_STATE_ERROR);
        break;
    }

    if (!(len > 0 && data))
        return;

    qemu_mutex_lock(&msock->lock);
    if (get) {
        if (address_space_write(&address_space_memory, gpa + offset,
                                MEMTXATTRS_UNSPECIFIED,
                                data, len) != MEMTX_OK) {
            mini_sock_hdr_set(hdr, -EFAULT, MINI_SOCK_STATE_ERROR);
        }
    } else {
        if (address_space_read(&address_space_memory, gpa + offset,
                               MEMTXATTRS_UNSPECIFIED,
                               data, len) != MEMTX_OK) {
            mini_sock_hdr_set(hdr, -EFAULT, MINI_SOCK_STATE_ERROR);
        }
    }
    qemu_mutex_unlock(&msock->lock);
}

static void mini_sock_handle_config_get(MiniSockState *msock, uint64_t gpa,
                                        struct mini_sock_hdr *hdr)
{
    mini_sock_handle_config(msock, gpa, hdr, true);
}

static void mini_sock_handle_config_set(MiniSockState *msock, uint64_t gpa,
                                        struct mini_sock_hdr *hdr)
{
    mini_sock_handle_config(msock, gpa, hdr, false);
}

static void mini_sock_interrupt(MiniSockState *msock)
{
    if (msock->irq) {
        qemu_irq_pulse(*msock->irq);
    }
    if (kvm_enabled() && msock->msi.data) {
        kvm_irqchip_send_msi(kvm_state, msock->msi);
    }
}

static int nr_paths;
static char **paths;

static void mini_sock_atexit(void)
{
    int i;

    for (i = 0; i < nr_paths; i++) {
        if (paths[i]) {
            remove(paths[i]);
        }
    }
}

static void mini_sock_atexit_path_removed(const char *removed)
{
    int i;

    for(i = 0; i < nr_paths; i++) {
        if (paths[i] == removed) {
            paths[i] = NULL;
            break;
        }
    }
}

static void mini_sock_socket_src_closing(struct mini_sock_socket *socket)
{
    socket->flags |= MINI_SOCK_FLAGS_SRC_CLOSING;
    if (socket->ep->sock_addr->type == SOCKET_ADDRESS_TYPE_UNIX) {
        trace_mini_sock_socket_close(socket->src_addr.sun_path);
        remove(socket->src_addr.sun_path);
        mini_sock_atexit_path_removed(socket->src_addr.sun_path);
    }
}

static void mini_sock_socket_close(struct mini_sock_socket *socket)
{
    if (socket->flags & MINI_SOCK_FLAGS_SRC_CLOSED) {
        return;
    }

    assert(socket->fd >= 0);
    if (!(socket->flags & MINI_SOCK_FLAGS_SRC_CLOSING)) {
        mini_sock_socket_src_closing(socket);
    }
    qemu_set_fd_handler(socket->fd, NULL, NULL, NULL);
    close(socket->fd);
    socket->fd = -1;
    socket->flags |= MINI_SOCK_FLAGS_SRC_CLOSED;
}

static int mini_sock_socket_un(struct sockaddr_un *addr)
{
    int sockfd;
    int optval;
    int i;

    trace_mini_sock_socket_un(addr->sun_path);
    sockfd = qemu_socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        return -errno;
    }

    optval = true;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval))) {
        return -errno;
    }

    remove(addr->sun_path);
    if (bind(sockfd, (struct sockaddr *)addr, sizeof(*addr))) {
        return -errno;
    }

    for (i = 0; i < nr_paths; i++) {
        if (paths[i])
            continue;
        paths[i] = addr->sun_path;
        break;
    }
    if (i == nr_paths) {
        nr_paths++;
        paths = g_realloc_n(paths, nr_paths, sizeof(*paths));
        paths[nr_paths - 1] = addr->sun_path;
    }

    return sockfd;
}

static void mini_sock_update_state(uint64_t gpa, struct mini_sock_state *state)
{
    if (gpa == MINI_SOCK_INVALID_GPA) {
        return;
    }

    if (address_space_write(&address_space_memory,
                            gpa + offsetof(struct mini_sock_hdr, _state),
                            MEMTXATTRS_UNSPECIFIED, state, sizeof(*state)) != MEMTX_OK) {
        error_report("mini-sock: failed to update mini sock header state.");
    }
}

static bool mini_sock_discard_send(struct mini_sock_socket *socket, int ret)
{
    struct mini_sock_state state = {
        .ret = cpu_to_le32(ret),
        .state = cpu_to_le32(MINI_SOCK_STATE_ERROR),
    };
    bool interrupt = false;
    struct MiniSockSend *send;

    while ((send = g_queue_pop_head(&socket->send))) {
        mini_sock_update_state(send->gpa,  &state);
        g_free(send);
        interrupt = true;
    }
    return interrupt;
}

static bool mini_sock_discard_recv_buf(struct mini_sock_socket *socket, int ret)
{
    struct mini_sock_state state = {
        .ret = cpu_to_le32(ret),
        .state = cpu_to_le32(MINI_SOCK_STATE_ERROR),
    };
    bool interrupt = false;
    struct MiniSockRecvBuf *buf;

    while ((buf = g_queue_pop_head(&socket->recv_buf))) {
        mini_sock_update_state(buf->gpa,  &state);
        g_free(buf);
        interrupt = true;
    }

    return interrupt;
}

static bool mini_sock_discard_recv(struct mini_sock_socket *socket, int ret)
{
    struct MiniSockRecvData *data;

    while ((data = g_queue_pop_head(&socket->recv_data))) {
        g_free(data->payload);
        g_free(data);
    }

    return mini_sock_discard_recv_buf(socket, ret);
}

static bool mini_sock_discard_response(struct mini_sock_socket *socket, int ret)
{
    struct mini_sock_state state = {
        .ret = cpu_to_le32(ret),
        .state = cpu_to_le32(MINI_SOCK_STATE_ERROR),
    };
    bool interrupt = false;
    struct MiniSockResponse *res;

    while ((res = g_queue_pop_head(&socket->response))) {
        mini_sock_update_state(res->gpa,  &state);
        g_free(res);
        interrupt = true;
    }

    return interrupt;
}

static bool mini_sock_socket_reset(struct mini_sock_socket *socket)
{
    bool interrupt;

    mini_sock_socket_close(socket);
    interrupt = mini_sock_discard_send(socket, -ECONNRESET);
    interrupt |= mini_sock_discard_recv(socket, -ECONNRESET);
    interrupt |= mini_sock_discard_response(socket, -ECONNRESET);

    return interrupt;
}

struct mini_sock_client_addr_cmp {
    uint64_t client_cid;
    uint32_t client_port;
    pid_t client_pid;
    struct sockaddr_un *client_addr;
};

static gint mini_sock_recv_buf_client_cmp(gconstpointer a, gconstpointer b)
{
    const struct MiniSockRecvBuf *buf = a;
    const struct mini_sock_client_addr_cmp *cmp = b;

    return !(buf->hdr.src_cid == cpu_to_le64(cmp->client_cid) &&
             buf->hdr.src_port == cpu_to_le32(cmp->client_port));
}

static gint mini_sock_recv_data_conn_cmp(gconstpointer a, gconstpointer b)
{
    const struct MiniSockRecvData *data = a;
    const struct mini_sock_client_conn *conn = b;

    return !(data->ucred.pid == conn->client_pid &&
             data->addr.sun_family == conn->client_addr.sun_family &&
             !g_strcmp0(data->addr.sun_path, conn->client_addr.sun_path));
}

static bool mini_sock_socket_discard_conn_recv_buf(struct mini_sock_socket *socket,
                                                   struct mini_sock_client_conn *conn,
                                                   int ret)
{
    const struct mini_sock_client_addr_cmp cmp = {
        .client_cid = conn->client_cid,
        .client_port = conn->client_port,
        .client_pid = conn->client_pid,
        .client_addr = &conn->client_addr,
    };
    GList *glist;
    struct mini_sock_state state = {
        .ret = cpu_to_le32(ret),
        .state = cpu_to_le32(MINI_SOCK_STATE_ERROR),
    };
    bool interrupt = false;

    while ((glist = g_queue_find_custom(&socket->recv_buf, &cmp,
                                       mini_sock_recv_buf_client_cmp))) {
        struct MiniSockRecvBuf *buf = glist->data;

        g_queue_delete_link(&socket->recv_buf, glist);
        mini_sock_update_state(buf->gpa,  &state);
        g_free(buf);
        interrupt = true;
    }

    return interrupt;
}

static bool mini_sock_socket_has_conn_recv_data(struct mini_sock_socket *socket,
                                               struct mini_sock_client_conn *conn)
{
    return !!g_queue_find_custom(&socket->recv_data, conn, mini_sock_recv_data_conn_cmp);
}

static void mini_sock_reset_endpoint_sockets(struct mini_sock_endpoint *ep)
{
    struct mini_sock_socket *socket;

    while ((socket = g_queue_pop_head(&ep->sockets))) {
        mini_sock_socket_src_closing(socket);
        mini_sock_socket_reset(socket);
        g_free(socket);
    }
}

static void mini_sock_endpoint_reset(MiniSockState *msock,
                                     struct mini_sock_endpoint *ep)
{
    switch (ep->type) {
    case MINI_SOCK_ENDPOINT_CLIENT:
        mini_sock_reset_endpoint_sockets(ep);
        break;
    case MINI_SOCK_ENDPOINT_SERVER: {
        GList *glist;

        if (!ep->server)
            break;

        mini_sock_socket_src_closing(ep->server);
        while ((glist = g_list_first(ep->conns))) {
            struct mini_sock_client_conn *conn = glist->data;

            g_free(conn);
            ep->conns = g_list_delete_link(ep->conns, glist);
        }
        mini_sock_reset_endpoint_sockets(ep);

        mini_sock_socket_reset(ep->server);
        g_free(ep->server);
        ep->server = NULL;
        break;
    }
    default:
        break;
    }
}

static void mini_sock_handle_reset(MiniSockState *msock,
                                   struct mini_sock_hdr *hdr)
{
    size_t i;

    if (hdr->flags) {
        mini_sock_hdr_set(hdr, -EINVAL, MINI_SOCK_STATE_ERROR);
        return;
    }

    qemu_mutex_lock(&msock->lock);
    for (i = 0; i < msock->n_endpoints; i++) {
        mini_sock_endpoint_reset(msock, &msock->endpoints[i]);
    }
    qemu_mutex_unlock(&msock->lock);

    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
}

struct mini_sock_src_port_cmp {
    uint32_t src_port;
};

static int mini_sock_socket_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_socket *socket = a;
    const struct mini_sock_src_port_cmp *cmp = b;
    uint32_t src_port = cmp->src_port;

    /* GCompareFunc returns 0 if a == b. */
    return !(socket->my_port == src_port);
}

static struct mini_sock_socket *mini_sock_socket_alloc(void)
{
    struct mini_sock_socket *socket = g_malloc(sizeof(*socket));
    socket->fd = -1;
    socket->flags = 0;
    g_queue_init(&socket->send);
    g_queue_init(&socket->recv_buf);
    g_queue_init(&socket->recv_data);
    g_queue_init(&socket->response);
    return socket;
}

static void mini_sock_fd_read(void * opqaue);

static void mini_sock_handle_request_client(struct mini_sock_endpoint *ep,
                                            struct mini_sock_hdr *hdr)
{
    uint64_t dst_cid = le64_to_cpu(hdr->dst_cid);
    uint32_t src_port = le32_to_cpu(hdr->src_port);
    uint32_t dst_port = le32_to_cpu(hdr->dst_port);
    struct mini_sock_src_port_cmp cmp = {
        .src_port = src_port,
    };
    struct mini_sock_socket *socket = NULL;
    int r = 0;

    if (g_queue_find_custom(&ep->sockets, &cmp, mini_sock_socket_cmp)) {
        mini_sock_hdr_set(hdr, -EADDRINUSE, MINI_SOCK_STATE_ERROR);
        return;
    }

    socket = mini_sock_socket_alloc();
    socket->ep = ep;
    socket->my_port = src_port;

    switch (ep->sock_type) {
    case MINI_SOCK_TYPE_DGRAM:
        socket->src_addr.sun_family = AF_UNIX;
        g_snprintf(socket->src_addr.sun_path, sizeof(socket->src_addr.sun_path),
                   "%s/%d:%"PRId32"-%"PRId64":%"PRId32,
                   ep->msock->path ? : UNIX_PATH_CLIENT_DEFAULT,
                   ep->msock->pid, src_port, dst_cid, dst_port);
        r = mini_sock_socket_un(&socket->src_addr);
        if (r < 0) {
            goto error;
        }
        socket->fd = r;
        r = connect(socket->fd, &ep->srv_addr.addr, sizeof(ep->srv_addr.un));
        if (r < 0) {
            r = -errno;
            mini_sock_socket_close(socket);
            goto error;
        }
        break;
    case MINI_SOCK_TYPE_STREAM:
        if (ep->sock_addr->type == SOCKET_ADDRESS_TYPE_UNIX)
            trace_mini_sock_socket_un(ep->sock_addr->u.q_unix.path);
        r = socket_connect(ep->sock_addr, NULL);
        if (r < 0) {
            r = -ECONNREFUSED;
            goto error;
        }
        qemu_socket_set_nonblock(r);
        socket->fd = r;
        break;
    default:
        r = -EPROTONOSUPPORT;
        goto error;
    }
    g_queue_push_head(&ep->sockets, socket);
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    qemu_set_fd_handler(socket->fd, mini_sock_fd_read, NULL, socket);
    return;

error:
    mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    g_free(socket);
}

static void mini_sock_handle_request_server(struct mini_sock_endpoint *ep,
                                            struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket;
    int r;

    if (ep->server) {
        mini_sock_hdr_set(hdr, -EADDRINUSE, MINI_SOCK_STATE_ERROR);
        return;
    }

    socket = mini_sock_socket_alloc();
    socket->ep = ep;
    socket->my_port = ep->server_port;

    switch (ep->sock_type) {
    case MINI_SOCK_TYPE_DGRAM:
        socket->src_addr = ep->srv_addr.un;
        r = mini_sock_socket_un(&socket->src_addr);
        if (r < 0) {
            goto error;
        }
        socket->fd = r;
        break;
    case MINI_SOCK_TYPE_STREAM:
        r = socket_listen(ep->sock_addr, 1, NULL);
        if (r < 0) {
            r = -EADDRINUSE;
            goto error;
        }
        qemu_socket_set_nonblock(r);
        socket->fd = r;
        socket->flags |= MINI_SOCK_FLAGS_LISTENING;
        break;
    default:
        r = -EPROTONOSUPPORT;
        goto error;
    }
    ep->server = socket;
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    qemu_set_fd_handler(socket->fd, mini_sock_fd_read, NULL, socket);
    return;

error:
    mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    g_free(socket);
}

static void mini_sock_handle_request(MiniSockState *msock,
                                     struct mini_sock_hdr *hdr)
{
    uint64_t src_cid = le64_to_cpu(hdr->src_cid);
    uint64_t dst_cid = le64_to_cpu(hdr->dst_cid);
    uint32_t src_port = le32_to_cpu(hdr->src_port);
    uint32_t dst_port = le32_to_cpu(hdr->dst_port);
    int i;

    trace_mini_sock_handle_request(src_cid, dst_cid, src_port, dst_port);
    for (i = 0; i < msock->n_endpoints; i++) {
        struct mini_sock_endpoint *ep = &msock->endpoints[i];

        if (le16_to_cpu(hdr->type) != ep->sock_type) {
            continue;
        }

        switch (ep->type) {
        case MINI_SOCK_ENDPOINT_CLIENT:
            if (ep->server_cid == dst_cid &&
                ep->server_port == dst_port &&
                msock->guest_cid == src_cid &&
                MINI_SOCK_PORT_ANY != src_port) {
                mini_sock_handle_request_client(ep, hdr);
                return;
            }
            continue;
        case MINI_SOCK_ENDPOINT_SERVER:
            if (ep->server_cid == src_cid &&
                ep->server_port == src_port &&
                MINI_SOCK_CID_ANY == dst_cid &&
                MINI_SOCK_PORT_ANY == dst_port) {
                mini_sock_handle_request_server(ep, hdr);
                return;
            }
            continue;
        default:
            continue;
        }
    }

    mini_sock_hdr_set(hdr, -ECONNREFUSED, MINI_SOCK_STATE_ERROR);
}

static gint mini_sock_client_addr_in6_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_socket *socket = a;
    const struct in6_addr *addr = b;

    /* GCompareFunc returns 0 if a == b. */
    return memcmp(&socket->client_addr.sin6_addr, addr, sizeof(*addr));
}

static gint mini_sock_client_cid_cmp(gconstpointer a, gconstpointer b,
                                     gpointer user_data)
{
    const struct mini_sock_socket *socket_a = a;
    const struct mini_sock_socket *socket_b = b;

    /* GCompareDataFunc returns 0 if a == b. */
    if (socket_a->client_cid < socket_b->client_cid)
        return -1;
    if (socket_a->client_cid > socket_b->client_cid)
        return 1;
    return 0;
}

static int mini_sock_socket_find_client_cid_in6(struct mini_sock_endpoint *ep,
                                                struct sockaddr_in6 *addr,
                                                uint64_t *client_cid)
{
    GList *glist;
    uint64_t cid;
    struct mini_sock_socket *socket;

    glist = g_queue_find_custom(&ep->sockets, addr,
                                mini_sock_client_addr_in6_cmp);
    if (glist) {
        socket = glist->data;
        return socket->client_cid;
    }

    g_queue_sort(&ep->sockets, mini_sock_client_cid_cmp, NULL);
    cid = ep->last_client_cid + 1;
    for (glist = g_queue_peek_head_link(&ep->sockets); glist;
         glist = g_list_next(glist)) {
        socket = glist->data;
        if (socket->client_cid < cid) {
            continue;
        }
        if (socket->client_cid == cid) {
            cid++;
            if (cid == MINI_SOCK_CID_MAX) {
                break;
            }
            continue;
        }
        break;
    }

    if (cid >= MINI_SOCK_CID_MAX) {
        cid = MINI_SOCK_CID_MIN;
        for (glist = g_queue_peek_head_link(&ep->sockets); glist;
             glist = g_list_next(glist)) {
            socket = glist->data;
            if (socket->client_cid < cid) {
                continue;
            }
            if (socket->client_cid == cid) {
                cid++;
                if (cid == ep->last_client_cid) {
                    break;
                }
                continue;
            }
            break;
        }
    }

    if (cid == ep->last_client_cid) {
        /* No available cid found. Give up */
        return -EPROTO;
    }
    ep->last_client_cid = cid;
    if (ep->last_client_cid == MINI_SOCK_CID_MAX) {
        ep->last_client_cid = MINI_SOCK_CID_MIN;
    }

    *client_cid = cid;
    return 0;
}

static gint mini_sock_client_port_cmp(gconstpointer a, gconstpointer b,
                                      gpointer user_data)
{
    const struct mini_sock_socket *socket_a = a;
    const struct mini_sock_socket *socket_b = b;
    return socket_a->client_port - socket_b->client_port;
}

static int mini_sock_socket_find_client_port_un(struct mini_sock_endpoint *ep,
                                                uint32_t *client_port)
{
    uint32_t port;
    GList *glist;
    struct mini_sock_socket *tmp;

    g_queue_sort(&ep->sockets, mini_sock_client_port_cmp, NULL);
    port = ep->last_client_port + 1;
    for (glist = g_queue_peek_head_link(&ep->sockets); glist;
         glist = g_list_next(glist)) {
        tmp = glist->data;
        if (tmp->client_port < port) {
            continue;
        }
        if (tmp->client_port == port) {
            port++;
            if (port == MINI_SOCK_PORT_MAX) {
                break;
            }
            continue;
        }
        break;
    }

    if (port >= MINI_SOCK_PORT_MAX) {
        port = MINI_SOCK_PORT_MIN;
        for (glist = g_queue_peek_head_link(&ep->sockets); glist;
             glist = g_list_next(glist)) {
            tmp = glist->data;
            if (tmp->client_port < port) {
                continue;
            }
            if (tmp->client_port == port) {
                port++;
                if (port == ep->last_client_port) {
                    break;
                }
                continue;
            }
            break;
        }
    }

    if (port == ep->last_client_port) {
        /* No available port found. Give up */
        return -EPROTO;
    }
    ep->last_client_port = port;
    if (ep->last_client_port == MINI_SOCK_PORT_MAX) {
        ep->last_client_port = MINI_SOCK_PORT_MIN;
    }

    *client_port = port;
    return 0;
}

static int mini_sock_socket_accept(struct mini_sock_socket *socket,
                                   struct mini_sock_hdr *hdr)
{
    struct mini_sock_endpoint *ep = socket->ep;
    union mini_sock_sockaddr addr;
    socklen_t len = sizeof(addr);
    struct mini_sock_socket *client;
    uint64_t client_cid;
    uint32_t client_port;
    int r;

    r = qemu_accept(socket->fd, &addr.addr, &len);
    trace_mini_sock_socket_accept(socket->fd, r, errno,
                                  (r >= 0 && addr.sa_family == AF_UNIX) ?
                                  addr.un.sun_path : "");
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -EAGAIN;
        }

        return -errno;
    }
    assert(len <= sizeof(client->src_addr));

    client = mini_sock_socket_alloc();
    client->ep = ep;
    client->fd = r;

    /* Generate peer (cid, port) based on the underlying socket peer address */
    switch (addr.sa_family) {
    case AF_INET:
        client_cid = addr.in.sin_addr.s_addr;
        client_port = addr.in.sin_port;
        break;
    case AF_INET6: {
        client->client_addr = addr.in6;
        client_port = addr.in6.sin6_port;
        r = mini_sock_socket_find_client_cid_in6(ep, &addr.in6, &client_cid);
        if (r < 0) {
            goto error;
        }
        break;
    }
    case AF_UNIX: {
        struct ucred ucred;
        socklen_t len = sizeof(ucred);

        r = getsockopt(client->fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
        assert(len <= sizeof(ucred));
        if (r < 0) {
            warn_report("getsockopt(SOL_SOCKET, SO_PEERCRED) failed %s",
                        strerror(errno));
            client_cid = MINI_SOCK_CID_HYPERVISOR;
        } else {
            client_cid = ucred.pid;
        }

        r = mini_sock_socket_find_client_port_un(ep, &client_port);
        if (r < 0) {
            goto error;
        }
        break;
    }
    case AF_VSOCK:
        client_cid = addr.vm.svm_cid;
        client_port = addr.vm.svm_port;
        break;
    default:
        abort();
    }

    client->my_port = socket->my_port;
    client->client_cid = client_cid;
    client->client_port = client_port;

    g_queue_push_head(&ep->sockets, client);

    hdr->dst_cid = cpu_to_le64(client_cid);
    hdr->dst_port = cpu_to_le32(client_port);
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    qemu_set_fd_handler(client->fd, mini_sock_fd_read, NULL, client);
    return 0;

error:
    assert(r < 0);
    close(client->fd);
    mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    g_free(client);
    return r;
}

static void mini_sock_handle_response_stream_server(struct mini_sock_endpoint *ep,
                                                    uint64_t gpa,
                                                    struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket;
    int r;

    qemu_mutex_lock(&ep->msock->lock);
    socket = ep->server;
    if (!socket) {
        r = -EBADF;
        goto out;
    }

    r = -EAGAIN;
    if (!g_queue_get_length(&socket->response)) {
        r = mini_sock_socket_accept(ep->server, hdr);
    }
    if (r == -EAGAIN) {
        struct MiniSockResponse *response = g_malloc(sizeof(*response));
        *response = (struct MiniSockResponse) {
            .gpa = gpa,
            .hdr = *hdr,
        };
        if (!g_queue_get_length(&socket->response)) {
            qemu_set_fd_handler(socket->fd, mini_sock_fd_read, NULL, socket);
        }
        g_queue_push_tail(&socket->response, response);
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
        r = 0;
    }

out:
    qemu_mutex_unlock(&ep->msock->lock);
    if (r < 0) {
        mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    }
}

static void mini_sock_handle_response(MiniSockState *msock,
                                      uint64_t gpa, struct mini_sock_hdr *hdr)
{
    uint64_t src_cid = le64_to_cpu(hdr->src_cid);
    uint64_t dst_cid = le64_to_cpu(hdr->dst_cid);
    uint32_t src_port = le32_to_cpu(hdr->src_port);
    uint32_t dst_port = le32_to_cpu(hdr->dst_port);
    int i;

    trace_mini_sock_handle_response(src_cid, dst_cid, src_port, dst_port);
    for (i = 0; i < msock->n_endpoints; i++) {
        struct mini_sock_endpoint *ep = &msock->endpoints[i];

        /* accept() makes sense only for stream server socket. */
        if (ep->sock_type != MINI_SOCK_TYPE_STREAM ||
            ep->type != MINI_SOCK_ENDPOINT_SERVER) {
            continue;
        }

        if (ep->server_cid == src_cid &&
            ep->server_port == src_port &&
            MINI_SOCK_CID_ANY == dst_cid &&
            MINI_SOCK_PORT_ANY == dst_port) {
            mini_sock_handle_response_stream_server(ep, gpa, hdr);
            return;
        }
    }

    mini_sock_hdr_set(hdr, -ECONNREFUSED, MINI_SOCK_STATE_ERROR);
}

static void mini_sock_socket_shutdown(GList *glist, struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket = glist->data;
    struct mini_sock_endpoint *ep = socket->ep;

    mini_sock_socket_src_closing(socket);
    if (mini_sock_discard_recv(socket, -ECONNREFUSED)) {
        mini_sock_interrupt(ep->msock);
    }
    if (!g_queue_get_length(&socket->send)) {
        g_queue_delete_link(&ep->sockets, glist);
        mini_sock_socket_close(socket);
        g_free(socket);
    }
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
}

static void mini_sock_handle_shutdown_client(struct mini_sock_endpoint *ep,
                                             struct mini_sock_hdr *hdr)
{
    struct mini_sock_src_port_cmp cmp = {
        .src_port = le32_to_cpu(hdr->src_port),
    };
    GList *glist;

    glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_socket_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    mini_sock_socket_shutdown(glist, hdr);
}

static void mini_sock_handle_shutdown_server(struct mini_sock_endpoint *ep,
                                             struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket = ep->server;
    GList *glist;

    if (!socket) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    mini_sock_socket_src_closing(socket);

    switch (ep->sock_type) {
    case MINI_SOCK_TYPE_DGRAM:
        while ((glist = g_list_first(ep->conns))) {
            struct mini_sock_client_conn *conn = glist->data;

            ep->conns = g_list_delete_link(ep->conns, glist);
            g_free(conn);
        }
        if (mini_sock_discard_recv(socket, -ENOTCONN)) {
            mini_sock_interrupt(ep->msock);
        }
        if (!g_queue_get_length(&socket->send)) {
            ep->server = NULL;
            mini_sock_socket_close(socket);
            g_free(socket);
        }
        break;
    case MINI_SOCK_TYPE_STREAM:
        if (mini_sock_discard_response(socket, -ECONNABORTED)) {
            mini_sock_interrupt(ep->msock);
        }
        ep->server = NULL;
        mini_sock_socket_close(socket);
        g_free(socket);
        break;
    default:
        abort();
    }
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
}

struct mini_sock_conn_addr_cmp {
    uint64_t server_cid;
    uint32_t server_port;
    uint64_t client_cid;
    uint32_t client_port;
};

static int mini_sock_conn_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_client_conn *conn = a;
    const struct mini_sock_conn_addr_cmp *cmp = b;

    /* GCompareFunc returns 0 if a == b. */
    return !(conn->server_cid == cmp->server_cid &&
             conn->server_port == cmp->server_port &&
             conn->client_cid == cmp->client_cid &&
             conn->client_port == cmp->client_port);
}

static void mini_sock_handle_shutdown_server_dgram(struct mini_sock_endpoint *ep,
                                                   struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket = ep->server;
    struct mini_sock_conn_addr_cmp cmp;
    GList *glist;
    struct mini_sock_client_conn *conn;

    if (!socket) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    cmp = (struct mini_sock_conn_addr_cmp) {
        .server_cid = le64_to_cpu(hdr->src_cid),
        .client_cid = le64_to_cpu(hdr->dst_cid),
        .server_port = le32_to_cpu(hdr->src_port),
        .client_port = le32_to_cpu(hdr->dst_port),
    };
    glist = g_list_find_custom(ep->conns, &cmp, mini_sock_conn_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    conn = glist->data;
    ep->conns = g_list_delete_link(ep->conns, glist);

    /*
     * This is a safe guard check for race between closing this connection and
     * arriving packets of the same connection.  The client can send requests
     * with the same connection fast to this unix dgram socket.  To avoid losing
     * the requests from the client, keep the connection for server to be able
     * to send back the response.  The use of unix dgram socket is mainly for
     * single round trip RPC style communication.  The successive arriving
     * packets with the same connection aren't supposed use case.  Use stream
     * socket for such.
     * The alternative is, discard pending data and let the client retry by
     * timeout.
     */
    if (mini_sock_socket_has_conn_recv_data(socket, conn)) {
        ep->conns = g_list_prepend(ep->conns, conn);
    } else {
        if (mini_sock_socket_discard_conn_recv_buf(socket, conn, -ENOTCONN)) {
            mini_sock_interrupt(ep->msock);
        }
        trace_mini_sock_client_conn_close(conn->server_cid, conn->client_cid,
                                          conn->server_port, conn->client_port,
                                          conn->client_pid,
                                          conn->client_addr.sun_path);
        g_free(conn);
    }

    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
}

static int mini_sock_client_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_socket *socket = a;
    const struct mini_sock_client_addr_cmp *cmp = b;

    /* GCompareFunc returns 0 if a == b. */
    return !(socket->client_cid == cmp->client_cid &&
             socket->client_port == cmp->client_port);
}

static void mini_sock_handle_shutdown_server_stream(struct mini_sock_endpoint *ep,
                                                    struct mini_sock_hdr *hdr)
{
    GList *glist;
    struct mini_sock_client_addr_cmp cmp = {
        .client_cid = le64_to_cpu(hdr->dst_cid),
        .client_port = le32_to_cpu(hdr->dst_port),
    };

    glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_client_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    mini_sock_socket_shutdown(glist, hdr);
}

static void mini_sock_handle_shutdown_server_conn(struct mini_sock_endpoint *ep,
                                                  struct mini_sock_hdr *hdr)
{
    switch (ep->sock_type) {
    case MINI_SOCK_TYPE_DGRAM:
        mini_sock_handle_shutdown_server_dgram(ep, hdr);
        break;
    case MINI_SOCK_TYPE_STREAM:
        mini_sock_handle_shutdown_server_stream(ep, hdr);
        break;
    default:
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        break;
    }
}

static void mini_sock_handle_shutdown(MiniSockState *msock,
                                      struct mini_sock_hdr *hdr)
{
    uint64_t src_cid = le64_to_cpu(hdr->src_cid);
    uint64_t dst_cid = le64_to_cpu(hdr->dst_cid);
    uint32_t src_port = le32_to_cpu(hdr->src_port);
    uint32_t dst_port = le32_to_cpu(hdr->dst_port);
    int i;

    mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);

    qemu_mutex_lock(&msock->lock);
    for (i = 0; i < msock->n_endpoints; i++) {
        struct mini_sock_endpoint *ep = &msock->endpoints[i];

        switch (ep->type) {
        case MINI_SOCK_ENDPOINT_CLIENT:
            if (ep->server_cid == dst_cid &&
                ep->server_port == dst_port &&
                msock->guest_cid == src_cid &&
                MINI_SOCK_PORT_ANY != src_port) {
                mini_sock_handle_shutdown_client(ep, hdr);
                break;
            }
            continue;
        case MINI_SOCK_ENDPOINT_SERVER:
            if (ep->server_cid == src_cid &&
                ep->server_port == src_port &&
                MINI_SOCK_CID_ANY != dst_cid &&
                MINI_SOCK_PORT_ANY != dst_port) {
                mini_sock_handle_shutdown_server_conn(ep, hdr);
                break;
            } else if (ep->server_cid == src_cid &&
                       ep->server_port == src_port &&
                       MINI_SOCK_CID_ANY == dst_cid &&
                       MINI_SOCK_PORT_ANY == dst_port) {
                mini_sock_handle_shutdown_server(ep, hdr);
                break;
            }
            continue;
        default:
            continue;
        }
    }
    qemu_mutex_unlock(&msock->lock);
}

static void mini_sock_update_hdr(uint64_t gpa, struct mini_sock_hdr *hdr)
{
    if (gpa == MINI_SOCK_INVALID_GPA) {
        return;
    }

    if (address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                            hdr, sizeof(*hdr)) != MEMTX_OK) {
        error_report("mini-sock: failed to update mini sock header.");
    }
}

static int mini_sock_send_payload(MiniSockState *msock, int sockfd, uint64_t gpa,
                                  struct mini_sock_hdr *hdr,
                                  struct sockaddr_un *dst, uint64_t src_cid,
                                  uint32_t offset)
{
    uint32_t len = le32_to_cpu(hdr->len) - offset;
    uint8_t *data = NULL;
    ssize_t r;

    if (len > msock->mtu - sizeof(*hdr)) {
        mini_sock_hdr_set(hdr, -EMSGSIZE, MINI_SOCK_STATE_ERROR);
        goto out;
    }

    data = g_malloc(len);
    if (address_space_read(&address_space_memory, gpa + sizeof(*hdr) + offset,
                           MEMTXATTRS_UNSPECIFIED, data,
                           len) != MEMTX_OK) {
        mini_sock_hdr_set(hdr, -EFAULT, MINI_SOCK_STATE_ERROR);
        goto out;
    }

    while (true) {
        if (dst) {
            r = sendto(sockfd, data, len, MSG_DONTWAIT,
                       (struct sockaddr *)dst, sizeof(*dst));
        } else {
            r = send(sockfd, data, len, MSG_DONTWAIT);
        }
        if (r == -1 && errno == -EINTR) {
            continue;
        }
        break;
    }
    if (r == 0) {
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
        r = -EAGAIN;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
            r = -EAGAIN;
        } else {
            mini_sock_hdr_set(hdr, -errno, MINI_SOCK_STATE_ERROR);
            r = -errno;
        }
    } else {
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    }

out:
    g_free(data);
    return r;
}

static int mini_sock_recvmsg(int sockfd, size_t mtu,
                             struct MiniSockRecvData *data)
{
    ssize_t ret;
    struct iovec iov = {
        .iov_base = g_malloc(mtu),
        .iov_len = mtu,
    };
    union {
        char buf[CMSG_SPACE(sizeof(data->ucred))];
        struct cmsghdr align;
    } msg_control;
    struct msghdr msghdr = {
        .msg_name = &data->addr,
        .msg_namelen = sizeof(data->addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = &msg_control,
        .msg_controllen = sizeof(msg_control),
        .msg_flags = 0,
    };
    struct cmsghdr *cmsg;

    data->payload = NULL;
    data->len = 0;
    data->copied = 0;
    while (true) {
        ret = recvmsg(sockfd, &msghdr, MSG_DONTWAIT);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            g_free(iov.iov_base);
            return -errno;
        }
        break;
    }
    if (!ret) {
        g_free(iov.iov_base);
        return -EAGAIN;
    }

    for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg;
         cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
        if (cmsg->cmsg_len == CMSG_LEN(sizeof(data->ucred)) &&
            cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS) {
            data->payload = iov.iov_base;
            data->len = ret;
            data->ucred = *(struct ucred *)CMSG_DATA(cmsg);
            return 0;
        }
    }
    g_free(iov.iov_base);
    return -EIO;
}

static int mini_sock_recv(int sockfd, size_t mtu, struct MiniSockRecvData *data)
{
    ssize_t ret;
    void *payload = g_malloc(mtu);

    data->payload = NULL;
    data->len = 0;
    data->copied = 0;
    while (true) {
        ret = recv(sockfd, payload, mtu, MSG_DONTWAIT);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            ret = -errno;
            g_free(payload);
            return ret;
        }
        break;
    }
    if (!ret) {
        g_free(payload);
        return -EAGAIN;
    }

    data->payload = payload;
    data->len = ret;
    return 0;
}

/* Copy received data into the guest memory space. */
static void mini_sock_recv_copy(bool is_dgram, struct MiniSockRecvBuf *buf,
                                struct MiniSockRecvData *data)
{
    uint32_t len;

    buf->hdr.src_cid = cpu_to_le64(data->src_cid);
    buf->hdr.dst_cid = cpu_to_le64(data->dst_cid);
    buf->hdr.src_port = cpu_to_le32(data->src_port);
    buf->hdr.dst_port = cpu_to_le32(data->dst_port);

    if (is_dgram) {
        assert(data->copied == 0);
        len = data->len;

        if (buf->len < data->len) {
            mini_sock_hdr_set(&buf->hdr, -EMSGSIZE, MINI_SOCK_STATE_ERROR);
        } else {
            mini_sock_hdr_set(&buf->hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
        }
    } else {
        len = MIN(buf->len, data->len - data->copied);
        mini_sock_hdr_set(&buf->hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    }
    buf->hdr.len = cpu_to_le32(len);

    if (buf->hdr.ret == cpu_to_le32(MINI_SOCK_SUCCESS) &&
        address_space_write(&address_space_memory,
                            buf->gpa + sizeof(buf->hdr) + data->copied,
                            MEMTXATTRS_UNSPECIFIED, data->payload,
                            len) != MEMTX_OK) {
        mini_sock_hdr_set(&buf->hdr, -EFAULT, MINI_SOCK_STATE_ERROR);
        error_report("failed to update mini sock payload.");
    }

    data->copied += len;
}

static bool mini_sock_data_buf_match(const struct MiniSockRecvData *data,
                                     const struct MiniSockRecvBuf *buf)
{
    return
        (buf->hdr.src_cid == cpu_to_le64(data->src_cid) ||
         buf->hdr.src_cid == cpu_to_le64(MINI_SOCK_CID_ANY)) &&
        (buf->hdr.dst_cid == cpu_to_le64(data->dst_cid) ||
         buf->hdr.dst_cid == cpu_to_le64(MINI_SOCK_CID_ANY)) &&
        (buf->hdr.src_port == cpu_to_le32(data->src_port) ||
         buf->hdr.src_port == cpu_to_le32(MINI_SOCK_PORT_ANY)) &&
        (buf->hdr.dst_port == cpu_to_le32(data->dst_port) ||
         buf->hdr.dst_port == cpu_to_le32(MINI_SOCK_PORT_ANY));
}

static int mini_sock_buf_data_cmp(gconstpointer a, gconstpointer b)
{
    const struct MiniSockRecvBuf *buf = a;
    const struct MiniSockRecvData *data = b;

    /* GCompareFunc returns 0 if a == b. */
    return !mini_sock_data_buf_match(data, buf);
}

static int mini_sock_conn_data_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_client_conn *conn = a;
    const struct MiniSockRecvData *data = b;

    /* GCompareFunc returns 0 if a == b. */
    return !(conn->client_pid == data->ucred.pid &&
             conn->client_addr.sun_family == data->addr.sun_family &&
             !g_strcmp0(conn->client_addr.sun_path, data->addr.sun_path));
}

static gint mini_sock_conn_client_port_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_client_conn *conn_a = a;
    const struct mini_sock_client_conn *conn_b = b;
    return conn_a->client_port - conn_b->client_port;
}

/* TODO: GC connections by timeout. */
static struct mini_sock_client_conn *mini_sock_socket_assign_conn(struct mini_sock_socket *socket,
                                                                  struct MiniSockRecvData *data)
{
    struct mini_sock_endpoint *ep = socket->ep;
    GList *glist = g_list_find_custom(ep->conns, data, mini_sock_conn_data_cmp);
    struct mini_sock_client_conn *conn;
    uint32_t port;

    if (glist) {
        /* Move the list to the head for later lookup. */
        conn = glist->data;
        ep->conns = g_list_delete_link(ep->conns, glist);
        ep->conns = g_list_prepend(ep->conns, conn);
        return conn;
    }

    /*
     * Compose client (cid, pid) using the address of the packet.
     * cid: peer pid, port: find unused port number.
     */

    /* Search from the last assigned number to avoid port number reuse. */
    port = ep->last_client_port + 1;

    /*
     * the assumption is the number of client is small.  The order of
     * hundreds at worst.  This is not very efficient, though.
     */
    ep->conns = g_list_sort(ep->conns, mini_sock_conn_client_port_cmp);
    for (glist = g_list_first(ep->conns); glist; glist = g_list_next(glist)) {
        conn = glist->data;
        if (conn->client_port < port) {
            continue;
        }
        if (conn->client_port == port) {
            port++;
            if (port == MINI_SOCK_PORT_MAX) {
                break;
            }
            continue;
        }
        break;
    }
    if (port >= MINI_SOCK_PORT_MAX) {
        port = MINI_SOCK_PORT_MIN;
        for (glist = g_list_first(ep->conns); glist;
             glist = g_list_next(glist)) {
            conn = glist->data;
            if (conn->client_port < port) {
                continue;
            }
            if (conn->client_port == port) {
                port++;
                if (port == ep->last_client_port) {
                    break;
                }
                continue;
            }
            break;
        }
    }
    if (port == ep->last_client_port) {
        /* No available port found.  Give up. */
        return NULL;
    }
    ep->last_client_port = port;
    if (ep->last_client_port == MINI_SOCK_PORT_MAX)
        ep->last_client_port = MINI_SOCK_PORT_MIN;

    conn = g_malloc(sizeof(*conn));
    *conn = (struct mini_sock_client_conn) {
        .server_cid = ep->msock->guest_cid,
        .server_port = socket->my_port,
        .client_cid = data->ucred.pid,
        .client_port = port,
        .client_pid = data->ucred.pid,
        .client_addr = data->addr,
    };

    ep->conns = g_list_prepend(ep->conns, conn);

    trace_mini_sock_client_conn(conn->server_cid, conn->client_cid,
                                conn->server_port, conn->client_port,
                                conn->client_pid,
                                conn->client_addr.sun_path);
    return conn;
}

/*
 * @ep: NULL for client
 *      non-NULL for server: populate connection
 */
static int __mini_sock_fd_read(struct mini_sock_socket *socket,
                               bool *interrupt)
{
    struct mini_sock_endpoint *ep = socket->ep;
    MiniSockState *msock = ep->msock;
    int fd = socket->fd;
    GList *buf_list;
    struct MiniSockRecvBuf *buf;
    struct MiniSockRecvData *data = g_malloc(sizeof(*data));
    bool for_server;
    int r;

    data->payload = NULL;
    for_server = (ep->type == MINI_SOCK_ENDPOINT_SERVER);
    switch (ep->sock_type) {
    case MINI_SOCK_TYPE_DGRAM:
        r = mini_sock_recvmsg(fd, msock->mtu - sizeof(buf->hdr), data);
        break;
    case MINI_SOCK_TYPE_STREAM:
        r = mini_sock_recv(fd, msock->mtu - sizeof(buf->hdr), data);
        break;
    default:
        r = -EINVAL;
        break;
    }
    if (r) {
        goto out;
    }
    if (socket->flags &
        (MINI_SOCK_FLAGS_SRC_CLOSING | MINI_SOCK_FLAGS_DST_CLOSED)) {
        goto out;
    }
    assert(data->len);

    qemu_mutex_lock(&msock->lock);
    if (for_server && ep->sock_type == MINI_SOCK_TYPE_DGRAM) {
        /* dgram server socket. track connection to assign port. */
        struct mini_sock_client_conn *conn = mini_sock_socket_assign_conn(socket, data);
        if (!conn) {
            goto out_unlock;
        }

        data->src_cid = conn->client_cid;
        data->dst_cid = conn->server_cid;
        data->src_port = conn->client_port;
        data->dst_port = conn->server_port;
    } else if (for_server && ep->sock_type == MINI_SOCK_TYPE_STREAM) {
        /* Stream server socket case. */
        data->src_cid = socket->client_cid;
        data->dst_cid = msock->guest_cid;
        data->src_port = socket->client_port;
        data->dst_port = ep->server_port;
    } else {
        /* Client socket case. */
        assert(!for_server);
        data->src_cid = ep->server_cid;
        data->dst_cid = msock->guest_cid;
        data->src_port = ep->server_port;
        data->dst_port = socket->my_port;
    }
    trace_mini_sock_fd_read(data->len,
                            ep->sock_type == MINI_SOCK_TYPE_DGRAM ?
                            data->addr.sun_path : "",
                            data->src_cid, data->dst_cid, data->src_port,
                            data->dst_port);

    /* Find matching recv buf. */
    buf_list = g_queue_find_custom(&socket->recv_buf, data, mini_sock_buf_data_cmp);
    if (!buf_list) {
        g_queue_push_tail(&socket->recv_data, data);
        data = NULL;
    } else {
        buf = buf_list->data;
        g_queue_delete_link(&socket->recv_buf, buf_list);

        *interrupt = true;
        mini_sock_recv_copy(ep->sock_type == MINI_SOCK_TYPE_DGRAM, buf, data);
        if (data->copied < data->len) {
            assert(ep->sock_type == MINI_SOCK_TYPE_STREAM);
            assert(g_queue_get_length(&socket->recv_data) == 0);
            g_queue_push_tail(&socket->recv_data, data);
            data = NULL;
        } else {
            assert(data->copied == data->len);
        }
        mini_sock_update_hdr(buf->gpa, &buf->hdr);
        g_free(buf);
    }

out_unlock:
    qemu_mutex_unlock(&msock->lock);
out:
    if (data) {
        g_free(data->payload);
        g_free(data);
    }
    return r;
}

static int __mini_sock_fd_accept(struct mini_sock_socket *socket,
                                 bool *interrupt)
{
    MiniSockState *msock = socket->ep->msock;
    struct MiniSockResponse *response;
    int r = 0;

    qemu_mutex_lock(&msock->lock);
    response = g_queue_pop_head(&socket->response);
    if (!response) {
        r = -EAGAIN;
        goto out;
    }
    r = mini_sock_socket_accept(socket, &response->hdr);
    if (r) {
        goto out;
    }
    mini_sock_update_hdr(response->gpa, &response->hdr);
    *interrupt = true;
    g_free(response);
    response = NULL;

out:
    if (response) {
        g_queue_push_head(&socket->response, response);
    }
    if (!g_queue_get_length(&socket->response)) {
        qemu_set_fd_handler(socket->fd, NULL, NULL, NULL);
    }
    qemu_mutex_unlock(&msock->lock);
    return r;
}

static void mini_sock_fd_read(void *opaque)
{
    struct mini_sock_socket *socket = opaque;
    MiniSockState *msock = socket->ep->msock;
    bool interrupt = false;

    while (true) {
        if (socket->flags & MINI_SOCK_FLAGS_LISTENING) {
            if (__mini_sock_fd_accept(socket, &interrupt)) {
                break;
            }
        } else {
            if (__mini_sock_fd_read(socket, &interrupt)) {
                break;
            }
        }
    }
    if (interrupt) {
        mini_sock_interrupt(msock);
    }
}

static int __mini_sock_fd_write(struct mini_sock_socket *socket, bool *interrupt)
{
    struct mini_sock_endpoint *ep = socket->ep;
    MiniSockState *msock = ep->msock;
    struct MiniSockSend *send;
    struct mini_sock_hdr *hdr;
    int r = 0;

    qemu_mutex_lock(&msock->lock);
    send = g_queue_pop_head(&socket->send);
    if (!send) {
        /* No more data to send. Stop poll for write. */
        if (socket->flags &
            (MINI_SOCK_FLAGS_SRC_CLOSING | MINI_SOCK_FLAGS_DST_CLOSED)) {
            switch (ep->type) {
            case MINI_SOCK_ENDPOINT_CLIENT:
                g_queue_remove(&ep->sockets, socket);
                break;
            case MINI_SOCK_ENDPOINT_SERVER:
                switch (ep->sock_type) {
                case MINI_SOCK_TYPE_DGRAM:
                    ep->server = NULL;
                    break;
                case MINI_SOCK_TYPE_STREAM:
                    g_queue_remove(&ep->sockets, socket);
                    break;
                default:
                    break;
                }
                break;
            default:
                break;
            }

            qemu_set_fd_handler(socket->fd, NULL, NULL, NULL);
            mini_sock_socket_close(socket);
            g_free(socket);
        } else {
            qemu_set_fd_handler(socket->fd, mini_sock_fd_read, NULL, socket);
        }
        qemu_mutex_unlock(&msock->lock);
        return -EAGAIN;
    }

    hdr = &send->hdr;
    r = mini_sock_send_payload(msock, socket->fd, send->gpa, hdr,
                               send->has_dst ? &send->dst : NULL,
                               send->my_cid, send->offset);
    if (r > 0 && r + send->offset < le32_to_cpu(hdr->len)) {
        /* dgram doesn't allow partial write. */
        assert(socket->ep->sock_type == MINI_SOCK_TYPE_STREAM);
        send->offset += r;
        r = -EAGAIN;
    }
    if (r == -EAGAIN) {
        g_queue_push_head(&socket->send, send);
        qemu_mutex_unlock(&msock->lock);
        return r;
    }
    qemu_mutex_unlock(&msock->lock);

    *interrupt = true;
    if (r) {
        mini_sock_hdr_set(hdr, -errno, MINI_SOCK_STATE_ERROR);
    } else {
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    }
    mini_sock_update_hdr(send->gpa, hdr);
    trace_mini_sock_fd_write(send->gpa, le32_to_cpu(send->hdr.len),
                             le64_to_cpu(send->hdr.src_cid),
                             le64_to_cpu(send->hdr.dst_cid),
                             le32_to_cpu(send->hdr.src_port),
                             le32_to_cpu(send->hdr.dst_port),
                             send->has_dst ? send->dst.sun_path : "no-addr");

    g_free(send);
    return 0;
}

static void mini_sock_fd_write(void *opaque)
{
    struct mini_sock_socket *socket = opaque;
    MiniSockState *msock = socket->ep->msock;
    bool interrupt = false;

    while (true) {
        if (__mini_sock_fd_write(socket, &interrupt)) {
            break;
        }
    }

    if (interrupt) {
        mini_sock_interrupt(msock);
    }
}

static int mini_sock_queue_send(struct mini_sock_socket *socket,
                                struct mini_sock_hdr *hdr,
                                struct MiniSockSend *send)
{
    if (g_queue_get_length(&socket->send) >= MINI_SOCK_QUEUE_MAX) {
        mini_sock_hdr_set(hdr, -ENOBUFS, MINI_SOCK_STATE_ERROR);
        return -ENOBUFS;
    }

    if (g_queue_get_length(&socket->send) == 0) {
        qemu_set_fd_handler(socket->fd, mini_sock_fd_read,
                            mini_sock_fd_write, socket);
    }
    g_queue_push_tail(&socket->send, send);
    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
    send->hdr = *hdr;
    return 0;
}

static void mini_sock_handle_send_client(MiniSockState *msock, uint64_t gpa,
                                         struct mini_sock_hdr *hdr,
                                         struct mini_sock_endpoint *ep)
{
    int r;
    struct mini_sock_src_port_cmp cmp = {
        .src_port = le32_to_cpu(hdr->src_port),
    };
    GList *glist;
    struct mini_sock_socket *socket;

    glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_socket_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }
    socket = glist->data;
    if (socket->fd == -1) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    r = -EAGAIN;
    if (g_queue_get_length(&socket->send) == 0) {
        /* No one is queued before us. Try to directly send payload. */
        r = mini_sock_send_payload(msock, socket->fd, gpa, hdr, NULL, msock->pid, 0);
    }

    if (r == -EAGAIN) {
        struct MiniSockSend *send = g_malloc(sizeof(*send));
        *send = (struct MiniSockSend) {
            .gpa = gpa,
            .has_dst = false,
            .my_cid = msock->pid,
        };
        if (mini_sock_queue_send(socket, hdr, send)) {
            g_free(send);
        }
    } else if (r < 0) {
        mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    } else {
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    }
}

static int mini_sock_addr_cmp(gconstpointer a, gconstpointer b)
{
    const struct mini_sock_client_conn *conn = a;
    const struct mini_sock_hdr *hdr = b;

    /* GCompareFunc returns 0 if a == b. */
    return !(cpu_to_le64(conn->server_cid) == hdr->src_cid &&
             cpu_to_le64(conn->server_port) == hdr->src_port &&
             cpu_to_le64(conn->client_cid) == hdr->dst_cid &&
             cpu_to_le64(conn->client_port) == hdr->dst_port);
}

static void mini_sock_handle_send_server_dgram(struct mini_sock_endpoint *ep,
                                               uint64_t gpa,
                                               struct mini_sock_hdr *hdr)
{
    struct mini_sock_socket *socket = ep->server;
    MiniSockState *msock = ep->msock;
    GList *glist;
    struct mini_sock_client_conn *conn;
    int r;

    if (!socket) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    glist = g_list_find_custom(ep->conns, hdr, mini_sock_addr_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }
    conn = (struct mini_sock_client_conn *)glist->data;

    /* move the entry to the head for later lookup. */
    ep->conns = g_list_delete_link(ep->conns, glist);
    ep->conns = g_list_prepend(ep->conns, conn);

    r = -EAGAIN;
    if (g_queue_get_length(&socket->send) == 0) {
        /* No send is queued before us.  Try directly send payload without queue. */
        r = mini_sock_send_payload(msock, socket->fd, gpa, hdr,
                                   &conn->client_addr, ep->server_cid, 0);
    }

    if (r > 0) {
        /* Partial write shouldn't happen for dgram. */
        assert(r == le32_to_cpu(hdr->len));
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    } else if (r == -EAGAIN) {
        struct MiniSockSend *send = g_malloc(sizeof(*send));
        *send = (struct MiniSockSend) {
            .gpa = gpa,
            .has_dst = true,
            .dst = conn->client_addr,
            .my_cid = ep->server_cid,
        };
        if (mini_sock_queue_send(socket, hdr, send)) {
            g_free(send);
        }
    } else {
        mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    }
}

static void mini_sock_handle_send_server_stream(struct mini_sock_endpoint *ep,
                                                uint64_t gpa,
                                                struct mini_sock_hdr *hdr)
{
    struct mini_sock_client_addr_cmp cmp = {
        .client_cid = le64_to_cpu(hdr->dst_cid),
        .client_port = le32_to_cpu(hdr->dst_port),
    };
    GList *glist;
    struct mini_sock_socket *socket;
    int r;

    glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_client_cmp);
    if (!glist) {
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }
    socket = glist->data;

    r = -EAGAIN;
    if (g_queue_get_length(&socket->send) == 0) {
        /* No send is queued before us.  Try directly send payload without queue. */
        r = mini_sock_send_payload(ep->msock, socket->fd, gpa, hdr, NULL, ep->server_cid, 0);
    }

    assert(r <= le32_to_cpu(hdr->len));
    if (r == le32_to_cpu(hdr->len)) {
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
    } else if (r > 0 || r == -EAGAIN) {
        struct MiniSockSend *send = g_malloc(sizeof(*send));
        *send = (struct MiniSockSend) {
            .gpa = gpa,
            /* As it's connection oriented, no destination address is needed. */
            .has_dst = false,
            .my_cid = ep->server_cid,
            /* partial write can happen. */
            .offset = r > 0 ? r : 0,
        };
        if (mini_sock_queue_send(socket, hdr, send)) {
            g_free(send);
        }
    } else {
        mini_sock_hdr_set(hdr, r, MINI_SOCK_STATE_ERROR);
    }
}

static bool mini_sock_ep_cmp(const struct mini_sock_endpoint *ep,
                             const struct mini_sock_hdr *hdr)
{
    switch (ep->type) {
    case MINI_SOCK_ENDPOINT_CLIENT:
        return (hdr->dst_cid == cpu_to_le32(ep->server_cid) &&
                hdr->dst_port == cpu_to_le32(ep->server_port));
        break;
    case MINI_SOCK_ENDPOINT_SERVER:
        return (hdr->src_cid == cpu_to_le64(ep->server_cid) &&
                hdr->src_port == cpu_to_le32(ep->server_port));
    default:
        return false;
    }
}

static void mini_sock_handle_send(MiniSockState *msock, uint64_t gpa,
                                  struct mini_sock_hdr *hdr)
{
    struct mini_sock_endpoint *ep;
    size_t i;

    mini_sock_hdr_set(hdr, -EINVAL, MINI_SOCK_STATE_ERROR);

    qemu_mutex_lock(&msock->lock);
    for (i = 0; i < msock->n_endpoints; i++) {
        ep = &msock->endpoints[i];

        if (mini_sock_ep_cmp(ep, hdr))
            break;
    }
    if (i == msock->n_endpoints) {
        qemu_mutex_unlock(&msock->lock);
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    switch (ep->type) {
    case MINI_SOCK_ENDPOINT_CLIENT:
        mini_sock_handle_send_client(msock, gpa, hdr, ep);
        break;
    case MINI_SOCK_ENDPOINT_SERVER:
        switch (ep->sock_type) {
        case MINI_SOCK_TYPE_DGRAM:
            mini_sock_handle_send_server_dgram(ep, gpa, hdr);
            break;
        case MINI_SOCK_TYPE_STREAM:
            mini_sock_handle_send_server_stream(ep, gpa, hdr);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    qemu_mutex_unlock(&msock->lock);
}

static bool mini_sock_recv_hdr_ep_cmp(const struct mini_sock_endpoint *ep,
                                      const struct mini_sock_hdr *hdr)
{
    uint64_t src_cid = le64_to_cpu(hdr->src_cid);
    uint64_t dst_cid = le64_to_cpu(hdr->dst_cid);
    uint32_t src_port = le32_to_cpu(hdr->src_port);
    uint32_t dst_port = le32_to_cpu(hdr->dst_port);

    switch (ep->type) {
    case MINI_SOCK_ENDPOINT_CLIENT:
        return src_cid == ep->server_cid && src_port == ep->server_port &&
            dst_cid == ep->msock->guest_cid;
    case MINI_SOCK_ENDPOINT_SERVER:
        return dst_cid == ep->server_cid && dst_port == ep->server_port;
    default:
        /* no match */
        return false;
    }
}

static int mini_sock_data_buf_cmp(gconstpointer a, gconstpointer b)
{
    const struct MiniSockRecvData *data = a;
    const struct MiniSockRecvBuf *buf = b;

    /* GCompareFunc returns 0 if a == b. */
    return !mini_sock_data_buf_match(data, buf);
}

static void mini_sock_handle_recv(MiniSockState *msock, uint64_t gpa,
                                  struct mini_sock_hdr *hdr)
{
    struct MiniSockRecvBuf *buf;
    struct mini_sock_endpoint *ep;
    GList *data_list;
    struct mini_sock_socket *socket;
    struct MiniSockRecvData *data;
    int i;

    mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);

    buf = g_malloc(sizeof(*buf));
    *buf = (struct MiniSockRecvBuf) {
        .gpa = gpa,
        .len = le32_to_cpu(hdr->len),
        .hdr = *hdr,
    };

    qemu_mutex_lock(&msock->lock);
    for (i = 0; msock->n_endpoints; i++) {
        ep = &msock->endpoints[i];
        if (mini_sock_recv_hdr_ep_cmp(ep, hdr)) {
            break;
        }
    }
    if (i == msock->n_endpoints) {
        qemu_mutex_unlock(&msock->lock);
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    socket = NULL;
    switch (ep->type) {
    case MINI_SOCK_ENDPOINT_CLIENT: {
        struct mini_sock_src_port_cmp cmp = {
            .src_port = le32_to_cpu(hdr->dst_port),
        };
        GList *glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_socket_cmp);
        if (glist) {
            socket = glist->data;
            g_queue_delete_link(&ep->sockets, glist);
            g_queue_push_head(&ep->sockets, socket);
        }
        break;
    }
    case MINI_SOCK_ENDPOINT_SERVER:
        switch (ep->sock_type) {
        case MINI_SOCK_TYPE_DGRAM:
            socket = ep->server;
            break;
        case MINI_SOCK_TYPE_STREAM: {
            struct mini_sock_client_addr_cmp cmp = {
                .client_cid = le64_to_cpu(hdr->src_cid),
                .client_port = le32_to_cpu(hdr->src_port),
            };
            GList *glist;

            glist = g_queue_find_custom(&ep->sockets, &cmp, mini_sock_client_cmp);
            if (glist) {
                socket = glist->data;
            }
            break;
        }
        default:
            break;
        }
        break;
    default:
        break;
    }
    if (!socket) {
        qemu_mutex_unlock(&msock->lock);
        mini_sock_hdr_set(hdr, -ENOTCONN, MINI_SOCK_STATE_ERROR);
        return;
    }

    data_list = g_queue_find_custom(&socket->recv_data, buf,
                                    mini_sock_data_buf_cmp);
    if (data_list) {
        data = data_list->data;
        mini_sock_recv_copy(ep->sock_type == MINI_SOCK_TYPE_DGRAM, buf, data);
        *hdr = buf->hdr;
        if (data->copied == data->len) {
            g_queue_delete_link(&socket->recv_data, data_list);
            mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_SUCCESS);
            g_free(data->payload);
            g_free(data);
        } else {
            assert(data->copied < data->len);
            assert(ep->sock_type == MINI_SOCK_TYPE_STREAM);
        }
    } else {
        data = NULL;
        g_queue_push_tail(&socket->recv_buf, buf);
        buf = NULL;
        mini_sock_hdr_set(hdr, MINI_SOCK_SUCCESS, MINI_SOCK_STATE_INFLIGHT);
    }

    qemu_mutex_unlock(&msock->lock);
    g_free(buf);
}

/* the guts of mini sock. */
static void mini_sock_handle_op(MiniSockState *msock, uint64_t gpa)
{
    struct mini_sock_hdr hdr;

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }
    trace_mini_sock_op(gpa, hdr.src_cid, hdr.dst_cid, hdr.src_port,
                       hdr.dst_port, hdr.len, hdr.type, hdr.op, hdr.flags);

    if (hdr.ret != cpu_to_le32(MINI_SOCK_SUCCESS) ||
        hdr.state != cpu_to_le32(MINI_SOCK_STATE_ONREQUEST) ||
        (hdr.type != cpu_to_le32(MINI_SOCK_TYPE_STREAM) &&
         hdr.type != cpu_to_le32(MINI_SOCK_TYPE_DGRAM))) {
        goto error_out;
    }

    switch (le64_to_cpu(hdr.op)) {
    case MINI_SOCK_OP_CONFIG:
        switch (le32_to_cpu(hdr.flags)) {
        case MINI_SOCK_CONFIG_GET:
            mini_sock_handle_config_get(msock, gpa, &hdr);
            break;
        case MINI_SOCK_CONFIG_SET:
            mini_sock_handle_config_set(msock, gpa, &hdr);
            break;
        default:
            goto error_out;
        }
        break;
    case MINI_SOCK_OP_RST:
        mini_sock_handle_reset(msock, &hdr);
        break;
    case MINI_SOCK_OP_REQUEST:
        mini_sock_handle_request(msock, &hdr);
        break;
    case MINI_SOCK_OP_RESPONSE:
        mini_sock_handle_response(msock, gpa, &hdr);
        break;
    case MINI_SOCK_OP_SHUTDOWN:
        mini_sock_handle_shutdown(msock, &hdr);
        break;
    case MINI_SOCK_OP_RW:
        /* mini_sock_handle_{send,recv}() updates header iteslf due to lock. */
        switch (le32_to_cpu(hdr.flags)) {
        case MINI_SOCK_RW_SEND:
            mini_sock_handle_send(msock, gpa, &hdr);
            break;
        case MINI_SOCK_RW_RECV:
            mini_sock_handle_recv(msock, gpa, &hdr);
            break;
        default:
            goto error_out;
        }
        break;
    default:
        goto error_out;
    }

out:
    mini_sock_update_hdr(gpa, &hdr);
    trace_mini_sock_op_end(le32_to_cpu(hdr.ret), le32_to_cpu(hdr.state));
    return;

error_out:
    mini_sock_hdr_set(&hdr, -EINVAL, MINI_SOCK_STATE_ERROR);
    goto out;
}

static void mini_sock_mmio_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned int size)
{
    MiniSockState *msock = (MiniSockState *)opaque;
    uint64_t gpa;

    trace_mini_sock_mmio_write(offset, value, size);

    if (size != 4 && size != 8) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "mini-sock: %s: wrong size access to register! "
                      "offset 0x%" HWADDR_PRIx " size %d value 0x%" PRIx64 "\n",
                      __func__, offset, size, value);
        return;
    }

    switch (offset) {
    case MINI_SOCK_MMIO_QUEUE_DESC_LOW:
        value = le64_to_cpu(value);
        if (size == 8) {
            gpa = value;
        } else if (size == 4) {
            gpa = (uint32_t)value;
        }
        mini_sock_handle_op(msock, gpa);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "mini-sock: %s: bad register offset 0x%" HWADDR_PRIx " size %d value 0x%" PRIx64 "\n",
                      __func__, offset, size, value);
    }
}

static uint64_t mini_sock_mmio_read(void *opaque, hwaddr offset, unsigned int size)
{
    trace_mini_sock_mmio_read(offset, size);

    if (!(size == 4 && offset < MINI_SOCK_MMIO_SIZE)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "mini-sock: %s: wrong size access to register! "
                      "offset 0x%" HWADDR_PRIx" size %d\n",
                      __func__, offset, size);
        return 0;
    }

    switch (offset) {
    case MINI_SOCK_MMIO_MAGIC_VALUE:
        return MINI_SOCK_MAGIC;
    case MINI_SOCK_MMIO_VERSION:
        return MINI_SOCK_VERSION;
    case MINI_SOCK_MMIO_DEVICE_ID:
        return MINI_SOCK_ID;
    case MINI_SOCK_MMIO_VENDOR_ID:
        return MINI_SOCK_VENDOR;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "mini-sock: %s: bad register offset 0x%" HWADDR_PRIx " size %d\n",
                      __func__, offset, size);
        return 0;
    }
    return 0;
}

static const MemoryRegionOps mini_sock_mem_ops = {
    .write = mini_sock_mmio_write,
    .read = mini_sock_mmio_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
        .unaligned = false,
    },
};

static char *mini_sock_get_endpoints(Object *obj, Error **errp)
{
    MiniSockState *msock = MINI_SOCK(obj);

    return g_strdup(msock->endpoints_str);
}

/*
 * Parse end point string. <type>:<cid>:<port>:<endpoint address>
 * ex server:3:42:dunix:/msock/service0;client:4:84:dunix:/msock/service1
 * 'dunix:' = datagram unix domain socket
 * 'unix:' = stream unix domain socket
 * ';' delimitor for each server/client
 * ':' delimitor for type, cid, port and endpoint address
 * Because qemu command line parser eats ','(comma), avoid it.
 */
static void mini_sock_set_endpoints(Object *obj, const char *value, Error **errp)
{
    MiniSockState *msock = MINI_SOCK(obj);
    SocketAddress *addr;
    gchar **strv;
    int i;
    bool dgram;

    qemu_mutex_lock(&msock->lock);
    g_free(msock->endpoints_str);
    msock->endpoints_str = g_strdup(value);

    strv = g_strsplit(value, ";", -1);
    for (msock->n_endpoints = 0; strv[msock->n_endpoints]; msock->n_endpoints++)
        /* nothing. just count */;

    msock->endpoints = g_malloc0_n(msock->n_endpoints, sizeof(*msock->endpoints));
    for (i = 0; i < msock->n_endpoints; i++) {
        struct mini_sock_endpoint *ep = &msock->endpoints[i];
        gchar **endpoint = g_strsplit(strv[i], ":", 4);
        unsigned long r;
        Error *tmp_err;

        ep->msock = msock;
        ep->sock_addr = NULL;
        ep->server = NULL;
        ep->conns = NULL;
        g_queue_init(&ep->sockets);

        if (!g_strcmp0(endpoint[0], "client")) {
            ep->type = MINI_SOCK_ENDPOINT_CLIENT;
        } else if (!g_strcmp0(endpoint[0], "server")) {
            ep->type = MINI_SOCK_ENDPOINT_SERVER;
        } else {
            warn_reportf_err(*errp, "unkonwn endpoint type \"%s\". Ignoring",
                             endpoint[0]);
            ep->type = MINI_SOCK_ENDPOINT_ERROR;
            g_strfreev(endpoint);
            continue;
        }

        r = strtoul(endpoint[1], NULL, 0);
        if (r == ULONG_MAX) {
            warn_reportf_err(*errp, "invalid cid number \"%s\". Ignoring",
                             endpoint[1]);
            ep->type = MINI_SOCK_ENDPOINT_ERROR;
            g_strfreev(endpoint);
            continue;
        } else {
            ep->server_cid = r;
        }

        r = strtoul(endpoint[2], NULL, 0);
        if (r == ULONG_MAX) {
            warn_reportf_err(*errp, "invalid port number \"%s\". Ignoring",
                             endpoint[2]);
            ep->type = MINI_SOCK_ENDPOINT_ERROR;
            g_strfreev(endpoint);
            continue;
        } else {
            ep->server_port = r;
        }

        tmp_err = NULL;

        if (g_str_has_prefix(endpoint[3], "dunix:")) {
            dgram = true;
            /* trick qemu common socket_parse: "dunix:" => "unix:" */
            addr = socket_parse(endpoint[3] + 1, &tmp_err);
        } else {
            dgram = false;
            addr = socket_parse(endpoint[3], &tmp_err);
        }
        if (tmp_err) {
            warn_reportf_err(tmp_err,
                             "invalid endpoint parameter \"%s\". Ignoring\n",
                             endpoint[3]);
            g_free(addr);
            ep->type = MINI_SOCK_ENDPOINT_ERROR;
        }

        if (dgram) {
            assert(addr->type == SOCKET_ADDRESS_TYPE_UNIX);
            ep->sock_type = MINI_SOCK_TYPE_DGRAM;
            ep->last_client_port = MINI_SOCK_PORT_MIN;
            ep->srv_addr.sa_family = AF_UNIX;
            g_strlcpy(ep->srv_addr.un.sun_path, addr->u.q_unix.path,
                      sizeof(ep->srv_addr.un.sun_path));
        } else {
            ep->sock_type = MINI_SOCK_TYPE_STREAM;
            switch (addr->type) {
            case SOCKET_ADDRESS_TYPE_INET:
                ep->srv_addr.sa_family = AF_INET;
                ep->last_client_cid = MINI_SOCK_CID_MIN;
                break;
            case SOCKET_ADDRESS_TYPE_UNIX:
                ep->srv_addr.sa_family = AF_UNIX;
                ep->last_client_port = MINI_SOCK_PORT_MIN;
                break;
            case SOCKET_ADDRESS_TYPE_VSOCK:
                ep->srv_addr.sa_family = AF_VSOCK;
                break;
            case SOCKET_ADDRESS_TYPE_FD:
                ep->type = MINI_SOCK_ENDPOINT_ERROR;
                warn_reportf_err(tmp_err,
                                 "FD type socket isn't supported. \"%s\" Ignoring\n",
                                 endpoint[3]);
                break;
            default:
                abort();
            }
        }
        ep->sock_addr = addr;
        g_strfreev(endpoint);
    }

    /* Check conflicting cid, port */
    for (i = 0; i < msock->n_endpoints; i++) {
        struct mini_sock_endpoint *ep = &msock->endpoints[i];
        int j;

        for (j = i + 1; j < msock->n_endpoints; j++) {
            struct mini_sock_endpoint *tmp = &msock->endpoints[j];

            if (tmp->server_cid == ep->server_cid &&
                tmp->server_port == ep->server_port) {
                error_report("mini-sock: conflicting cid/port %d-th and %d-th has same cid %"PRId64" port %d.",
                             i, j, ep->server_cid, ep->server_port);
                abort();
            }
        }
    }

    qemu_mutex_unlock(&msock->lock);

    g_strfreev(strv);
}

static char *mini_sock_get_path(Object *obj, Error **errp)
{
    MiniSockState *msock = MINI_SOCK(obj);

    return g_strdup(msock->path);
}

static void mini_sock_set_path(Object *obj, const char *value, Error **errp)
{
    MiniSockState *msock = MINI_SOCK(obj);

    g_free(msock->path);
    if (g_str_has_prefix(value, "unix:")) {
        value += strlen("unix:");
    }

    msock->path = g_strdup(value);
}

static void mini_sock_init(Object *obj)
{
    MiniSockState *msock = MINI_SOCK(obj);

    msock->pid = getpid();
    qemu_mutex_init(&msock->lock);
    msock->irq = NULL;

    object_property_add_link(obj, MINI_SOCK_PROP_IRQ, TYPE_IRQ,
                             (Object **)&msock->irq,
                             qdev_prop_allow_set_link_before_realize, 0);
}

static void mini_sock_realize(DeviceState *d, Error **errp)
{
    DeviceState *dev = DEVICE(d);
    MiniSockState *msock = MINI_SOCK(dev);

    error_report("mtu 0x%"PRIx64" mmio_base 0x%"PRIx64" guest_cid %"PRId64,
                 msock->mtu, msock->mmio_base, msock->guest_cid);
    if (msock->mtu <= sizeof(struct mini_sock_hdr)) {
        error_reportf_err(*errp, "mtu property must be greater than %zd",
                          sizeof(struct mini_sock_hdr));
        return;
    }

    if (msock->guest_cid <= 2) {
        error_reportf_err(*errp,
                          "guest-cid property must be greater than 2 guest_cid=%"PRId64,
                          msock->guest_cid);
        return;
    }
    if (msock->guest_cid > UINT32_MAX) {
        error_reportf_err(*errp, "guest-cid property must be a 32-bit number");
        return;
    }

    memory_region_init_io(&msock->iomem, OBJECT(d), &mini_sock_mem_ops, msock,
                          TYPE_MINI_SOCK, MINI_SOCK_MMIO_SIZE);
    memory_region_add_subregion(get_system_memory(), msock->mmio_base,
                                &msock->iomem);
}

static Property mini_sock_properties[] = {
    DEFINE_PROP_UNSIGNED_NODEFAULT(MINI_SOCK_PROP_GUEST_CID, MiniSockState,
                                   guest_cid, qdev_prop_uint64, uint64_t),
    DEFINE_PROP_UINT64(MINI_SOCK_PROP_MMIO, MiniSockState, mmio_base,
                       MINI_SOCK_MMIO_BASE_DEFAULT),
    DEFINE_PROP_UINT64(MINI_SOCK_PROP_MTU, MiniSockState, mtu,
                       MINI_SOCK_MTU_DEFAULT),
    DEFINE_PROP_END_OF_LIST(),
};

static void mini_sock_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = mini_sock_realize;

    device_class_set_props(DEVICE_CLASS(oc), mini_sock_properties);
    object_class_property_set_description(oc, MINI_SOCK_PROP_GUEST_CID,
                                          "guest CID as client");
    object_class_property_set_description(oc, MINI_SOCK_PROP_MMIO,
                                          "MMIO base address");
    object_class_property_set_description(oc, MINI_SOCK_PROP_MTU, "mtu");

    object_class_property_add_str(oc, MINI_SOCK_PROP_ENDPOINTS,
                                  mini_sock_get_endpoints, mini_sock_set_endpoints);
    object_class_property_set_description(oc, MINI_SOCK_PROP_ENDPOINTS,
                                          "<type>:<cid>:<port>:<endpoint>;... "
                                          "type=server|client "
                                          "cid=integer port=integer "
                                          "endpoint=unix:<unix domain socket path>");

    object_class_property_add_str(oc, MINI_SOCK_PROP_PATH,
                                  mini_sock_get_path, mini_sock_set_path);
    object_class_property_set_description(oc, MINI_SOCK_PROP_PATH,
                                          "path for unix domain socket");
    atexit(mini_sock_atexit);
}

static const TypeInfo mini_sock_info = {
    .name          = TYPE_MINI_SOCK,
    .parent        = TYPE_DEVICE,
    .instance_size = sizeof(MiniSockState),
    .instance_init = mini_sock_init,
    .class_init = mini_sock_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { NULL },
    }
};

static void mini_sock_register_types(void)
{
    type_register_static(&mini_sock_info);
}

type_init(mini_sock_register_types);
