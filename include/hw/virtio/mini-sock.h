/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mini sock device
 *
 * Copyright (c) 2023 Intel Corporation
 *
 * Author:
 *  Isaku Yamahata <isaku.yamahata@gmail.com>
 */
#ifndef HW_MINI_SOCK_H
#define HW_MINI_SOCK_H

#include <linux/vm_sockets.h>   /* for struct sockaddr_vm */

#include "qom/object.h"
#include "qemu/sockets.h"
#include "hw/pci/msi.h"

/*
 * Duplicate virtio definitions to avoid accidental use of undesired code and
 * definitions of virtio.
 */

/* Magic value ("virm" string) - Read Only */
#define MINI_SOCK_MMIO_MAGIC_VALUE      0x000

/* mini sock device version - Read Only */
#define MINI_SOCK_MMIO_VERSION          0x004

/* mini sock device ID - Read Only */
#define MINI_SOCK_MMIO_DEVICE_ID        0x008

/* min sock vendor ID - Read Only */
#define MINI_SOCK_MMIO_VENDOR_ID        0x00c

/* Selected queue's Descriptor Table address, 64 bits in two halves */
#define MINI_SOCK_MMIO_QUEUE_DESC_LOW   0x080
#define MINI_SOCK_MMIO_QUEUE_DESC_HIGH  0x084

/* No config space.  Use MINI_SOCK_CONFIG_GET */
#define MINI_SOCK_MMIO_SIZE             0x100

#define MINI_SOCK_MAGIC                 0x6D726976      /* 'virm' != VIRT_MAGIC */
#define MINI_SOCK_VERSION               1
#define MINI_SOCK_VENDOR                0x554D4551     /* 'QEMU' */
#define MINI_SOCK_ID                    19 /* virtio vsock transport */

#define MINI_SOCK_CID_ANY               ((uint64_t)-1)
#define MINI_SOCK_CID_HYPERVISOR        ((uint64_t)1)
#define MINI_SOCK_CID_HOST              ((uint64_t)2)

#define MINI_SOCK_PORT_ANY              ((uint32_t)-1)

#define MINI_SOCK_SUCCESS               ((int32_t)0)

#define MINI_SOCK_STATE_SUCCESS         ((int32_t)0)
#define MINI_SOCK_STATE_ERROR           ((int32_t)-1)
#define MINI_SOCK_STATE_ONREQUEST       ((int32_t)-2)
#define MINI_SOCK_STATE_INFLIGHT        ((int32_t)-3)

/* Repourpose buf_alloc and fwd_cnt of virtio vsock header. */
struct mini_sock_state {
    int32_t ret;
    int32_t state;
} QEMU_PACKED;

struct mini_sock_hdr {
    uint64_t src_cid;
    uint64_t dst_cid;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t len;
    uint16_t type;              /* enum mini_sock_type */
    uint16_t op;                /* enum mini_sock_op */
    uint32_t flags;
    union {
        struct {
            union {
                uint32_t buf_alloc;     /* vsock name */
                int32_t ret;            /* repurpose for mini-sock */
            };
            union {
                uint32_t fwd_cnt;       /* vsock name */
                int32_t state;          /* repurpose for mini-sock */
            };
        };
        struct mini_sock_state _state;
    };
} QEMU_PACKED;

enum mini_sock_type {
    MINI_SOCK_TYPE_STREAM = 1,
    MINI_SOCK_TYPE_DGRAM = 3,
};

/*
 * datagram socket:
 *
 *  Guest: send requests with vsock header + payload
 *    |
 *  MMIO
 *    |
 *    V
 *  client qemu <----> unix domian dgram server
 *  client qemu sends/receives playload only to/from server.
 *
 *  Guest: send requests with vsock header + payload
 *    |
 *  MMIO
 *    |
 *    V
 *  server qemu <----> unix domain dgram socket client
 *  server qemu sends/receives playload only to/from client.
 *
 * Client qemu behavior:
 *  When guest of client qemu requests to client qemu:
 *  - REQUEST: Create unix domain socket. connect to sever. No packets to
 *             server.
 *  - RW(SEND): Send RW(SEND) packets to server.
 *  - RW(RECV): Create read buffer internally in client qemu.
 *  - SHUTDOWN: Remove the unix domain socket node, Discard queued received
 *              data.  Keep queued sending data and try to flush it.
 *  - RST(device): Remove all the unix docmain sockets, Close the unix domain
 *                 socket. discard all queued sending data and receiving data.
 *  When client qemu receives packets from server:
 *  - Receive packets and queue them from server.
 *  When client qemu receives from unknown peer:
 *  - silently discard the packet.
 *
 * Server qemu behavior:
 *  When guest of server qemu requests to server qemu:
 *  - REQUEST: Create unix domain socket.  No connect as server qemu
 *             accepts packets from any client or server qemu.
 *  - RW(SEND): Send RW(SEND) packets to client if server qemu knows the
 *              client.
 *  - RW(RECV): Create read buffer internally in server qemu.
 *  - SHUTDOWN(connection): Discard connection tracking information to the
 *                          client.
 *  - SHUTDOWN(socket): Removed the unix domain socket node.  Close the socket
 *                      after flushing queued sending data.
 *  - RST(device): Remove all the unix docmain sockets, close the unix domain
 *                 socket. discard all queued sending data and receiving data.
 * When server qemu receives from client
 *  - Create connection information if not yet and receive packets and queue
 *    them.
 *
 * Stream socket:
 *
 *  Guest
 *    |
 *  MMIO
 *    |
 *    V
 *  client qemu <----> stream socket server
 *
 * client qemu:
 * REQUEST: socket() + bind() + connect()
 * SHUTDOWN: close()
 * RW(SEND): send()
 * RW(RECV): recv()
 *
 *  Guest
 *    |
 *  MMIO
 *    |
 *    V
 *  server qemu <----> stream socket client
 *
 * server qemu:
 * REQUEST: socket() + bind() + listen()
 * RESPOND: accept()
 * SHUTDOWN: close()
 * RW(SEND): send()
 * RW(RECV): recv()
 * CONFIG(SET:BACKLOG) for listen(backlog)
 */
enum mini_sock_op {
    MINI_SOCK_OP_INVALID = 0,

    /* Establish connection */
    MINI_SOCK_OP_REQUEST = 1,

    /* Accept connection request */
    MINI_SOCK_OP_RESPONSE = 2,

    /* Reset the device or connection. */
    MINI_SOCK_OP_RST = 3,

    MINI_SOCK_OP_SHUTDOWN = 4,

    /* To send/receive payload */
    MINI_SOCK_OP_RW = 5,

    /* system configuration: new for mini-sock */
    MINI_SOCK_OP_CONFIG = 64,
};

/* MINI_SOCK_OP_RW flags values */
enum mini_sock_rw {
    MINI_SOCK_RW_SEND = 1,
    MINI_SOCK_RW_RECV = 2,
};

/* MINI_SOCK_OP_CONFIG flags value */
enum mini_sock_config_op {
    MINI_SOCK_CONFIG_GET = 1,
    MINI_SOCK_CONFIG_SET = 2,
};

/* MINI_SOCK_OP_CONFIG keys */
#define MINI_SOCK_CONFIG_CID    0ULL    /* uint64_t read-only */
#define MINI_SOCK_CONFIG_MTU    1ULL    /* uint64_t read-only */
#define MINI_SOCK_CONFIG_MSI    2ULL    /* MSIMessage read-write */

struct mini_sock_config_data {
    uint64_t key;
    uint8_t data[];
} QEMU_PACKED;

/* Internal state */
struct MiniSockState;

#define TYPE_MINI_SOCK  "mini-sock"
OBJECT_DECLARE_SIMPLE_TYPE(MiniSockState, MINI_SOCK);

/* To explicitly show that this data includes payload. */
struct mini_sock_hdr_pyld {
    struct mini_sock_hdr hdr;
    uint8_t payload[];
} QEMU_PACKED;

#define MINI_SOCK_INVALID_GPA   ((uint64_t)-1)

struct MiniSockResponse {
    uint64_t gpa;
    struct mini_sock_hdr hdr;
};

struct MiniSockSend {
    uint64_t gpa;
    /*
     * Header without payload.  Read payload from guest address space when
     * necessary.
     */
    struct mini_sock_hdr hdr;
    uint64_t my_cid;   /* = src_cid */

    /* For stream, partial write can happen. */
    uint32_t offset;

    /* For unix domain dgram socket. */
    bool has_dst;
    struct sockaddr_un dst;
};

struct MiniSockRecvBuf {
    uint64_t gpa;
    uint64_t len;

    /* Header without payload. */
    struct mini_sock_hdr hdr;
};

struct MiniSockRecvData {
    uint8_t *payload;
    ssize_t len;

    /* For stream socket, to track copied size. */
    uint32_t copied;

    uint64_t src_cid;
    uint64_t dst_cid;
    uint32_t src_port;
    uint32_t dst_port;

    /* For unix domaing dgram socket. */
    struct ucred ucred;
    struct sockaddr_un addr;
};

#define MINI_SOCK_FLAGS_SRC_CLOSING     BIT(0)
#define MINI_SOCK_FLAGS_SRC_CLOSED      BIT(1)
#define MINI_SOCK_FLAGS_DST_CLOSED      BIT(2)
#define MINI_SOCK_FLAGS_LISTENING       BIT(3)

struct mini_sock_socket {
    struct mini_sock_endpoint *ep;

    int fd;
    uint32_t flags;

    GQueue send;
    GQueue recv_buf;
    GQueue recv_data;

    /* For client */
    uint32_t my_port;

    /* For server */
    GQueue response;

    /* For connect server socket */
    uint64_t client_cid;
    uint32_t client_port;

    union {
        /* For Unix domain socket to remove path */
        struct sockaddr_un src_addr;

        /* For ipv6 server socket to maintain client_cid */
        struct sockaddr_in6 client_addr;
    };
};

/* For server to track client endpoint. */
struct mini_sock_client_conn {
    uint64_t server_cid;
    uint32_t server_port;
    uint64_t client_cid;
    uint32_t client_port;

    /* track unix domain */
    pid_t client_pid;
    struct sockaddr_un client_addr;
};

enum mini_sock_endpoint_type {
    MINI_SOCK_ENDPOINT_ERROR,
    MINI_SOCK_ENDPOINT_CLIENT,
    MINI_SOCK_ENDPOINT_SERVER,
};

union mini_sock_sockaddr {
    sa_family_t sa_family;
    struct sockaddr addr;
    struct sockaddr_storage ss;
    struct sockaddr_un un;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_vm vm;
};

struct mini_sock_endpoint {
    MiniSockState *msock;

    /*
     * (server_cid, server_pid):
     * for server, src endpoint.
     * for client, dst endpoint.
     */
    enum mini_sock_endpoint_type type;
    enum mini_sock_type sock_type;
    SocketAddress *sock_addr;
    uint64_t server_cid;
    uint32_t server_port;
    union mini_sock_sockaddr srv_addr;

    /* For server */
    struct mini_sock_socket *server;
    GList *conns;
    union {
        /* For unix domain socket. */
        uint32_t last_client_port;

        /* For ipv6 socket. */
        uint64_t last_client_cid;
    };

    /*
     * for server: accepted sockets.
     * for client: created socket connected to server.
     */
    GQueue sockets;
};

#define MINI_SOCK_PROP_ENDPOINTS        "endpoints"
#define MINI_SOCK_PROP_PATH             "path"
#define MINI_SOCK_PROP_MTU              "mtu"
#define MINI_SOCK_PROP_MMIO             "mmio"
#define MINI_SOCK_PROP_GUEST_CID        "guest-cid"
#define MINI_SOCK_PROP_IRQ              "irq"

/*
 * 4KB below IOAPIC_DEFAULT_ADDRESS=0xfec00000 as it's highly likely unused.
 * microvm virtio-mmio uses base address VIRTIO_MMIO_BASE=0xfeb00000 as base
 * address. length = 512 (virtio mmio region size) * 8 (number of devices).
 */
#define MINI_SOCK_MMIO_BASE_DEFAULT     (0xfec00000 - 4 * 1024)

struct MiniSockState {
    DeviceState parent_obj;

    /* config */
    QemuMutex lock;
    uint64_t guest_cid;
    pid_t pid;
    char *endpoints_str;
    size_t n_endpoints;
    struct mini_sock_endpoint *endpoints;
    uint64_t mtu;

    /* For client */
    char *path; /* path for path for client unix domain socket. */

    /* MMIO and interrupts */
    hwaddr mmio_base;
    MemoryRegion iomem;
    qemu_irq *irq;
    MSIMessage msi;
};

#endif /* HW_MINI_SOCK_H*/
