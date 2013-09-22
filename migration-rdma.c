/*
 * RDMA protocol and interfaces
 *
 * Copyright IBM, Corp. 2010-2013
 *
 * Authors:
 *  Michael R. Hines <mrhines@us.ibm.com>
 *  Jiuxing Liu <jl@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */
/*
 * RDMA postcopy
 * Copyright (c) 2013
 * National Institute of Advanced Industrial Science and Technology
 *
 * https://sites.google.com/site/grivonhome/quick-kvm-migration
 * Author: Isaku Yamahata  <isaku.yamahata at gmail com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */
#include "qemu-common.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "migration/rdma.h"
#include "migration/postcopy.h"
#include "exec/cpu-common.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qemu/bitmap.h"
#include "sysemu/arch_init.h"
#include "block/coroutine.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <rdma/rdma_cma.h>

#define DEBUG_RDMA
#define DEBUG_RDMA_VERBOSE
#define DEBUG_RDMA_REALLY_VERBOSE

#ifdef DEBUG_RDMA
#define DPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_RDMA_VERBOSE
#define DDPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_RDMA_REALLY_VERBOSE
#define DDDPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDDPRINTF(fmt, ...) \
    do { } while (0)
#endif

/*
 * Print and error on both the Monitor and the Log file.
 */
#define ERROR(errp, fmt, ...) \
    do { \
        fprintf(stderr, "RDMA ERROR: " fmt "\n", ## __VA_ARGS__); \
        if (errp && (*(errp) == NULL)) { \
            error_setg(errp, "RDMA ERROR: " fmt, ## __VA_ARGS__); \
        } \
    } while (0)

#define RDMA_RESOLVE_TIMEOUT_MS 10000

/* Do not merge data if larger than this. */
#define RDMA_MERGE_MAX (2 * 1024 * 1024)
#define RDMA_SIGNALED_SEND_MAX (RDMA_MERGE_MAX / 4096)

#define RDMA_REG_CHUNK_SHIFT 20 /* 1 MB */
#define RDMA_REG_CHUNK_SIZE (1UL << RDMA_REG_CHUNK_SHIFT)
#define RDMA_REG_CHUNK_MASK (~(RDMA_REG_CHUNK_SIZE -1))

/*
 * This is only for non-live state being migrated.
 * Instead of RDMA_WRITE messages, we use RDMA_SEND
 * messages for that state, which requires a different
 * delivery design than main memory.
 */
#define RDMA_SEND_INCREMENT 32768

/*
 * Maximum size infiniband SEND message
 */
#define RDMA_CONTROL_MAX_BUFFER (512 * 1024)
#define RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE 4096

#define RDMA_CONTROL_VERSION_CURRENT 1
/*
 * Capabilities for negotiation.
 */
#define RDMA_CAPABILITY_PIN_ALL 0x01
#define RDMA_CAPABILITY_POSTCOPY 0x80

/*
 * Add the other flags above to this list of known capabilities
 * as they are introduced.
 */
static uint32_t known_capabilities = RDMA_CAPABILITY_PIN_ALL |
                                     RDMA_CAPABILITY_POSTCOPY;

#define CHECK_ERROR_STATE() \
    do { \
        if (rdma->error_state) { \
            if (!rdma->error_reported) { \
                fprintf(stderr, "RDMA is in an error state waiting migration" \
                                " to abort!\n"); \
                rdma->error_reported = 1; \
            } \
            return rdma->error_state; \
        } \
    } while (0);

/*
 * A work request ID is 64-bits and we split up these bits
 * into 3 parts:
 *
 * bits 0-15 : type of control message, 2^16
 * bits 16-29: ram block index, 2^14
 * bits 30-63: ram block chunk number, 2^34
 *
 * The last two bit ranges are only used for RDMA writes,
 * in order to track their completion and potentially
 * also track unregistration status of the message.
 */
#define RDMA_WRID_TYPE_SHIFT  0UL
#define RDMA_WRID_BLOCK_SHIFT 16UL
#define RDMA_WRID_CHUNK_SHIFT 30UL

#define RDMA_WRID_TYPE_MASK \
    ((1UL << RDMA_WRID_BLOCK_SHIFT) - 1UL)

#define RDMA_WRID_BLOCK_MASK \
    (~RDMA_WRID_TYPE_MASK & ((1UL << RDMA_WRID_CHUNK_SHIFT) - 1UL))

#define RDMA_WRID_CHUNK_MASK (~RDMA_WRID_BLOCK_MASK & ~RDMA_WRID_TYPE_MASK)

/*
 * RDMA migration protocol:
 * 1. RDMA Writes (data messages, i.e. RAM)
 * 2. IB Send/Recv (control channel messages)
 */
enum {
    RDMA_WRID_NONE = 0,
    RDMA_WRID_RDMA_WRITE = 1,
    RDMA_WRID_SEND_CONTROL = 2000,
    RDMA_WRID_RECV_CONTROL = 4000,
};

const char *wrid_desc[] = {
    [RDMA_WRID_NONE] = "NONE",
    [RDMA_WRID_RDMA_WRITE] = "WRITE RDMA",
    [RDMA_WRID_SEND_CONTROL] = "CONTROL SEND",
    [RDMA_WRID_RECV_CONTROL] = "CONTROL RECV",
};

/*
 * Work request IDs for IB SEND messages only (not RDMA writes).
 * This is used by the migration protocol to transmit
 * control messages (such as device state and registration commands)
 *
 * We could use more WRs, but we have enough for now.
 */
enum {
    RDMA_WRID_READY = 0,
    RDMA_WRID_DATA,
    RDMA_WRID_CONTROL,
    RDMA_WRID_MAX,
};

/*
 * SEND/RECV IB Control Messages.
 */
enum {
    RDMA_CONTROL_NONE = 0,
    RDMA_CONTROL_ERROR,
    RDMA_CONTROL_READY,               /* ready to receive */
    RDMA_CONTROL_QEMU_FILE,           /* QEMUFile-transmitted bytes */
    RDMA_CONTROL_RAM_BLOCKS_REQUEST,  /* RAMBlock synchronization */
    RDMA_CONTROL_RAM_BLOCKS_RESULT,   /* RAMBlock synchronization */
    RDMA_CONTROL_COMPRESS,            /* page contains repeat values */
    RDMA_CONTROL_REGISTER_REQUEST,    /* dynamic page registration */
    RDMA_CONTROL_REGISTER_RESULT,     /* key to use after registration */
    RDMA_CONTROL_REGISTER_FINISHED,   /* current iteration finished */
    RDMA_CONTROL_UNREGISTER_REQUEST,  /* dynamic UN-registration */
    RDMA_CONTROL_UNREGISTER_FINISHED, /* unpinning finished */

    /* postcopy related messages */

    /* outgoing -> incoming */
    /* RDMA_CONTROL_REGISTER_REQUEST, */
    /* RDMA_CONTROL_UNREGISTER_REQUEST,*/  /* RDMA write is completed.
                                            * unregister target page.
                                            * no replay from incoming side
                                            */
    RDMA_CONTROL_EOS,                 /* outgoing -> incoming
                                       * end of session
                                       * No data
                                       */
    RDMA_CONTROL_RDMA_RESULT,         /* outgoing->incoming
                                       * RDMA write completion
                                       * RDMARequest with rkey unused
                                       */
    RDMA_CONTROL_RDMA_RESULT_BG,      /* outgoing->incoming
                                       * RDMA write completion
                                       * RDMARequest with rkey unused
                                       * incoming side will reply with READY
                                       */
    RDMA_CONTROL_RDMA_RESULT_PRE,     /* outgoing->incoming
                                       * prefault RDMA write completion
                                       * RDMARequest with rkey unused
                                       * window control is done by
                                       * RDMA_CONTROL_RDMA_RESULT
                                       */
    RDMA_CONTROL_REGISTER_AREQUEST,   /* outgoing -> incoming
                                       * asynchronous dynamic page registration
                                       */
    RDMA_CONTROL_BITMAP_RESULT,       /* outgoing -> incoming
                                       * clean bitmap for pre+post copy
                                       * RDMARequest
                                       */
    /* incoming -> outgoing */
    RDMA_CONTROL_RDMA_REQUEST,        /* request to start RDMA write
                                       * RDMARequest
                                       */
    RDMA_CONTROL_REGISTER_ARESULT,    /* incoming -> outgoing
                                       * asynchronous result to
                                       * RDMA_CONTROL_REGISTER_ASYNC
                                       */
    RDMA_CONTROL_EOC,                 /* end of connection
                                       * outgoing part will close the channel
                                       * No data
                                       */
    RDMA_CONTROL_BITMAP_REQUEST,      /* incoming -> outgoing
                                       * clean bitmap for pre+post copy
                                       * RDMARequest
                                       */
    RDMA_CONTROL_COMPRESS_RESULT,     /* incoming -> outgoing
                                       * response to RDMA_CONTROL_COMPRESS
                                       * used for window control
                                       */
};

const char *control_desc[] = {
    [RDMA_CONTROL_NONE] = "NONE",
    [RDMA_CONTROL_ERROR] = "ERROR",
    [RDMA_CONTROL_READY] = "READY",
    [RDMA_CONTROL_QEMU_FILE] = "QEMU FILE",
    [RDMA_CONTROL_RAM_BLOCKS_REQUEST] = "RAM BLOCKS REQUEST",
    [RDMA_CONTROL_RAM_BLOCKS_RESULT] = "RAM BLOCKS RESULT",
    [RDMA_CONTROL_COMPRESS] = "COMPRESS",
    [RDMA_CONTROL_REGISTER_REQUEST] = "REGISTER REQUEST",
    [RDMA_CONTROL_REGISTER_RESULT] = "REGISTER RESULT",
    [RDMA_CONTROL_REGISTER_FINISHED] = "REGISTER FINISHED",
    [RDMA_CONTROL_UNREGISTER_REQUEST] = "UNREGISTER REQUEST",
    [RDMA_CONTROL_UNREGISTER_FINISHED] = "UNREGISTER FINISHED",

    /* postcopy */
    [RDMA_CONTROL_EOS] = "EOS",
    [RDMA_CONTROL_RDMA_RESULT] = "RDMA RESULT",
    [RDMA_CONTROL_RDMA_RESULT_BG] = "RDMA RESULT BG",
    [RDMA_CONTROL_RDMA_RESULT_PRE] = "RDMA RESULT PRE",
    [RDMA_CONTROL_REGISTER_AREQUEST] = "ASYNC REGISTER REQUEST",
    [RDMA_CONTROL_BITMAP_RESULT] = "BITMAP RESULT",
    [RDMA_CONTROL_RDMA_REQUEST] = "RDMA REQUEST",
    [RDMA_CONTROL_REGISTER_ARESULT] = "ASYNC REGISTER RESULT",
    [RDMA_CONTROL_EOC] = "RDMA EOC",
    [RDMA_CONTROL_BITMAP_REQUEST] = "BITMAP REQUEST",
    [RDMA_CONTROL_COMPRESS_RESULT] = "COMPRESS RESULT",
};

/*
 * Memory and MR structures used to represent an IB Send/Recv work request.
 * This is *not* used for RDMA writes, only IB Send/Recv.
 */
typedef struct {
    uint8_t  control[RDMA_CONTROL_MAX_BUFFER]; /* actual buffer to register */
    struct   ibv_mr *control_mr;               /* registration metadata */
    size_t   control_len;                      /* length of the message */
    uint8_t *control_curr;                     /* start of unconsumed bytes */
} RDMAWorkRequestData;

/*
 * Negotiate RDMA capabilities during connection-setup time.
 */
typedef struct {
    uint32_t version;
    uint32_t flags;
} RDMACapabilities;

static void caps_to_network(RDMACapabilities *cap)
{
    cap->version = htonl(cap->version);
    cap->flags = htonl(cap->flags);
}

static void network_to_caps(RDMACapabilities *cap)
{
    cap->version = ntohl(cap->version);
    cap->flags = ntohl(cap->flags);
}

/*
 * Representation of a RAMBlock from an RDMA perspective.
 * This is not transmitted, only local.
 * This and subsequent structures cannot be linked lists
 * because we're using a single IB message to transmit
 * the information. It's small anyway, so a list is overkill.
 */
typedef struct RDMALocalBlock {
    uint8_t  *local_host_addr; /* local virtual address */
    uint64_t remote_host_addr; /* remote virtual address */
    uint64_t offset;
    uint64_t length;
    struct   ibv_mr **pmr;     /* MRs for chunk-level registration */
    struct   ibv_mr *mr;       /* MR for non-chunk-level registration */
    uint32_t *remote_keys;     /* rkeys for chunk-level registration */
    uint32_t remote_rkey;      /* rkeys for non-chunk-level registration */
    int      index;            /* which block are we */
    bool     is_ram_block;
    int      nb_chunks;
    unsigned long *transit_bitmap;
    unsigned long *unregister_bitmap;

    /* for postcopy outgoing */
    RAMBlock *ram_block;
    unsigned int *nb_rdma;
    uint64_t *clean_bitmap;

    /* for postcopy incoming */
    UMemBlock *umem_block;

    /* for postcopy outgoing/incoming */
    int *bit;
    struct ibv_mr *bitmap_key;  /* for clean bitmap */
} RDMALocalBlock;

/*
 * Also represents a RAMblock, but only on the dest.
 * This gets transmitted by the dest during connection-time
 * to the source VM and then is used to populate the
 * corresponding RDMALocalBlock with
 * the information needed to perform the actual RDMA.
 */
typedef struct QEMU_PACKED RDMARemoteBlock {
    uint64_t remote_host_addr;
    uint64_t offset;
    uint64_t length;
    uint32_t remote_rkey;
    uint32_t padding;
} RDMARemoteBlock;

static uint64_t htonll(uint64_t v)
{
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.lv[0] = htonl(v >> 32);
    u.lv[1] = htonl(v & 0xFFFFFFFFULL);
    return u.llv;
}

static uint64_t ntohll(uint64_t v) {
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.llv = v;
    return ((uint64_t)ntohl(u.lv[0]) << 32) | (uint64_t) ntohl(u.lv[1]);
}

static void remote_block_to_network(RDMARemoteBlock *rb)
{
    rb->remote_host_addr = htonll(rb->remote_host_addr);
    rb->offset = htonll(rb->offset);
    rb->length = htonll(rb->length);
    rb->remote_rkey = htonl(rb->remote_rkey);
}

static void network_to_remote_block(RDMARemoteBlock *rb)
{
    rb->remote_host_addr = ntohll(rb->remote_host_addr);
    rb->offset = ntohll(rb->offset);
    rb->length = ntohll(rb->length);
    rb->remote_rkey = ntohl(rb->remote_rkey);
}

/*
 * Virtual address of the above structures used for transmitting
 * the RAMBlock descriptions at connection-time.
 * This structure is *not* transmitted.
 */
typedef struct RDMALocalBlocks {
    int nb_blocks;
    bool     init;             /* main memory init complete */
    RDMALocalBlock *block;
} RDMALocalBlocks;

/*
 * Main data structure for RDMA state.
 * While there is only one copy of this structure being allocated right now,
 * this is the place where one would start if you wanted to consider
 * having more than one RDMA connection open at the same time.
 */
typedef struct RDMAContext {
    char *host;
    int port;

    RDMAWorkRequestData wr_data[RDMA_WRID_MAX];
    uint8_t file_data[RDMA_CONTROL_MAX_BUFFER];
    size_t data_len;
    uint8_t *data_curr;

    /*
     * This is used by *_exchange_send() to figure out whether or not
     * the initial "READY" message has already been received or not.
     * This is because other functions may potentially poll() and detect
     * the READY message before send() does, in which case we need to
     * know if it completed.
     */
    int control_ready_expected;

    /* number of outstanding writes */
    int nb_sent;

    /* store info about current buffer so that we can
       merge it with future sends */
    uint64_t current_addr;
    uint64_t current_length;
    /* index of ram block the current buffer belongs to */
    int current_index;
    /* index of the chunk in the current ram block */
    int current_chunk;

    bool keep_listen_id;
    bool pin_all;
    bool postcopy;

    /*
     * infiniband-specific variables for opening the device
     * and maintaining connection state and so forth.
     *
     * cm_id also has ibv_context, rdma_event_channel, and ibv_qp in
     * cm_id->verbs, cm_id->channel, and cm_id->qp.
     */
    struct rdma_cm_id *cm_id;               /* connection manager ID */
    struct rdma_cm_id *listen_id;
    bool connected;

    struct ibv_context          *verbs;
    struct rdma_event_channel   *channel;
    struct ibv_qp *qp;                      /* queue pair */
    struct ibv_comp_channel *comp_channel;  /* completion channel */
    struct ibv_pd *pd;                      /* protection domain */
    struct ibv_cq *cq;                      /* completion queue */

    /*
     * If a previous write failed (perhaps because of a failed
     * memory registration, then do not attempt any future work
     * and remember the error state.
     */
    int error_state;
    int error_reported;

    /*
     * Description of ram blocks used throughout the code.
     */
    RDMALocalBlocks local_ram_blocks;
    RDMARemoteBlock *block;

    /*
     * Migration on *destination* started.
     * Then use coroutine yield function.
     * Source runs in a thread, so we don't care.
     */
    int migration_started_on_destination;

    int total_registrations;
    int total_writes;

    int unregister_current, unregister_next;
    uint64_t unregistrations[RDMA_SIGNALED_SEND_MAX];

    GHashTable *blockmap;
} RDMAContext;

/*
 * Interface to the rest of the migration call stack.
 */
typedef struct QEMUFileRDMA {
    RDMAContext *rdma;
    size_t len;
    void *file;
} QEMUFileRDMA;

/*
 * Main structure for IB Send/Recv control messages.
 * This gets prepended at the beginning of every Send/Recv.
 */
typedef struct QEMU_PACKED {
    uint32_t len;     /* Total length of data portion */
    uint32_t type;    /* which control command to perform */
    uint32_t repeat;  /* number of commands in data portion of same type */
    uint32_t padding;
} RDMAControlHeader;

static void control_to_network(RDMAControlHeader *control)
{
    control->type = htonl(control->type);
    control->len = htonl(control->len);
    control->repeat = htonl(control->repeat);
}

static void network_to_control(RDMAControlHeader *control)
{
    control->type = ntohl(control->type);
    control->len = ntohl(control->len);
    control->repeat = ntohl(control->repeat);
}

/*
 * Register a single Chunk.
 * Information sent by the source VM to inform the dest
 * to register an single chunk of memory before we can perform
 * the actual RDMA operation.
 */
typedef struct QEMU_PACKED {
    union QEMU_PACKED {
        uint64_t current_addr;  /* offset into the ramblock of the chunk */
        uint64_t chunk;         /* chunk to lookup if unregistering */
    } key;
    uint32_t current_index; /* which ramblock the chunk belongs to */
    uint32_t padding;
    uint64_t chunks;            /* how many sequential chunks to register */
} RDMARegister;

static void register_to_network(RDMARegister *reg)
{
    reg->key.current_addr = htonll(reg->key.current_addr);
    reg->current_index = htonl(reg->current_index);
    reg->chunks = htonll(reg->chunks);
}

static void network_to_register(RDMARegister *reg)
{
    reg->key.current_addr = ntohll(reg->key.current_addr);
    reg->current_index = ntohl(reg->current_index);
    reg->chunks = ntohll(reg->chunks);
}

typedef struct QEMU_PACKED {
    uint32_t value;     /* if zero, we will madvise() */
    uint32_t block_idx; /* which ram block index */
    uint64_t offset;    /* where in the remote ramblock this chunk */
    uint64_t length;    /* length of the chunk */
} RDMACompress;

static void compress_to_network(RDMACompress *comp)
{
    comp->value = htonl(comp->value);
    comp->block_idx = htonl(comp->block_idx);
    comp->offset = htonll(comp->offset);
    comp->length = htonll(comp->length);
}

static void network_to_compress(RDMACompress *comp)
{
    comp->value = ntohl(comp->value);
    comp->block_idx = ntohl(comp->block_idx);
    comp->offset = ntohll(comp->offset);
    comp->length = ntohll(comp->length);
}

/*
 * The result of the dest's memory registration produces an "rkey"
 * which the source VM must reference in order to perform
 * the RDMA operation.
 */
typedef struct QEMU_PACKED {
    uint32_t rkey;
    uint32_t padding;
    uint64_t host_addr;
} RDMARegisterResult;

static void result_to_network(RDMARegisterResult *result)
{
    result->rkey = htonl(result->rkey);
    result->host_addr = htonll(result->host_addr);
};

static void network_to_result(RDMARegisterResult *result)
{
    result->rkey = ntohl(result->rkey);
    result->host_addr = ntohll(result->host_addr);
};

const char *print_wrid(int wrid);
static int qemu_rdma_exchange_send(RDMAContext *rdma, RDMAControlHeader *head,
                                   uint8_t *data, RDMAControlHeader *resp,
                                   int *resp_idx,
                                   int (*callback)(RDMAContext *rdma));
static void postcopy_rdma_incoming_prepare_ram_block(
    RDMAContext *rdma, UMemBlockHead *umem_blcoks);

static inline uint64_t ram_chunk_index(const uint8_t *start,
                                       const uint8_t *host)
{
    return ((uintptr_t) host - (uintptr_t) start) >> RDMA_REG_CHUNK_SHIFT;
}

static inline uint8_t *ram_chunk_start(const RDMALocalBlock *rdma_ram_block,
                                       uint64_t i)
{
    return (uint8_t *) (((uintptr_t) rdma_ram_block->local_host_addr)
                                    + (i << RDMA_REG_CHUNK_SHIFT));
}

static inline uint8_t *ram_chunk_end(const RDMALocalBlock *rdma_ram_block,
                                     uint64_t i)
{
    uint8_t *result = ram_chunk_start(rdma_ram_block, i) +
                                         (1UL << RDMA_REG_CHUNK_SHIFT);

    if (result > (rdma_ram_block->local_host_addr + rdma_ram_block->length)) {
        result = rdma_ram_block->local_host_addr + rdma_ram_block->length;
    }

    return result;
}

static int __qemu_rdma_add_block(RDMAContext *rdma, void *host_addr,
                         ram_addr_t block_offset, uint64_t length)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
        (void *) block_offset);
    RDMALocalBlock *old = local->block;
    int chunk;

    assert(block == NULL);

    local->block = g_malloc0(sizeof(RDMALocalBlock) * (local->nb_blocks + 1));

    if (local->nb_blocks) {
        int x;

        for (x = 0; x < local->nb_blocks; x++) {
            g_hash_table_remove(rdma->blockmap, (void *)old[x].offset);
            g_hash_table_insert(rdma->blockmap, (void *)old[x].offset,
                                                &local->block[x]);
        }
        memcpy(local->block, old, sizeof(RDMALocalBlock) * local->nb_blocks);
        g_free(old);
    }

    block = &local->block[local->nb_blocks];

    block->local_host_addr = host_addr;
    block->offset = block_offset;
    block->length = length;
    block->index = local->nb_blocks;
    block->nb_chunks = ram_chunk_index(host_addr, host_addr + length) + 1UL;
    block->transit_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->transit_bitmap, 0, block->nb_chunks);
    block->unregister_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->unregister_bitmap, 0, block->nb_chunks);
    block->remote_keys = g_malloc0(block->nb_chunks * sizeof(uint32_t));
    block->bit = g_malloc(block->nb_chunks * sizeof(block->bit[0]));
    for (chunk = 0; chunk < block->nb_chunks; chunk++) {
        block->bit[chunk] =
            (chunk << RDMA_REG_CHUNK_SHIFT) >> TARGET_PAGE_BITS;
    }

    block->is_ram_block = local->init ? false : true;

    g_hash_table_insert(rdma->blockmap, (void *) block_offset, block);

    DDPRINTF("Added Block: %d, addr: 0x%" PRIx64 ", offset: 0x%" PRIx64
           " length: 0x%" PRIx64 " end: 0x%" PRIx64
             " bits %" PRIu64" chunks %d\n",
            local->nb_blocks, (uint64_t) block->local_host_addr, block->offset,
            block->length, (uint64_t) (block->local_host_addr + block->length),
                BITS_TO_LONGS(block->nb_chunks) *
                    sizeof(unsigned long) * 8, block->nb_chunks);

    local->nb_blocks++;

    return 0;
}

/*
 * Memory regions need to be registered with the device and queue pairs setup
 * in advanced before the migration starts. This tells us where the RAM blocks
 * are so that we can register them individually.
 */
static void qemu_rdma_init_one_block(void *host_addr,
    ram_addr_t block_offset, ram_addr_t length, void *opaque)
{
    __qemu_rdma_add_block(opaque, host_addr, block_offset, length);
}

/*
 * Identify the RAMBlocks and their quantity. They will be references to
 * identify chunk boundaries inside each RAMBlock and also be referenced
 * during dynamic page registration.
 */
static int qemu_rdma_init_ram_blocks(RDMAContext *rdma)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;

    assert(rdma->blockmap == NULL);
    rdma->blockmap = g_hash_table_new(g_direct_hash, g_direct_equal);
    memset(local, 0, sizeof *local);
    qemu_ram_foreach_block(qemu_rdma_init_one_block, rdma);
    DPRINTF("Allocated %d local ram block structures\n", local->nb_blocks);
    rdma->block = (RDMARemoteBlock *) g_malloc0(sizeof(RDMARemoteBlock) *
                        rdma->local_ram_blocks.nb_blocks);
    local->init = true;
    return 0;
}

static int __qemu_rdma_delete_block(RDMAContext *rdma, ram_addr_t block_offset)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
        (void *) block_offset);
    RDMALocalBlock *old = local->block;
    int x;

    assert(block);

    if (block->pmr) {
        int j;

        for (j = 0; j < block->nb_chunks; j++) {
            if (!block->pmr[j]) {
                continue;
            }
            ibv_dereg_mr(block->pmr[j]);
            rdma->total_registrations--;
        }
        g_free(block->pmr);
        block->pmr = NULL;
    }

    if (block->mr) {
        ibv_dereg_mr(block->mr);
        rdma->total_registrations--;
        block->mr = NULL;
    }

    g_free(block->transit_bitmap);
    block->transit_bitmap = NULL;

    g_free(block->unregister_bitmap);
    block->unregister_bitmap = NULL;

    g_free(block->remote_keys);
    block->remote_keys = NULL;

    g_free(block->nb_rdma);
    block->nb_rdma = NULL;

    g_free(block->bit);
    block->bit = NULL;

    for (x = 0; x < local->nb_blocks; x++) {
        g_hash_table_remove(rdma->blockmap, (void *)old[x].offset);
    }

    if (local->nb_blocks > 1) {

        local->block = g_malloc0(sizeof(RDMALocalBlock) *
                                    (local->nb_blocks - 1));

        if (block->index) {
            memcpy(local->block, old, sizeof(RDMALocalBlock) * block->index);
        }

        if (block->index < (local->nb_blocks - 1)) {
            memcpy(local->block + block->index, old + (block->index + 1),
                sizeof(RDMALocalBlock) *
                    (local->nb_blocks - (block->index + 1)));
        }
    } else {
        assert(block == local->block);
        local->block = NULL;
    }

    DDPRINTF("Deleted Block: %d, addr: %" PRIu64 ", offset: %" PRIu64
           " length: %" PRIu64 " end: %" PRIu64 " bits %" PRIu64 " chunks %d\n",
            local->nb_blocks, (uint64_t) block->local_host_addr, block->offset,
            block->length, (uint64_t) (block->local_host_addr + block->length),
                BITS_TO_LONGS(block->nb_chunks) *
                    sizeof(unsigned long) * 8, block->nb_chunks);

    g_free(old);

    local->nb_blocks--;

    if (local->nb_blocks) {
        for (x = 0; x < local->nb_blocks; x++) {
            g_hash_table_insert(rdma->blockmap, (void *)local->block[x].offset,
                                                &local->block[x]);
        }
    }

    return 0;
}

/*
 * Put in the log file which RDMA device was opened and the details
 * associated with that device.
 */
static void qemu_rdma_dump_id(const char *who, struct ibv_context *verbs)
{
    struct ibv_port_attr port;

    if (ibv_query_port(verbs, 1, &port)) {
        fprintf(stderr, "FAILED TO QUERY PORT INFORMATION!\n");
        return;
    }

    printf("%s RDMA Device opened: kernel name %s "
           "uverbs device name %s, "
           "infiniband_verbs class device path %s, "
           "infiniband class device path %s, "
           "transport: (%d) %s\n",
                who,
                verbs->device->name,
                verbs->device->dev_name,
                verbs->device->dev_path,
                verbs->device->ibdev_path,
                port.link_layer,
                (port.link_layer == IBV_LINK_LAYER_INFINIBAND) ? "Infiniband" :
                 ((port.link_layer == IBV_LINK_LAYER_ETHERNET) 
                    ? "Ethernet" : "Unknown"));
}

/*
 * Put in the log file the RDMA gid addressing information,
 * useful for folks who have trouble understanding the
 * RDMA device hierarchy in the kernel.
 */
static void qemu_rdma_dump_gid(const char *who, struct rdma_cm_id *id)
{
    char sgid[33];
    char dgid[33];
    inet_ntop(AF_INET6, &id->route.addr.addr.ibaddr.sgid, sgid, sizeof sgid);
    inet_ntop(AF_INET6, &id->route.addr.addr.ibaddr.dgid, dgid, sizeof dgid);
    DPRINTF("%s Source GID: %s, Dest GID: %s\n", who, sgid, dgid);
}

/*
 * As of now, IPv6 over RoCE / iWARP is not supported by linux.
 * We will try the next addrinfo struct, and fail if there are
 * no other valid addresses to bind against.
 *
 * If user is listening on '[::]', then we will not have a opened a device
 * yet and have no way of verifying if the device is RoCE or not.
 *
 * In this case, the source VM will throw an error for ALL types of
 * connections (both IPv4 and IPv6) if the destination machine does not have
 * a regular infiniband network available for use.
 *
 * The only way to gaurantee that an error is thrown for broken kernels is
 * for the management software to choose a *specific* interface at bind time
 * and validate what time of hardware it is.
 *
 * Unfortunately, this puts the user in a fix:
 * 
 *  If the source VM connects with an IPv4 address without knowing that the
 *  destination has bound to '[::]' the migration will unconditionally fail
 *  unless the management software is explicitly listening on the the IPv4
 *  address while using a RoCE-based device.
 *
 *  If the source VM connects with an IPv6 address, then we're OK because we can
 *  throw an error on the source (and similarly on the destination).
 * 
 *  But in mixed environments, this will be broken for a while until it is fixed
 *  inside linux.
 *
 * We do provide a *tiny* bit of help in this function: We can list all of the
 * devices in the system and check to see if all the devices are RoCE or
 * Infiniband. 
 *
 * If we detect that we have a *pure* RoCE environment, then we can safely
 * thrown an error even if the management sofware has specified '[::]' as the
 * bind address.
 *
 * However, if there is are multiple hetergeneous devices, then we cannot make
 * this assumption and the user just has to be sure they know what they are
 * doing.
 *
 * Patches are being reviewed on linux-rdma.
 */
static int qemu_rdma_broken_ipv6_kernel(Error **errp, struct ibv_context *verbs)
{
    struct ibv_port_attr port_attr;

    /* This bug only exists in linux, to our knowledge. */
#ifdef CONFIG_LINUX

    /* 
     * Verbs are only NULL if management has bound to '[::]'.
     * 
     * Let's iterate through all the devices and see if there any pure IB
     * devices (non-ethernet).
     * 
     * If not, then we can safely proceed with the migration.
     * Otherwise, there are no gaurantees until the bug is fixed in linux.
     */
    if (!verbs) {
	    int num_devices, x;
        struct ibv_device ** dev_list = ibv_get_device_list(&num_devices);
        bool roce_found = false;
        bool ib_found = false;

        for (x = 0; x < num_devices; x++) {
            verbs = ibv_open_device(dev_list[x]);

            if (ibv_query_port(verbs, 1, &port_attr)) {
                ibv_close_device(verbs);
                ERROR(errp, "Could not query initial IB port");
                return -EINVAL;
            }

            if (port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
                ib_found = true;
            } else if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
                roce_found = true;
            }

            ibv_close_device(verbs);

        }

        if (roce_found) {
            if (ib_found) {
                fprintf(stderr, "WARN: migrations may fail:"
                                " IPv6 over RoCE / iWARP in linux"
                                " is broken. But since you appear to have a"
                                " mixed RoCE / IB environment, be sure to only"
                                " migrate over the IB fabric until the kernel "
                                " fixes the bug.\n");
            } else {
                ERROR(errp, "You only have RoCE / iWARP devices in your systems"
                            " and your management software has specified '[::]'"
                            ", but IPv6 over RoCE / iWARP is not supported in Linux.");
                return -ENONET;
            }
        }

        return 0;
    }

    /*
     * If we have a verbs context, that means that some other than '[::]' was
     * used by the management software for binding. In which case we can actually 
     * warn the user about a potential broken kernel;
     */

    /* IB ports start with 1, not 0 */
    if (ibv_query_port(verbs, 1, &port_attr)) {
        ERROR(errp, "Could not query initial IB port");
        return -EINVAL;
    }

    if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
        ERROR(errp, "Linux kernel's RoCE / iWARP does not support IPv6 "
                    "(but patches on linux-rdma in progress)");
        return -ENONET;
    }

#endif

    return 0;
}

/*
 * Figure out which RDMA device corresponds to the requested IP hostname
 * Also create the initial connection manager identifiers for opening
 * the connection.
 */
static int qemu_rdma_resolve_host(RDMAContext *rdma, Error **errp)
{
    int ret;
    struct rdma_addrinfo *res;
    char port_str[16];
    struct rdma_cm_event *cm_event;
    char ip[40] = "unknown";
    struct rdma_addrinfo *e;

    if (rdma->host == NULL || !strcmp(rdma->host, "")) {
        ERROR(errp, "RDMA hostname has not been set");
        return -EINVAL;
    }

    /* create CM channel */
    rdma->channel = rdma_create_event_channel();
    if (!rdma->channel) {
        ERROR(errp, "could not create CM channel");
        return -EINVAL;
    }
    DPRINTF("qemu_rdma_resolve_host create_event_channel\n");

    /* create CM id */
    ret = rdma_create_id(rdma->channel, &rdma->cm_id, NULL, RDMA_PS_TCP);
    if (ret) {
        ERROR(errp, "could not create channel id");
        goto err_resolve_create_id;
    }
    DPRINTF("qemu_rdma_resolve_host rdma_create_id\n");

    snprintf(port_str, 16, "%d", rdma->port);
    port_str[15] = '\0';

    ret = rdma_getaddrinfo(rdma->host, port_str, NULL, &res);
    if (ret < 0) {
        ERROR(errp, "could not rdma_getaddrinfo address %s", rdma->host);
        goto err_resolve_get_addr;
    }
    DPRINTF("qemu_rdma_resolve_host getaddrinfo\n");

    for (e = res; e != NULL; e = e->ai_next) {
        inet_ntop(e->ai_family,
            &((struct sockaddr_in *) e->ai_dst_addr)->sin_addr, ip, sizeof ip);
        DPRINTF("Trying %s => %s\n", rdma->host, ip);

        ret = rdma_resolve_addr(rdma->cm_id, NULL, e->ai_dst_addr,
                RDMA_RESOLVE_TIMEOUT_MS);
        if (!ret) {
            ret = qemu_rdma_broken_ipv6_kernel(errp, rdma->cm_id->verbs);
            if (ret) {
                continue;
            }
            rdma_freeaddrinfo(res);
            goto route;
        }
    }
    DPRINTF("qemu_rdma_resolve_host rdma_resolve_addr\n");
    rdma_freeaddrinfo(res);

    ERROR(errp, "could not resolve address %s", rdma->host);
    goto err_resolve_get_addr;

route:
    qemu_rdma_dump_gid("source_resolve_addr", rdma->cm_id);

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        ERROR(errp, "could not perform event_addr_resolved");
        goto err_resolve_get_addr;
    }
    DPRINTF("qemu_rdma_resolve_host rdma_get_cm_event\n");

    if (cm_event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
        ERROR(errp, "result not equal to event_addr_resolved %s",
                rdma_event_str(cm_event->event));
        perror("rdma_resolve_addr");
        ret = -EINVAL;
        goto err_resolve_get_addr;
    }
    rdma_ack_cm_event(cm_event);

    /* resolve route */
    ret = rdma_resolve_route(rdma->cm_id, RDMA_RESOLVE_TIMEOUT_MS);
    if (ret) {
        ERROR(errp, "could not resolve rdma route");
        goto err_resolve_get_addr;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        ERROR(errp, "could not perform event_route_resolved");
        goto err_resolve_get_addr;
    }
    if (cm_event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
        ERROR(errp, "result not equal to event_route_resolved: %s",
                        rdma_event_str(cm_event->event));
        rdma_ack_cm_event(cm_event);
        ret = -EINVAL;
        goto err_resolve_get_addr;
    }
    rdma_ack_cm_event(cm_event);
    rdma->verbs = rdma->cm_id->verbs;
    qemu_rdma_dump_id("source_resolve_host", rdma->cm_id->verbs);
    qemu_rdma_dump_gid("source_resolve_host", rdma->cm_id);
    return 0;

err_resolve_get_addr:
    rdma_destroy_id(rdma->cm_id);
    rdma->cm_id = NULL;
err_resolve_create_id:
    rdma_destroy_event_channel(rdma->channel);
    rdma->channel = NULL;
    return ret;
}

/*
 * Create protection domain and completion queues
 */
static int qemu_rdma_alloc_pd_cq(RDMAContext *rdma)
{
    /* allocate pd */
    rdma->pd = ibv_alloc_pd(rdma->verbs);
    if (!rdma->pd) {
        fprintf(stderr, "failed to allocate protection domain\n");
        return -1;
    }

    /* create completion channel */
    rdma->comp_channel = ibv_create_comp_channel(rdma->verbs);
    if (!rdma->comp_channel) {
        fprintf(stderr, "failed to allocate completion channel\n");
        goto err_alloc_pd_cq;
    }

    /*
     * Completion queue can be filled by both read and write work requests,
     * so must reflect the sum of both possible queue sizes.
     */
    rdma->cq = ibv_create_cq(rdma->verbs, (RDMA_SIGNALED_SEND_MAX * 3),
            NULL, rdma->comp_channel, 0);
    if (!rdma->cq) {
        fprintf(stderr, "failed to allocate completion queue\n");
        goto err_alloc_pd_cq;
    }

    return 0;

err_alloc_pd_cq:
    if (rdma->pd) {
        ibv_dealloc_pd(rdma->pd);
    }
    if (rdma->comp_channel) {
        ibv_destroy_comp_channel(rdma->comp_channel);
    }
    rdma->pd = NULL;
    rdma->comp_channel = NULL;
    return -1;

}

/*
 * Create queue pairs.
 */
static int qemu_rdma_alloc_qp(RDMAContext *rdma)
{
    struct ibv_qp_init_attr attr = { 0 };
    int ret;

    attr.cap.max_send_wr = RDMA_SIGNALED_SEND_MAX;
    attr.cap.max_recv_wr = 3;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.send_cq = rdma->cq;
    attr.recv_cq = rdma->cq;
    attr.qp_type = IBV_QPT_RC;

    ret = rdma_create_qp(rdma->cm_id, rdma->pd, &attr);
    if (ret) {
        return -1;
    }

    rdma->qp = rdma->cm_id->qp;
    return 0;
}

static int qemu_rdma_reg_whole_ram_blocks(RDMAContext *rdma)
{
    int i;
    RDMALocalBlocks *local = &rdma->local_ram_blocks;

    for (i = 0; i < local->nb_blocks; i++) {
        local->block[i].mr =
            ibv_reg_mr(rdma->pd,
                    local->block[i].local_host_addr,
                    local->block[i].length,
                    IBV_ACCESS_LOCAL_WRITE |
                    IBV_ACCESS_REMOTE_WRITE
                    );
        if (!local->block[i].mr) {
            perror("Failed to register local dest ram block!\n");
            break;
        }
        rdma->total_registrations++;
    }

    if (i >= local->nb_blocks) {
        return 0;
    }

    for (i--; i >= 0; i--) {
        ibv_dereg_mr(local->block[i].mr);
        rdma->total_registrations--;
    }

    return -1;

}

/*
 * Find the ram block that corresponds to the page requested to be
 * transmitted by QEMU.
 *
 * Once the block is found, also identify which 'chunk' within that
 * block that the page belongs to.
 *
 * This search cannot fail or the migration will fail.
 */
static int qemu_rdma_search_ram_block(RDMAContext *rdma,
                                      uint64_t block_offset,
                                      uint64_t offset,
                                      uint64_t length,
                                      uint64_t *block_index,
                                      uint64_t *chunk_index)
{
    uint64_t current_addr = block_offset + offset;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
                                                (void *) block_offset);
    assert(block);
    assert(current_addr >= block->offset);
    assert((current_addr + length) <= (block->offset + block->length));

    *block_index = block->index;
    *chunk_index = ram_chunk_index(block->local_host_addr,
                block->local_host_addr + (current_addr - block->offset));

    return 0;
}

/*
 * Register a chunk with IB. If the chunk was already registered
 * previously, then skip.
 *
 * Also return the keys associated with the registration needed
 * to perform the actual RDMA operation.
 */
static int qemu_rdma_register_and_get_keys(RDMAContext *rdma,
        RDMALocalBlock *block, uint8_t *host_addr,
        uint32_t *lkey, uint32_t *rkey, int chunk)
{
    if (block->mr) {
        if (lkey) {
            *lkey = block->mr->lkey;
        }
        if (rkey) {
            *rkey = block->mr->rkey;
        }
        return 0;
    }

    /* allocate memory to store chunk MRs */
    if (!block->pmr) {
        block->pmr = g_malloc0(block->nb_chunks * sizeof(struct ibv_mr *));
        if (!block->pmr) {
            return -1;
        }
    }

    /*
     * If 'rkey', then we're the destination, so grant access to the source.
     *
     * If 'lkey', then we're the source VM, so grant access only to ourselves.
     */
    if (!block->pmr[chunk]) {
        uint8_t *chunk_start = ram_chunk_start(block, chunk);
        uint8_t *chunk_end = ram_chunk_end(block, chunk);
        uint64_t len = chunk_end - chunk_start;

        DDPRINTF("Registering %" PRIu64 " bytes @ %p\n",
                 len, chunk_start);

        block->pmr[chunk] = ibv_reg_mr(rdma->pd,
                chunk_start, len,
                (rkey ? (IBV_ACCESS_LOCAL_WRITE |
                        IBV_ACCESS_REMOTE_WRITE) : 0));

        if (!block->pmr[chunk]) {
            perror("Failed to register chunk!");
            fprintf(stderr, "Chunk details: block: %d chunk index %d"
                            " start %" PRIu64 " end %" PRIu64 " host %" PRIu64
                            " local %" PRIu64 " registrations: %d\n",
                            block->index, chunk, (uint64_t) chunk_start,
                            (uint64_t) chunk_end, (uint64_t) host_addr,
                            (uint64_t) block->local_host_addr,
                            rdma->total_registrations);
            return -1;
        }
        DDDPRINTF("%s:%d reg_mr "
                  "block_index %d chunk %d key %"PRIx32" total %d\n",
                 __func__, __LINE__, block->index, chunk,
                 block->pmr[chunk]->lkey, rdma->total_registrations);
        rdma->total_registrations++;
    }

    if (lkey) {
        *lkey = block->pmr[chunk]->lkey;
    }
    if (rkey) {
        *rkey = block->pmr[chunk]->rkey;
    }
    return 0;
}

/*
 * Register (at connection time) the memory used for control
 * channel messages.
 */
static int qemu_rdma_reg_control(RDMAContext *rdma, int idx)
{
    rdma->wr_data[idx].control_mr = ibv_reg_mr(rdma->pd,
            rdma->wr_data[idx].control, RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (rdma->wr_data[idx].control_mr) {
        rdma->total_registrations++;
        return 0;
    }
    fprintf(stderr, "qemu_rdma_reg_control failed!\n");
    return -1;
}

const char *print_wrid(int wrid)
{
    if (wrid >= RDMA_WRID_RECV_CONTROL) {
        return wrid_desc[RDMA_WRID_RECV_CONTROL];
    }
    return wrid_desc[wrid];
}

/*
 * RDMA requires memory registration (mlock/pinning), but this is not good for
 * overcommitment.
 *
 * In preparation for the future where LRU information or workload-specific
 * writable writable working set memory access behavior is available to QEMU
 * it would be nice to have in place the ability to UN-register/UN-pin
 * particular memory regions from the RDMA hardware when it is determine that
 * those regions of memory will likely not be accessed again in the near future.
 *
 * While we do not yet have such information right now, the following
 * compile-time option allows us to perform a non-optimized version of this
 * behavior.
 *
 * By uncommenting this option, you will cause *all* RDMA transfers to be
 * unregistered immediately after the transfer completes on both sides of the
 * connection. This has no effect in 'rdma-pin-all' mode, only regular mode.
 *
 * This will have a terrible impact on migration performance, so until future
 * workload information or LRU information is available, do not attempt to use
 * this feature except for basic testing.
 */
//#define RDMA_UNREGISTRATION_EXAMPLE

/*
 * Perform a non-optimized memory unregistration after every transfer
 * for demonsration purposes, only if pin-all is not requested.
 *
 * Potential optimizations:
 * 1. Start a new thread to run this function continuously
        - for bit clearing
        - and for receipt of unregister messages
 * 2. Use an LRU.
 * 3. Use workload hints.
 */
static int qemu_rdma_unregister_waiting(RDMAContext *rdma)
{
    while (rdma->unregistrations[rdma->unregister_current]) {
        int ret;
        uint64_t wr_id = rdma->unregistrations[rdma->unregister_current];
        uint64_t chunk =
            (wr_id & RDMA_WRID_CHUNK_MASK) >> RDMA_WRID_CHUNK_SHIFT;
        uint64_t index =
            (wr_id & RDMA_WRID_BLOCK_MASK) >> RDMA_WRID_BLOCK_SHIFT;
        RDMALocalBlock *block =
            &(rdma->local_ram_blocks.block[index]);
        RDMARegister reg = { .current_index = index };
        RDMAControlHeader resp = { .type = RDMA_CONTROL_UNREGISTER_FINISHED,
                                 };
        RDMAControlHeader head = { .len = sizeof(RDMARegister),
                                   .type = RDMA_CONTROL_UNREGISTER_REQUEST,
                                   .repeat = 1,
                                 };

        DDPRINTF("Processing unregister for chunk: %" PRIu64
                 " at position %d\n", chunk, rdma->unregister_current);

        rdma->unregistrations[rdma->unregister_current] = 0;
        rdma->unregister_current++;

        if (rdma->unregister_current == RDMA_SIGNALED_SEND_MAX) {
            rdma->unregister_current = 0;
        }


        /*
         * Unregistration is speculative (because migration is single-threaded
         * and we cannot break the protocol's inifinband message ordering).
         * Thus, if the memory is currently being used for transmission,
         * then abort the attempt to unregister and try again
         * later the next time a completion is received for this memory.
         */
        clear_bit(chunk, block->unregister_bitmap);

        if (test_bit(chunk, block->transit_bitmap)) {
            DDPRINTF("Cannot unregister inflight chunk: %" PRIu64 "\n", chunk);
            continue;
        }

        DDPRINTF("Sending unregister for chunk: %" PRIu64 "\n", chunk);

        ret = ibv_dereg_mr(block->pmr[chunk]);
        block->pmr[chunk] = NULL;
        block->remote_keys[chunk] = 0;

        if (ret != 0) {
            perror("unregistration chunk failed");
            return -ret;
        }
        rdma->total_registrations--;

        reg.key.chunk = chunk;
        register_to_network(&reg);
        ret = qemu_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                &resp, NULL, NULL);
        if (ret < 0) {
            return ret;
        }

        DDPRINTF("Unregister for chunk: %" PRIu64 " complete.\n", chunk);
    }

    return 0;
}

static uint64_t qemu_rdma_make_wrid(uint64_t wr_id, uint64_t index,
                                         uint64_t chunk)
{
    uint64_t result = wr_id & RDMA_WRID_TYPE_MASK;

    result |= (index << RDMA_WRID_BLOCK_SHIFT);
    result |= (chunk << RDMA_WRID_CHUNK_SHIFT);

    return result;
}

/*
 * Set bit for unregistration in the next iteration.
 * We cannot transmit right here, but will unpin later.
 */
static void qemu_rdma_signal_unregister(RDMAContext *rdma, uint64_t index,
                                        uint64_t chunk, uint64_t wr_id)
{
    if (rdma->unregistrations[rdma->unregister_next] != 0) {
        fprintf(stderr, "rdma migration: queue is full!\n");
    } else {
        RDMALocalBlock *block = &(rdma->local_ram_blocks.block[index]);

        if (!test_and_set_bit(chunk, block->unregister_bitmap)) {
            DDPRINTF("Appending unregister chunk %" PRIu64
                    " at position %d\n", chunk, rdma->unregister_next);

            rdma->unregistrations[rdma->unregister_next++] =
                    qemu_rdma_make_wrid(wr_id, index, chunk);

            if (rdma->unregister_next == RDMA_SIGNALED_SEND_MAX) {
                rdma->unregister_next = 0;
            }
        } else {
            DDPRINTF("Unregister chunk %" PRIu64 " already in queue.\n",
                    chunk);
        }
    }
}

/*
 * Consult the connection manager to see a work request
 * (of any kind) has completed.
 * Return the work request ID that completed.
 */
static uint64_t qemu_rdma_poll(RDMAContext *rdma, uint64_t *wr_id_out,
                               uint32_t *byte_len)
{
    int ret;
    struct ibv_wc wc;
    uint64_t wr_id;

    ret = ibv_poll_cq(rdma->cq, 1, &wc);

    if (!ret) {
        *wr_id_out = RDMA_WRID_NONE;
        return 0;
    }

    if (ret < 0) {
        fprintf(stderr, "ibv_poll_cq return %d!\n", ret);
        return ret;
    }

    wr_id = wc.wr_id & RDMA_WRID_TYPE_MASK;

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));
        fprintf(stderr, "ibv_poll_cq wrid=%s!\n", wrid_desc[wr_id]);

        return -1;
    }

    if (rdma->control_ready_expected &&
        (wr_id >= RDMA_WRID_RECV_CONTROL)) {
        DDDPRINTF("completion %s #%" PRId64 " received (%" PRId64 ")"
                  " left %d\n", wrid_desc[RDMA_WRID_RECV_CONTROL],
                  wr_id - RDMA_WRID_RECV_CONTROL, wr_id, rdma->nb_sent);
        rdma->control_ready_expected = 0;
    }

    if (wr_id == RDMA_WRID_RDMA_WRITE) {
        uint64_t chunk =
            (wc.wr_id & RDMA_WRID_CHUNK_MASK) >> RDMA_WRID_CHUNK_SHIFT;
        uint64_t index =
            (wc.wr_id & RDMA_WRID_BLOCK_MASK) >> RDMA_WRID_BLOCK_SHIFT;
        RDMALocalBlock *block = &(rdma->local_ram_blocks.block[index]);

        DDDPRINTF("completions %s (%" PRId64 ") left %d, "
                 "block %" PRIu64 ", chunk: %" PRIu64 " %p %p\n",
                 print_wrid(wr_id), wr_id, rdma->nb_sent, index, chunk,
                 block->local_host_addr, (void *)block->remote_host_addr);

        clear_bit(chunk, block->transit_bitmap);

        if (rdma->nb_sent > 0) {
            rdma->nb_sent--;
        }

        if (!rdma->pin_all) {
            /*
             * FYI: If one wanted to signal a specific chunk to be unregistered
             * using LRU or workload-specific information, this is the function
             * you would call to do so. That chunk would then get asynchronously
             * unregistered later.
             */
#ifdef RDMA_UNREGISTRATION_EXAMPLE
            qemu_rdma_signal_unregister(rdma, index, chunk, wc.wr_id);
#endif
        }
    } else {
        DDDPRINTF("other completion %s (%" PRId64 ") received left %d\n",
            print_wrid(wr_id), wr_id, rdma->nb_sent);
    }

    *wr_id_out = wc.wr_id;
    if (byte_len) {
        *byte_len = wc.byte_len;
    }

    return  0;
}

/*
 * Block until the next work request has completed.
 *
 * First poll to see if a work request has already completed,
 * otherwise block.
 *
 * If we encounter completed work requests for IDs other than
 * the one we're interested in, then that's generally an error.
 *
 * The only exception is actual RDMA Write completions. These
 * completions only need to be recorded, but do not actually
 * need further processing.
 */
static int qemu_rdma_block_for_wrid(RDMAContext *rdma, int wrid_requested,
                                    uint32_t *byte_len)
{
    int num_cq_events = 0, ret = 0;
    struct ibv_cq *cq;
    void *cq_ctx;
    uint64_t wr_id = RDMA_WRID_NONE, wr_id_in;

    if (ibv_req_notify_cq(rdma->cq, 0)) {
        return -1;
    }
    /* poll cq first */
    while (wr_id != wrid_requested) {
        ret = qemu_rdma_poll(rdma, &wr_id_in, byte_len);
        if (ret < 0) {
            return ret;
        }

        wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

        if (wr_id == RDMA_WRID_NONE) {
            break;
        }
        if (wr_id != wrid_requested) {
            DDDPRINTF("A Wanted wrid %s (%d) but got %s (%" PRIu64 ")\n",
                print_wrid(wrid_requested),
                wrid_requested, print_wrid(wr_id), wr_id);
        }
    }

    if (wr_id == wrid_requested) {
        return 0;
    }

    while (1) {
        /*
         * Coroutine doesn't start until process_incoming_migration()
         * so don't yield unless we know we're running inside of a coroutine.
         */
        if (rdma->migration_started_on_destination) {
            yield_until_fd_readable(rdma->comp_channel->fd);
        }

        if (ibv_get_cq_event(rdma->comp_channel, &cq, &cq_ctx)) {
            perror("ibv_get_cq_event");
            goto err_block_for_wrid;
        }

        num_cq_events++;

        if (ibv_req_notify_cq(cq, 0)) {
            goto err_block_for_wrid;
        }

        while (wr_id != wrid_requested) {
            ret = qemu_rdma_poll(rdma, &wr_id_in, byte_len);
            if (ret < 0) {
                goto err_block_for_wrid;
            }

            wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

            if (wr_id == RDMA_WRID_NONE) {
                break;
            }
            if (wr_id != wrid_requested) {
                DDDPRINTF("B Wanted wrid %s (%d) but got %s (%" PRIu64 ")\n",
                    print_wrid(wrid_requested), wrid_requested,
                    print_wrid(wr_id), wr_id);
            }
        }

        if (wr_id == wrid_requested) {
            goto success_block_for_wrid;
        }
    }

success_block_for_wrid:
    if (num_cq_events) {
        ibv_ack_cq_events(cq, num_cq_events);
    }
    return 0;

err_block_for_wrid:
    if (num_cq_events) {
        ibv_ack_cq_events(cq, num_cq_events);
    }
    return ret;
}

/*
 * Post a SEND message work request for the control channel
 * containing some data and block until the post completes.
 */
static int qemu_rdma_post_send_control(RDMAContext *rdma, uint8_t *buf,
                                       RDMAControlHeader *head)
{
    int ret = 0;
    RDMAWorkRequestData *wr = &rdma->wr_data[RDMA_WRID_CONTROL];
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uint64_t)(wr->control),
                           .length = head->len + sizeof(RDMAControlHeader),
                           .lkey = wr->control_mr->lkey,
                         };
    struct ibv_send_wr send_wr = {
                                   .wr_id = RDMA_WRID_SEND_CONTROL,
                                   .opcode = IBV_WR_SEND,
                                   .send_flags = IBV_SEND_SIGNALED,
                                   .sg_list = &sge,
                                   .num_sge = 1,
                                };

    DDDPRINTF("CONTROL: sending %s..\n", control_desc[head->type]);

    /*
     * We don't actually need to do a memcpy() in here if we used
     * the "sge" properly, but since we're only sending control messages
     * (not RAM in a performance-critical path), then its OK for now.
     *
     * The copy makes the RDMAControlHeader simpler to manipulate
     * for the time being.
     */
    assert(head->len <= RDMA_CONTROL_MAX_BUFFER - sizeof(*head));
    memcpy(wr->control, head, sizeof(RDMAControlHeader));
    control_to_network((void *) wr->control);

    if (buf) {
        memcpy(wr->control + sizeof(RDMAControlHeader), buf, head->len);
    }


    if (ibv_post_send(rdma->qp, &send_wr, &bad_wr)) {
        return -1;
    }

    if (ret < 0) {
        fprintf(stderr, "Failed to use post IB SEND for control!\n");
        return ret;
    }

    ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_SEND_CONTROL, NULL);
    if (ret < 0) {
        fprintf(stderr, "rdma migration: send polling control error!\n");
    }

    return ret;
}

/*
 * Post a RECV work request in anticipation of some future receipt
 * of data on the control channel.
 */
static int qemu_rdma_post_recv_control(RDMAContext *rdma, int idx)
{
    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uint64_t)(rdma->wr_data[idx].control),
                            .length = RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->wr_data[idx].control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .wr_id = RDMA_WRID_RECV_CONTROL + idx,
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->qp, &recv_wr, &bad_wr)) {
        return -1;
    }

    return 0;
}

/*
 * Block and wait for a RECV control channel message to arrive.
 */
static int qemu_rdma_exchange_get_response(RDMAContext *rdma,
                RDMAControlHeader *head, int expecting, int idx)
{
    uint32_t byte_len;
    int ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RECV_CONTROL + idx,
                                       &byte_len);

    if (ret < 0) {
        fprintf(stderr, "rdma migration: recv polling control error!\n");
        return ret;
    }

    network_to_control((void *) rdma->wr_data[idx].control);
    memcpy(head, rdma->wr_data[idx].control, sizeof(RDMAControlHeader));

    DDDPRINTF("CONTROL: %s receiving...\n", control_desc[expecting]);

    if (expecting == RDMA_CONTROL_NONE) {
        DDDPRINTF("Surprise: got %s (%d)\n",
                  control_desc[head->type], head->type);
    } else if (head->type != expecting || head->type == RDMA_CONTROL_ERROR) {
        fprintf(stderr, "Was expecting a %s (%d) control message"
                ", but got: %s (%d), length: %d\n",
                control_desc[expecting], expecting,
                control_desc[head->type], head->type, head->len);
        return -EIO;
    }
    if (head->len > RDMA_CONTROL_MAX_BUFFER - sizeof(*head)) {
        fprintf(stderr, "too long length: %d\n", head->len);
        return -EINVAL;
    }
    if (sizeof(*head) + head->len != byte_len) {
        fprintf(stderr, "Malformed length: %d byte_len %d\n",
                head->len, byte_len);
        return -EINVAL;
    }

    return 0;
}

/*
 * When a RECV work request has completed, the work request's
 * buffer is pointed at the header.
 *
 * This will advance the pointer to the data portion
 * of the control message of the work request's buffer that
 * was populated after the work request finished.
 */
static void qemu_rdma_move_header(RDMAContext *rdma, int idx,
                                  RDMAControlHeader *head)
{
    rdma->wr_data[idx].control_len = head->len;
    rdma->wr_data[idx].control_curr =
        rdma->wr_data[idx].control + sizeof(RDMAControlHeader);
}

/*
 * This is an 'atomic' high-level operation to deliver a single, unified
 * control-channel message.
 *
 * Additionally, if the user is expecting some kind of reply to this message,
 * they can request a 'resp' response message be filled in by posting an
 * additional work request on behalf of the user and waiting for an additional
 * completion.
 *
 * The extra (optional) response is used during registration to us from having
 * to perform an *additional* exchange of message just to provide a response by
 * instead piggy-backing on the acknowledgement.
 */
static int qemu_rdma_exchange_send(RDMAContext *rdma, RDMAControlHeader *head,
                                   uint8_t *data, RDMAControlHeader *resp,
                                   int *resp_idx,
                                   int (*callback)(RDMAContext *rdma))
{
    int ret = 0;

    /*
     * Wait until the dest is ready before attempting to deliver the message
     * by waiting for a READY message.
     */
    if (rdma->control_ready_expected) {
        RDMAControlHeader resp;
        ret = qemu_rdma_exchange_get_response(rdma,
                                    &resp, RDMA_CONTROL_READY, RDMA_WRID_READY);
        if (ret < 0) {
            return ret;
        }
    }

    /*
     * If the user is expecting a response, post a WR in anticipation of it.
     */
    if (resp) {
        ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_DATA);
        if (ret) {
            fprintf(stderr, "rdma migration: error posting"
                    " extra control recv for anticipated result!");
            return ret;
        }
    }

    /*
     * Post a WR to replace the one we just consumed for the READY message.
     */
    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting first control recv!");
        return ret;
    }

    /*
     * Deliver the control message that was requested.
     */
    ret = qemu_rdma_post_send_control(rdma, data, head);

    if (ret < 0) {
        fprintf(stderr, "Failed to send control buffer!\n");
        return ret;
    }

    /*
     * If we're expecting a response, block and wait for it.
     */
    if (resp) {
        if (callback) {
            DDPRINTF("Issuing callback before receiving response...\n");
            ret = callback(rdma);
            if (ret < 0) {
                return ret;
            }
        }

        DDPRINTF("Waiting for response %s\n", control_desc[resp->type]);
        ret = qemu_rdma_exchange_get_response(rdma, resp,
                                              resp->type, RDMA_WRID_DATA);

        if (ret < 0) {
            return ret;
        }

        qemu_rdma_move_header(rdma, RDMA_WRID_DATA, resp);
        if (resp_idx) {
            *resp_idx = RDMA_WRID_DATA;
        }
        DDPRINTF("Response %s received.\n", control_desc[resp->type]);
    }

    rdma->control_ready_expected = 1;

    return 0;
}

/*
 * This is an 'atomic' high-level operation to receive a single, unified
 * control-channel message.
 */
static int qemu_rdma_exchange_recv(RDMAContext *rdma, RDMAControlHeader *head,
                                int expecting)
{
    RDMAControlHeader ready = {
                                .len = 0,
                                .type = RDMA_CONTROL_READY,
                                .repeat = 1,
                              };
    int ret;

    /*
     * Inform the source that we're ready to receive a message.
     */
    ret = qemu_rdma_post_send_control(rdma, NULL, &ready);

    if (ret < 0) {
        fprintf(stderr, "Failed to send control buffer!\n");
        return ret;
    }

    /*
     * Block and wait for the message.
     */
    ret = qemu_rdma_exchange_get_response(rdma, head,
                                          expecting, RDMA_WRID_READY);

    if (ret < 0) {
        return ret;
    }

    qemu_rdma_move_header(rdma, RDMA_WRID_READY, head);

    /*
     * Post a new RECV work request to replace the one we just consumed.
     */
    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting second control recv!");
        return ret;
    }

    return 0;
}

/*
 * Write an actual chunk of memory using RDMA.
 *
 * If we're using dynamic registration on the dest-side, we have to
 * send a registration command first.
 */
static int qemu_rdma_write_one(QEMUFile *f, RDMAContext *rdma,
                               int current_index, uint64_t current_addr,
                               uint64_t length)
{
    struct ibv_sge sge;
    struct ibv_send_wr send_wr = { 0 };
    struct ibv_send_wr *bad_wr;
    int reg_result_idx, ret, count = 0;
    uint64_t chunk, chunks;
    RDMALocalBlock *block = &(rdma->local_ram_blocks.block[current_index]);
    RDMARegister reg;
    RDMARegisterResult *reg_result;
    RDMAControlHeader resp = { .type = RDMA_CONTROL_REGISTER_RESULT };
    RDMAControlHeader head = { .len = sizeof(RDMARegister),
                               .type = RDMA_CONTROL_REGISTER_REQUEST,
                               .repeat = 1,
                             };

retry:
    sge.addr = (uint64_t)(block->local_host_addr +
                            (current_addr - block->offset));
    sge.length = length;

    chunk = ram_chunk_index(block->local_host_addr, (uint8_t *) sge.addr);

    if (block->is_ram_block) {
        chunks = length / (1UL << RDMA_REG_CHUNK_SHIFT);

        if (chunks && ((length % (1UL << RDMA_REG_CHUNK_SHIFT)) == 0)) {
            chunks--;
        }
    } else {
        chunks = block->length / (1UL << RDMA_REG_CHUNK_SHIFT);

        if (chunks && ((block->length % (1UL << RDMA_REG_CHUNK_SHIFT)) == 0)) {
            chunks--;
        }
    }

    DDPRINTF("Writing %" PRIu64 " chunks, (%" PRIu64 " MB)\n",
        chunks + 1, (chunks + 1) * (1UL << RDMA_REG_CHUNK_SHIFT) / 1024 / 1024);

    if (!rdma->pin_all) {
#ifdef RDMA_UNREGISTRATION_EXAMPLE
        qemu_rdma_unregister_waiting(rdma);
#endif
    }

    while (test_bit(chunk, block->transit_bitmap)) {
        (void)count;
        DDPRINTF("(%d) Not clobbering: block: %d chunk %" PRIu64
                " current %" PRIu64 " len %" PRIu64 " %d %d\n",
                count++, current_index, chunk,
                sge.addr, length, rdma->nb_sent, block->nb_chunks);

        ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RDMA_WRITE, NULL);

        if (ret < 0) {
            fprintf(stderr, "Failed to Wait for previous write to complete "
                    "block %d chunk %" PRIu64
                    " current %" PRIu64 " len %" PRIu64 " %d\n",
                    current_index, chunk, sge.addr, length, rdma->nb_sent);
            return ret;
        }
    }

    if (!rdma->pin_all || !block->is_ram_block) {
        if (!block->remote_keys[chunk]) {
            /*
             * This chunk has not yet been registered, so first check to see
             * if the entire chunk is zero. If so, tell the other size to
             * memset() + madvise() the entire chunk without RDMA.
             */

            if (can_use_buffer_find_nonzero_offset((void *)sge.addr, length)
                   && buffer_find_nonzero_offset((void *)sge.addr,
                                                    length) == length) {
                RDMACompress comp = {
                                        .offset = current_addr,
                                        .value = 0,
                                        .block_idx = current_index,
                                        .length = length,
                                    };

                head.len = sizeof(comp);
                head.type = RDMA_CONTROL_COMPRESS;

                DDPRINTF("Entire chunk is zero, sending compress: %"
                    PRIu64 " for %d "
                    "bytes, index: %d, offset: %" PRId64 "...\n",
                    chunk, sge.length, current_index, current_addr);

                compress_to_network(&comp);
                ret = qemu_rdma_exchange_send(rdma, &head,
                                (uint8_t *) &comp, NULL, NULL, NULL);

                if (ret < 0) {
                    return -EIO;
                }

                acct_update_position(f, sge.length, true);

                return 1;
            }

            /*
             * Otherwise, tell other side to register.
             */
            reg.current_index = current_index;
            if (block->is_ram_block) {
                reg.key.current_addr = current_addr;
            } else {
                reg.key.chunk = chunk;
            }
            reg.chunks = chunks;

            DDPRINTF("Sending registration request chunk %" PRIu64 " for %d "
                    "bytes, index: %d, offset: %" PRId64 "...\n",
                    chunk, sge.length, current_index, current_addr);

            register_to_network(&reg);
            ret = qemu_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                    &resp, &reg_result_idx, NULL);
            if (ret < 0) {
                return ret;
            }

            /* try to overlap this single registration with the one we sent. */
            if (qemu_rdma_register_and_get_keys(rdma, block,
                                                (uint8_t *) sge.addr,
                                                &sge.lkey, NULL, chunk)) {
                fprintf(stderr, "cannot get lkey!\n");
                return -EINVAL;
            }

            reg_result = (RDMARegisterResult *)
                    rdma->wr_data[reg_result_idx].control_curr;

            network_to_result(reg_result);

            DDPRINTF("Received registration result:"
                    " my key: %x their key %x, chunk %" PRIu64 "\n",
                    block->remote_keys[chunk], reg_result->rkey, chunk);

            block->remote_keys[chunk] = reg_result->rkey;
            block->remote_host_addr = reg_result->host_addr;
        } else {
            /* already registered before */
            if (qemu_rdma_register_and_get_keys(rdma, block,
                                                (uint8_t *)sge.addr,
                                                &sge.lkey, NULL, chunk)) {
                fprintf(stderr, "cannot get lkey!\n");
                return -EINVAL;
            }
        }

        send_wr.wr.rdma.rkey = block->remote_keys[chunk];
    } else {
        send_wr.wr.rdma.rkey = block->remote_rkey;

        if (qemu_rdma_register_and_get_keys(rdma, block, (uint8_t *)sge.addr,
                                                     &sge.lkey, NULL, chunk)) {
            fprintf(stderr, "cannot get lkey!\n");
            return -EINVAL;
        }
    }

    /*
     * Encode the ram block index and chunk within this wrid.
     * We will use this information at the time of completion
     * to figure out which bitmap to check against and then which
     * chunk in the bitmap to look for.
     */
    send_wr.wr_id = qemu_rdma_make_wrid(RDMA_WRID_RDMA_WRITE,
                                        current_index, chunk);

    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr.rdma.remote_addr = block->remote_host_addr +
                                (current_addr - block->offset);

    DDDPRINTF("Posting chunk: %" PRIu64 ", addr: %lx"
              " remote: %lx, bytes %" PRIu32 "\n",
              chunk, sge.addr, send_wr.wr.rdma.remote_addr,
              sge.length);

    /*
     * ibv_post_send() does not return negative error numbers,
     * per the specification they are positive - no idea why.
     */
    ret = ibv_post_send(rdma->qp, &send_wr, &bad_wr);

    if (ret == ENOMEM) {
        DDPRINTF("send queue is full. wait a little....\n");
        ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RDMA_WRITE, NULL);
        if (ret < 0) {
            fprintf(stderr, "rdma migration: failed to make "
                            "room in full send queue! %d\n", ret);
            return ret;
        }

        goto retry;

    } else if (ret > 0) {
        perror("rdma migration: post rdma write failed");
        return -ret;
    }

    set_bit(chunk, block->transit_bitmap);
    acct_update_position(f, sge.length, false);
    rdma->total_writes++;

    return 0;
}

/*
 * Push out any unwritten RDMA operations.
 *
 * We support sending out multiple chunks at the same time.
 * Not all of them need to get signaled in the completion queue.
 */
static int qemu_rdma_write_flush(QEMUFile *f, RDMAContext *rdma)
{
    int ret;

    if (!rdma->current_length) {
        return 0;
    }

    ret = qemu_rdma_write_one(f, rdma,
            rdma->current_index, rdma->current_addr, rdma->current_length);

    if (ret < 0) {
        return ret;
    }

    if (ret == 0) {
        rdma->nb_sent++;
        DDDPRINTF("sent total: %d\n", rdma->nb_sent);
    }

    rdma->current_length = 0;
    rdma->current_addr = 0;

    return 0;
}

static inline int qemu_rdma_buffer_mergable(RDMAContext *rdma,
                    uint64_t offset, uint64_t len)
{
    RDMALocalBlock *block;
    uint8_t *host_addr;
    uint8_t *chunk_end;

    if (rdma->current_index < 0) {
        return 0;
    }

    if (rdma->current_chunk < 0) {
        return 0;
    }

    block = &(rdma->local_ram_blocks.block[rdma->current_index]);
    host_addr = block->local_host_addr + (offset - block->offset);
    chunk_end = ram_chunk_end(block, rdma->current_chunk);

    if (rdma->current_length == 0) {
        return 0;
    }

    /*
     * Only merge into chunk sequentially.
     */
    if (offset != (rdma->current_addr + rdma->current_length)) {
        return 0;
    }

    if (offset < block->offset) {
        return 0;
    }

    if ((offset + len) > (block->offset + block->length)) {
        return 0;
    }

    if ((host_addr + len) > chunk_end) {
        return 0;
    }

    return 1;
}

/*
 * We're not actually writing here, but doing three things:
 *
 * 1. Identify the chunk the buffer belongs to.
 * 2. If the chunk is full or the buffer doesn't belong to the current
 *    chunk, then start a new chunk and flush() the old chunk.
 * 3. To keep the hardware busy, we also group chunks into batches
 *    and only require that a batch gets acknowledged in the completion
 *    qeueue instead of each individual chunk.
 */
static int qemu_rdma_write(QEMUFile *f, RDMAContext *rdma,
                           uint64_t block_offset, uint64_t offset,
                           uint64_t len)
{
    uint64_t current_addr = block_offset + offset;
    uint64_t index = rdma->current_index;
    uint64_t chunk = rdma->current_chunk;
    int ret;

    /* If we cannot merge it, we flush the current buffer first. */
    if (!qemu_rdma_buffer_mergable(rdma, current_addr, len)) {
        ret = qemu_rdma_write_flush(f, rdma);
        if (ret) {
            return ret;
        }
        rdma->current_length = 0;
        rdma->current_addr = current_addr;

        ret = qemu_rdma_search_ram_block(rdma, block_offset,
                                         offset, len, &index, &chunk);
        if (ret) {
            fprintf(stderr, "ram block search failed\n");
            return ret;
        }
        rdma->current_index = index;
        rdma->current_chunk = chunk;
    }

    /* merge it */
    rdma->current_length += len;

    /* flush it if buffer is too large */
    if (rdma->current_length >= RDMA_MERGE_MAX) {
        return qemu_rdma_write_flush(f, rdma);
    }

    return 0;
}

static void qemu_rdma_cleanup(RDMAContext *rdma)
{
    struct rdma_cm_event *cm_event;
    int ret, idx;

    if (rdma->cm_id && rdma->connected) {
        if (rdma->error_state) {
            RDMAControlHeader head = { .len = 0,
                                       .type = RDMA_CONTROL_ERROR,
                                       .repeat = 1,
                                     };
            fprintf(stderr, "Early error. Sending error.\n");
            qemu_rdma_post_send_control(rdma, NULL, &head);
        }

        ret = rdma_disconnect(rdma->cm_id);
        if (!ret) {
            DDPRINTF("waiting for disconnect\n");
            ret = rdma_get_cm_event(rdma->channel, &cm_event);
            if (!ret) {
                rdma_ack_cm_event(cm_event);
            }
        }
        DDPRINTF("Disconnected.\n");
        rdma->connected = false;
    }

    g_free(rdma->block);
    rdma->block = NULL;

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        if (rdma->wr_data[idx].control_mr) {
            rdma->total_registrations--;
            ibv_dereg_mr(rdma->wr_data[idx].control_mr);
        }
        rdma->wr_data[idx].control_mr = NULL;
    }

    if (rdma->local_ram_blocks.block) {
        while (rdma->local_ram_blocks.nb_blocks) {
            __qemu_rdma_delete_block(rdma,
                    rdma->local_ram_blocks.block->offset);
        }
    }

    if (rdma->qp) {
        rdma_destroy_qp(rdma->cm_id);
        rdma->qp = NULL;
    }
    if (rdma->cq) {
        ibv_destroy_cq(rdma->cq);
        rdma->cq = NULL;
    }
    if (rdma->comp_channel) {
        ibv_destroy_comp_channel(rdma->comp_channel);
        rdma->comp_channel = NULL;
    }
    if (rdma->pd) {
        ibv_dealloc_pd(rdma->pd);
        rdma->pd = NULL;
    }
    if (rdma->cm_id) {
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = NULL;
    }
    if (!rdma->keep_listen_id) {
        /* Hack for postcopy */
        if (rdma->listen_id) {
            rdma_destroy_id(rdma->listen_id);
            rdma->listen_id = NULL;
        }
        if (rdma->channel) {
            rdma_destroy_event_channel(rdma->channel);
            rdma->channel = NULL;
        }
    }
    g_free(rdma->host);
    rdma->host = NULL;
}


static int qemu_rdma_source_init(RDMAContext *rdma, Error **errp)
{
    int ret, idx;
    Error *local_err = NULL, **temp = &local_err;

    /*
     * Will be validated against destination's actual capabilities
     * after the connect() completes.
     */
    rdma->pin_all = migrate_rdma_pin_all();
    rdma->postcopy = migrate_postcopy_outgoing();
    if (rdma->pin_all && rdma->postcopy) {
        ERROR(temp, "rdma migration: rdma postcopy doesn't support pin-all\n");
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_resolve_host(rdma, temp);
    if (ret) {
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_alloc_pd_cq(rdma);
    if (ret) {
        ERROR(temp, "rdma migration: error allocating pd and cq! Your mlock()"
                    " limits may be too low. Please check $ ulimit -a # and "
                    "search for 'ulimit -l' in the output");
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_alloc_qp(rdma);
    if (ret) {
        ERROR(temp, "rdma migration: error allocating qp!");
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        ERROR(temp, "rdma migration: error initializing ram blocks!");
        goto err_rdma_source_init;
    }

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            ERROR(temp, "rdma migration: error registering %d control!",
                                                            idx);
            goto err_rdma_source_init;
        }
    }

    return 0;

err_rdma_source_init:
    error_propagate(errp, local_err);
    qemu_rdma_cleanup(rdma);
    return -1;
}

static int qemu_rdma_connect(RDMAContext *rdma, Error **errp)
{
    RDMACapabilities cap = {
                                .version = RDMA_CONTROL_VERSION_CURRENT,
                                .flags = 0,
                           };
    struct rdma_conn_param conn_param = { .initiator_depth = 2,
                                          .retry_count = 5,
                                          .private_data = &cap,
                                          .private_data_len = sizeof(cap),
                                        };
    struct rdma_cm_event *cm_event;
    int ret;

    /*
     * Only negotiate the capability with destination if the user
     * on the source first requested the capability.
     */
    if (rdma->pin_all) {
        DPRINTF("Server pin-all memory requested.\n");
        cap.flags |= RDMA_CAPABILITY_PIN_ALL;
    }
    if (rdma->postcopy) {
        DPRINTF("Server postcopy requested.\n");
        cap.flags |= RDMA_CAPABILITY_POSTCOPY;
    }

    caps_to_network(&cap);

    ret = rdma_connect(rdma->cm_id, &conn_param);
    if (ret) {
        perror("rdma_connect");
        ERROR(errp, "connecting to destination!");
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = NULL;
        goto err_rdma_source_connect;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        perror("rdma_get_cm_event after rdma_connect");
        ERROR(errp, "connecting to destination!");
        rdma_ack_cm_event(cm_event);
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = NULL;
        goto err_rdma_source_connect;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        perror("rdma_get_cm_event != EVENT_ESTABLISHED after rdma_connect");
        ERROR(errp, "connecting to destination!");
        rdma_ack_cm_event(cm_event);
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = NULL;
        goto err_rdma_source_connect;
    }
    rdma->connected = true;

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));
    network_to_caps(&cap);

    /*
     * Verify that the *requested* capabilities are supported by the destination
     * and disable them otherwise.
     */
    if (rdma->pin_all && !(cap.flags & RDMA_CAPABILITY_PIN_ALL)) {
        ERROR(errp, "Server cannot support pinning all memory. "
                        "Will register memory dynamically.");
        rdma->pin_all = false;
    }
    if (rdma->postcopy && !(cap.flags & RDMA_CAPABILITY_POSTCOPY)) {
        ERROR(errp, "Server cannot support postcopy.\n");
        rdma_ack_cm_event(cm_event);
        rdma->postcopy = false;
        goto err_rdma_source_connect;
    }

    DPRINTF("Pin all memory: %s\n", rdma->pin_all ? "enabled" : "disabled");
    DPRINTF("Postcopy: %s\n", rdma->postcopy ? "enabled" : "disabled");

    rdma_ack_cm_event(cm_event);

    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        ERROR(errp, "posting second control recv!");
        goto err_rdma_source_connect;
    }

    rdma->control_ready_expected = 1;
    rdma->nb_sent = 0;
    return 0;

err_rdma_source_connect:
    qemu_rdma_cleanup(rdma);
    return -1;
}

static int qemu_rdma_dest_init(RDMAContext *rdma, Error **errp)
{
    int ret = -EINVAL, idx;
    struct rdma_cm_id *listen_id;
    char ip[40] = "unknown";
    struct rdma_addrinfo *res;
    char port_str[16];

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        rdma->wr_data[idx].control_len = 0;
        rdma->wr_data[idx].control_curr = NULL;
    }

    if (rdma->host == NULL) {
        ERROR(errp, "RDMA host is not set!");
        rdma->error_state = -EINVAL;
        return -1;
    }
    ibv_fork_init();    /* for postcopy to fork */
    /* create CM channel */
    rdma->channel = rdma_create_event_channel();
    if (!rdma->channel) {
        ERROR(errp, "could not create rdma event channel");
        rdma->error_state = -EINVAL;
        return -1;
    }

    /* create CM id */
    ret = rdma_create_id(rdma->channel, &listen_id, NULL, RDMA_PS_TCP);
    if (ret) {
        ERROR(errp, "could not create cm_id!");
        goto err_dest_init_create_listen_id;
    }

    snprintf(port_str, 16, "%d", rdma->port);
    port_str[15] = '\0';

    if (rdma->host && strcmp("", rdma->host)) {
        struct rdma_addrinfo *e;

        ret = rdma_getaddrinfo(rdma->host, port_str, NULL, &res);
        if (ret < 0) {
            ERROR(errp, "could not rdma_getaddrinfo address %s", rdma->host);
            goto err_dest_init_bind_addr;
        }

        for (e = res; e != NULL; e = e->ai_next) {
            inet_ntop(e->ai_family,
                &((struct sockaddr_in *) e->ai_dst_addr)->sin_addr, ip, sizeof ip);
            DPRINTF("Trying %s => %s\n", rdma->host, ip);
            ret = rdma_bind_addr(listen_id, e->ai_dst_addr);
            if (!ret) {
                if (e->ai_family == AF_INET6) {
                    ret = qemu_rdma_broken_ipv6_kernel(errp, listen_id->verbs);
                    if (ret) {
                        continue;
                    }
                }
                rdma_freeaddrinfo(res);
                goto listen;
            }
        }

        ERROR(errp, "Error: could not rdma_bind_addr!");
        rdma_freeaddrinfo(res);
        goto err_dest_init_bind_addr;
    } else {
        ERROR(errp, "migration host and port not specified!");
        ret = -EINVAL;
        goto err_dest_init_bind_addr;
    }
listen:

    rdma->listen_id = listen_id;
    qemu_rdma_dump_gid("dest_init", listen_id);
    return 0;

err_dest_init_bind_addr:
    rdma_destroy_id(listen_id);
err_dest_init_create_listen_id:
    rdma_destroy_event_channel(rdma->channel);
    rdma->channel = NULL;
    rdma->error_state = ret;
    return ret;

}

/* to tell rdma postcopy host_port */
static char *current_host_port = NULL;

static void *qemu_rdma_data_init(const char *host_port, Error **errp)
{
    RDMAContext *rdma = NULL;
    InetSocketAddress *addr = NULL;

    if (host_port != current_host_port) {
        g_free(current_host_port);
        current_host_port = g_strdup(host_port);
    }
    if (host_port) {
        rdma = g_malloc0(sizeof(RDMAContext));
        rdma->current_index = -1;
        rdma->current_chunk = -1;

        addr = inet_parse(host_port, NULL);
        if (addr != NULL) {
            rdma->port = atoi(addr->port);
            rdma->host = g_strdup(addr->host);
        } else {
            ERROR(errp, "bad RDMA migration address '%s'", host_port);
            g_free(rdma);
            rdma = NULL;
        }
    }

    if (addr != NULL) {
        g_free(addr->host);
        g_free(addr->port);
        g_free(addr);
    }
    return rdma;
}

/*
 * QEMUFile interface to the control channel.
 * SEND messages for control only.
 * pc.ram is handled with regular RDMA messages.
 */
static int qemu_rdma_put_buffer(void *opaque, const uint8_t *buf,
                                int64_t pos, int size)
{
    QEMUFileRDMA *r = opaque;
    QEMUFile *f = r->file;
    RDMAContext *rdma = r->rdma;
    size_t remaining = size;
    uint8_t * data = (void *) buf;
    int ret;

    CHECK_ERROR_STATE();

    /*
     * Push out any writes that
     * we're queued up for pc.ram.
     */
    ret = qemu_rdma_write_flush(f, rdma);
    if (ret < 0) {
        rdma->error_state = ret;
        return ret;
    }

    while (remaining) {
        RDMAControlHeader head;
        uint8_t *tmp;

        r->len = MIN(remaining, RDMA_SEND_INCREMENT);
        remaining -= r->len;

        head.len = r->len;
        head.type = RDMA_CONTROL_QEMU_FILE;

        DPRINTF("qemu_rdma_put_buffer size %zd remaining %zd "
                "0x%x 0x%x 0x%x 0x%x\n",
                r->len, remaining, data[0], data[1], data[2], data[3]);
        ret = qemu_rdma_exchange_send(rdma, &head, data, NULL, NULL, NULL);
        tmp = rdma->wr_data[RDMA_WRID_CONTROL].control;
        tmp += sizeof(RDMAControlHeader);

        if (ret < 0) {
            rdma->error_state = ret;
            return ret;
        }

        data += r->len;
    }

    return size;
}

static size_t qemu_rdma_fill(RDMAContext *rdma, uint8_t *buf, int size)
{
    size_t len = 0;

    if (rdma->data_len) {
        DDDPRINTF("RDMA %" PRId64 " of %d bytes already in buffer\n",
                  rdma->data_len, size);

        len = MIN(size, rdma->data_len);
        memcpy(buf, rdma->data_curr, len);
        rdma->data_curr += len;
        rdma->data_len -= len;
    }

    return len;
}

/*
 * QEMUFile interface to the control channel.
 * RDMA links don't use bytestreams, so we have to
 * return bytes to QEMUFile opportunistically.
 */
static int qemu_rdma_get_buffer(void *opaque, uint8_t *buf,
                                int64_t pos, int size)
{
    QEMUFileRDMA *r = opaque;
    RDMAContext *rdma = r->rdma;
    RDMAControlHeader head;
    int ret = 0;

    CHECK_ERROR_STATE();

    /*
     * First, we hold on to the last SEND message we
     * were given and dish out the bytes until we run
     * out of bytes.
     */
    r->len = qemu_rdma_fill(r->rdma, buf, size);
    if (r->len) {
        return r->len;
    }

    /*
     * Once we run out, we block and wait for another
     * SEND message to arrive.
     */
    ret = qemu_rdma_exchange_recv(rdma, &head, RDMA_CONTROL_QEMU_FILE);

    if (ret < 0) {
        rdma->error_state = ret;
        return ret;
    }
    rdma->data_curr = rdma->file_data;
    rdma->data_len = rdma->wr_data[RDMA_WRID_READY].control_len;
    assert(rdma->data_len <= RDMA_CONTROL_MAX_BUFFER);
    assert(rdma->data_len <= sizeof(rdma->file_data));
    memcpy(rdma->data_curr, rdma->wr_data[RDMA_WRID_READY].control_curr,
           rdma->data_len);
    DDDPRINTF("RDMA QEMU FILE recv %"PRId64"\n", rdma->data_len);

    /*
     * SEND was received with new bytes, now try again.
     */
    return qemu_rdma_fill(r->rdma, buf, size);
}

/*
 * Block until all the outstanding chunks have been delivered by the hardware.
 */
static int qemu_rdma_drain_cq(QEMUFile *f, RDMAContext *rdma)
{
    int ret;

    if (qemu_rdma_write_flush(f, rdma) < 0) {
        return -EIO;
    }

    while (rdma->nb_sent) {
        ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RDMA_WRITE, NULL);
        if (ret < 0) {
            fprintf(stderr, "rdma migration: complete polling error!\n");
            return -EIO;
        }
    }

    qemu_rdma_unregister_waiting(rdma);

    return 0;
}

static int qemu_rdma_close(void *opaque)
{
    DPRINTF("Shutting down connection.\n");
    QEMUFileRDMA *r = opaque;
    if (r->rdma) {
        qemu_rdma_cleanup(r->rdma);
        g_free(r->rdma);
    }
    g_free(r);
    return 0;
}

/*
 * Parameters:
 *    @offset == 0 :
 *        This means that 'block_offset' is a full virtual address that does not
 *        belong to a RAMBlock of the virtual machine and instead
 *        represents a private malloc'd memory area that the caller wishes to
 *        transfer.
 *
 *    @offset != 0 :
 *        Offset is an offset to be added to block_offset and used
 *        to also lookup the corresponding RAMBlock.
 *
 *    @size > 0 :
 *        Initiate an transfer this size.
 *
 *    @size == 0 :
 *        A 'hint' or 'advice' that means that we wish to speculatively
 *        and asynchronously unregister this memory. In this case, there is no
 *        guarantee that the unregister will actually happen, for example,
 *        if the memory is being actively transmitted. Additionally, the memory
 *        may be re-registered at any future time if a write within the same
 *        chunk was requested again, even if you attempted to unregister it
 *        here.
 *
 *    @size < 0 : TODO, not yet supported
 *        Unregister the memory NOW. This means that the caller does not
 *        expect there to be any future RDMA transfers and we just want to clean
 *        things up. This is used in case the upper layer owns the memory and
 *        cannot wait for qemu_fclose() to occur.
 *
 *    @bytes_sent : User-specificed pointer to indicate how many bytes were
 *                  sent. Usually, this will not be more than a few bytes of
 *                  the protocol because most transfers are sent asynchronously.
 */
static size_t qemu_rdma_save_page(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset, ram_addr_t offset,
                                  size_t size, int *bytes_sent)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    int ret;

    CHECK_ERROR_STATE();

    qemu_fflush(f);

    if (size > 0) {
        /*
         * Add this page to the current 'chunk'. If the chunk
         * is full, or the page doen't belong to the current chunk,
         * an actual RDMA write will occur and a new chunk will be formed.
         */
        ret = qemu_rdma_write(f, rdma, block_offset, offset, size);
        if (ret < 0) {
            fprintf(stderr, "rdma migration: write error! %d\n", ret);
            goto err;
        }

        /*
         * We always return 1 bytes because the RDMA
         * protocol is completely asynchronous. We do not yet know
         * whether an  identified chunk is zero or not because we're
         * waiting for other pages to potentially be merged with
         * the current chunk. So, we have to call qemu_update_position()
         * later on when the actual write occurs.
         */
        if (bytes_sent) {
            *bytes_sent = 1;
        }
    } else {
        uint64_t index, chunk;

        /* TODO: Change QEMUFileOps prototype to be signed: size_t => long
        if (size < 0) {
            ret = qemu_rdma_drain_cq(f, rdma);
            if (ret < 0) {
                fprintf(stderr, "rdma: failed to synchronously drain"
                                " completion queue before unregistration.\n");
                goto err;
            }
        }
        */

        ret = qemu_rdma_search_ram_block(rdma, block_offset,
                                         offset, size, &index, &chunk);

        if (ret) {
            fprintf(stderr, "ram block search failed\n");
            goto err;
        }

        qemu_rdma_signal_unregister(rdma, index, chunk, 0);

        /*
         * TODO: Synchronous, guaranteed unregistration (should not occur during
         * fast-path). Otherwise, unregisters will process on the next call to
         * qemu_rdma_drain_cq()
        if (size < 0) {
            qemu_rdma_unregister_waiting(rdma);
        }
        */
    }

    /*
     * Drain the Completion Queue if possible, but do not block,
     * just poll.
     *
     * If nothing to poll, the end of the iteration will do this
     * again to make sure we don't overflow the request queue.
     */
    while (1) {
        uint64_t wr_id, wr_id_in;
        int ret = qemu_rdma_poll(rdma, &wr_id_in, NULL);
        if (ret < 0) {
            fprintf(stderr, "rdma migration: polling error! %d\n", ret);
            goto err;
        }

        wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

        if (wr_id == RDMA_WRID_NONE) {
            break;
        }
    }

    return RAM_SAVE_CONTROL_DELAYED;
err:
    rdma->error_state = ret;
    return ret;
}

static int qemu_rdma_accept(RDMAContext *rdma)
{
    RDMACapabilities cap;
    struct rdma_conn_param conn_param = {
                                            .responder_resources = 2,
                                            .private_data = &cap,
                                            .private_data_len = sizeof(cap),
                                         };
    struct rdma_cm_event *cm_event;
    struct ibv_context *verbs;
    int ret = -EINVAL;
    int idx;
    UMemBlockHead *umem_blocks;

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        goto err_rdma_dest_wait;
    }

    if (cm_event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));

    network_to_caps(&cap);

    if (cap.version < 1 || cap.version > RDMA_CONTROL_VERSION_CURRENT) {
            fprintf(stderr, "Unknown source RDMA version: %d, bailing...\n",
                            cap.version);
            rdma_ack_cm_event(cm_event);
            goto err_rdma_dest_wait;
    }

    /*
     * Respond with only the capabilities this version of QEMU knows about.
     */
    cap.flags &= known_capabilities;

    /*
     * Enable the ones that we do know about.
     * Add other checks here as new ones are introduced.
     */
    if (cap.flags & RDMA_CAPABILITY_PIN_ALL) {
        rdma->pin_all = true;
    }
    if (cap.flags & RDMA_CAPABILITY_POSTCOPY) {
        rdma->postcopy = true;
        ret = postcopy_incoming_prepare(&umem_blocks);
        if (ret) {
            rdma_ack_cm_event(cm_event);
            goto err_rdma_dest_wait;
        }
    }

    rdma->cm_id = cm_event->id;
    verbs = cm_event->id->verbs;

    rdma_ack_cm_event(cm_event);
    if (!rdma->postcopy) {
        rdma_destroy_id(rdma->listen_id);
        rdma->listen_id = NULL;
    }

    DPRINTF("Memory pin all: %s\n", rdma->pin_all ? "enabled" : "disabled");
    DPRINTF("Postcopy: %s\n", rdma->postcopy ? "enabled" : "disabled");

    caps_to_network(&cap);

    DPRINTF("verbs context after listen: %p\n", verbs);

    if (!rdma->verbs) {
        rdma->verbs = verbs;
    } else if (rdma->verbs != verbs) {
            fprintf(stderr, "ibv context not matching %p, %p!\n",
                    rdma->verbs, verbs);
            goto err_rdma_dest_wait;
    }

    qemu_rdma_dump_id("dest_init", verbs);

    ret = qemu_rdma_alloc_pd_cq(rdma);
    if (ret) {
        fprintf(stderr, "rdma migration: error allocating pd and cq!\n");
        goto err_rdma_dest_wait;
    }

    ret = qemu_rdma_alloc_qp(rdma);
    if (ret) {
        fprintf(stderr, "rdma migration: error allocating qp!\n");
        goto err_rdma_dest_wait;
    }

    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        fprintf(stderr, "rdma migration: error initializing ram blocks!\n");
        goto err_rdma_dest_wait;
    }
    if (rdma->postcopy) {
        postcopy_rdma_incoming_prepare_ram_block(rdma, umem_blocks);
    }

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            fprintf(stderr, "rdma: error registering %d control!\n", idx);
            goto err_rdma_dest_wait;
        }
    }

    qemu_set_fd_handler2(rdma->channel->fd, NULL, NULL, NULL, NULL);

    ret = rdma_accept(rdma->cm_id, &conn_param);
    if (ret) {
        fprintf(stderr, "rdma_accept returns %d!\n", ret);
        goto err_rdma_dest_wait;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        fprintf(stderr, "rdma_accept get_cm_event failed %d!\n", ret);
        goto err_rdma_dest_wait;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        fprintf(stderr, "rdma_accept not event established!\n");
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    rdma_ack_cm_event(cm_event);
    rdma->connected = true;

    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting second control recv!\n");
        goto err_rdma_dest_wait;
    }

    qemu_rdma_dump_gid("dest_connect", rdma->cm_id);

    return 0;

err_rdma_dest_wait:
    rdma->error_state = ret;
    qemu_rdma_cleanup(rdma);
    return ret;
}

static int qemu_rdma_ram_blocks_request(RDMAContext *rdma,
                                        RDMAControlHeader *blocks)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    int ret;
    int i;

    blocks->type = RDMA_CONTROL_RAM_BLOCKS_RESULT;
    blocks->repeat = 1;
    if (rdma->pin_all) {
        ret = qemu_rdma_reg_whole_ram_blocks(rdma);
        if (ret) {
            fprintf(stderr, "rdma migration: error dest "
                    "registering ram blocks!\n");
            return ret;
        }
    }

    /*
     * Dest uses this to prepare to transmit the RAMBlock descriptions
     * to the source VM after connection setup.
     * Both sides use the "remote" structure to communicate and update
     * their "local" descriptions with what was sent.
     */
    for (i = 0; i < local->nb_blocks; i++) {
        rdma->block[i].remote_host_addr =
            (uint64_t)(local->block[i].local_host_addr);

        if (rdma->pin_all) {
            rdma->block[i].remote_rkey = local->block[i].mr->rkey;
        }

        rdma->block[i].offset = local->block[i].offset;
        rdma->block[i].length = local->block[i].length;

        remote_block_to_network(&rdma->block[i]);
    }

    blocks->len = local->nb_blocks * sizeof(rdma->block[0]);
    return 0;
}

/*
 * During each iteration of the migration, we listen for instructions
 * by the source VM to perform dynamic page registrations before they
 * can perform RDMA operations.
 *
 * We respond with the 'rkey'.
 *
 * Keep doing this until the source tells us to stop.
 */
static int qemu_rdma_registration_handle(QEMUFile *f, void *opaque,
                                         uint64_t flags)
{
    RDMAControlHeader reg_resp = { .len = sizeof(RDMARegisterResult),
                               .type = RDMA_CONTROL_REGISTER_RESULT,
                               .repeat = 0,
                             };
    RDMAControlHeader unreg_resp = { .len = 0,
                               .type = RDMA_CONTROL_UNREGISTER_FINISHED,
                               .repeat = 0,
                             };
    RDMAControlHeader blocks;
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMAControlHeader head;
    RDMARegister *reg, *registers;
    RDMACompress *comp;
    RDMARegisterResult *reg_result;
    static RDMARegisterResult results[RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE];
    RDMALocalBlock *block;
    void *host_addr;
    int ret = 0;
    int idx = 0;
    int count = 0;

    CHECK_ERROR_STATE();

    do {
        DDDPRINTF("Waiting for next request %" PRIu64 "...\n", flags);

        ret = qemu_rdma_exchange_recv(rdma, &head, RDMA_CONTROL_NONE);

        if (ret < 0) {
            break;
        }

        if (head.repeat > RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE) {
            fprintf(stderr, "rdma: Too many requests in this message (%d)."
                            "Bailing.\n", head.repeat);
            ret = -EIO;
            break;
        }

        switch (head.type) {
        case RDMA_CONTROL_COMPRESS:
            comp = (RDMACompress *) rdma->wr_data[idx].control_curr;
            network_to_compress(comp);

            DDPRINTF("Zapping zero chunk: %" PRId64
                    " bytes, index %d, offset %" PRId64 "\n",
                    comp->length, comp->block_idx, comp->offset);
            block = &(rdma->local_ram_blocks.block[comp->block_idx]);

            host_addr = block->local_host_addr +
                            (comp->offset - block->offset);

            ram_handle_compressed(host_addr, comp->value, comp->length);
            break;

        case RDMA_CONTROL_REGISTER_FINISHED:
            DDDPRINTF("Current registrations complete.\n");
            goto out;

        case RDMA_CONTROL_RAM_BLOCKS_REQUEST:
            DPRINTF("Initial setup info requested.\n");
            ret = qemu_rdma_ram_blocks_request(rdma, &blocks);
            if (ret) {
                goto out;
            }

            ret = qemu_rdma_post_send_control(rdma,
                                        (uint8_t *) rdma->block, &blocks);

            if (ret < 0) {
                fprintf(stderr, "rdma migration: error sending remote info!\n");
                goto out;
            }

            break;
        case RDMA_CONTROL_REGISTER_REQUEST:
            DDPRINTF("There are %d registration requests\n", head.repeat);

            reg_resp.repeat = head.repeat;
            registers = (RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                uint64_t chunk;

                reg = &registers[count];
                network_to_register(reg);

                reg_result = &results[count];

                DDPRINTF("Registration request (%d): index %d, current_addr %"
                         PRIu64 " chunks: %" PRIu64 "\n", count,
                         reg->current_index, reg->key.current_addr, reg->chunks);

                block = &(rdma->local_ram_blocks.block[reg->current_index]);
                if (block->is_ram_block) {
                    host_addr = (block->local_host_addr +
                                (reg->key.current_addr - block->offset));
                    chunk = ram_chunk_index(block->local_host_addr,
                                            (uint8_t *) host_addr);
                } else {
                    chunk = reg->key.chunk;
                    host_addr = block->local_host_addr +
                        (reg->key.chunk * (1UL << RDMA_REG_CHUNK_SHIFT));
                }
                if (qemu_rdma_register_and_get_keys(rdma, block,
                            (uint8_t *)host_addr, NULL, &reg_result->rkey,
                            chunk)) {
                    fprintf(stderr, "cannot get rkey!\n");
                    ret = -EINVAL;
                    goto out;
                }

                reg_result->host_addr = (uint64_t) block->local_host_addr;

                DDPRINTF("Registered rkey for this request: %x\n",
                                reg_result->rkey);

                result_to_network(reg_result);
            }

            ret = qemu_rdma_post_send_control(rdma,
                            (uint8_t *) results, &reg_resp);

            if (ret < 0) {
                fprintf(stderr, "Failed to send control buffer!\n");
                goto out;
            }
            break;
        case RDMA_CONTROL_UNREGISTER_REQUEST:
            DDPRINTF("There are %d unregistration requests\n", head.repeat);
            unreg_resp.repeat = head.repeat;
            registers = (RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                reg = &registers[count];
                network_to_register(reg);

                DDPRINTF("Unregistration request (%d): "
                         " index %d, chunk %" PRIu64 "\n",
                         count, reg->current_index, reg->key.chunk);

                block = &(rdma->local_ram_blocks.block[reg->current_index]);

                ret = ibv_dereg_mr(block->pmr[reg->key.chunk]);
                block->pmr[reg->key.chunk] = NULL;

                if (ret != 0) {
                    perror("rdma unregistration chunk failed");
                    ret = -ret;
                    goto out;
                }

                rdma->total_registrations--;

                DDPRINTF("Unregistered chunk %" PRIu64 " successfully.\n",
                            reg->key.chunk);
            }

            ret = qemu_rdma_post_send_control(rdma, NULL, &unreg_resp);

            if (ret < 0) {
                fprintf(stderr, "Failed to send control buffer!\n");
                goto out;
            }
            break;
        case RDMA_CONTROL_REGISTER_RESULT:
            fprintf(stderr, "Invalid RESULT message at dest.\n");
            ret = -EIO;
            goto out;
        default:
            fprintf(stderr, "Unknown control message %s\n",
                                control_desc[head.type]);
            ret = -EIO;
            goto out;
        }
    } while (1);
out:
    if (ret < 0) {
        rdma->error_state = ret;
    }
    return ret;
}

static int qemu_rdma_registration_start(QEMUFile *f, void *opaque,
                                        uint64_t flags)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    CHECK_ERROR_STATE();

    DDDPRINTF("start section: %" PRIu64 "\n", flags);
    qemu_put_be64(f, RAM_SAVE_FLAG_HOOK);
    qemu_fflush(f);

    return 0;
}

static int qemu_rdma_ram_blocks_result(RDMAContext *rdma,
                                       const RDMAControlHeader *resp,
                                       Error **errp)
{
    int nb_remote_blocks;
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    int i;

    DPRINTF("%s:%d len %x type %x repeat %d\n", __func__, __LINE__,
            resp->len, resp->type, resp->repeat);
    if (resp->type != RDMA_CONTROL_RAM_BLOCKS_RESULT) {
        DPRINTF("%s:%d type 0x%x\n", __func__, __LINE__, resp->type);
        return -EINVAL;
    }

    nb_remote_blocks = resp->len / sizeof(RDMARemoteBlock);

    /*
     * The protocol uses two different sets of rkeys (mutually exclusive):
     * 1. One key to represent the virtual address of the entire ram block.
     *    (dynamic chunk registration disabled - pin everything with one rkey.)
     * 2. One to represent individual chunks within a ram block.
     *    (dynamic chunk registration enabled - pin individual chunks.)
     *
     * Once the capability is successfully negotiated, the destination transmits
     * the keys to use (or sends them later) including the virtual addresses
     * and then propagates the remote ram block descriptions to his local copy.
     */

    if (local->nb_blocks != nb_remote_blocks) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        ERROR(errp, "ram blocks mismatch #1! "
              "Your QEMU command line parameters are probably "
              "not identical on both the source and destination.");
        return -EINVAL;
    }

    memcpy(rdma->block, resp + 1, resp->len);
    for (i = 0; i < nb_remote_blocks; i++) {
        int j;
        network_to_remote_block(&rdma->block[i]);

        /* search local ram blocks */
        for (j = 0; j < local->nb_blocks; j++) {
            if (rdma->block[i].offset != local->block[j].offset) {
                continue;
            }

            if (rdma->block[i].length != local->block[j].length) {
                ERROR(errp, "ram blocks mismatch #2! "
                      "Your QEMU command line parameters are probably "
                      "not identical on both the source and destination.");
                return -EINVAL;
            }
            local->block[j].remote_host_addr =
                rdma->block[i].remote_host_addr;
            local->block[j].remote_rkey = rdma->block[i].remote_rkey;
            break;
        }

        if (j >= local->nb_blocks) {
            ERROR(errp, "ram blocks mismatch #3! "
                  "Your QEMU command line parameters are probably "
                  "not identical on both the source and destination.");
            return -EINVAL;
        }
        if (i != j) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            return -EINVAL;
        }
    }
    return 0;
}

/*
 * Inform dest that dynamic registrations are done for now.
 * First, flush writes, if any.
 */
static int qemu_rdma_registration_stop(QEMUFile *f, void *opaque,
                                       uint64_t flags)
{
    Error *local_err = NULL, **errp = &local_err;
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMAControlHeader head = { .len = 0, .repeat = 1 };
    int ret = 0;

    CHECK_ERROR_STATE();

    qemu_fflush(f);
    ret = qemu_rdma_drain_cq(f, rdma);

    if (ret < 0) {
        goto err;
    }

    if (flags == RAM_CONTROL_SETUP) {
        RDMAControlHeader resp = {.type = RDMA_CONTROL_RAM_BLOCKS_RESULT };
        int reg_result_idx;

        head.type = RDMA_CONTROL_RAM_BLOCKS_REQUEST;
        DPRINTF("Sending registration setup for ram blocks...\n");

        /*
         * Make sure that we parallelize the pinning on both sides.
         * For very large guests, doing this serially takes a really
         * long time, so we have to 'interleave' the pinning locally
         * with the control messages by performing the pinning on this
         * side before we receive the control response from the other
         * side that the pinning has completed.
         */
        ret = qemu_rdma_exchange_send(rdma, &head, NULL, &resp,
                    &reg_result_idx, rdma->pin_all ?
                    qemu_rdma_reg_whole_ram_blocks : NULL);
        if (ret < 0) {
            ERROR(errp, "receiving remote info!");
            return ret;
        }

        ret = qemu_rdma_ram_blocks_result(
            rdma, (RDMAControlHeader*)rdma->wr_data[reg_result_idx].control,
            errp);
        if (ret) {
            return ret;
        }
    }

    DDDPRINTF("Sending registration finish %" PRIu64 "...\n", flags);

    head.type = RDMA_CONTROL_REGISTER_FINISHED;
    ret = qemu_rdma_exchange_send(rdma, &head, NULL, NULL, NULL, NULL);

    if (ret < 0) {
        goto err;
    }

    return 0;
err:
    rdma->error_state = ret;
    return ret;
}

static int qemu_rdma_get_fd(void *opaque)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    return rdma->comp_channel->fd;
}

const QEMUFileOps rdma_read_ops = {
    .get_buffer    = qemu_rdma_get_buffer,
    .get_fd        = qemu_rdma_get_fd,
    .close         = qemu_rdma_close,
    .hook_ram_load = qemu_rdma_registration_handle,
};

const QEMUFileOps rdma_write_ops = {
    .put_buffer         = qemu_rdma_put_buffer,
    .close              = qemu_rdma_close,
    .before_ram_iterate = qemu_rdma_registration_start,
    .after_ram_iterate  = qemu_rdma_registration_stop,
    .save_page          = qemu_rdma_save_page,
};

static QEMUFile *qemu_fopen_rdma(RDMAContext *rdma, const char *mode)
{
    QEMUFileRDMA *r = g_malloc0(sizeof(QEMUFileRDMA));

    if (qemu_file_mode_is_not_valid(mode)) {
        return NULL;
    }

    r->rdma = rdma;

    if (mode[0] == 'w') {
        r->file = qemu_fopen_ops(r, &rdma_write_ops);
    } else {
        r->file = qemu_fopen_ops(r, &rdma_read_ops);
    }

    return r->file;
}

static void rdma_accept_incoming_migration(void *opaque)
{
    RDMAContext *rdma = opaque;
    int ret;
    QEMUFile *f;
    Error *local_err = NULL, **errp = &local_err;

    DPRINTF("Accepting rdma connection...\n");
    ret = qemu_rdma_accept(rdma);

    if (ret) {
        ERROR(errp, "RDMA Migration initialization failed!");
        return;
    }

    DPRINTF("Accepted migration\n");

    f = qemu_fopen_rdma(rdma, "rb");
    if (f == NULL) {
        ERROR(errp, "could not qemu_fopen_rdma!");
        qemu_rdma_cleanup(rdma);
        return;
    }

    rdma->migration_started_on_destination = 1;
    process_incoming_migration(f);
}

void rdma_start_incoming_migration(const char *host_port, Error **errp)
{
    int ret;
    RDMAContext *rdma;
    Error *local_err = NULL;

    DPRINTF("Starting RDMA-based incoming migration\n");
    rdma = qemu_rdma_data_init(host_port, &local_err);

    if (rdma == NULL) {
        goto err;
    }

    ret = qemu_rdma_dest_init(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_dest_init success\n");

    ret = rdma_listen(rdma->listen_id, 5);

    if (ret) {
        ERROR(errp, "listening on socket!");
        goto err;
    }

    DPRINTF("rdma_listen success\n");

    qemu_set_fd_handler2(rdma->channel->fd, NULL,
                         rdma_accept_incoming_migration, NULL,
                            (void *)(intptr_t) rdma);
    return;
err:
    error_propagate(errp, local_err);
    g_free(rdma);
}

void rdma_start_outgoing_migration(void *opaque,
                            const char *host_port, Error **errp)
{
    MigrationState *s = opaque;
    Error *local_err = NULL, **temp = &local_err;
    RDMAContext *rdma = qemu_rdma_data_init(host_port, &local_err);
    int ret = 0;

    DPRINTF("rdma_start_outgoing_migration\n");
    if (rdma == NULL) {
        ERROR(temp, "Failed to initialize RDMA data structures! %d", ret);
        goto err;
    }

    ret = qemu_rdma_source_init(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_source_init success\n");
    ret = qemu_rdma_connect(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_source_connect success\n");

    s->file = qemu_fopen_rdma(rdma, "wb");
    migrate_fd_connect(s);
    return;
err:
    error_propagate(errp, local_err);
    g_free(rdma);
    migrate_fd_error(s);
}

/****************************************************************************
 * RDMA Postcopy
 */

#define RDMA_POSTCOPY_VERSION_CURRENT   1
/* too large number may result in error when creating cq/qp */
/* #define RDMA_POSTCOPY_REQ_MAX           64 */
#define RDMA_POSTCOPY_REQ_MAX           16
//#define RDMA_POSTCOPY_REQ_MAX           2       /* exercise window control */
#define RDMA_POSTCOPY_REPLAY_THRESHOLD (RDMA_POSTCOPY_REQ_MAX / 2)
#define RDMA_POSTCOPY_BG_CHECK          32

/*
 * from migration-postcopy.c
 * #define MAX_PAGE_NR     ((32 * 1024 - 1 - 1 - 256 - 2) / sizeof(uint64_t))
 * adjust to RDMARegister
 */
#define RDMA_POSTCOPY_REQUEST_MAX_BUFFER        (128 * 1024)
/* #define MAX_PAGE_NR     ((RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(RDMAControlHeader)) / sizeof(RDMARequest)) */       /* too large causing ENOMEM */
#define MAX_PAGE_NR     4       /* to exercise window control */
//#define MAX_PAGE_NR     1       /* to exercise window control */
#define MAX_COMPRESS_NR (((RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(RDMAControlHeader)) / sizeof(RDMACompress)))

typedef struct QEMU_PACKED
{
    uint32_t block_index;
    uint32_t rkey;              /* unused when RDMA_CONTROL_RDMA_RESULT */
    uint64_t host_addr;         /* virtual address of incoming side
                                 * Event when RDMA_CONTROL_RDMA_RESULT
                                 * i.e. host_addr is of incoming side.
                                 * Not outgoing side.
                                 */
    uint64_t length;
} RDMARequest;

#define RDMA_POSTCOPY_RDMA_REQUEST_MAX  \
        ((RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(RDMAControlHeader)) / \
         sizeof(RDMARequest))
QEMU_BUILD_BUG_ON(RDMA_POSTCOPY_RDMA_REQUEST_MAX < MAX_PAGE_NR);

static void request_to_network(RDMARequest *req)
{
    req->block_index = htonl(req->block_index);
    req->rkey = htonl(req->rkey);
    req->host_addr = htonll(req->host_addr);
    req->length = htonll(req->length);
}

static void network_to_request(RDMARequest *req)
{
    req->block_index = ntohl(req->block_index);
    req->rkey = ntohl(req->rkey);
    req->host_addr = ntohll(req->host_addr);
    req->length = ntohll(req->length);
}

typedef struct QEMU_PAM_H
{
    uint64_t chunk;
    uint32_t block_index;
    uint32_t rkey;      /* valid only when _RESULT. */
} RDMAAsyncRegister;

#define RDMA_POSTCOPY_RDMA_AREGISTER_MAX \
    ((RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(RDMAControlHeader) / \
      sizeof(RDMAAsyncRegister)))

static void aregister_to_network(RDMAAsyncRegister *reg)
{
    reg->chunk = ntohll(reg->chunk);
    reg->block_index = ntohl(reg->block_index);
    reg->rkey = ntohl(reg->rkey);
}

static void network_to_aregister(RDMAAsyncRegister *reg)
{
    reg->chunk = htonll(reg->chunk);
    reg->block_index = htonl(reg->block_index);
    reg->rkey = htonl(reg->rkey);
}

struct RDMAPostcopyData
{
    struct ibv_mr *mr;
    uint8_t *data;
};
typedef struct RDMAPostcopyData RDMAPostcopyData;

struct RDMAPostcopyBuffer
{
    RDMAPostcopyData **free;
    unsigned int inuse;
    unsigned int size;
    RDMAPostcopyData *data;

    struct ibv_qp *qp;
    struct ibv_cq *cq;
    struct ibv_comp_channel *channel;
};
typedef struct RDMAPostcopyBuffer RDMAPostcopyBuffer;

static RDMAPostcopyBuffer*
postcopy_rdma_buffer_init(struct ibv_pd *pd,
                          struct ibv_qp *qp, struct ibv_cq *cq,
                          struct ibv_comp_channel *channel,
                          unsigned int size, bool remote_writable)
{
    int i;
    const int pagesize = getpagesize();
    int access = IBV_ACCESS_LOCAL_WRITE |
        (remote_writable? IBV_ACCESS_REMOTE_WRITE: 0);
    RDMAPostcopyBuffer *buffer = g_malloc0(sizeof(*buffer));
    buffer->free = g_malloc0(sizeof(buffer->free[0]) * size);
    buffer->size = size;
    buffer->data = g_malloc(sizeof(buffer->data[0]) * size);

    for (i = 0; i < size; i++) {
        buffer->data[i].data = qemu_memalign(pagesize,
                                             RDMA_POSTCOPY_REQUEST_MAX_BUFFER);
        buffer->data[i].mr = ibv_reg_mr(
            pd, buffer->data[i].data, RDMA_POSTCOPY_REQUEST_MAX_BUFFER,
            access);
        if (buffer->data[i].mr == NULL) {
            goto error;
        }

        buffer->free[i] = &buffer->data[i];
    }

    buffer->inuse = 0;
    buffer->qp = qp;
    buffer->cq = cq;
    buffer->channel = channel;
    DPRINTF("%s:%d qp %p cq %p ch %p %d\n",
            __func__, __LINE__, qp, cq, channel, size);
    return buffer;

error:
    for (; i >= 0; i--) {
        ibv_dereg_mr(buffer->data[i].mr);
        g_free(buffer->data[i].data);
    }
    g_free(buffer->data);
    g_free(buffer->free);
    g_free(buffer);
    return NULL;
}

static void postcopy_rdma_buffer_destroy(RDMAPostcopyBuffer *buffer)
{
    int i;
    for (i = 0; i < buffer->size; i++) {
        ibv_dereg_mr(buffer->data[i].mr);
        g_free(buffer->data[i].data);
    }
    g_free(buffer->data);
    g_free(buffer->free);
    g_free(buffer);
}

static RDMAPostcopyData*
postcopy_rdma_buffer_alloc(RDMAPostcopyBuffer *buffer)
{
    RDMAPostcopyData* ret = buffer->free[buffer->inuse];

    assert(buffer->inuse < buffer->size);
    buffer->inuse++;
    return ret;
}

static void postcopy_rdma_buffer_free(RDMAPostcopyBuffer *buffer,
                                      RDMAPostcopyData *data)
{
    assert(0 < buffer->inuse);
    assert(buffer->inuse <= buffer->size);
    buffer->inuse--;
    buffer->free[buffer->inuse] = data;
}

static bool postcopy_rdma_buffer_empty(const RDMAPostcopyBuffer *buffer)
{
    return buffer->inuse == buffer->size;
}

static uint32_t postcopy_rdma_buffer_get_index(
    const RDMAPostcopyBuffer *buffer, const RDMAPostcopyData *data)
{
    int index = data - buffer->data;
    assert(0 <= index);
    assert(index < buffer->size);
    return index;
}

static RDMAPostcopyData*
postcopy_rdma_buffer_get_data(RDMAPostcopyBuffer *buffer, int index)
{
    assert(0 <= index);
    assert(index < buffer->size);
    return &buffer->data[index];
}

static int postcopy_rdma_buffer_post_recv_data(RDMAPostcopyBuffer *buffer,
                                               RDMAPostcopyData *data)
{
    int ret;
    int index = postcopy_rdma_buffer_get_index(buffer, data);
    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {.addr = (uint64_t)(data->data),
                          .length = RDMA_POSTCOPY_REQUEST_MAX_BUFFER,
                          .lkey = data->mr->lkey,};
    struct ibv_recv_wr recv_wr = {.wr_id = index,
                                  .sg_list = &sge,
                                  .num_sge = 1,};

    DDDPRINTF("%s:%d index %d\n", __func__, __LINE__, index);
    ret = ibv_post_recv(buffer->qp, &recv_wr, &bad_wr);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        abort();
    }
    return -ret;
}

static int postcopy_rdma_buffer_post_recv(RDMAPostcopyBuffer *buffer)
{
    RDMAPostcopyData *data = postcopy_rdma_buffer_alloc(buffer);
    return postcopy_rdma_buffer_post_recv_data(buffer, data);
}

static int postcopy_rdma_buffer_post_send(RDMAPostcopyBuffer *buffer,
                                          RDMAPostcopyData *data)
{
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;
    int index = postcopy_rdma_buffer_get_index(buffer, data);
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {.addr = (uint64_t)(data->data),
                          .length = sizeof(*head) + head->len,
                          .lkey = data->mr->lkey,};
    struct ibv_send_wr send_wr = {.wr_id = index,
                                  .sg_list = &sge,
                                  .num_sge = 1,
                                  .opcode = IBV_WR_SEND,
                                  .send_flags = IBV_SEND_SIGNALED,};

    DDDPRINTF("%s:%d index %d len %x type %s 0x%x repeat %d\n",
              __func__, __LINE__, index,
              head->len, control_desc[head->type], head->type, head->repeat);
    assert(head->len < RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(*head));
    control_to_network((RDMAControlHeader*)data->data);
    return -ibv_post_send(buffer->qp, &send_wr, &bad_wr);
}

static int postcopy_rdma_buffer_post_send_buf(
    RDMAPostcopyBuffer *buffer, RDMAPostcopyData *data,
    const RDMAControlHeader *head, const uint8_t *buf)
{
    int index = postcopy_rdma_buffer_get_index(buffer, data);
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {.addr = (uint64_t)(data->data),
                          .length = sizeof(*head) + head->len,
                          .lkey = data->mr->lkey,};
    struct ibv_send_wr send_wr = {.wr_id = index,
                                  .sg_list = &sge,
                                  .num_sge = 1,
                                  .opcode = IBV_WR_SEND,
                                  .send_flags = IBV_SEND_SIGNALED,};

    DDDPRINTF("%s:%d index %d len %x type %s %x repeat %d\n",
              __func__, __LINE__, index,
              head->len, control_desc[head->type], head->type, head->repeat);
    assert(head->len < RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(*head));
    memcpy(data->data, head, sizeof(*head));
    control_to_network((RDMAControlHeader*)data->data);
    if (buf) {
        memcpy(data->data + sizeof(*head), buf, head->len);
    }
    return -ibv_post_send(buffer->qp, &send_wr, &bad_wr);
}

static int postcopy_rdma_buffer_poll(RDMAPostcopyBuffer *buffer,
                                     uint64_t *wr_id,
                                     enum ibv_wc_opcode *opcode,
                                     RDMAPostcopyData **data)
{
    int ret;
    struct ibv_wc wc;
    RDMAControlHeader *head;

    ret = ibv_poll_cq(buffer->cq, 1, &wc);
    if (ret < 0) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        return ret;
    }
    if (ret == 0) {
        return 0;
    }
    assert(ret == 1);

    *wr_id = wc.wr_id;
    *opcode = wc.opcode;
    if (wc.status != IBV_WC_SUCCESS) {
        DPRINTF("error wr_id 0x%"PRIx64" status %d %s vendor_err %"PRId32"\n",
                wc.wr_id, wc.status, ibv_wc_status_str(wc.status),
                wc.vendor_err);
        return -wc.status;
    }

    switch (wc.opcode) {
    case IBV_WC_RDMA_WRITE:
        /* nothing */
        break;
    case IBV_WC_SEND:
        *data = postcopy_rdma_buffer_get_data(buffer, wc.wr_id);
        break;
    case IBV_WC_RECV:
        if (wc.byte_len < sizeof(*head) ||
            wc.byte_len > RDMA_POSTCOPY_REQUEST_MAX_BUFFER) {
            return -EINVAL;
        }
        *data = postcopy_rdma_buffer_get_data(buffer, wc.wr_id);
        head = (RDMAControlHeader *)(*data)->data;
        network_to_control(head);
        if (head->len != wc.byte_len - sizeof(*head)) {
            DPRINTF("invalid byte_len %d != %zd + %d\n",
                    wc.byte_len, sizeof(*head), head->len);
            return -EINVAL;
        }
        switch (head->type) {
        case RDMA_CONTROL_RAM_BLOCKS_RESULT:
            /* nothing */
            break;
        case RDMA_CONTROL_READY:
            if (head->len != 0) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            break;
	case RDMA_CONTROL_COMPRESS:
            if (head->repeat == 0 ||
                head->repeat * sizeof(RDMACompress) != head->len) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            break;
	case RDMA_CONTROL_COMPRESS_RESULT:
        case RDMA_CONTROL_EOS:
        case RDMA_CONTROL_EOC:
            if (head->len != 0 || head->repeat != 0) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            break;
        case RDMA_CONTROL_RDMA_REQUEST:
        case RDMA_CONTROL_RDMA_RESULT_BG:
        case RDMA_CONTROL_RDMA_RESULT_PRE:
        case RDMA_CONTROL_BITMAP_REQUEST:
        case RDMA_CONTROL_BITMAP_RESULT:
            if (head->repeat == 0) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            /* fall through */
        case RDMA_CONTROL_RDMA_RESULT:
            if (head->repeat * sizeof(RDMARequest) != head->len) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            break;
        case RDMA_CONTROL_REGISTER_AREQUEST:
            if (head->repeat == 0) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            /* fall through */
        case RDMA_CONTROL_REGISTER_ARESULT:
            if (head->repeat * sizeof(RDMAAsyncRegister) != head->len) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                return -EINVAL;
            }
            break;
        default:
            DPRINTF("unknown type %s\n", control_desc[head->type]);
            abort();
            break;
        }
        break;
    default:
        /* other operations aren't used */
        DPRINTF("unknown wr_id 0x%"PRIx64" opcode %d status %d %s\n",
                wc.wr_id, wc.opcode, wc.status, ibv_wc_status_str(wc.status));
        if (wc.status != IBV_WC_SUCCESS) {
            return -wc.status;
        }
        abort();
        break;
    }

    return ret;
}

static int postcopy_rdma_buffer_get_wc(
    RDMAPostcopyBuffer *buffer, RDMAPostcopyData **data, RDMAContext *rdma)
{
    struct rdma_event_channel *cm_channel = rdma->channel;
    int ret = 0;
    int num_cq_events = 0;

    while (true) {
        uint64_t wr_id;
        enum ibv_wc_opcode opcode;
        fd_set fds;
        int nfds;
        int ret;
        struct ibv_cq *cq;
        void *cq_ctx;

        ret = ibv_req_notify_cq(buffer->cq, 0);
        if (ret) {
            ret = -ret;
            break;
        }
        ret = postcopy_rdma_buffer_poll(buffer, &wr_id, &opcode, data);
        if (ret < 0) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            break;
        }
        if (ret == 1) {
            if (opcode != IBV_WC_RECV) {
                ret = -EINVAL;
                break;
            }
            ret = 0;
            break;
        }

        FD_ZERO(&fds);
        FD_SET(cm_channel->fd, &fds);
        FD_SET(buffer->channel->fd, &fds);
        nfds = MAX(cm_channel->fd, buffer->channel->fd);
        ret = select(nfds + 1, &fds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ret;
        }
        if (FD_ISSET(cm_channel->fd, &fds)) {
            struct rdma_cm_event *cm_event;
            ret = rdma_get_cm_event(cm_channel, &cm_event);
            if (ret) {
                perror("rdma_get_cm_event\n");
                DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                return ret;
            }
            DPRINTF("cm_event %s\n", rdma_event_str(cm_event->event));
            if (cm_event->event == RDMA_CM_EVENT_DISCONNECTED) {
                DPRINTF("%s:%d\n", __func__, __LINE__);
                rdma_ack_cm_event(cm_event);
                rdma->connected = false;
                *data = NULL;
                break;
            }
            rdma_ack_cm_event(cm_event);
        }
        if (FD_ISSET(buffer->channel->fd, &fds)) {
            ret = ibv_get_cq_event(buffer->channel, &cq, &cq_ctx);
            if (ret < 0) {
                break;
            }
            num_cq_events++;
        }
    }

    if (num_cq_events) {
        ibv_ack_cq_events(buffer->cq, num_cq_events);
    }
    return ret;
}

static void postcopy_rdma_buffer_drain(RDMAPostcopyBuffer *buffer)
{
    while (true) {
        int ret;
        uint64_t wr_id;
        enum ibv_wc_opcode opcode;
        RDMAPostcopyData *data;

        ret = postcopy_rdma_buffer_poll(buffer, &wr_id, &opcode, &data);
        if (ret < 0) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            break;
        }
        if (ret == 0) {
            break;
        }
    }
}

#define RDMA_POSTCOPY_EMPTY_WRID        (~0ULL)
static void postcopy_rdma_buffer_cq_empty(RDMAPostcopyBuffer *buffer)
{
    int ret;
    struct ibv_send_wr wr = {
        .wr_id = RDMA_POSTCOPY_EMPTY_WRID,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED,
        .sg_list = NULL,
        .num_sge = 0,
    };
    struct ibv_send_wr *bad_wr;

    postcopy_rdma_buffer_drain(buffer);
    ret = ibv_req_notify_cq(buffer->cq, 0);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        return;
    }

    ret = ibv_post_send(buffer->qp, &wr, &bad_wr);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        return;
    }

    while (true) {
        struct ibv_cq *cq;
        void *cq_ctx;

        ret = ibv_get_cq_event(buffer->channel, &cq, &cq_ctx);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            return;
        }
        ret = ibv_req_notify_cq(buffer->cq, 0);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            return;
        }
        ibv_ack_cq_events(buffer->cq, 1);

        while (true) {
            struct ibv_wc wc;
            ret = ibv_poll_cq(buffer->cq, 1, &wc);
            if (ret < 0) {
                DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                return;
            }
            if (ret == 0) {
                break;
            }
            assert(ret == 1);

            if (wc.wr_id == RDMA_POSTCOPY_EMPTY_WRID) {
                return;
            }
        }
    }
}

/****************************************************************************
 * RDMA postcopy outgoing part
 */

/* TODO:XXX temporal. find best value */
#define RDMA_POSTCOPY_BG_QUEUED_MAX_BYTES       (16 * 1024 * 1024)

enum RDMA_POSTCOPY_RDMA_TYPE {
    RDMA_POSTCOPY_RDMA_SEND = 0,
    RDMA_POSTCOPY_RDMA_ONDEMAND,
    RDMA_POSTCOPY_RDMA_BACKGROUND,
    RDMA_POSTCOPY_RDMA_PREFAULT,
    RDMA_POSTCOPY_RDMA_BITMAP,
};
typedef enum RDMA_POSTCOPY_RDMA_TYPE RDMA_POSTCOPY_RDMA_TYPE;

struct RDMAPostcopyInflight
{
    RDMA_POSTCOPY_RDMA_TYPE rdma_type;
    unsigned int nb;
    uint64_t bytes;
};
typedef struct RDMAPostcopyInflight RDMAPostcopyInflight;

struct RDMAPostcopySavePage {
#define RDMA_POSTCOPY_OUTGOING_SAVE_INVALID  (-1)
    int rdma_index;

    RDMALocalBlock *local_block;
    struct ibv_sge sge;
    struct ibv_send_wr wr;
};
typedef struct RDMAPostcopySavePage RDMAPostcopySavePage;

struct RDMAPostcopyOutgoing
{
    RDMAContext *rdma;

    struct rdma_cm_id *cm_id;
    struct rdma_event_channel *channel;
    struct ibv_context *verbs;

    struct ibv_pd *pd;
    struct ibv_cq *scq;
    struct ibv_comp_channel *s_comp_channel;
    struct ibv_cq *rcq;
    struct ibv_comp_channel *r_comp_channel;
    struct ibv_qp *qp;

    RDMAPostcopyBuffer *sbuffer;
    RDMAPostcopyBuffer *rbuffer;

    MigrationState *ms;
    MigrationRateLimitStat *rlstat;

    RDMAPostcopyInflight *inflight;     /* indexed by sbuffer index */

    unsigned int nb_rdma_total;
    uint64_t bytes_rdma_total;
    unsigned int nb_bg_total;
    uint64_t bytes_bg_total;
    unsigned int nb_pre_total;
    uint64_t bytes_pre_total;

    unsigned int nb_compress;
    RDMAPostcopySavePage bg_save;

    unsigned int nb_bg_result;
    unsigned int nb_register;
    bool bg_break_loop;

    /* the number of register request and rdma_result_bg in flight */
    unsigned int nb_inflight;
};

static const QEMUFileOps postcopy_rdma_outgoing_write_ops;

void postcopy_rdma_outgoing_cleanup(RDMAPostcopyOutgoing *outgoing)
{
    RDMAContext *rdma = outgoing->rdma;
    struct rdma_cm_event *cm_event;

    if (rdma && rdma->cm_id && rdma->connected) {
        postcopy_rdma_buffer_cq_empty(outgoing->sbuffer);
        int ret = rdma_disconnect(rdma->cm_id);
        if (!ret) {
            DDPRINTF("waiting for disconnect\n");
            ret = rdma_get_cm_event(rdma->channel, &cm_event);
            if (!ret) {
                rdma_ack_cm_event(cm_event);
            }
        }
        DDPRINTF("Disconnected.\n");
        rdma->connected = false;

        postcopy_rdma_buffer_drain(outgoing->rbuffer);
        postcopy_rdma_buffer_drain(outgoing->sbuffer);
    }
    if (outgoing->qp) {
        rdma_destroy_qp(outgoing->rdma->cm_id);
        outgoing->qp = NULL;
    }
    if (outgoing->scq) {
        ibv_destroy_cq(outgoing->scq);
        outgoing->scq = NULL;
    }
    if (outgoing->rcq) {
        ibv_destroy_cq(outgoing->rcq);
        outgoing->rcq = NULL;
    }
    if (outgoing->s_comp_channel) {
        ibv_destroy_comp_channel(outgoing->s_comp_channel);
        outgoing->s_comp_channel = NULL;
    }
    if (outgoing->r_comp_channel) {
        ibv_destroy_comp_channel(outgoing->r_comp_channel);
        outgoing->r_comp_channel = NULL;
    }
    if (outgoing->pd) {
        ibv_dealloc_pd(outgoing->pd);
        outgoing->pd = NULL;
    }
    if (outgoing->rdma) {
        qemu_rdma_cleanup(outgoing->rdma);
        outgoing->rdma = NULL;
    }
    if (outgoing->sbuffer) {
        postcopy_rdma_buffer_destroy(outgoing->sbuffer);
    }
    if (outgoing->rbuffer) {
        postcopy_rdma_buffer_destroy(outgoing->rbuffer);
    }
    g_free(rdma);
    g_free(outgoing->inflight);
    g_free(outgoing);
}

static int postcopy_rdma_outgoing_alloc_pd_cq_qp(
    RDMAPostcopyOutgoing *outgoing)
{
    struct RDMAContext *rdma = outgoing->rdma;
    struct ibv_qp_init_attr attr;
    int ret;

    uint32_t scqe =
        /* RDMA WRITE for RDMARequest + RDMA result */
        RDMA_POSTCOPY_REQ_MAX * (MAX_PAGE_NR + 1)
        /* RDMACompress */
        + RDMA_POSTCOPY_REQ_MAX
        /* Register request */
        + RDMA_POSTCOPY_REQ_MAX * MAX_PAGE_NR
        /* RDMA for BG + RDMA result BG */
        + RDMA_POSTCOPY_REQ_MAX * (MAX_PAGE_NR + 1)
        /* RDMA for BG + RDMA result PRE froward */
        + RDMA_POSTCOPY_REQ_MAX * (MAX_PAGE_NR + 1)
        /* RDMA for BG + RDMA result PRE backward */
        + RDMA_POSTCOPY_REQ_MAX * (MAX_PAGE_NR + 1)
        /* for EOS */
        + 1;
    uint32_t rcqe =
        /* for RDMA Request */
        + RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Compress result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for Register Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for READY */
        + RDMA_POSTCOPY_REQ_MAX
        /* for EOC */
        + 1;

    /* allocate pd */
    outgoing->pd = ibv_alloc_pd(outgoing->verbs);
    if (!outgoing->pd) {
        fprintf(stdout, "failed to allocate protection domain\n");
        return -1;
    }
    rdma->pd = outgoing->pd;    /* qemu_rdma_register_and_get_keys() uses */

    /* create send completion channel */
    outgoing->s_comp_channel = ibv_create_comp_channel(outgoing->verbs);
    if (!outgoing->s_comp_channel) {
        fprintf(stdout, "failed to allocate send completion channel\n");
        goto err_alloc_pd_cq;
    }
    outgoing->scq = ibv_create_cq(outgoing->verbs,
                                  scqe, NULL, outgoing->s_comp_channel, 0);
    if (!outgoing->scq) {
        fprintf(stdout, "failed to allocate send completion queue\n");
        goto err_alloc_pd_cq;
    }

    /* create recv completion channel */
    outgoing->r_comp_channel = ibv_create_comp_channel(outgoing->verbs);
    if (!outgoing->r_comp_channel) {
        fprintf(stdout, "failed to allocate recv completion channel\n");
        goto err_alloc_pd_cq;
    }
    outgoing->rcq = ibv_create_cq(outgoing->verbs,
                                  rcqe, NULL, outgoing->r_comp_channel, 0);
    if (!outgoing->rcq) {
        fprintf(stdout, "failed to allocate recv completion queue\n");
        goto err_alloc_pd_cq;
    }

    /* allocate qp */
    attr.qp_context = NULL;
    attr.send_cq = outgoing->scq;
    attr.recv_cq = outgoing->rcq;
    attr.srq = NULL;
    attr.cap.max_send_wr = scqe;
    attr.cap.max_recv_wr = rcqe;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.cap.max_inline_data = 0;
    attr.qp_type = IBV_QPT_RC;
    attr.sq_sig_all = 0;

    ret = rdma_create_qp(outgoing->cm_id, outgoing->pd, &attr);
    if (ret) {
        perror("rdma_create_qp\n");
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto err_alloc_pd_cq;
    }
    outgoing->qp = rdma->cm_id->qp;
    DPRINTF("send_wr requested %d result %d\n", scqe, attr.cap.max_send_wr);
    DPRINTF("recv_wr requested %d result %d\n", rcqe, attr.cap.max_recv_wr);
    if (attr.cap.max_send_wr < scqe || attr.cap.max_recv_wr < rcqe) {
        abort();
    }

    return 0;

err_alloc_pd_cq:
    DPRINTF("%s:%d\n", __func__, __LINE__);
    if (outgoing->rcq) {
        ibv_destroy_cq(outgoing->rcq);
    }
    if (outgoing->r_comp_channel) {
        ibv_destroy_comp_channel(outgoing->r_comp_channel);
    }
    if (outgoing->scq) {
        ibv_destroy_cq(outgoing->scq);
    }
    if (outgoing->s_comp_channel) {
        ibv_destroy_comp_channel(outgoing->s_comp_channel);
    }
    if (outgoing->pd) {
        ibv_dealloc_pd(outgoing->pd);
    }

    outgoing->pd = NULL;
    outgoing->s_comp_channel = NULL;
    outgoing->scq = NULL;
    outgoing->r_comp_channel = NULL;
    outgoing->rcq = NULL;
    outgoing->qp = NULL;
    return -1;

}

static int postcopy_rdma_outgoing_init(RDMAPostcopyOutgoing *outgoing)
{
    int ret;
    RDMAContext *rdma = outgoing->rdma;
    RDMALocalBlocks *local_ram_blocks = &rdma->local_ram_blocks;
    int index;
    RAMBlock *ram_block;

    rdma->pin_all = migrate_rdma_pin_all();
    rdma->postcopy = migrate_postcopy_outgoing();

    DPRINTF("%s:%d\n", __func__, __LINE__);
    ret = qemu_rdma_resolve_host(rdma, NULL);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }

    outgoing->cm_id = rdma->cm_id;
    outgoing->verbs = rdma->verbs;
    ret = postcopy_rdma_outgoing_alloc_pd_cq_qp(outgoing);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    for (index = 0; index < local_ram_blocks->nb_blocks; index++) {
        RDMALocalBlock *local_block = &local_ram_blocks->block[index];
        local_block->nb_rdma = g_malloc0(sizeof(local_block->nb_rdma[0]) *
                                         local_block->nb_chunks);
    }

    index = 0;
    QTAILQ_FOREACH(ram_block, &ram_list.blocks, next) {
        rdma->local_ram_blocks.block[index].ram_block = ram_block;
        index++;
    }
    return 0;

error:
    postcopy_rdma_outgoing_cleanup(outgoing);
    return ret;
}

/* TODO: consolidate qemu_rdma_connect() */
static int postcopy_rdma_outgoing_connect(RDMAPostcopyOutgoing *outgoing)
{
    RDMAContext *rdma = outgoing->rdma;
    RDMACapabilities cap = { .version = RDMA_CONTROL_VERSION_CURRENT,
                             .flags = 0,
                           };
    struct rdma_conn_param conn_param = { .initiator_depth = 2,
                                          .retry_count = 5,
                                          .private_data = &cap,
                                          .private_data_len = sizeof(cap),
                                        };
    struct rdma_cm_event *cm_event;
    int ret;

    /*
     * Only negotiate the capability with destination if the user
     * on the source first requested the capability.
     */
    if (rdma->pin_all) {
        DPRINTF("Server pin-all memory requested.\n");
        cap.flags |= RDMA_CAPABILITY_PIN_ALL;
    }
    if (rdma->postcopy) {
        DPRINTF("Server postcopy requested.\n");
        cap.flags |= RDMA_CAPABILITY_POSTCOPY;
    }

    caps_to_network(&cap);

    ret = rdma_connect(rdma->cm_id, &conn_param);
    if (ret) {
        perror("rdma_connect");
        return -1;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        perror("rdma_get_cm_event after rdma_connect");
        rdma_ack_cm_event(cm_event);
        return -1;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        fprintf(stdout, "event %s %d\n", rdma_event_str(cm_event->event),
                cm_event->status);
        perror("rdma_get_cm_event != EVENT_ESTABLISHED after rdma_connect");
        rdma_ack_cm_event(cm_event);
        return -1;
    }
    rdma->connected = true;

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));
    network_to_caps(&cap);
    rdma_ack_cm_event(cm_event);

    /*
     * Verify that the *requested* capabilities are supported by the destination
     * and disable them otherwise.
     */
    if (rdma->pin_all && !(cap.flags & RDMA_CAPABILITY_PIN_ALL)) {
        rdma->pin_all = false;
    }
    if (rdma->postcopy && !(cap.flags & RDMA_CAPABILITY_POSTCOPY)) {
        rdma->postcopy = false;
        return -1;
    }

    DPRINTF("Pin all memory: %s\n", rdma->pin_all ? "enabled" : "disabled");
    DPRINTF("Postcopy: %s\n", rdma->postcopy ? "enabled" : "disabled");

    return 0;
}

static void postcopy_rdma_outgoing_reap_clean_bitmap(
    RDMAPostcopyOutgoing *outgoing)
{
    RDMALocalBlocks *local_ram_blocks = &outgoing->rdma->local_ram_blocks;
    int i;

    for (i = 0; i < local_ram_blocks->nb_blocks; i++) {
        RDMALocalBlock *local_block = &local_ram_blocks->block[i];
        if (local_block->bitmap_key != NULL) {
            ibv_dereg_mr(local_block->bitmap_key);
        }
        g_free(local_block->clean_bitmap);
        local_block->clean_bitmap = NULL;
    }
}

static int postcopy_rdma_outgoing_send_clean_bitmap(
    RDMAPostcopyOutgoing *outgoing)
{
    int ret = 0;
    const unsigned long *bitmap = migration_bitmap_get();
    RDMAPostcopyData *data;
    RDMAControlHeader *head;

    RDMAPostcopyData *sdata;
    RDMAControlHeader *res_head;
    RDMARequest *result;
    uint32_t sdata_index;

    RDMAContext *rdma = outgoing->rdma;
    RDMALocalBlocks *local_ram_blocks = &rdma->local_ram_blocks;
    int nb_request;

    ret = postcopy_rdma_buffer_get_wc(outgoing->rbuffer, &data, rdma);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return -EINVAL;
    }
    if (data == NULL) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return -ESHUTDOWN;
    }
    head = (RDMAControlHeader*)data->data;

    sdata = postcopy_rdma_buffer_alloc(outgoing->sbuffer);
    sdata_index = postcopy_rdma_buffer_get_index(outgoing->sbuffer, sdata);
    outgoing->inflight[sdata_index].rdma_type = RDMA_POSTCOPY_RDMA_BITMAP;
    assert(outgoing->inflight[sdata_index].nb == 0);
    assert(outgoing->inflight[sdata_index].bytes == 0);

    res_head = (RDMAControlHeader*)sdata->data;
    *res_head = *head;
    res_head->type = RDMA_CONTROL_BITMAP_RESULT;
    result = (RDMARequest*)(res_head + 1);

    for (nb_request = 0; nb_request < head->repeat; nb_request++) {
        RDMARequest *request = (RDMARequest *)(head + 1) + nb_request;
        RDMALocalBlock *local_block;
        uint64_t length;
        uint64_t *clean_bitmap;
        uint64_t start;
        uint64_t end;
        uint64_t end_uint64;
        int i;
        uint64_t val;
        unsigned long tmp[sizeof(uint64_t) / sizeof(unsigned long)];
        struct ibv_sge sge;
        struct ibv_send_wr wr;
        struct ibv_send_wr *bad_wr;

        network_to_request(request);
        local_block = &local_ram_blocks->block[request->block_index];
        if (local_block->clean_bitmap != NULL) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            ret = -EINVAL;
            goto error;
        }

        length = postcopy_bitmap_length(local_block->length);
        start = local_block->offset >> TARGET_PAGE_BITS;
        end = (local_block->offset + local_block->length) >> TARGET_PAGE_BITS;
        end_uint64 = start + ((end - start) & ~63);

        clean_bitmap = g_malloc(length);
        local_block->clean_bitmap = clean_bitmap;
        if (start % 64 == 0) {
            for (i = start; i < end_uint64; i += 64) {
                val = postcopy_bitmap_to_uint64(&bitmap[BIT_WORD(i)]);
                val = ~val;
                clean_bitmap[(i - start) / 64] = cpu_to_be64(val);
            }
        } else {
            for (i = start; i < end_uint64; i += 64) {
                int j;
                bitmap_zero(tmp, 64);
                for (j = 0; j < 63; j++) {
                    if (!test_bit(i + j, bitmap)) {
                        set_bit(j, tmp);
                    }
                }
                val = postcopy_bitmap_to_uint64(tmp);
                clean_bitmap[(i - start) / 64] = cpu_to_be64(val);
            }
        }
        if (end_uint64 < end) {
            bitmap_zero(tmp, 64);
            for (i = end_uint64; i < end; i++) {
                if (!test_bit(i, bitmap)) {
                    set_bit(i - end_uint64, tmp);
                }
            }
            val = postcopy_bitmap_to_uint64(tmp);
            clean_bitmap[(end_uint64 - start) / 64] = cpu_to_be64(val);
        }

        local_block->bitmap_key = ibv_reg_mr(
            outgoing->pd, clean_bitmap, length, IBV_ACCESS_LOCAL_WRITE);
        if (local_block->bitmap_key == NULL) {
            ret = -errno;
            DPRINTF("%s:%d\n", __func__, __LINE__);
            goto error;
        }

        sge.addr = (uint64_t)clean_bitmap;
        sge.length = length;
        sge.lkey = local_block->bitmap_key->lkey;
        wr.wr_id = postcopy_rdma_buffer_get_index(outgoing->sbuffer, sdata);
        wr.next = NULL;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_RDMA_WRITE;
        wr.send_flags = 0;
        wr.wr.rdma.remote_addr = request->host_addr;
        wr.wr.rdma.rkey = request->rkey;
        ret = ibv_post_send(outgoing->qp, &wr, &bad_wr);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            ret = -ret;
            goto error;
        }

        *result = *request;
        DDDPRINTF("%s:%d index %d 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx32"\n",
                  __func__, __LINE__, result->block_index,
                  result->host_addr, result->length, result->rkey);
        request_to_network(result);
        result++;
    }
    DDDPRINTF("%s:%d repeat %d\n", __func__, __LINE__, head->repeat);
    postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
    return postcopy_rdma_buffer_post_send(outgoing->sbuffer, sdata);

error:
    postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
    postcopy_rdma_outgoing_reap_clean_bitmap(outgoing);
    postcopy_rdma_buffer_free(outgoing->sbuffer, data);
    return ret;
}

int postcopy_rdma_outgoing(MigrationState *ms, MigrationRateLimitStat *rlstat)
{
    int ret;
    int i;
    RDMAContext *rdma;
    RDMAPostcopyOutgoing *outgoing;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    uint32_t scqe =
        /* for RDMA Result */
        RDMA_POSTCOPY_REQ_MAX
        /* for RDMA COMPRESS */
        + RDMA_POSTCOPY_REQ_MAX + 1
        /* for Register Request */
        + RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Result BG */
        + RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Result PRE forward */
        + RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Result PRE backward */
        + RDMA_POSTCOPY_REQ_MAX
        /* for EOS */
        + 1;
    uint32_t rcqe =
        /* for RDMA Request */
        RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Compress result */
        + RDMA_POSTCOPY_REQ_MAX
        /* Register Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* Ready */
        + RDMA_POSTCOPY_REQ_MAX
        /* for EOC */
        + 1;

    outgoing = g_malloc0(sizeof(*ms->rdma_outgoing));
    outgoing->bg_save.rdma_index = RDMA_POSTCOPY_OUTGOING_SAVE_INVALID;
    qemu_fclose_null(ms->file, outgoing, &postcopy_rdma_outgoing_write_ops);

    rdma = qemu_rdma_data_init(current_host_port, NULL);
    if (rdma == NULL) {
        g_free(outgoing);
        return -EINVAL;
    }

    outgoing->rdma = rdma;

    ret = postcopy_rdma_outgoing_init(outgoing);
    if (ret) {
        goto error;
    }

    outgoing->inflight = g_malloc0(sizeof(outgoing->inflight[0]) * scqe);
    outgoing->sbuffer = postcopy_rdma_buffer_init(
        outgoing->pd, outgoing->qp, outgoing->scq, outgoing->s_comp_channel,
        scqe, false);
    outgoing->rbuffer = postcopy_rdma_buffer_init(
        outgoing->pd, outgoing->qp, outgoing->rcq, outgoing->r_comp_channel,
        rcqe, true);
    if (outgoing->sbuffer == NULL || outgoing->rbuffer == NULL) {
        ret = -ENOMEM;
        goto error;
    }
    for (i = 0; i < outgoing->rbuffer->size; i++) {
        ret = postcopy_rdma_buffer_post_recv(outgoing->rbuffer);
        if (ret) {
            goto error;
        }
    }

    ret = postcopy_rdma_outgoing_connect(outgoing);
    if (ret) {
        goto error;
    }

    ms->rdma_outgoing = outgoing;
    outgoing->ms = ms;
    outgoing->rlstat = rlstat;

    if (outgoing->ms->params.precopy_count > 0) {
        ret = postcopy_rdma_outgoing_send_clean_bitmap(outgoing);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            goto error;
        }
    }

    ret = postcopy_rdma_buffer_get_wc(outgoing->rbuffer, &data, rdma);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        ret = -EINVAL;
        goto error;
    }
    if (data == NULL) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        ret = -ESHUTDOWN;
        goto error;
    }
    head = (RDMAControlHeader*)data->data;
    ret = qemu_rdma_ram_blocks_result(rdma, head, NULL);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);

    DPRINTF("%s:%d postcopy_rdma_outgoing done\n", __func__, __LINE__);
    return 0;

error:
    postcopy_rdma_outgoing_cleanup(outgoing);
    return ret;
}

static void postcopy_rdma_outgoing_rdma_done(RDMAPostcopyOutgoing *outgoing,
                                             uint64_t wr_id)
{
    const unsigned long *migration_bitmap = migration_bitmap_get();
    RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                           wr_id);
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;
    int i;

    /* data->data is bswapped when post_send. So bswap it again before
     * referencing it
     */
    network_to_control(head);
    assert(head->repeat == head->len / sizeof(RDMARequest));
    for (i = 0; i < head->repeat; i++) {
        RDMARequest *result = (RDMARequest *)(head + 1) + i;
        RDMALocalBlock *local_block;
        uint64_t chunk;
        int bit_s;
        int bit_e;

        network_to_request(result);
        local_block =
            &outgoing->rdma->local_ram_blocks.block[result->block_index];
        chunk = ram_chunk_index((uint8_t*)local_block->remote_host_addr,
                                (uint8_t*)result->host_addr);
        bit_s = (local_block->offset + (chunk << RDMA_REG_CHUNK_SHIFT)) >>
            TARGET_PAGE_BITS;
        bit_e = MIN(bit_s + (RDMA_REG_CHUNK_SIZE >> TARGET_PAGE_BITS),
                    ((local_block->offset + local_block->length) >>
                     TARGET_PAGE_BITS) + 1);

        local_block->nb_rdma[chunk]--;
        if (local_block->nb_rdma[chunk] > 0) {
            continue;
        }
        if (local_block->pmr[chunk] == NULL) {
            continue;
        }
        if (test_bit(local_block->bit[chunk], migration_bitmap)) {
            continue;
        }
        local_block->bit[chunk] = find_next_bit(migration_bitmap, bit_e,
                                                local_block->bit[chunk]);
        if (local_block->bit[chunk] == bit_e) {
            DDDPRINTF("%s:%d dereg_mr block_index %d chunk %"PRIx64
                      " key %"PRIx32" total %d\n",
                      __func__, __LINE__, local_block->index, chunk,
                      local_block->pmr[chunk]->lkey,
                      outgoing->rdma->total_registrations);
            ibv_dereg_mr(local_block->pmr[chunk]);
            local_block->pmr[chunk] = NULL;
            outgoing->rdma->total_registrations--;
        }
    }
}

static void postcopy_rdma_outgoing_reap_send(
    RDMAPostcopyOutgoing *outgoing, uint64_t wr_id)
{
    uint64_t bytes;
    DDDPRINTF("%s:%d RDMA wr_id 0x%"PRIx64" nb %u\n",
              __func__, __LINE__, wr_id, outgoing->inflight[wr_id].nb);
    assert(wr_id != outgoing->bg_save.rdma_index);

    bytes = outgoing->inflight[wr_id].bytes;
    switch (outgoing->inflight[wr_id].rdma_type) {
    case RDMA_POSTCOPY_RDMA_SEND:
        /* nothing */
        assert(outgoing->inflight[wr_id].nb == 0);
        assert(outgoing->inflight[wr_id].bytes == 0);
        break;
    case RDMA_POSTCOPY_RDMA_BITMAP:
        postcopy_rdma_outgoing_reap_clean_bitmap(outgoing);
        break;
    case RDMA_POSTCOPY_RDMA_ONDEMAND:
        outgoing->inflight[wr_id].nb = 0;
        outgoing->inflight[wr_id].bytes = 0;
        if (bytes == 0) {
            /* in case of ONDEMAND, result is sent back for window control
             * even when no RDMA WRITE is done.
             */
            break;
        }
        assert(outgoing->nb_rdma_total > 0);
        assert(outgoing->bytes_rdma_total >= bytes);
        outgoing->bytes_rdma_total -= bytes;
        outgoing->nb_rdma_total--;
        postcopy_rdma_outgoing_rdma_done(outgoing, wr_id);
        break;
    case RDMA_POSTCOPY_RDMA_BACKGROUND:
        assert(outgoing->inflight[wr_id].nb > 0);
        assert(outgoing->inflight[wr_id].bytes > 0);
        outgoing->inflight[wr_id].nb = 0;
        outgoing->inflight[wr_id].bytes = 0;
        assert(outgoing->nb_bg_total > 0);
        assert(outgoing->bytes_bg_total >= bytes);
        outgoing->bytes_bg_total -= bytes;
        outgoing->nb_bg_total--;
        postcopy_rdma_outgoing_rdma_done(outgoing, wr_id);
        break;
    case RDMA_POSTCOPY_RDMA_PREFAULT:
        assert(outgoing->inflight[wr_id].nb > 0);
        assert(outgoing->inflight[wr_id].bytes > 0);
        outgoing->inflight[wr_id].nb = 0;
        outgoing->inflight[wr_id].bytes = 0;
        assert(outgoing->nb_pre_total > 0);
        assert(outgoing->bytes_pre_total >= bytes);
        outgoing->bytes_pre_total -= bytes;
        outgoing->nb_pre_total--;
        postcopy_rdma_outgoing_rdma_done(outgoing, wr_id);
        break;
    default:
        abort();
        break;
    }
}

static int postcopy_rdma_outgoing_reap_sbuffer(RDMAPostcopyOutgoing *outgoing)
{
    uint64_t wr_id;
    enum ibv_wc_opcode opcode;
    RDMAPostcopyData *data;
    int ret = 0;

    while (true) {
        ret = postcopy_rdma_buffer_poll(outgoing->sbuffer,
                                        &wr_id, &opcode, &data);
        if (ret < 0) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            break;
        }
        if (ret == 0) {
            break;
        }
        assert(ret == 1);

        ret = 0;
        assert(wr_id < RDMA_POSTCOPY_REQ_MAX * 6 + 2);
        switch (opcode) {
        case IBV_WC_SEND:
            DDPRINTF("%s:%d SEND wr_id %"PRIx64"\n",
                     __func__, __LINE__, wr_id);
            postcopy_rdma_outgoing_reap_send(outgoing, wr_id);
            assert(outgoing->inflight[wr_id].nb == 0);
            assert(outgoing->inflight[wr_id].bytes == 0);
            postcopy_rdma_buffer_free(outgoing->sbuffer, data);
            break;
        case IBV_WC_RDMA_WRITE: /* RDMA WRITE is used without signaled flag */
        default:
            DPRINTF("unexpected opcode %d wr_id %"PRIu64"\n", opcode, wr_id);
            abort();
            break;
        }
        if (ret) {
            break;
        }
    }
    return ret;
}

static int
postcopy_rdma_outgoing_alloc_sdata(RDMAPostcopyOutgoing *outgoing,
                                   RDMAPostcopyData **sdata)
{
    int rdma_index;
    if (postcopy_rdma_buffer_empty(outgoing->sbuffer)) {
        int ret = postcopy_rdma_outgoing_reap_sbuffer(outgoing);
        if (ret) {
            return ret;
        }
    }
    *sdata = postcopy_rdma_buffer_alloc(outgoing->sbuffer);
    rdma_index = postcopy_rdma_buffer_get_index(outgoing->sbuffer, *sdata);
    outgoing->inflight[rdma_index].rdma_type = RDMA_POSTCOPY_RDMA_SEND;
    return 0;
}

static int postcopy_rdma_outgoing_save_alloc(RDMAPostcopyOutgoing* outgoing,
                                             RDMAPostcopySavePage *save,
                                             RDMA_POSTCOPY_RDMA_TYPE rdma_type)
{
    int ret;
    RDMAPostcopyData *sdata;
    RDMAControlHeader *res_head;
    uint32_t result_type;
    switch (rdma_type) {
    case RDMA_POSTCOPY_RDMA_ONDEMAND:
        result_type = RDMA_CONTROL_RDMA_RESULT;
        break;
    case RDMA_POSTCOPY_RDMA_BACKGROUND:
        result_type = RDMA_CONTROL_RDMA_RESULT_BG;
        break;
    case RDMA_POSTCOPY_RDMA_PREFAULT:
        result_type = RDMA_CONTROL_RDMA_RESULT_PRE;
        break;
    default:
        abort();
    }

    /* allocate rdma_index */
    ret = postcopy_rdma_outgoing_alloc_sdata(outgoing, &sdata);
    if (ret) {
        return ret;
    }
    save->rdma_index = postcopy_rdma_buffer_get_index(outgoing->sbuffer,
                                                      sdata);
    outgoing->inflight[save->rdma_index].rdma_type = rdma_type;
    assert(outgoing->inflight[save->rdma_index].nb == 0);
    assert(outgoing->inflight[save->rdma_index].bytes == 0);

    res_head = (RDMAControlHeader*)sdata->data;
    res_head->type = result_type;
    res_head->repeat = 0;
    DDDPRINTF("%s:%d index %d\n", __func__, __LINE__, save->rdma_index);
    return 0;
}

static void postcopy_rdma_outgoing_save_init(RDMAPostcopySavePage *save)
{
    struct ibv_sge *sge = &save->sge;
    struct ibv_send_wr *wr = &save->wr;

    memset(sge, 0, sizeof(*sge));
    memset(wr, 0, sizeof(*wr));
    wr->wr_id = save->rdma_index;
    wr->sg_list = sge;
    wr->num_sge = 1;
    wr->opcode = IBV_WR_RDMA_WRITE;
    wr->send_flags = 0;
}

static void postcopy_rdma_outgoing_save_first_page(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save,
    RDMALocalBlock *local_block, uint64_t host_addr, uint32_t lkey,
    uint64_t remote_host_addr, uint32_t rkey)
{
    RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                           save->rdma_index);
    RDMAControlHeader *res_head = (RDMAControlHeader *)data->data;
    RDMARequest *result = (RDMARequest *)(res_head + 1) + res_head->repeat;

    assert(save->sge.length == 0);

    save->local_block = local_block;
    save->sge.addr = host_addr;
    save->sge.lkey = lkey;
    save->wr.wr.rdma.remote_addr = remote_host_addr;
    save->wr.wr.rdma.rkey = rkey;

    result->block_index = save->local_block->index;
    result->rkey = rkey;
    result->host_addr = remote_host_addr;
}

static bool postcopy_rdma_outgoing_save_mergable(
    const RDMAPostcopySavePage *save,
    uint64_t host_addr, uint32_t lkey, uint32_t rkey)
{
    assert(save->sge.length > 0);
    return save->sge.lkey == lkey &&
        save->wr.wr.rdma.rkey == rkey &&
        save->sge.addr + save->sge.length == host_addr;
}

static void postcopy_rdma_outgoing_save_prepend(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save,
    uint32_t length)
{
    RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(
        outgoing->sbuffer, save->rdma_index);
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;
    RDMARequest *result = (RDMARequest *)(head + 1) + head->repeat;
    result->host_addr -= length;
    save->wr.wr.rdma.remote_addr -= length;
    save->sge.addr -= length;
    save->sge.length += length;
    outgoing->inflight[save->rdma_index].bytes += length;
    acct_update_position(outgoing->ms->file, length, false);
}

static void postcopy_rdma_outgoing_save_extend(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save,
    uint32_t length)
{
    save->sge.length += length;
    outgoing->inflight[save->rdma_index].bytes += length;
    acct_update_position(outgoing->ms->file, length, false);
}

static int postcopy_rdma_outgoing_save_post(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save)
{
    RDMALocalBlock *local_block = save->local_block;
    RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                           save->rdma_index);
    RDMAControlHeader *res_head = (RDMAControlHeader *)data->data;
    RDMARequest *result = (RDMARequest *)(res_head + 1) + res_head->repeat;
    int chunk = ram_chunk_index(local_block->local_host_addr,
                                (uint8_t*)save->sge.addr);
    struct ibv_send_wr *bad_wr;
    int ret;

    result->length = save->sge.length;
    request_to_network(result);
    res_head->repeat++;
    DDDPRINTF("%s:%d rdma write wr_id %d block_index %d"
              " 0x%"PRIx64" 0x%"PRIx32" 0x%"PRIx32
              " 0x%"PRIx64" 0x%"PRIx32"\n",
              __func__, __LINE__, save->rdma_index, local_block->index,
              save->sge.addr, save->sge.length, save->sge.lkey,
              save->wr.wr.rdma.remote_addr, save->wr.wr.rdma.rkey);

    ret = ibv_post_send(outgoing->qp, &save->wr, &bad_wr);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        return -ret;
    }
    local_block->nb_rdma[chunk]++;
    outgoing->inflight[save->rdma_index].nb++;
    postcopy_rdma_outgoing_save_init(save);
    return 0;
}

static bool postcopy_rdma_outgoing_save_done(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save)
{
    RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                           save->rdma_index);
    RDMAControlHeader *res_head = (RDMAControlHeader *)data->data;
    res_head->len = sizeof(RDMARequest) * res_head->repeat;
    DDDPRINTF("%s:%d index %d repeat %d\n",
              __func__, __LINE__, save->rdma_index, res_head->repeat);
    assert(outgoing->inflight[save->rdma_index].nb == res_head->repeat);
    save->rdma_index = RDMA_POSTCOPY_OUTGOING_SAVE_INVALID;
    return res_head->len > 0;
}

static int postcopy_rdma_outgoing_request_handle_one(
    RDMAPostcopyOutgoing *outgoing, RDMAPostcopySavePage *save,
    RDMARequest *request)
{
    RDMAContext *rdma = outgoing->rdma;
    RDMALocalBlock *local_block;
    ram_addr_t offset_s;
    ram_addr_t offset_e;
    ram_addr_t offset;
    int chunk_s;
    int chunk_e;
    int chunk;
    int ret;

    if (request->block_index >= rdma->local_ram_blocks.nb_blocks) {
        return -EINVAL;
    }
    local_block = &rdma->local_ram_blocks.block[request->block_index];
    if (request->host_addr < local_block->remote_host_addr ||
        request->host_addr + request->length >
        local_block->remote_host_addr + local_block->length) {
        return -EINVAL;
    }
    if (((request->host_addr - local_block->remote_host_addr) &
         ~TARGET_PAGE_MASK) != 0 ||
        (request->length & ~TARGET_PAGE_MASK) != 0) {
        return -EINVAL;
    }

    offset_s = request->host_addr - local_block->remote_host_addr;
    offset_e = offset_s + request->length;
    if ((offset_s & ~TARGET_PAGE_MASK) != 0 ||
        (offset_e & ~TARGET_PAGE_MASK) != 0) {
        return -EINVAL;
    }

    chunk_s = ram_chunk_index((uint8_t*)local_block->remote_host_addr,
                              (uint8_t*)request->host_addr);
    chunk_e = ram_chunk_index((uint8_t*)local_block->remote_host_addr,
                              (uint8_t*)request->host_addr +
                              request->length - 1);
    for (chunk = chunk_s; chunk <= chunk_e; chunk++) {
        if (local_block->remote_keys[chunk] == 0) {
            local_block->remote_keys[chunk] = request->rkey;
        } else if (local_block->remote_keys[chunk] != request->rkey) {
            DPRINTF("invalid rkey 0x%x != 0x%x"
                    " block_index %d chunk %x addr %"PRIx64"\n",
                    local_block->remote_keys[chunk], request->rkey,
                    request->block_index, chunk, request->host_addr);
            return -EINVAL;
        }
    }

    postcopy_rdma_outgoing_save_init(save);
    for (offset = offset_s; offset < offset_e; offset += TARGET_PAGE_SIZE) {
        uint8_t *host_addr;
        uint32_t lkey;

        if (!migration_bitmap_test_and_reset_dirty(local_block->ram_block->mr,
                                                   offset)) {
            continue;
        }

        host_addr = local_block->local_host_addr + offset;
        chunk = ram_chunk_index(local_block->local_host_addr, host_addr);
        ret = qemu_rdma_register_and_get_keys(
            rdma, local_block, host_addr, &lkey, NULL, chunk);
        if (save->sge.length > 0 &&
            !postcopy_rdma_outgoing_save_mergable(
                save, (uint64_t)host_addr, lkey, request->rkey)){
            outgoing->bytes_rdma_total += save->sge.length;
            ret = postcopy_rdma_outgoing_save_post(outgoing, save);
            if (ret) {
                return ret;
            }
        }
        if (save->sge.length == 0) {
            postcopy_rdma_outgoing_save_first_page(outgoing, save,
                                                   local_block,
                                                   (uint64_t)host_addr,
                                                   lkey,
                                                   request->host_addr,
                                                   request->rkey);
        }
        postcopy_rdma_outgoing_save_extend(outgoing, save,
                                           TARGET_PAGE_SIZE);
    }
    if (save->sge.length > 0) {
        outgoing->bytes_rdma_total += save->sge.length;
        ret = postcopy_rdma_outgoing_save_post(outgoing, save);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static int postcopy_rdma_outgoing_prefault_forward(
    RDMAPostcopyOutgoing *outgoing,
    RDMALocalBlock *local_block, ram_addr_t offset)
{
    int ret;
    RDMAPostcopySavePage save;
    ram_addr_t offset_e;
    RDMAPostcopyData *data;

    if (outgoing->ms->params.prefault_forward <= 0) {
        return 0;
    }

    ret = postcopy_rdma_outgoing_save_alloc(outgoing, &save,
                                            RDMA_POSTCOPY_RDMA_PREFAULT);
    if (ret) {
        return ret;
    }

    offset_e = offset +
        (outgoing->ms->params.prefault_forward << TARGET_PAGE_BITS);
    offset_e = MIN(offset_e, local_block->length);

    postcopy_rdma_outgoing_save_init(&save);
    for (; offset < offset_e; offset += TARGET_PAGE_SIZE) {
        uint8_t *host_addr = local_block->local_host_addr + offset;
        int chunk = ram_chunk_index(local_block->local_host_addr, host_addr);
        uint32_t lkey;
        uint32_t rkey = local_block->remote_keys[chunk];

        if (rkey == 0) {
            break;
        }
        if (!migration_bitmap_test_and_reset_dirty(local_block->ram_block->mr,
                                                   offset)) {
            continue;
        }
        ret = qemu_rdma_register_and_get_keys(
            outgoing->rdma, local_block, host_addr, &lkey, NULL, chunk);
        if (save.sge.length > 0 &&
            !postcopy_rdma_outgoing_save_mergable(
                &save, (uint64_t)host_addr, lkey, rkey)){
            RDMAPostcopyData *data;
            RDMAControlHeader *head;
            outgoing->bytes_pre_total += save.sge.length;
            ret = postcopy_rdma_outgoing_save_post(outgoing, &save);
            if (ret) {
                return ret;
            }
            data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                 save.rdma_index);
            head = (RDMAControlHeader *)data->data;
            if (head->repeat >= MAX_PAGE_NR) {
                break;
            }
        }
        if (save.sge.length == 0) {
            uint64_t remote_host_addr = local_block->remote_host_addr + offset;
            postcopy_rdma_outgoing_save_first_page(outgoing, &save,
                                                   local_block,
                                                   (uint64_t)host_addr,
                                                   lkey,
                                                   remote_host_addr,
                                                   rkey);
        }
        postcopy_rdma_outgoing_save_extend(outgoing, &save,
                                           TARGET_PAGE_SIZE);
    }
    if (save.sge.length > 0) {
        outgoing->bytes_pre_total += save.sge.length;
        ret = postcopy_rdma_outgoing_save_post(outgoing, &save);
        if (ret) {
            return ret;
        }
    }

    data = postcopy_rdma_buffer_get_data(outgoing->sbuffer, save.rdma_index);
    if (postcopy_rdma_outgoing_save_done(outgoing, &save)) {
        outgoing->nb_pre_total++;
        ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
        if (ret) {
            return ret;
        }
    } else {
        DDDPRINTF("%s:%d forward no post index %d\n", __func__, __LINE__,
                  postcopy_rdma_buffer_get_index(outgoing->sbuffer, data));
        postcopy_rdma_buffer_free(outgoing->sbuffer, data);
    }
    return 0;
}

static int postcopy_rdma_outgoing_prefault_backward(
    RDMAPostcopyOutgoing *outgoing,
    RDMALocalBlock *local_block, ram_addr_t offset)
{
    int ret;
    RDMAPostcopySavePage save;
    ram_addr_t diff;
    ram_addr_t offset_s;
    RDMAPostcopyData *data;

    if (outgoing->ms->params.prefault_backward <= 0) {
        return 0;
    }
    ret = postcopy_rdma_outgoing_save_alloc(outgoing, &save,
                                            RDMA_POSTCOPY_RDMA_PREFAULT);
    if (ret) {
        return ret;
    }

    diff = outgoing->ms->params.prefault_backward << TARGET_PAGE_BITS;
    offset_s = offset - MIN(offset, diff);
    offset -= TARGET_PAGE_SIZE;
    postcopy_rdma_outgoing_save_init(&save);
    for (; offset >= offset_s; offset -= TARGET_PAGE_SIZE) {
        uint8_t *host_addr = local_block->local_host_addr + offset;
        int chunk = ram_chunk_index(local_block->local_host_addr, host_addr);
        uint32_t lkey;
        uint32_t rkey = local_block->remote_keys[chunk];

        if (rkey == 0) {
            break;
        }
        if (!migration_bitmap_test_and_reset_dirty(local_block->ram_block->mr,
                                                   offset)) {
            continue;
        }
        ret = qemu_rdma_register_and_get_keys(
            outgoing->rdma, local_block, host_addr, &lkey, NULL, chunk);
        if (save.sge.length > 0) {
            if (save.sge.lkey == lkey &&
                save.wr.wr.rdma.rkey == rkey &&
                save.sge.addr == (uint64_t)host_addr + TARGET_PAGE_SIZE) {
                postcopy_rdma_outgoing_save_prepend(outgoing, &save,
                                                    TARGET_PAGE_SIZE);
            } else {
                RDMAPostcopyData *data = postcopy_rdma_buffer_get_data(
                    outgoing->sbuffer, save.rdma_index);
                RDMAControlHeader *head = (RDMAControlHeader *)data->data;
                outgoing->bytes_pre_total += save.sge.length;
                ret = postcopy_rdma_outgoing_save_post(outgoing, &save);
                if (ret) {
                    return ret;
                }
                if (head->repeat >= MAX_PAGE_NR) {
                    break;
                }
            }
        }
        if (save.sge.length == 0) {
            uint64_t remote_host_addr = local_block->remote_host_addr + offset;
            postcopy_rdma_outgoing_save_first_page(outgoing, &save,
                                                   local_block,
                                                   (uint64_t)host_addr,
                                                   lkey,
                                                   remote_host_addr,
                                                   rkey);
            postcopy_rdma_outgoing_save_extend(outgoing, &save,
                                               TARGET_PAGE_SIZE);
        }
    }
    if (save.sge.length > 0) {
        outgoing->bytes_pre_total += save.sge.length;
        ret = postcopy_rdma_outgoing_save_post(outgoing, &save);
        if (ret) {
            return ret;
        }
    }

    data = postcopy_rdma_buffer_get_data(outgoing->sbuffer, save.rdma_index);
    if (postcopy_rdma_outgoing_save_done(outgoing, &save)) {
        outgoing->nb_pre_total++;
        ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
        if (ret) {
            return ret;
        }
    } else {
        DDDPRINTF("%s:%d backward no post index %d\n", __func__, __LINE__,
                  postcopy_rdma_buffer_get_index(outgoing->sbuffer, data));
        postcopy_rdma_buffer_free(outgoing->sbuffer, data);
    }
    return 0;
}

static int
postcopy_rdma_outgoing_rdma_request_handle(RDMAPostcopyOutgoing *outgoing,
                                           RDMAPostcopyData *data)
{
    RDMAContext *rdma = outgoing->rdma;
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMARequest *request = (RDMARequest*)(head + 1);
    RDMALocalBlock *local_block;
    RDMAPostcopySavePage save;
    int rdma_index;
    ram_addr_t offset_s;
    ram_addr_t offset_e;
    RDMAPostcopyData *sdata;
    int i;
    int ret;

    DDPRINTF("%s:%d\n", __func__, __LINE__);
    assert(outgoing->nb_rdma_total < RDMA_POSTCOPY_REQ_MAX);

    ret = postcopy_rdma_outgoing_save_alloc(outgoing, &save,
                                            RDMA_POSTCOPY_RDMA_ONDEMAND);
    for (i = 0; i < head->repeat; i++) {
        network_to_request(request);
        ret = postcopy_rdma_outgoing_request_handle_one(outgoing, &save,
                                                        request);
        if (ret) {
            return ret;
        }
        request++;
    }

    request = (RDMARequest*)(head + 1) + (head->repeat - 1);
    local_block = &rdma->local_ram_blocks.block[request->block_index];
    offset_s = request->host_addr - local_block->remote_host_addr;
    offset_e = request->host_addr + request->length -
        local_block->remote_host_addr;
    postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);

    rdma_index = save.rdma_index;
    if (postcopy_rdma_outgoing_save_done(outgoing, &save)) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        outgoing->nb_rdma_total++;
    }
    /* Even RDMA write wasn't posted, send back the result for flow
     * control */
    sdata = postcopy_rdma_buffer_get_data(outgoing->sbuffer, rdma_index);
    ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, sdata);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }

    ret = postcopy_rdma_outgoing_prefault_forward(outgoing,
                                                  local_block, offset_e);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }
    ret = postcopy_rdma_outgoing_prefault_backward(outgoing,
                                                   local_block, offset_s);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }
    if (migrate_postcopy_outgoing_move_background()) {
        ram_addr_t last_offset = offset_e +
            (outgoing->ms->params.prefault_forward << TARGET_PAGE_BITS);
        last_offset = MIN(last_offset, local_block->length - TARGET_PAGE_SIZE);
        ram_save_set_last_seen_block(local_block->ram_block, last_offset);
    }
    return 0;
}

static int
postcopy_rdma_outgoing_register_result_handle(RDMAPostcopyOutgoing *outgoing,
                                              RDMAPostcopyData *data)
{
    RDMAContext *rdma = outgoing->rdma;
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMAAsyncRegister *result = (RDMAAsyncRegister*)(head + 1);
    int i;

    for (i = 0; i < head->repeat; i++) {
        RDMALocalBlock *local_block;
        network_to_aregister(result);
        if (result->block_index > rdma->local_ram_blocks.nb_blocks) {
            return -EINVAL;
        }
        local_block = &rdma->local_ram_blocks.block[result->block_index];
        if (result->chunk > local_block->nb_chunks) {
            return -EINVAL;
        }
        if (result->rkey == 0) {
            DPRINTF("%s:%d rkey 0\n", __func__, __LINE__);
            return -EINVAL;
        }
        if (local_block->remote_keys[result->chunk] != 0 &&
            local_block->remote_keys[result->chunk] != result->rkey) {
            DPRINTF("%s:%d %d rkey %d\n", __func__, __LINE__,
                    local_block->remote_keys[result->chunk], result->rkey);
            return -EINVAL;
        }
        DDDPRINTF("%s:%d block_index %d chunk 0x%"PRIx64" rkey %"PRIx32"\n",
                  __func__, __LINE__,
                  result->block_index, result->chunk, result->rkey);
        local_block->remote_keys[result->chunk] = result->rkey;

        result++;
    }
    outgoing->nb_register--;
    outgoing->nb_inflight--;
    return 0;
}

static void postcopy_rdma_outgoing_ready_handle(RDMAPostcopyOutgoing *outgoing,
                                                RDMAPostcopyData *data)
{
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;
    if (head->repeat == 0) {
        head->repeat = 1;
    }
    outgoing->nb_bg_result -= head->repeat;
    outgoing->nb_inflight -= head->repeat;
}

static int postcopy_rdma_outgoing_eoc_handle(RDMAPostcopyOutgoing *outgoing)
{
    int ret;
    RDMAPostcopyData *sdata;
    RDMAControlHeader *head;

    ret = postcopy_rdma_outgoing_alloc_sdata(outgoing, &sdata);
    if (ret) {
        return ret;
    }
    head = (RDMAControlHeader *)sdata->data;
    head->len = 0;
    head->type = RDMA_CONTROL_EOS;
    head->repeat = 0;
    ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, sdata);
    if (ret == 0) {
        outgoing->ms->postcopy->state = PO_STATE_COMPLETED;
    }
    return ret;
}

static void postcopy_rdma_outgoing_compress_result_handle(
    RDMAPostcopyOutgoing *outgoing)
{
    outgoing->nb_compress--;
    outgoing->nb_inflight--;
}

static int poscopy_rdma_outgoing_rq_handle(RDMAPostcopyOutgoing *outgoing,
                                           RDMAPostcopyData *data)
{
    int ret = 0;
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;

    DDDPRINTF("%s:%d rq %s\n", __func__, __LINE__, control_desc[head->type]);
    switch (head->type) {
    case RDMA_CONTROL_RDMA_REQUEST:
        ret = postcopy_rdma_outgoing_rdma_request_handle(outgoing, data);
        break;
    case RDMA_CONTROL_REGISTER_ARESULT:
        ret = postcopy_rdma_outgoing_register_result_handle(outgoing, data);
        postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
        break;
    case RDMA_CONTROL_READY:
        postcopy_rdma_outgoing_ready_handle(outgoing, data);
        postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
        break;
    case RDMA_CONTROL_EOC:
        postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
        ret = postcopy_rdma_outgoing_eoc_handle(outgoing);
        break;
    case RDMA_CONTROL_COMPRESS_RESULT:
        postcopy_rdma_outgoing_compress_result_handle(outgoing);
        postcopy_rdma_buffer_post_recv_data(outgoing->rbuffer, data);
        break;
    default:
        abort();
        break;
    }
    return ret;
}

static int postcopy_rdma_outgoing_ram_all_sent(RDMAPostcopyOutgoing *outgoing)
{
    PostcopyOutgoingState *s = outgoing->ms->postcopy;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    int ret = postcopy_rdma_outgoing_alloc_sdata(outgoing, &data);
    if (ret) {
        return ret;
    }
    head = (RDMAControlHeader *)data->data;

    assert(s->state == PO_STATE_ACTIVE);
    s->state = PO_STATE_ALL_PAGES_SENT;
    head->type = RDMA_CONTROL_EOS;
    head->len = 0;
    head->repeat = 0;
    postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
    DPRINTF("sent RDMA_CONTROL_EOS\n");
    return 0;
}

static int postcopy_rdma_outgoing_bg_flush(RDMAPostcopyOutgoing *outgoing)
{
    RDMAPostcopySavePage *save = &outgoing->bg_save;
    int ret;

    assert(save->rdma_index != RDMA_POSTCOPY_OUTGOING_SAVE_INVALID);
    if (save->sge.length == 0) {
        return 0;
    }
    ret = postcopy_rdma_outgoing_save_post(outgoing, save);
    if (ret) {
        return ret;
    }
    outgoing->bytes_bg_total += save->sge.length;
    return 0;
}

static int postcopy_rdma_outgoing_bg_done(RDMAPostcopyOutgoing *outgoing)
{
    int ret;
    RDMAPostcopySavePage *save = &outgoing->bg_save;
    int rdma_index = save->rdma_index;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;

    if (rdma_index == RDMA_POSTCOPY_OUTGOING_SAVE_INVALID) {
        return 0;
    }
    ret = postcopy_rdma_outgoing_bg_flush(outgoing);
    if (ret) {
        return ret;
    }

    data = postcopy_rdma_buffer_get_data(outgoing->sbuffer, rdma_index);
    head = (RDMAControlHeader *)data->data;
    DDDPRINTF("%s:%d bg_index %d repeat %d\n",
              __func__, __LINE__, rdma_index, head->repeat);
    if (head->repeat == 0) {
        return 0;
    }
    assert(outgoing->inflight[rdma_index].nb > 0);
    postcopy_rdma_outgoing_save_done(outgoing, &outgoing->bg_save);
    return postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
}

static size_t postcopy_rdma_outgoing_bg_save_page(
    QEMUFile *f, void *opaque, ram_addr_t block_offset, ram_addr_t offset,
    size_t size, int *bytes_sent)
{
    RDMAPostcopyOutgoing *outgoing = opaque;
    RDMAContext *rdma = outgoing->rdma;
    RDMAPostcopySavePage *save = &outgoing->bg_save;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    uint64_t block_index;
    uint64_t chunk;
    RDMALocalBlock *local_block;
    uint8_t *host;
    uint32_t lkey;
    uint32_t rkey;
    int ret;

    ret = qemu_rdma_search_ram_block(rdma, block_offset, offset, size,
                                     &block_index, &chunk);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        goto error;
    }
    local_block = &rdma->local_ram_blocks.block[block_index];
    host = local_block->local_host_addr + offset;
    rkey = local_block->remote_keys[chunk];
    if (rkey == 0) {
        RDMAAsyncRegister *areg;

        ret = postcopy_rdma_outgoing_bg_done(outgoing);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            goto error;
        }
        outgoing->bg_break_loop = true;
        if (test_bit(chunk, local_block->transit_bitmap)) {
            DDDPRINTF("%s:%d block_index %"PRId64" chunk 0x%"PRIx64"\n",
                      __func__, __LINE__, block_index, chunk);
            return RAM_SAVE_CONTROL_EAGAIN;
        }
        ret = postcopy_rdma_outgoing_alloc_sdata(outgoing, &data);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            goto error;
        }
        head = (RDMAControlHeader *)data->data;

        if (migrate_postcopy_outgoing_rdma_compress() &&
            can_use_buffer_find_nonzero_offset((void *)host, size) &&
            buffer_find_nonzero_offset((void *)host, size) == size) {
            RDMACompress *comp;
            uint8_t *chunk_end;

            head->type = RDMA_CONTROL_COMPRESS;
            head->repeat = 1;
            comp = (RDMACompress*)(head + 1);
            comp->value = 0;
            comp->block_idx = block_index;
            comp->offset = offset;
            comp->length = size;
            acct_update_position(outgoing->ms->file, size, true);
            outgoing->nb_compress++;

            /* try to expand area to compress */
            host += size;
            offset += size;
            chunk_end = ram_chunk_end(local_block, chunk);
            for (; host < chunk_end;
                 host += TARGET_PAGE_SIZE, offset += TARGET_PAGE_SIZE) {
                if (!migration_bitmap_test_dirty(local_block->ram_block->mr,
                                                 offset)) {
                    continue;
                }
                if (buffer_find_nonzero_offset((void *)host, TARGET_PAGE_SIZE)
                    != TARGET_PAGE_SIZE) {
                    continue;
                }
                migration_bitmap_test_and_reset_dirty(
                    local_block->ram_block->mr, offset);

                if (comp->offset + comp->length != offset) {
                    if (head->repeat >= MAX_COMPRESS_NR) {
                        break;
                    }
                    DDDPRINTF("%s:%d compress block_index %"PRId64
                              " offset 0x%"PRIx64" length 0x%"PRIx64
                              " sindex %d\n", __func__, __LINE__, block_index,
                              comp->offset, comp->length,
                              postcopy_rdma_buffer_get_index(outgoing->sbuffer,
                                                             data));
                    compress_to_network(comp);

                    head->repeat++;
                    comp++;
                    comp->value = 0;
                    comp->block_idx = block_index;
                    comp->offset = offset;
                    comp->length = 0;
                }
                comp->length += TARGET_PAGE_SIZE;
                acct_update_position(outgoing->ms->file, TARGET_PAGE_SIZE,
                                     true);
            }
            DDDPRINTF("%s:%d compress block_index %"PRId64
                      " offset 0x%"PRIx64" length 0x%"PRIx64
                      " sindex %d\n", __func__, __LINE__, block_index,
                      comp->offset, comp->length,
                      postcopy_rdma_buffer_get_index(outgoing->sbuffer,
                                                     data));
            compress_to_network(comp);

            head->len = sizeof(*comp) * head->repeat;
            outgoing->nb_inflight++;
            ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
            if (ret) {
                DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                goto error;
            }
            *bytes_sent = 1;
            return RAM_SAVE_CONTROL_DELAYED;
        }

        set_bit(chunk, local_block->transit_bitmap);
        head->type = RDMA_CONTROL_REGISTER_AREQUEST;
        head->repeat = 1;
        head->len = sizeof(*areg);
        areg = (RDMAAsyncRegister*)(head + 1);
        areg->chunk = chunk;
        areg->block_index = block_index;
        areg->rkey = 0;
        aregister_to_network(areg);
        ret = postcopy_rdma_buffer_post_send(outgoing->sbuffer, data);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            goto error;
        }
        outgoing->nb_register++;
        outgoing->nb_inflight++;
        DDDPRINTF("%s:%d aregister block_index %"PRId64" chunk 0x%"PRIx64
                  " sindex %d\n", __func__, __LINE__, block_index, chunk,
                  postcopy_rdma_buffer_get_index(outgoing->sbuffer, data));
        return RAM_SAVE_CONTROL_EAGAIN;
    }

    if (save->rdma_index == RDMA_POSTCOPY_OUTGOING_SAVE_INVALID) {
        ret = postcopy_rdma_outgoing_save_alloc(outgoing, save,
                                                RDMA_POSTCOPY_RDMA_BACKGROUND);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            goto error;
        }
        DDDPRINTF("%s:%d bg_index %d\n", __func__, __LINE__, save->rdma_index);

        outgoing->nb_bg_total++;
        outgoing->nb_bg_result++;
        outgoing->nb_inflight++;
        postcopy_rdma_outgoing_save_init(save);
    }

    ret = qemu_rdma_register_and_get_keys(rdma, local_block, host,
                                          &lkey, NULL, chunk);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        goto error;
    }
    if (save->sge.length > 0) {
        if (!postcopy_rdma_outgoing_save_mergable(save, (uint64_t)host,
                                                  lkey, rkey)) {
            data = postcopy_rdma_buffer_get_data(outgoing->sbuffer,
                                                 save->rdma_index);
            head = (RDMAControlHeader *)data->data;
            if (head->repeat >= MAX_PAGE_NR) {
                ret = postcopy_rdma_outgoing_bg_done(outgoing);
                if (ret) {
                    DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                    goto error;
                }
                return RAM_SAVE_CONTROL_EAGAIN;
            }

            ret = postcopy_rdma_outgoing_bg_flush(outgoing);
            if (ret) {
                DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                goto error;
            }
        } else {
            assert(save->sge.addr + save->sge.length == (uint64_t)host);
            postcopy_rdma_outgoing_save_extend(outgoing, save, size);
            outgoing->bytes_bg_total += size;
        }
    }
    if (save->sge.length == 0) {
        postcopy_rdma_outgoing_save_first_page(
            outgoing, save, local_block, (uint64_t)host, lkey,
            local_block->remote_host_addr + offset, rkey);
        postcopy_rdma_outgoing_save_extend(outgoing, save, size);
        outgoing->bytes_bg_total += size;
    }

    if (outgoing->inflight[save->rdma_index].bytes > RDMA_MERGE_MAX) {
        ret = postcopy_rdma_outgoing_bg_done(outgoing);
        if (ret) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            goto error;
        }
    }

    DDDPRINTF("%s:%d bg_index %d wr_id %"PRIx64
              " addr 0x%"PRIx64" length 0x%"PRIx32" lkey 0x%"PRIx32
              " chunk 0x%"PRIx64" nb_bg %d\n",
              __func__, __LINE__,
              save->rdma_index, save->wr.wr_id,
              save->sge.addr, save->sge.length, save->sge.lkey,
              chunk, outgoing->inflight[save->rdma_index].nb);
    *bytes_sent = 1;
    return RAM_SAVE_CONTROL_DELAYED;

error:
    DPRINTF("%s:%d error\n", __func__, __LINE__);
    outgoing->ms->postcopy->state = PO_STATE_ERROR_RECEIVE;
    return RAM_SAVE_CONTROL_EAGAIN;
}

static const QEMUFileOps postcopy_rdma_outgoing_write_ops = {
    .save_page = postcopy_rdma_outgoing_bg_save_page,
};

static int
postcopy_rdma_outgoing_ram_save_background(RDMAPostcopyOutgoing *outgoing,
                                           MigrationRateLimitStat *rlstat)
{
    MigrationState *ms = outgoing->ms;
    PostcopyOutgoingState *s = ms->postcopy;
    QEMUFile *f = outgoing->ms->file;
    int i;
    int64_t t0;
    int ret = 0;

    assert(s->state == PO_STATE_ACTIVE ||
           s->state == PO_STATE_EOC_RECEIVED ||
           s->state == PO_STATE_ERROR_RECEIVE);

    switch (s->state) {
    case PO_STATE_ACTIVE:
        /* nothing. processed below */
        break;
    case PO_STATE_ERROR_RECEIVE:
        DPRINTF("PO_STATE_ERROR_RECEIVE\n");
        return -1;
    case PO_STATE_EOC_RECEIVED:
        /* this case doesn't happen because directly sending RDMA_CONTROL_EOS
         * on receiving RDMA_CONTROL_EOC, and move onto PO_STATE_COMPLETED
         */
        abort();
    default:
        abort();
    }

    if (migrate_postcopy_outgoing_no_background()) {
        DDPRINTF("%s:%d\n", __func__, __LINE__);
        if (ram_bytes_remaining() == 0) {
            ret = postcopy_rdma_outgoing_ram_all_sent(outgoing);
        }
        return ret;
    }

    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    outgoing->bg_break_loop = false;
    i = 0;
    t0 = qemu_get_clock_ns(rt_clock);
    migration_update_rate_limit_stat(ms, rlstat, t0);
    qemu_mutex_lock_ramlist();
    while (qemu_file_rate_limit(f) == 0) {
        fd_set fds;
        int rfd = outgoing->r_comp_channel->fd;
        int sfd = outgoing->s_comp_channel->fd;
        struct timeval timeout = {.tv_sec = 0, .tv_usec = 0};

        if (outgoing->nb_inflight >= RDMA_POSTCOPY_REQ_MAX) {
            DDDPRINTF("inflight max\n");
            break;
        }
        if (outgoing->bytes_bg_total >= RDMA_POSTCOPY_BG_QUEUED_MAX_BYTES) {
            DDDPRINTF("queue bg 0x%"PRIx64"\n", outgoing->bytes_bg_total);
            break;
        }

        if (!ram_save_block(f, true, true)) { /* no more blocks */
            DDDPRINTF("outgoing background all sent\n");
            assert(s->state == PO_STATE_ACTIVE);
            ret = postcopy_rdma_outgoing_bg_done(outgoing);
            if (ret == 0) {
                ret = postcopy_rdma_outgoing_ram_all_sent(outgoing);
            }
            break;
        }
        migration_update_rate_limit_stat(ms, rlstat,
                                         qemu_get_clock_ms(rt_clock));
        if (outgoing->bg_break_loop) {
            DDDPRINTF("%s:%d\n", __func__, __LINE__);
            break;
        }

        i++;
        if ((i % RDMA_POSTCOPY_BG_CHECK) == 0) {
            FD_ZERO(&fds);
            FD_SET(rfd, &fds);
            FD_SET(sfd, &fds);
            ret = select(MAX(rfd, sfd) + 1, &fds, NULL, NULL, &timeout);
            if (ret >= 0 && (FD_ISSET(rfd, &fds) || FD_ISSET(sfd, &fds))) {
                ret = 0;
                DDDPRINTF("pending request\n");
                break;
            }
        }

        /* stolen from ram_save_iterate(): not to hold ram lock too long
         * Since this is postcopy phase and VM is already quiescent,
         * bitmap doesn't need to be synced.
         */
#define MAX_WAIT 50
        if ((i & 63) == 0) {
            uint64_t t1 = (qemu_get_clock_ns(rt_clock) - t0) / 1000000;
            if (t1 > MAX_WAIT) {
                DPRINTF("big wait: %" PRIu64 " milliseconds, %d iterations\n",
                        t1, i);
                break;
            }
        }
    }
    if (ret == 0) {
        ret = postcopy_rdma_outgoing_bg_done(outgoing);
    }
    qemu_mutex_unlock_ramlist();

    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    return ret;
}


int postcopy_rdma_outgoing_loop(MigrationState *ms,
                                MigrationRateLimitStat *rlstat)
{
    PostcopyOutgoingState *s = ms->postcopy;
    RDMAPostcopyOutgoing *outgoing = ms->rdma_outgoing;
    int ret;
    uint64_t wr_id;
    enum ibv_wc_opcode opcode;
    RDMAPostcopyData *data;

    fd_set fds;
    int nfds;
    int rfd = outgoing->r_comp_channel->fd;
    int sfd = outgoing->s_comp_channel->fd;
    struct timeval *timeoutp = &(struct timeval) {
        .tv_sec = 0,
        .tv_usec = 0,
    };
    struct ibv_cq *ev_cq;
    void *ev_ctx;
    int64_t current_time;

    /* postcopy_rdma_outgoing_eoc_handle() directly replies EOS without
     * transitioning PO_STATE_EOC_RECEIVED unlike
     * postcopy_outgoing_handle_req()
     */
    assert(s->state != PO_STATE_EOC_RECEIVED);

    ret = ibv_req_notify_cq(outgoing->rbuffer->cq, 0);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return -ret;
    }
    ret = ibv_req_notify_cq(outgoing->sbuffer->cq, 0);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return -ret;
    }
    while((s->state == PO_STATE_ACTIVE ||
           s->state == PO_STATE_ALL_PAGES_SENT) &&
          (outgoing->nb_rdma_total < RDMA_POSTCOPY_REQ_MAX)) {
        ret = postcopy_rdma_buffer_poll(outgoing->rbuffer,
                                        &wr_id, &opcode, &data);
        if (ret < 0) {
            DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
            return ret;
        }
        if (ret == 0) {
            break;
        }
        assert(ret == 1);

        ret = poscopy_rdma_outgoing_rq_handle(outgoing, data);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            s->state = PO_STATE_ERROR_RECEIVE;
            return ret;
        }
    }

    if (s->state == PO_STATE_ACTIVE) {
        ret = postcopy_rdma_outgoing_reap_sbuffer(outgoing);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            s->state = PO_STATE_ERROR_RECEIVE;
            return ret;
        }
    }

    if (s->state == PO_STATE_ACTIVE) {
        ret = postcopy_rdma_outgoing_ram_save_background(outgoing, rlstat);
        if (ret) {
            s->state = PO_STATE_ERROR_RECEIVE;
            return ret;
        }
    }

    current_time = qemu_get_clock_ms(rt_clock);
    migration_update_rate_limit_stat(ms, rlstat, current_time);
    if (qemu_file_rate_limit(ms->file) || s->state != PO_STATE_ACTIVE) {
        int64_t sleep_ms = migration_sleep_time_ms(rlstat, current_time);
        timeoutp->tv_sec = sleep_ms / 1000;
        timeoutp->tv_usec = (sleep_ms % 1000) * 1000;
    } else {
        timeoutp = NULL;
    }

    FD_ZERO(&fds);
    FD_SET(rfd, &fds);
    FD_SET(sfd, &fds);
    nfds = MAX(rfd, sfd);
    ret = select(nfds + 1, &fds, NULL, NULL, timeoutp);
    if (ret == -1) {
        if (errno == EINTR) {
            return 0;
        }
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }
    if (FD_ISSET(rfd, &fds)) {
        ret = ibv_get_cq_event(outgoing->rbuffer->channel, &ev_cq, &ev_ctx);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            return ret;
        }
        ibv_ack_cq_events(ev_cq, 1);
    }
    if (FD_ISSET(sfd, &fds)) {
        ret = ibv_get_cq_event(outgoing->sbuffer->channel, &ev_cq, &ev_ctx);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            return ret;
        }
        ibv_ack_cq_events(ev_cq, 1);
    }
    return 0;
}

/****************************************************************************
 * RDMA postcopy incoming part
 */

struct RDMAPostcopyIncoming
{
    RDMAContext *rdma;

    struct rdma_cm_id *cm_id;
    struct rdma_event_channel *channel;
    struct ibv_context *verbs;

    struct ibv_pd *pd;
    struct ibv_cq *scq;
    struct ibv_comp_channel *s_comp_channel;
    struct ibv_cq *rcq;
    struct ibv_comp_channel *r_comp_channel;
    struct ibv_qp *qp;

    QemuMutex sbuffer_lock;
    RDMAPostcopyBuffer *sbuffer;
    RDMAPostcopyBuffer *rbuffer;

    RDMAPostcopyData *ready_reply;

    /* protects nb_rdma_req rdma.local_ram_block.block[i].pmr */
    QemuMutex mutex;
    QemuCond cond;
    unsigned int nb_rdma_req;
    bool eos_received;
};

static int
postcopy_rdma_incoming_sbuffer_alloc(RDMAPostcopyIncoming *incoming,
                                     RDMAPostcopyData **data)
{
    int ret = 0;

    qemu_mutex_lock(&incoming->sbuffer_lock);
    if (postcopy_rdma_buffer_empty(incoming->sbuffer)) {
        while (true) {
            uint64_t wr_id;
            enum ibv_wc_opcode opcode;
            RDMAPostcopyData *data;

            ret = postcopy_rdma_buffer_poll(incoming->sbuffer,
                                            &wr_id, &opcode, &data);
            if (ret < 0) {
                DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
                goto out;
            }
            if (ret == 0) {
                break;
            }
            assert(ret == 1);

            /* incoming side uses only IBV_WR_SEND */
            assert(opcode == IBV_WC_SEND);
            postcopy_rdma_buffer_free(incoming->sbuffer, data);
        }
    }

    *data = postcopy_rdma_buffer_alloc(incoming->sbuffer);
out:
    qemu_mutex_unlock(&incoming->sbuffer_lock);
    return ret;
}

static void
postcopy_rdma_incoming_sbuffer_free(RDMAPostcopyIncoming *incoming,
                                    RDMAPostcopyData *data)
{
    qemu_mutex_lock(&incoming->sbuffer_lock);
    postcopy_rdma_buffer_free(incoming->sbuffer, data);
    qemu_mutex_unlock(&incoming->sbuffer_lock);
}

static int rdma_poscopy_incoming_alloc_pd_cq_qp(
    RDMAPostcopyIncoming *incoming)
{
    struct RDMAContext *rdma = incoming->rdma;
    struct ibv_qp_init_attr attr;
    int ret;
    uint32_t scqe =
        /* for RDMA Request */
        RDMA_POSTCOPY_REQ_MAX
        /* for Register Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for Compress Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for Ready */
        + RDMA_POSTCOPY_REQ_MAX
        /* for EOC */
        + 1;
    uint32_t rcqe =
        /* for RDMA Result */
        RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Compress */
        + RDMA_POSTCOPY_REQ_MAX
        /* Register request */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result BG */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE forward */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE backward */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE inflight */
        + 2
        /* +1 for EOS */
        + 1;

    /* allocate pd */
    incoming->pd = ibv_alloc_pd(incoming->verbs);
    if (!incoming->pd) {
        fprintf(stderr, "failed to allocate protection domain\n");
        return -1;
    }

    /* create send completion channel */
    incoming->s_comp_channel = ibv_create_comp_channel(incoming->verbs);
    if (!incoming->s_comp_channel) {
        fprintf(stderr, "failed to allocate send completion channel\n");
        goto error;
    }
    incoming->scq = ibv_create_cq(incoming->verbs,
                                  scqe, NULL, incoming->s_comp_channel, 0);
    if (!incoming->scq) {
        fprintf(stderr, "failed to allocate send completion queue\n");
        goto error;
    }

    /* create recv completion channel */
    incoming->r_comp_channel = ibv_create_comp_channel(incoming->verbs);
    if (!incoming->r_comp_channel) {
        fprintf(stderr, "failed to allocate recv completion channel\n");
        goto error;
    }
    incoming->rcq = ibv_create_cq(incoming->verbs,
                                  rcqe, NULL, incoming->r_comp_channel, 0);
    if (!incoming->rcq) {
        fprintf(stderr, "failed to allocate recv completion queue\n");
        goto error;
    }

    /* allocate qp */
    attr.qp_context = NULL;
    attr.send_cq = incoming->scq;
    attr.recv_cq = incoming->rcq;
    attr.srq = NULL;
    attr.cap.max_send_wr = scqe;
    attr.cap.max_recv_wr = rcqe;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.cap.max_inline_data = 0;
    attr.qp_type = IBV_QPT_RC;
    attr.sq_sig_all = 0;

    ret = rdma_create_qp(incoming->rdma->cm_id, incoming->pd, &attr);
    if (ret) {
        perror("rdma_create_qp\n");
        goto error;
    }
    incoming->qp = rdma->cm_id->qp;
    DPRINTF("send_wr requested %d result %d\n", scqe, attr.cap.max_send_wr);
    DPRINTF("recv_wr requested %d result %d\n", rcqe, attr.cap.max_recv_wr);
    if (attr.cap.max_send_wr < scqe || attr.cap.max_recv_wr < rcqe) {
        abort();
    }
    return 0;

error:
    if (incoming->rcq) {
        ibv_destroy_cq(incoming->rcq);
    }
    if (incoming->r_comp_channel) {
        ibv_destroy_comp_channel(incoming->r_comp_channel);
    }
    if (incoming->scq) {
        ibv_destroy_cq(incoming->scq);
    }
    if (incoming->s_comp_channel) {
        ibv_destroy_comp_channel(incoming->s_comp_channel);
    }
    if (incoming->pd) {
        ibv_dealloc_pd(incoming->pd);
    }

    incoming->pd = NULL;
    incoming->s_comp_channel = NULL;
    incoming->scq = NULL;
    incoming->r_comp_channel = NULL;
    incoming->rcq = NULL;
    incoming->qp = NULL;
    return -1;
}

static void postcopy_rdma_incoming_prepare_ram_block(
    RDMAContext *rdma, UMemBlockHead *umem_blocks)
{
    UMemBlock *umem_block;
    QLIST_FOREACH(umem_block, umem_blocks, next) {
        /* mitigate vma pressure
         * ib verb issues madvise(DONTFORK or DOFORK) on each memory region
         * when ibv_reg_mr() or ibv_dereg_mr()
         */
        RDMALocalBlock *local_block;
        UMem *umem = umem_block->umem;
        qemu_madvise(umem->shmem, umem->size, QEMU_MADV_DONTFORK);

        local_block = &rdma->local_ram_blocks.block[umem_block->block_index];
        local_block->umem_block = umem_block;
        /* hack: to get page contents to uvmem device */
        local_block->local_host_addr = umem->shmem;

        DDDPRINTF("UMEM shmem: %d, addr: 0x%" PRIx64 ", offset: 0x%" PRIx64
                  " length: 0x%" PRIx64 " end: 0x%" PRIx64 " chunks %d\n",
                  local_block->index,
                  (uint64_t) local_block->local_host_addr,
                  local_block->offset,
                  local_block->length,
                  (uint64_t) (local_block->local_host_addr +
                              local_block->length),
                  local_block->nb_chunks);
    }
}

/* mostly copied from qemu_rdma_accept()
 * TODO: consolidate
 */
static int postcopy_rdma_incoming_rdma_accept(RDMAPostcopyIncoming *incoming,
                                              UMemBlockHead *umem_blocks)
{
    int i;
    RDMAContext *rdma = incoming->rdma;
    struct rdma_cm_event *cm_event;
    RDMACapabilities cap;
    struct rdma_conn_param conn_param = {
        .responder_resources = 2,
        .private_data = &cap,
        .private_data_len = sizeof(cap),
        .srq = 0,
    };
    struct ibv_context *verbs;
    int ret = -EINVAL;
    uint32_t scqe =
        /* for RDMA Request */
        RDMA_POSTCOPY_REQ_MAX
        /* for Register Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for Compress Result */
        + RDMA_POSTCOPY_REQ_MAX
        /* for Ready */
        + RDMA_POSTCOPY_REQ_MAX
        /* for EOC */
        + 1;
    uint32_t rcqe =
        /* for RDMA Result */
        RDMA_POSTCOPY_REQ_MAX
        /* for RDMA Compress : +1 */
        + RDMA_POSTCOPY_REQ_MAX + 1
        /* Register request */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result BG */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE forward */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE backward */
        + RDMA_POSTCOPY_REQ_MAX
        /* RDMA Result PRE inflight */
        + 2
        /* +1 for EOS */
        + 1;

    DPRINTF("%s:%d\n", __func__, __LINE__);
    ret = rdma_get_cm_event(incoming->channel, &cm_event);
    if (ret) {
        perror("rdma_get_cm_event\n");
        fprintf(stderr, "ret %d event %s %d\n",
                ret, rdma_event_str(cm_event->event), cm_event->status);
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }
    if (cm_event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));
    network_to_caps(&cap);
    if (cap.version < 1 || cap.version > RDMA_POSTCOPY_VERSION_CURRENT) {
        fprintf(stderr,
                "Unknown source RDMA postcopy version: %d, bailing...\n",
                cap.version);
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    /*
     * Respond with only the capabilities this version of QEMU knows about.
     */
    cap.flags &= known_capabilities;

    /*
     * Enable the ones that we do know about.
     * Add other checks here as new ones are introduced.
     */
    if (cap.flags & RDMA_CAPABILITY_PIN_ALL) {
        rdma->pin_all = true;
    }
    if (cap.flags & RDMA_CAPABILITY_POSTCOPY) {
        rdma->postcopy = true;
    }
    if (rdma->pin_all && rdma->postcopy) {
        fprintf(stderr, "rdma postcopy doesn't support pin-all.\n");
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    verbs = cm_event->id->verbs;
    rdma->cm_id = cm_event->id;
    incoming->cm_id = cm_event->id;

    rdma_ack_cm_event(cm_event);
    rdma_destroy_id(rdma->listen_id);
    rdma->listen_id = NULL;

    DPRINTF("Memory pin all: %s\n", rdma->pin_all ? "enabled" : "disabled");
    DPRINTF("Postcopy: %s\n", rdma->postcopy ? "enabled" : "disabled");

    caps_to_network(&cap);

    DPRINTF("verbs context after listen: %p\n", verbs);

    if (!rdma->verbs) {
        rdma->verbs = incoming->cm_id->verbs;
    } else if (rdma->verbs != verbs) {
        fprintf(stderr, "ibv context not matching %p, %p!\n",
                rdma->verbs, verbs);
        goto err_rdma_dest_wait;
    }
    incoming->verbs = verbs;

    qemu_rdma_dump_id("dest_init", verbs);

    ret = rdma_poscopy_incoming_alloc_pd_cq_qp(incoming);
    if (ret) {
        fprintf(stderr, "rdma migration: error allocating pd, cq and qp!\n");
        goto err_rdma_dest_wait;
    }

    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        fprintf(stderr, "rdma migration: error initializing ram blocks!\n");
        goto err_rdma_dest_wait;
    }
    postcopy_rdma_incoming_prepare_ram_block(rdma, umem_blocks);

    DPRINTF("%s:%d rdma_listen success\n", __func__, __LINE__);
    qemu_mutex_init(&incoming->sbuffer_lock);
    incoming->sbuffer = postcopy_rdma_buffer_init(
        incoming->pd, incoming->qp, incoming->scq, incoming->s_comp_channel,
        scqe, false);
    incoming->rbuffer = postcopy_rdma_buffer_init(
        incoming->pd, incoming->qp, incoming->rcq, incoming->r_comp_channel,
        rcqe, true);
    if (incoming->sbuffer == NULL || incoming->rbuffer == NULL) {
        DPRINTF("%s:%d postcopy_rdma_buffer_init %p %p\n",
                __func__, __LINE__, incoming->sbuffer, incoming->rbuffer);
        goto err_rdma_dest_wait;
    }
    DPRINTF("%s:%d REQ_MAX %d\n", __func__, __LINE__, RDMA_POSTCOPY_REQ_MAX);
    for (i = 0; i < incoming->rbuffer->size; i++) {
        ret = postcopy_rdma_buffer_post_recv(incoming->rbuffer);
        if (ret) {
            DPRINTF("%s:%d %d postcopy_rdma_buffer_post_recv\n",
                    __func__, __LINE__, i);
            goto err_rdma_dest_wait;
        }
    }

    ret = rdma_accept(incoming->cm_id, &conn_param);
    if (ret) {
        perror("rdma_accept\n");
        fprintf(stderr, "rdma_accept returns %d!\n", ret);
        goto err_rdma_dest_wait;
    }

    ret = rdma_get_cm_event(incoming->channel, &cm_event);
    if (ret) {
        fprintf(stderr, "rdma_accept get_cm_event failed %d!\n", ret);
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        fprintf(stderr, "rdma_accept not event established!\n");
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }
    rdma->connected = true;

    rdma_ack_cm_event(cm_event);
    qemu_rdma_dump_gid("dest_connect", incoming->cm_id);
    return 0;

err_rdma_dest_wait:
    DPRINTF("%s:%d\n", __func__, __LINE__);
    rdma->error_state = ret;
    qemu_rdma_cleanup(rdma);
    return ret;
}

static int postcopy_rdma_incoming_bitmap_request(
    RDMAPostcopyIncoming *incoming, UMemBlockHead *umem_blocks)
{
    int ret;
    RDMAPostcopyData *data = postcopy_rdma_buffer_alloc(incoming->sbuffer);
    RDMAControlHeader *head = (RDMAControlHeader *)data->data;
    RDMARequest *request = (RDMARequest *)(head + 1);
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    int i;

    head->type = RDMA_CONTROL_BITMAP_REQUEST;
    head->repeat = local_ram_blocks->nb_blocks;
    head->len = sizeof(*request) * head->repeat;
    for (i = 0; i < head->repeat; i++) {
        RDMALocalBlock *local_block = &local_ram_blocks->block[i];
        UMemBlock *umem_block = local_block->umem_block;
        uint64_t length = postcopy_bitmap_length(local_block->length);
        local_block->bitmap_key =
            ibv_reg_mr(incoming->pd, umem_block->phys_received, length,
                       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
        if (local_block->bitmap_key == NULL) {
            ret = -errno;
            goto error;
        }
        request->block_index = i;
        request->rkey = local_block->bitmap_key->rkey;
        request->host_addr = (uint64_t)umem_block->phys_received;
        request->length = length;
        request_to_network(request);
        request++;
    }

    ret = postcopy_rdma_buffer_post_send(incoming->sbuffer, data);
    if (ret) {
        goto error;
    }
    return 0;

error:
    for (; i >=0; i--) {
        ibv_dereg_mr(local_ram_blocks->block[i].bitmap_key);
        local_ram_blocks->block[i].bitmap_key = NULL;
    }
    return ret;
}

int postcopy_rdma_incoming_umemd_read_clean_bitmap(
    RDMAPostcopyIncoming *incoming, UMemBlockHead *umem_blocks)
{
    int ret;
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    int i;

    ret = postcopy_rdma_buffer_get_wc(incoming->rbuffer, &data,
                                      incoming->rdma);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }
    if (data == NULL) {
        DPRINTF("%s:%d disconnected\n", __func__, __LINE__);
        return -ESHUTDOWN;
    }

    head = (RDMAControlHeader *)data->data;
    if (head->type != RDMA_CONTROL_BITMAP_RESULT) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return -EINVAL;
    }
    DDPRINTF("%s:%d repeat %d\n", __func__, __LINE__, head->repeat);
    for (i = 0; i < head->repeat; i++) {
        RDMARequest *result = (RDMARequest *)(head + 1) + i;
        RDMALocalBlock *local_block;
        UMemBlock *umem_block;
        uint64_t length;

        network_to_request(result);
        DDDPRINTF("%s:%d i %d index %d 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx32"\n",
                  __func__, __LINE__, i, result->block_index,
                  result->host_addr, result->length, result->rkey);
        if (result->block_index >= local_ram_blocks->nb_blocks) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            return -EINVAL;
        }
        local_block = &local_ram_blocks->block[result->block_index];
        umem_block = local_block->umem_block;

        if (local_block->bitmap_key == NULL) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            return -EINVAL;
        }
        ibv_dereg_mr(local_block->bitmap_key);
        local_block->bitmap_key = NULL;

        length = postcopy_bitmap_length(local_block->length);
        postcopy_be64_to_bitmap((uint8_t*)umem_block->phys_received, length);
        postcopy_incoming_umemd_read_clean_bitmap_done(umem_block);
    }
    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);
    DPRINTF("%s:%d\n", __func__, __LINE__);
    return 0;
}

void postcopy_rdma_incoming_prefork(QEMUFile *f, RDMAPostcopyIncomingInit *arg)
{
    QEMUFileRDMA *r = qemu_file_opaque(f);
    RDMAContext *rdma = r->rdma;
    rdma->keep_listen_id = true;
    arg->channel = rdma->channel;
    arg->listen_id = rdma->listen_id;
}

void postcopy_rdma_incoming_postfork_parent(RDMAPostcopyIncomingInit *arg)
{
    rdma_destroy_event_channel(arg->channel);
}

RDMAPostcopyIncoming*
postcopy_rdma_incoming_init(RDMAPostcopyIncomingInit *arg)
{
    UMemBlockHead *umem_blocks = arg->umem_blocks;
    bool precopy_enabled = arg->precopy_enabled;
    int ret;
    RDMAContext *rdma = NULL;
    RDMAPostcopyIncoming* incoming = g_malloc0(sizeof(*incoming));
    RDMAControlHeader blocks;
    RDMAPostcopyData *data;
    assert(current_host_port != NULL);

    qemu_mutex_init(&incoming->mutex);
    qemu_cond_init(&incoming->cond);

    DPRINTF("%s:%d postcopy incoming init\n", __func__, __LINE__);
    rdma = qemu_rdma_data_init(current_host_port, NULL);
    if (rdma == NULL) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    DPRINTF("%s:%d qemu_rdma_data_init success\n", __func__, __LINE__);
    incoming->rdma = rdma;

    rdma->channel = arg->channel;
    rdma->listen_id = arg->listen_id;
    DPRINTF("%s:%d qemu_rdma_dest_init success channel %p\n",
            __func__, __LINE__, rdma->channel);
    incoming->channel = rdma->channel;

    ret = postcopy_rdma_incoming_rdma_accept(incoming, umem_blocks);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    DPRINTF("%s:%d postcopy_rdma_incoming_rdma_accept\n", __func__, __LINE__);

    if (precopy_enabled) {
        ret = postcopy_rdma_incoming_bitmap_request(incoming, umem_blocks);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            goto error;
        }
    }

    ret = qemu_rdma_ram_blocks_request(rdma, &blocks);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }
    data = postcopy_rdma_buffer_alloc(incoming->sbuffer);
    ret = postcopy_rdma_buffer_post_send_buf(incoming->sbuffer, data,
                                             &blocks, (uint8_t*)rdma->block);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        goto error;
    }

    DPRINTF("%s:%d postcopy_rdma_incoming_init done\n", __func__, __LINE__);
    return incoming;

error:
    postcopy_rdma_incoming_cleanup(incoming);
    return NULL;
}

static void postcopy_rdma_incoming_dereg_mr(
    RDMAPostcopyIncoming *incoming, RDMALocalBlock *local_block, int chunk);
void postcopy_rdma_incoming_cleanup(RDMAPostcopyIncoming *incoming)
{
    RDMAContext *rdma = incoming->rdma;
    struct rdma_cm_event *cm_event;
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    int i;

    DPRINTF("%s:%d mr cleanup\n", __func__, __LINE__);
    for (i = 0; i < local_ram_blocks->nb_blocks; ++i) {
        RDMALocalBlock *local_block = &local_ram_blocks->block[i];
        int chunk;
        if (!local_block->pmr) {
            continue;
        }
        for (chunk = 0; chunk < local_block->nb_chunks; ++chunk) {
            if (local_block->pmr[chunk]) {
                postcopy_rdma_incoming_dereg_mr(incoming, local_block,
                                                chunk);
            }
        }
    }

    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (rdma->cm_id && rdma->connected) {
        int ret;

        postcopy_rdma_buffer_cq_empty(incoming->sbuffer);
        ret = rdma_disconnect(rdma->cm_id);
        if (!ret) {
            DDPRINTF("waiting for disconnect\n");
            ret = rdma_get_cm_event(rdma->channel, &cm_event);
            if (!ret) {
                rdma_ack_cm_event(cm_event);
            }
        }
        DDPRINTF("Disconnected.\n");
        rdma->connected = false;

        postcopy_rdma_buffer_drain(incoming->rbuffer);
        postcopy_rdma_buffer_drain(incoming->sbuffer);
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->qp) {
        rdma_destroy_qp(incoming->rdma->cm_id);
        incoming->qp = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->scq) {
        ibv_destroy_cq(incoming->scq);
        incoming->scq = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->rcq) {
        ibv_destroy_cq(incoming->rcq);
        incoming->rcq = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->s_comp_channel) {
        ibv_destroy_comp_channel(incoming->s_comp_channel);
        incoming->s_comp_channel = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->r_comp_channel) {
        ibv_destroy_comp_channel(incoming->r_comp_channel);
        incoming->r_comp_channel = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->pd) {
        ibv_dealloc_pd(incoming->pd);
        incoming->pd = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (rdma->listen_id) {
        rdma_destroy_id(rdma->listen_id);
        rdma->listen_id = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (rdma->cm_id) {
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (rdma->channel) {
        rdma_destroy_event_channel(rdma->channel);
        rdma->channel = NULL;
    }

    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->rdma) {
        qemu_rdma_cleanup(incoming->rdma);
        incoming->rdma = NULL;
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->sbuffer) {
        postcopy_rdma_buffer_destroy(incoming->sbuffer);
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    if (incoming->rbuffer) {
        postcopy_rdma_buffer_destroy(incoming->rbuffer);
    }
    DDDPRINTF("%s:%d\n", __func__, __LINE__);
    qemu_mutex_destroy(&incoming->mutex);
    qemu_cond_destroy(&incoming->cond);
    g_free(rdma);
    g_free(incoming);
}

/*
 * return value
 * 1: This mr is already deregestered. It implies that this page is
 *    already received.
 * 0: success
 * -1: error
 */
static int postcopy_rdma_incoming_reg_mr(
    RDMAPostcopyIncoming *incoming, RDMALocalBlock *local_block,
    int chunk, uint32_t *rkey)
{
    int ret = 0;

    qemu_mutex_lock(&incoming->mutex);
    if (test_bit(chunk, local_block->unregister_bitmap)) {
        ret = 1;
        goto out;
    }
    if (local_block->pmr == NULL) {
        local_block->pmr = g_malloc0(local_block->nb_chunks *
                                     sizeof(struct ibv_mr*));
    }
    if (local_block->pmr[chunk] == NULL) {
        uint8_t *chunk_start = ram_chunk_start(local_block, chunk);
        size_t size = MIN(RDMA_REG_CHUNK_SIZE, local_block->length);
        local_block->pmr[chunk] = ibv_reg_mr(
            incoming->pd, chunk_start,
            size, (IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE));
        if (local_block->pmr[chunk] == NULL) {
            perror("Failed to register chunk!");
            DPRINTF("%s:%d total registrations %d"
                    " block_index %d chunk 0x%x addr %p"
                    " size 0x%zx\n",
                    __func__, __LINE__,
                    incoming->rdma->total_registrations,
                    local_block->index, chunk, chunk_start, size);
            ret = -1;
            goto out;
        }
        incoming->rdma->total_registrations++;
        DDPRINTF("%s:%d block_index %d chunk %x"
                 " start %p size 0x%zx rkey %"PRIx32" total %d\n",
                 __func__, __LINE__,
                 local_block->index, chunk, chunk_start, size,
                 local_block->pmr[chunk]->rkey,
                 incoming->rdma->total_registrations);
    }
    *rkey = local_block->pmr[chunk]->rkey;

out:
    qemu_mutex_unlock(&incoming->mutex);
    return ret;
}

static void postcopy_rdma_incoming_dereg_mr(
    RDMAPostcopyIncoming *incoming, RDMALocalBlock *local_block, int chunk)
{
    qemu_mutex_lock(&incoming->mutex);
    assert(local_block->pmr[chunk] != NULL);
    DDPRINTF("%s:%d block_index %d chunk %x rkey %"PRIx32" total %d\n",
             __func__, __LINE__,
             local_block->index, chunk, local_block->pmr[chunk]->rkey,
             incoming->rdma->total_registrations);
    assert(!test_bit(chunk, local_block->unregister_bitmap));
    set_bit(chunk, local_block->unregister_bitmap);
    ibv_dereg_mr(local_block->pmr[chunk]);
    local_block->pmr[chunk] = NULL;
    incoming->rdma->total_registrations--;
    qemu_mutex_unlock(&incoming->mutex);
}

static int postcopy_rdma_incoming_send_eoc(RDMAPostcopyIncoming* incoming)
{
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    int ret = postcopy_rdma_incoming_sbuffer_alloc(incoming, &data);
    if (ret) {
        return ret;
    }
    head = (RDMAControlHeader*)data->data;
    head->len = 0;
    head->type = RDMA_CONTROL_EOC;
    head->repeat = 0;
    return postcopy_rdma_buffer_post_send(incoming->sbuffer, data);
}

static int
postcopy_rdma_incoming_send_rdma_request_one(RDMAPostcopyIncoming* incoming,
                                             const QEMUUMemReq *umem_req,
                                             const UMemBlock *umem_block)
{
    RDMALocalBlock *local_block =
        &incoming->rdma->local_ram_blocks.block[umem_block->block_index];
    RDMAPostcopyData *data;
    RDMAControlHeader *head;
    RDMARequest *prev;
    RDMARequest *req;
    int i;
    int ret;

    DDPRINTF("%s:%d\n", __func__, __LINE__);
    assert(umem_req->nr <= MAX_PAGE_NR);
    ret = postcopy_rdma_incoming_sbuffer_alloc(incoming, &data);
    if (ret) {
        DPRINTF("%s:%d\n", __func__, __LINE__);
        return ret;
    }

    head = (RDMAControlHeader*)data->data;
    head->len = 0;
    head->type = RDMA_CONTROL_RDMA_REQUEST;
    head->repeat = 0;
    prev = NULL;
    req = (RDMARequest*)(head + 1);
    for (i = 0; i < umem_req->nr; i++) {
        uint8_t *start = umem_block->umem->shmem;
        uint8_t *host = start + (umem_req->pgoffs[i] << TARGET_PAGE_BITS);
        uint64_t chunk = ram_chunk_index(start, host);
        uint32_t rkey;

        DDDPRINTF("%s:%d chunk %"PRIx64"\n", __func__, __LINE__, chunk);
        ret = postcopy_rdma_incoming_reg_mr(incoming, local_block, chunk,
                                            &rkey);
        if (ret < 0) {
            return ret;
        }
        if (ret > 0) {
            continue;
        }
        set_bit(chunk, local_block->transit_bitmap);

        if (prev && prev->host_addr + prev->length == (uint64_t)host &&
            prev->rkey == rkey) {
            DDDPRINTF("%s:%d\n", __func__, __LINE__);
            prev->length += TARGET_PAGE_SIZE;
        } else {
            DDDPRINTF("%s:%d\n", __func__, __LINE__);
            req->block_index = local_block->index;
            req->rkey = rkey;
            req->host_addr = (uint64_t)host;
            req->length = TARGET_PAGE_SIZE;

            head->repeat++;
            prev = req;
            req++;
        }
    }
    if (head->repeat == 0) {
        DDDPRINTF("%s:%d\n", __func__, __LINE__);;
        postcopy_rdma_incoming_sbuffer_free(incoming, data);
        return 0;
    }

    assert(head->repeat <= MAX_PAGE_NR);
    req = (RDMARequest*)(head + 1);
    for (i = 0; i < head->repeat; i++) {
        DDDPRINTF("%s:%d"
                  " request block %"PRId32" chunk 0x%"PRIx64" rkey 0x%"PRIx32
                  " addr 0x%"PRIx64" length 0x%"PRIx64"\n",
                  __func__, __LINE__,
                  req[i].block_index,
                  ram_chunk_index(umem_block->umem->shmem,
                                  (uint8_t*)req[i].host_addr),
                  req[i].rkey, req[i].host_addr, req[i].length);
        request_to_network(&req[i]);
    }

    head->len = head->repeat * sizeof(*req);
    assert(head->len < RDMA_POSTCOPY_REQUEST_MAX_BUFFER - sizeof(*head));
    return postcopy_rdma_buffer_post_send(incoming->sbuffer, data);
}

static int
postcopy_rdma_incoming_send_rdma_request(RDMAPostcopyIncoming* incoming,
                                         const QEMUUMemReq *umem_req,
                                         const UMemBlock *umem_block)
{
    int ret = 0;
    uint32_t nr = umem_req->nr;
    QEMUUMemReq tmp = *umem_req;

    while (nr > 0) {
        qemu_mutex_lock(&incoming->mutex);
        while (incoming->nb_rdma_req >= RDMA_POSTCOPY_REQ_MAX &&
               !incoming->eos_received) {
            qemu_cond_wait(&incoming->cond, &incoming->mutex);
        }
        if (incoming->eos_received) {
            qemu_mutex_unlock(&incoming->mutex);
            return -EINVAL;
        }
        incoming->nb_rdma_req++;
        qemu_mutex_unlock(&incoming->mutex);

        DDDPRINTF("%s:%d\n", __func__, __LINE__);
        tmp.nr = MIN(nr, MAX_PAGE_NR);
        ret = postcopy_rdma_incoming_send_rdma_request_one(incoming, &tmp,
                                                           umem_block);
        if (ret) {
            DPRINTF("%s:%d\n", __func__, __LINE__);
            break;
        }

        nr -= tmp.nr;
        tmp.pgoffs += tmp.nr;
    }
    DDPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
    return ret;
}

int postcopy_rdma_incoming_send_req(RDMAPostcopyIncoming *incoming,
                                    const QEMUUMemReq *umem_req,
                                    const UMemBlock *umem_block)
{
    switch (umem_req->cmd) {
    case QEMU_UMEM_REQ_EOC:
        return postcopy_rdma_incoming_send_eoc(incoming);
    case QEMU_UMEM_REQ_PAGE:
    case QEMU_UMEM_REQ_PAGE_CONT:
        return postcopy_rdma_incoming_send_rdma_request(incoming,
                                                        umem_req, umem_block);
    default:
        abort();
        break;
    }
    return 0;
}

static int postcopy_rdma_incoming_page_received_one(
    RDMAPostcopyIncoming *incoming,
    uint32_t block_index, uint64_t host_addr, uint64_t length)
{
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    UMemBlock *umem_block;
    UMem *umem;
    uint64_t host_s;
    uint64_t host_e;
    int host_bit_s;
    int host_bit_e;
    ram_addr_t offset;
    uint64_t chunk_s;
    uint64_t chunk_e;
    uint64_t chunk;
    RDMALocalBlock *local_block;

    if (block_index >= local_ram_blocks->nb_blocks) {
        DPRINTF("%s:%d index %d > %d\n", __func__, __LINE__,
                block_index, local_ram_blocks->nb_blocks);
        return -EINVAL;
    }

    local_block = &local_ram_blocks->block[block_index];
    umem_block = local_block->umem_block;
    umem = umem_block->umem;
    assert(!umem_shmem_finished(umem));
    DDDPRINTF("%s:%d result 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64
              " shmem 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64"\n",
              __func__, __LINE__, host_addr, length, host_addr + length,
              (uint64_t)umem->shmem, umem->size,
              (uint64_t)umem->shmem + umem->size);
    if (host_addr < (uint64_t)umem->shmem ||
        (uint64_t)umem->shmem + umem->size < host_addr) {
        DPRINTF("%s:%d index %d invalid addr\n",
                __func__, __LINE__, block_index);
        return -EINVAL;
    }
    if (length == 0 || (length % TARGET_PAGE_SIZE) != 0) {
        DPRINTF("%s:%d result 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64
                " shmem 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64"\n",
                __func__, __LINE__, host_addr, length, host_addr + length,
                (uint64_t)umem->shmem, umem->size,
                (uint64_t)umem->shmem + umem->size);
        return -EINVAL;
    }

    host_s = host_addr;
    host_e = host_addr + length;
    offset = host_s - (uint64_t)umem->shmem;
    if ((offset % TARGET_PAGE_SIZE) != 0)  {
        DPRINTF("%s:%d offset 0x%"PRIx64"\n", __func__, __LINE__, offset);
        DPRINTF("%s:%d result 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64
                " shmem 0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64"\n",
                __func__, __LINE__, host_addr, length, host_addr + length,
                (uint64_t)umem->shmem, umem->size,
                (uint64_t)umem->shmem + umem->size);
        return -EINVAL;
    }
    for (;
         offset < host_e - (uint64_t)umem->shmem;
         offset += TARGET_PAGE_SIZE) {
        DPRINTF("%s:%d %s 0x%"PRIx64"\n",
                __func__, __LINE__, umem_block->idstr, offset);
        postcopy_incoming_umem_ram_loaded(umem_block, offset);
    }

    host_bit_s = (host_s - (uint64_t)umem->shmem) >> TARGET_PAGE_BITS;
    host_bit_e = (host_e - (uint64_t)umem->shmem) >> TARGET_PAGE_BITS;
    chunk_s = ram_chunk_index(umem->shmem, (uint8_t*)host_s);
    chunk_e = ram_chunk_index(umem->shmem, (uint8_t*)host_e - 1);
    for (chunk = chunk_s; chunk <= chunk_e; chunk++) {
        int bit_s = (chunk_s << RDMA_REG_CHUNK_SHIFT) >> TARGET_PAGE_BITS;
        int bit_e = MIN(bit_s + (RDMA_REG_CHUNK_SIZE >> TARGET_PAGE_BITS),
                        (umem_block->length >> TARGET_PAGE_BITS) + 1);

        if (local_block->pmr[chunk] == NULL) {
            continue;
        }
        if (host_bit_s <= bit_s && bit_e <= host_bit_e) {
            postcopy_rdma_incoming_dereg_mr(incoming, local_block, chunk);
            continue;
        }
        if (!test_bit(local_block->bit[chunk], umem_block->phys_received)) {
            continue;
        }
        local_block->bit[chunk] =
            find_next_zero_bit(umem_block->phys_received, bit_e,
                               local_block->bit[chunk]);
        if (local_block->bit[chunk] == bit_e) {
            postcopy_rdma_incoming_dereg_mr(incoming, local_block, chunk);
        }
    }
    return 0;
}

static int postcopy_rdma_incoming_page_received(
    RDMAPostcopyIncoming *incoming, RDMARequest *rdma_result, int nb_result)
{
    int i;

    for (i = 0; i < nb_result; i++) {
        int ret;

        network_to_request(rdma_result);
        ret = postcopy_rdma_incoming_page_received_one(
            incoming, rdma_result->block_index,
            rdma_result->host_addr, rdma_result->length);
        if (ret) {
            return ret;
        }
        rdma_result++;
    }
    return 0;
}

static int postcopy_rdma_incoming_rmda_result(RDMAPostcopyIncoming *incoming,
                                              RDMAPostcopyData *data)
{
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMARequest *rdma_result = (RDMARequest *)(head + 1);
    int ret;
    bool wakeup;

    DDPRINTF("%s:%d repeat %d data_index %d\n",
             __func__, __LINE__, head->repeat,
             postcopy_rdma_buffer_get_index(incoming->rbuffer, data));
    ret = postcopy_rdma_incoming_page_received(incoming,
                                               rdma_result, head->repeat);
    if (ret) {
        return ret;
    }

    wakeup = false;
    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);
    qemu_mutex_lock(&incoming->mutex);
    if (incoming->nb_rdma_req >= RDMA_POSTCOPY_REQ_MAX) {
        wakeup = true;
    }
    incoming->nb_rdma_req--;
    qemu_mutex_unlock(&incoming->mutex);
    if (wakeup) {
        qemu_cond_signal(&incoming->cond);
    }
    return 0;
}

static int postcopy_rdma_incoming_rmda_result_bg(
    RDMAPostcopyIncoming *incoming, RDMAPostcopyData *data)
{
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMARequest *rdma_result = (RDMARequest *)(head + 1);
    RDMAPostcopyData *sdata;
    RDMAControlHeader *res_head;
    int ret;

    sdata = incoming->ready_reply;
    if (sdata == NULL) {
        ret = postcopy_rdma_incoming_sbuffer_alloc(incoming, &sdata);
        if (ret) {
            return ret;
        }
        incoming->ready_reply = sdata;
        res_head = (RDMAControlHeader *)sdata->data;
        res_head->type = RDMA_CONTROL_READY;
        res_head->len = 0;
        res_head->repeat = 0;
    }
    res_head = (RDMAControlHeader *)sdata->data;
    res_head->repeat++;

    ret = postcopy_rdma_incoming_page_received(incoming,
                                               rdma_result, head->repeat);
    if (ret) {
        return ret;
    }
    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);

    if (res_head->repeat > RDMA_POSTCOPY_REPLAY_THRESHOLD) {
        incoming->ready_reply = NULL;
        return postcopy_rdma_buffer_post_send(incoming->sbuffer, sdata);
    }
    return 0;
}

static int postcopy_rdma_incoming_rmda_result_pre(
    RDMAPostcopyIncoming *incoming, RDMAPostcopyData *data)
{
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMARequest *rdma_result = (RDMARequest *)(head + 1);
    int ret;

    ret = postcopy_rdma_incoming_page_received(incoming,
                                               rdma_result, head->repeat);
    if (ret) {
        return ret;
    }
    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);

    return 0;
}

static int postcopy_rdma_incoming_register_arequest(
    RDMAPostcopyIncoming *incoming, RDMAPostcopyData *data)
{
    int ret;
    int i;
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMAAsyncRegister *areg = (RDMAAsyncRegister *)(head + 1);
    RDMAPostcopyData *sdata;
    RDMAControlHeader *res_head;
    RDMAAsyncRegister *res;

    ret = postcopy_rdma_incoming_sbuffer_alloc(incoming, &sdata);
    if (ret) {
        return ret;
    }
    res_head = (RDMAControlHeader *)sdata->data;
    res = (RDMAAsyncRegister *)(res_head + 1);
    res_head->type = RDMA_CONTROL_REGISTER_ARESULT;
    res_head->repeat = 0;

    DDPRINTF("%s:%d repeat %d data_index %d\n",
             __func__, __LINE__, head->repeat,
             postcopy_rdma_buffer_get_index(incoming->rbuffer, data));
    for (i = 0; i < head->repeat; i++) {
        RDMALocalBlock *local_block;
        uint32_t rkey;

        network_to_aregister(areg);
        DDDPRINTF("%s:%d block_index %d chunk 0x%"PRIx64"\n",
                  __func__, __LINE__, areg->block_index, areg->chunk);
        if (areg->block_index >= local_ram_blocks->nb_blocks) {
            DPRINTF("%s:%d index %d > %d\n", __func__, __LINE__,
                    areg->block_index, local_ram_blocks->nb_blocks);
            return -EINVAL;
        }
        local_block = &local_ram_blocks->block[areg->block_index];
        if (areg->chunk >= local_block->nb_chunks) {
            DPRINTF("%s:%d index %d chunk 0x%"PRIx64" > %d\n",
                    __func__, __LINE__,
                    local_block->index, areg->chunk, local_block->nb_chunks);
            return -EINVAL;
        }
        if (test_and_set_bit(areg->chunk, local_block->transit_bitmap)) {
            areg++;
            continue;
        }
        res->chunk = areg->chunk;
        res->block_index = areg->block_index;
        ret = postcopy_rdma_incoming_reg_mr(incoming, local_block,
                                            res->chunk, &rkey);
        if (ret) {
            return ret;
        }
        res->rkey = rkey;
        DDDPRINTF("%s:%d block_index %d chunk 0x%"PRIx64" rkey %"PRIx32"\n",
                  __func__, __LINE__, res->block_index, res->chunk, res->rkey);
        aregister_to_network(res);

        areg++;
        res++;
        res_head->repeat++;
    }
    res_head->len = sizeof(*res) * res_head->repeat;

    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);
    /* Even when res_head->repeat = 0, post the result for window control */
    return postcopy_rdma_buffer_post_send(incoming->sbuffer, sdata);
}

static int postcopy_rdma_incoming_compress(RDMAPostcopyIncoming *incoming,
                                           RDMAPostcopyData *data)
{
    RDMALocalBlocks *local_ram_blocks = &incoming->rdma->local_ram_blocks;
    RDMAControlHeader *head = (RDMAControlHeader*)data->data;
    RDMACompress *comp = (RDMACompress*)(head + 1);
    int i;
    int ret;
    RDMAPostcopyData *sdata;
    RDMAControlHeader *res_head;

    for (i = 0; i < head->repeat; i++, comp++) {
        uint8_t *host;
        RDMALocalBlock *local_block;
        int chunk;

        network_to_compress(comp);
        if (comp->block_idx >= local_ram_blocks->nb_blocks) {
            DPRINTF("%s:%d index %d > %d\n", __func__, __LINE__,
                    comp->block_idx, local_ram_blocks->nb_blocks);
            return -EINVAL;
        }
        local_block = &local_ram_blocks->block[comp->block_idx];
        if (comp->offset >= local_block->length) {
            DPRINTF("%s:%d too large offset block_index %d offset %"PRIx64
                    " > %"PRIx64"\n",
                    __func__, __LINE__,
                    comp->block_idx, comp->offset, local_block->length);
            return -EINVAL;
        }
        if ((comp->offset % TARGET_PAGE_SIZE) != 0 ||
            comp->length == 0 || (comp->length % TARGET_PAGE_SIZE) != 0) {
            DPRINTF("%s:%d invalid offset or length block=index %d "
                    "offset %"PRIx64" length %"PRIx64"\n",
                    __func__, __LINE__,
                    comp->block_idx, comp->offset, comp->length);
            return -EINVAL;
        }

        host = local_block->local_host_addr + comp->offset;
        chunk = ram_chunk_index(local_block->local_host_addr, host);
        assert(chunk < local_block->nb_chunks);

        qemu_mutex_lock(&incoming->mutex);
        if (local_block->pmr == NULL || local_block->pmr[chunk] == NULL) {
            ram_handle_compressed(host, comp->value, comp->length);
        } else {
            memset(host, comp->value, comp->length);
        }
        qemu_mutex_unlock(&incoming->mutex);

        DDPRINTF("%s:%d %d block_index %d offset %"PRIx64" length %"PRIx64"\n",
                 __func__, __LINE__, i,
                 comp->block_idx, comp->offset, comp->length);
        ret = postcopy_rdma_incoming_page_received_one(
            incoming, comp->block_idx, (uint64_t)host, comp->length);
        if (ret) {
            return ret;
        }
    }
    postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);

    ret = postcopy_rdma_incoming_sbuffer_alloc(incoming, &sdata);
    if (ret) {
        return ret;
    }
    res_head = (RDMAControlHeader *)sdata->data;
    res_head->type = RDMA_CONTROL_COMPRESS_RESULT;
    res_head->repeat = 0;
    res_head->len = 0;
    return postcopy_rdma_buffer_post_send(incoming->sbuffer, sdata);
}

int postcopy_rdma_incoming_recv(RDMAPostcopyIncoming *incoming)
{
    int ret;
    RDMAPostcopyData *data;
    RDMAControlHeader *head;

    if (!incoming->rdma->connected) {
        return 0;
    }

    ret = postcopy_rdma_buffer_get_wc(incoming->rbuffer, &data,
                                      incoming->rdma);
    if (ret) {
        DPRINTF("%s:%d ret %d\n", __func__, __LINE__, ret);
        return ret;
    }
    if (data == NULL) {
        DPRINTF("%s:%d disconnected\n", __func__, __LINE__);
        return 0;
    }

    head = (RDMAControlHeader*)data->data;
    DDDPRINTF("%s:%d %s repeat %"PRId32"\n", __func__, __LINE__,
              control_desc[head->type], head->repeat);
    switch (head->type) {
    case RDMA_CONTROL_EOS:
        postcopy_rdma_buffer_post_recv_data(incoming->rbuffer, data);
        qemu_mutex_lock(&incoming->mutex);
        incoming->eos_received = true;
        qemu_mutex_unlock(&incoming->mutex);
        qemu_cond_broadcast(&incoming->cond);

        postcopy_incoming_umem_req_eoc();
        postcopy_incoming_umem_eos_received();
        break;
    case RDMA_CONTROL_RDMA_RESULT:
        ret = postcopy_rdma_incoming_rmda_result(incoming, data);
        break;
    case RDMA_CONTROL_RDMA_RESULT_BG:
        ret = postcopy_rdma_incoming_rmda_result_bg(incoming, data);
        break;
    case RDMA_CONTROL_RDMA_RESULT_PRE:
        ret = postcopy_rdma_incoming_rmda_result_pre(incoming, data);
        break;
    case RDMA_CONTROL_REGISTER_AREQUEST:
        ret = postcopy_rdma_incoming_register_arequest(incoming, data);
        break;
    case RDMA_CONTROL_COMPRESS:
        ret = postcopy_rdma_incoming_compress(incoming, data);
        break;
    default:
        abort();
        break;
    }

    if (ret) {
        DPRINTF("%s:%d %s ret %d\n",
                __func__, __LINE__, control_desc[head->type], ret);
    }
    return ret;
}
