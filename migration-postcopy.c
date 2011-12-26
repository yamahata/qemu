/*
 * migration-postcopy.c: postcopy livemigration
 *
 * Copyright (c) 2011
 * National Institute of Advanced Industrial Science and Technology
 *
 * https://sites.google.com/site/grivonhome/quick-kvm-migration
 * Author: Isaku Yamahata <yamahata at valinux co jp>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "config-host.h"

#if defined(CONFIG_MADVISE) || defined(CONFIG_POSIX_MADVISE)
#include <sys/mman.h>
#endif

#include "bitmap.h"
#include "sysemu.h"
#include "hw/hw.h"
#include "arch_init.h"
#include "migration.h"
#include "buffered_file.h"
#include "qemu_socket.h"
#include "umem.h"

#include "memory.h"
#define WANT_EXEC_OBSOLETE
#include "exec-obsolete.h"

#define DEBUG_POSTCOPY
#ifdef DEBUG_POSTCOPY
#include <sys/syscall.h>
#define DPRINTF(fmt, ...)                                               \
    do {                                                                \
        printf("%d:%ld %s:%d: " fmt, getpid(), syscall(SYS_gettid),     \
               __func__, __LINE__, ## __VA_ARGS__);                     \
    } while (0)
#else
#define DPRINTF(fmt, ...)       do { } while (0)
#endif

#define ALIGN_UP(size, align)   (((size) + (align) - 1) & ~((align) - 1))

static void fd_close(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/***************************************************************************
 * umem daemon on destination <-> qemu on source protocol
 */

#define QEMU_UMEM_REQ_INIT              0x00
#define QEMU_UMEM_REQ_ON_DEMAND         0x01
#define QEMU_UMEM_REQ_ON_DEMAND_CONT    0x02
#define QEMU_UMEM_REQ_BACKGROUND        0x03
#define QEMU_UMEM_REQ_BACKGROUND_CONT   0x04
#define QEMU_UMEM_REQ_REMOVE            0x05
#define QEMU_UMEM_REQ_EOC               0x06

struct qemu_umem_req {
    int8_t cmd;
    uint8_t len;
    char *idstr;        /* ON_DEMAND, BACKGROUND, REMOVE */
    uint32_t nr;        /* ON_DEMAND, ON_DEMAND_CONT,
                           BACKGROUND, BACKGROUND_CONT, REMOVE */

    /* in target page size as qemu migration protocol */
    uint64_t *pgoffs;   /* ON_DEMAND, ON_DEMAND_CONT,
                           BACKGROUND, BACKGROUND_CONT, REMOVE */
};

static void postcopy_incoming_send_req_idstr(QEMUFile *f, const char* idstr)
{
    qemu_put_byte(f, strlen(idstr));
    qemu_put_buffer(f, (uint8_t *)idstr, strlen(idstr));
}

static void postcopy_incoming_send_req_pgoffs(QEMUFile *f, uint32_t nr,
                                              const uint64_t *pgoffs)
{
    uint32_t i;

    qemu_put_be32(f, nr);
    for (i = 0; i < nr; i++) {
        qemu_put_be64(f, pgoffs[i]);
    }
}

static void postcopy_incoming_send_req_one(QEMUFile *f,
                                           const struct qemu_umem_req *req)
{
    DPRINTF("cmd %d\n", req->cmd);
    qemu_put_byte(f, req->cmd);
    switch (req->cmd) {
    case QEMU_UMEM_REQ_INIT:
    case QEMU_UMEM_REQ_EOC:
        /* nothing */
        break;
    case QEMU_UMEM_REQ_ON_DEMAND:
    case QEMU_UMEM_REQ_BACKGROUND:
    case QEMU_UMEM_REQ_REMOVE:
        postcopy_incoming_send_req_idstr(f, req->idstr);
        postcopy_incoming_send_req_pgoffs(f, req->nr, req->pgoffs);
        break;
    case QEMU_UMEM_REQ_ON_DEMAND_CONT:
    case QEMU_UMEM_REQ_BACKGROUND_CONT:
        postcopy_incoming_send_req_pgoffs(f, req->nr, req->pgoffs);
        break;
    default:
        abort();
        break;
    }
}

/* QEMUFile can buffer up to IO_BUF_SIZE = 32 * 1024.
 * So one message size must be <= IO_BUF_SIZE
 * cmd: 1
 * id len: 1
 * id: 256
 * nr: 2
 */
#define MAX_PAGE_NR     ((32 * 1024 - 1 - 1 - 256 - 2) / sizeof(uint64_t))
static void postcopy_incoming_send_req(QEMUFile *f,
                                       const struct qemu_umem_req *req)
{
    uint32_t nr = req->nr;
    struct qemu_umem_req tmp = *req;

    switch (req->cmd) {
    case QEMU_UMEM_REQ_INIT:
    case QEMU_UMEM_REQ_EOC:
        postcopy_incoming_send_req_one(f, &tmp);
        break;
    case QEMU_UMEM_REQ_ON_DEMAND:
    case QEMU_UMEM_REQ_BACKGROUND:
        tmp.nr = MIN(nr, MAX_PAGE_NR);
        postcopy_incoming_send_req_one(f, &tmp);

        nr -= tmp.nr;
        tmp.pgoffs += tmp.nr;
        if (tmp.cmd == QEMU_UMEM_REQ_ON_DEMAND) {
            tmp.cmd = QEMU_UMEM_REQ_ON_DEMAND_CONT;
        }else {
            tmp.cmd = QEMU_UMEM_REQ_BACKGROUND_CONT;
        }
        /* fall through */
    case QEMU_UMEM_REQ_REMOVE:
    case QEMU_UMEM_REQ_ON_DEMAND_CONT:
    case QEMU_UMEM_REQ_BACKGROUND_CONT:
        while (nr > 0) {
            tmp.nr = MIN(nr, MAX_PAGE_NR);
            postcopy_incoming_send_req_one(f, &tmp);

            nr -= tmp.nr;
            tmp.pgoffs += tmp.nr;
        }
        break;
    default:
        abort();
        break;
    }
}

static int postcopy_outgoing_recv_req_idstr(QEMUFile *f,
                                            struct qemu_umem_req *req,
                                            size_t *offset)
{
    int ret;

    req->len = qemu_peek_byte(f, *offset);
    *offset += 1;
    if (req->len == 0) {
        return -EAGAIN;
    }
    req->idstr = g_malloc((int)req->len + 1);
    ret = qemu_peek_buffer(f, (uint8_t*)req->idstr, req->len, *offset);
    *offset += ret;
    if (ret != req->len) {
        g_free(req->idstr);
        req->idstr = NULL;
        return -EAGAIN;
    }
    req->idstr[req->len] = 0;
    return 0;
}

static int postcopy_outgoing_recv_req_pgoffs(QEMUFile *f,
                                             struct qemu_umem_req *req,
                                             size_t *offset)
{
    int ret;
    uint32_t be32;
    uint32_t i;

    ret = qemu_peek_buffer(f, (uint8_t*)&be32, sizeof(be32), *offset);
    *offset += sizeof(be32);
    if (ret != sizeof(be32)) {
        return -EAGAIN;
    }

    req->nr = be32_to_cpu(be32);
    req->pgoffs = g_new(uint64_t, req->nr);
    for (i = 0; i < req->nr; i++) {
        uint64_t be64;
        ret = qemu_peek_buffer(f, (uint8_t*)&be64, sizeof(be64), *offset);
        *offset += sizeof(be64);
        if (ret != sizeof(be64)) {
            g_free(req->pgoffs);
            req->pgoffs = NULL;
            return -EAGAIN;
        }
        req->pgoffs[i] = be64_to_cpu(be64);
    }
    return 0;
}

static int postcopy_outgoing_recv_req(QEMUFile *f, struct qemu_umem_req *req)
{
    int size;
    int ret;
    size_t offset = 0;

    size = qemu_peek_buffer(f, (uint8_t*)&req->cmd, 1, offset);
    if (size <= 0) {
        return -EAGAIN;
    }
    offset += 1;

    switch (req->cmd) {
    case QEMU_UMEM_REQ_INIT:
    case QEMU_UMEM_REQ_EOC:
        /* nothing */
        break;
    case QEMU_UMEM_REQ_ON_DEMAND:
    case QEMU_UMEM_REQ_BACKGROUND:
    case QEMU_UMEM_REQ_REMOVE:
        ret = postcopy_outgoing_recv_req_idstr(f, req, &offset);
        if (ret < 0) {
            return ret;
        }
        ret = postcopy_outgoing_recv_req_pgoffs(f, req, &offset);
        if (ret < 0) {
            return ret;
        }
        break;
    case QEMU_UMEM_REQ_ON_DEMAND_CONT:
    case QEMU_UMEM_REQ_BACKGROUND_CONT:
        ret = postcopy_outgoing_recv_req_pgoffs(f, req, &offset);
        if (ret < 0) {
            return ret;
        }
        break;
    default:
        abort();
        break;
    }
    qemu_file_skip(f, offset);
    DPRINTF("cmd %d\n", req->cmd);
    return 0;
}

static void postcopy_outgoing_free_req(struct qemu_umem_req *req)
{
    g_free(req->idstr);
    g_free(req->pgoffs);
}

/***************************************************************************
 * outgoing part
 */

#define QEMU_SAVE_LIVE_STAGE_START      0x01    /* = QEMU_VM_SECTION_START */
#define QEMU_SAVE_LIVE_STAGE_PART       0x02    /* = QEMU_VM_SECTION_PART */
#define QEMU_SAVE_LIVE_STAGE_END        0x03    /* = QEMU_VM_SECTION_END */

enum POState {
    PO_STATE_ERROR_RECEIVE,
    PO_STATE_ACTIVE,
    PO_STATE_EOC_RECEIVED,
    PO_STATE_ALL_PAGES_SENT,
    PO_STATE_COMPLETED,
};
typedef enum POState POState;

struct PostcopyOutgoingState {
    POState state;
    QEMUFile *mig_read;
    int fd_read;
    RAMBlock *last_block_read;

    QEMUFile *mig_buffered_write;
    MigrationState *ms;

    /* For nobg mode. Check if all pages are sent */
    RAMBlock *block;
    ram_addr_t offset;
};
typedef struct PostcopyOutgoingState PostcopyOutgoingState;

int postcopy_outgoing_create_read_socket(MigrationState *s)
{
    if (!s->params.postcopy) {
        return 0;
    }

    s->fd_read = dup(s->fd);
    if (s->fd_read == -1) {
        int ret = -errno;
        perror("dup");
        return ret;
    }
    s->file_read = qemu_fopen_socket(s->fd_read);
    if (s->file_read == NULL) {
        return -EINVAL;
    }
    return 0;
}

int postcopy_outgoing_ram_save_live(QEMUFile *f, int stage, void *opaque)
{
    int ret = 0;
    DPRINTF("stage %d\n", stage);
    switch (stage) {
    case QEMU_SAVE_LIVE_STAGE_START:
        sort_ram_list();
        ram_save_live_mem_size(f);
        break;
    case QEMU_SAVE_LIVE_STAGE_PART:
        ret = 1;
        break;
    case QEMU_SAVE_LIVE_STAGE_END:
        break;
    default:
        abort();
    }
    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
    return ret;
}

static void postcopy_outgoing_ram_save_page(PostcopyOutgoingState *s,
                                            uint64_t pgoffset, bool *written,
                                            bool forward,
                                            int prefault_pgoffset)
{
    ram_addr_t offset;
    int ret;

    if (forward) {
        pgoffset += prefault_pgoffset;
    } else {
        if (pgoffset < prefault_pgoffset) {
            return;
        }
        pgoffset -= prefault_pgoffset;
    }

    offset = pgoffset << TARGET_PAGE_BITS;
    if (offset >= s->last_block_read->length) {
        assert(forward);
        assert(prefault_pgoffset > 0);
        return;
    }

    ret = ram_save_page(s->mig_buffered_write, s->last_block_read, offset);
    if (ret > 0) {
        *written = true;
    }
}

/*
 * return value
 *   0: continue postcopy mode
 * > 0: completed postcopy mode.
 * < 0: error
 */
static int postcopy_outgoing_handle_req(PostcopyOutgoingState *s,
                                        const struct qemu_umem_req *req,
                                        bool *written)
{
    int i;
    uint64_t j;
    RAMBlock *block;

    DPRINTF("cmd %d state %d\n", req->cmd, s->state);
    switch(req->cmd) {
    case QEMU_UMEM_REQ_INIT:
        /* nothing */
        break;
    case QEMU_UMEM_REQ_EOC:
        /* tell to finish migration. */
        if (s->state == PO_STATE_ALL_PAGES_SENT) {
            s->state = PO_STATE_COMPLETED;
            DPRINTF("-> PO_STATE_COMPLETED\n");
        } else {
            s->state = PO_STATE_EOC_RECEIVED;
            DPRINTF("-> PO_STATE_EOC_RECEIVED\n");
        }
        return 1;
    case QEMU_UMEM_REQ_ON_DEMAND:
    case QEMU_UMEM_REQ_BACKGROUND:
        DPRINTF("idstr: %s\n", req->idstr);
        block = ram_find_block(req->idstr, strlen(req->idstr));
        if (block == NULL) {
            return -EINVAL;
        }
        s->last_block_read = block;
        /* fall through */
    case QEMU_UMEM_REQ_ON_DEMAND_CONT:
    case QEMU_UMEM_REQ_BACKGROUND_CONT:
        DPRINTF("nr %d\n", req->nr);
        if (s->mig_buffered_write == NULL) {
            assert(s->state == PO_STATE_ALL_PAGES_SENT);
            break;
        }
        for (i = 0; i < req->nr; i++) {
            DPRINTF("pgoffs[%d] 0x%"PRIx64"\n", i, req->pgoffs[i]);
            postcopy_outgoing_ram_save_page(s, req->pgoffs[i], written,
                                            true, 0);
        }
        /* forward prefault */
        for (j = 1; j <= s->ms->params.prefault_forward; j++) {
            for (i = 0; i < req->nr; i++) {
                DPRINTF("pgoffs[%d] + 0x%"PRIx64" 0x%"PRIx64"\n",
                        i, j, req->pgoffs[i] + j);
                postcopy_outgoing_ram_save_page(s, req->pgoffs[i], written,
                                                true, j);
            }
        }
        if (s->ms->params.movebg) {
            ram_addr_t last_offset =
                (req->pgoffs[req->nr - 1] + s->ms->params.prefault_forward) <<
                TARGET_PAGE_BITS;
            last_offset = MIN(last_offset,
                              s->last_block_read->length - TARGET_PAGE_SIZE);
            ram_save_set_last_block(s->last_block_read, last_offset);
        }
        /* backward prefault */
        for (j = 1; j <= s->ms->params.prefault_backward; j++) {
            for (i = 0; i < req->nr; i++) {
                DPRINTF("pgoffs[%d] - 0x%"PRIx64" 0x%"PRIx64"\n",
                        i, j, req->pgoffs[i] - j);
                postcopy_outgoing_ram_save_page(s, req->pgoffs[i], written,
                                                false, j);
            }
        }
        break;
    case QEMU_UMEM_REQ_REMOVE:
        block = ram_find_block(req->idstr, strlen(req->idstr));
        if (block == NULL) {
            return -EINVAL;
        }
        for (i = 0; i < req->nr; i++) {
            ram_addr_t offset = req->pgoffs[i] << TARGET_PAGE_BITS;
            memory_region_reset_dirty(block->mr, offset, TARGET_PAGE_SIZE,
                                      MIGRATION_DIRTY_FLAG);
        }
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static void postcopy_outgoing_close_mig_read(PostcopyOutgoingState *s)
{
    if (s->mig_read != NULL) {
        qemu_set_fd_handler(s->fd_read, NULL, NULL, NULL);
        qemu_fclose(s->mig_read);
        s->mig_read = NULL;
        fd_close(&s->fd_read);

        s->ms->file_read = NULL;
        s->ms->fd_read = -1;
    }
}

static void postcopy_outgoing_completed(PostcopyOutgoingState *s)
{
    postcopy_outgoing_close_mig_read(s);
    s->ms->postcopy = NULL;
    g_free(s);
}

static void postcopy_outgoing_recv_handler(void *opaque)
{
    PostcopyOutgoingState *s = opaque;
    bool written = false;
    int ret = 0;

    assert(s->state == PO_STATE_ACTIVE ||
           s->state == PO_STATE_ALL_PAGES_SENT);

    do {
        struct qemu_umem_req req = {.idstr = NULL,
                                    .pgoffs = NULL};

        ret = postcopy_outgoing_recv_req(s->mig_read, &req);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                ret = 0;
            }
            break;
        }

        /* Even when s->state == PO_STATE_ALL_PAGES_SENT,
           some request can be received like QEMU_UMEM_REQ_EOC */
        ret = postcopy_outgoing_handle_req(s, &req, &written);
        postcopy_outgoing_free_req(&req);
    } while (ret == 0);

    /*
     * flush buffered_file.
     * Although mig_write is rate-limited buffered file, those written pages
     * are requested on demand by the destination. So forcibly push
     * those pages ignoring rate limiting
     */
    if (written) {
        qemu_buffered_file_drain(s->mig_buffered_write);
    }

    if (ret < 0) {
        switch (s->state) {
        case PO_STATE_ACTIVE:
            s->state = PO_STATE_ERROR_RECEIVE;
            DPRINTF("-> PO_STATE_ERROR_RECEIVE\n");
            break;
        case PO_STATE_ALL_PAGES_SENT:
            s->state = PO_STATE_COMPLETED;
            DPRINTF("-> PO_STATE_ALL_PAGES_SENT\n");
            break;
        default:
            abort();
        }
    }
    if (s->state == PO_STATE_ERROR_RECEIVE || s->state == PO_STATE_COMPLETED) {
        postcopy_outgoing_close_mig_read(s);
    }
    if (s->state == PO_STATE_COMPLETED) {
        DPRINTF("PO_STATE_COMPLETED\n");
        MigrationState *ms = s->ms;
        postcopy_outgoing_completed(s);
        migrate_fd_completed(ms);
    }
}

void *postcopy_outgoing_begin(MigrationState *ms)
{
    PostcopyOutgoingState *s = g_new(PostcopyOutgoingState, 1);
    DPRINTF("outgoing begin\n");
    qemu_fflush(ms->file);

    s->ms = ms;
    s->state = PO_STATE_ACTIVE;
    s->fd_read = ms->fd_read;
    s->mig_read = ms->file_read;
    s->mig_buffered_write = ms->file;
    s->block = NULL;
    s->offset = 0;

    /* Make sure all dirty bits are set */
    cpu_physical_memory_set_dirty_tracking(0);
    ram_save_memory_set_dirty();

    qemu_set_fd_handler(s->fd_read,
                        &postcopy_outgoing_recv_handler, NULL, s);
    return s;
}

static void postcopy_outgoing_ram_all_sent(QEMUFile *f,
                                           PostcopyOutgoingState *s)
{
    assert(s->state == PO_STATE_ACTIVE);

    s->state = PO_STATE_ALL_PAGES_SENT;
    /* tell incoming side that all pages are sent */
    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
    qemu_buffered_file_drain(f);
    DPRINTF("sent RAM_SAVE_FLAG_EOS\n");
    migrate_fd_cleanup(s->ms);

    /* Later migrate_fd_complete() will be called which calls
     * migrate_fd_cleanup() again. So dummy file is created
     * for qemu monitor to keep working.
     */
    s->ms->file = qemu_fopen_ops(NULL, NULL, NULL, NULL, NULL,
                                 NULL, NULL);
    s->mig_buffered_write = NULL;
}

static int postcopy_outgoing_check_all_ram_sent(PostcopyOutgoingState *s,
                                                RAMBlock *block,
                                                ram_addr_t offset)
{
    if (block == NULL) {
        block = QLIST_FIRST(&ram_list.blocks);
        offset = 0;
    }

    for (; block != NULL; block = QLIST_NEXT(block, next), offset = 0) {
        for (; offset < block->length; offset += TARGET_PAGE_SIZE) {
            if (memory_region_get_dirty(block->mr, offset, TARGET_PAGE_SIZE,
                                        DIRTY_MEMORY_MIGRATION)) {
                s->block = block;
                s->offset = offset;
                return 0;
            }
        }
    }

    return 1;
}

int postcopy_outgoing_ram_save_background(QEMUFile *f, void *postcopy)
{
    PostcopyOutgoingState *s = postcopy;

    assert(s->state == PO_STATE_ACTIVE ||
           s->state == PO_STATE_EOC_RECEIVED ||
           s->state == PO_STATE_ERROR_RECEIVE);

    switch (s->state) {
    case PO_STATE_ACTIVE:
        /* nothing. processed below */
        break;
    case PO_STATE_EOC_RECEIVED:
        qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
        s->state = PO_STATE_COMPLETED;
        postcopy_outgoing_completed(s);
        DPRINTF("PO_STATE_COMPLETED\n");
        return 1;
    case PO_STATE_ERROR_RECEIVE:
        postcopy_outgoing_completed(s);
        DPRINTF("PO_STATE_ERROR_RECEIVE\n");
        return -1;
    default:
        abort();
    }

    if (s->ms->params.nobg) {
        /* See if all pages are sent. */
        if (postcopy_outgoing_check_all_ram_sent(s,
                                                 s->block, s->offset) == 0) {
            return 0;
        }
        /* ram_list can be reordered. (it doesn't seem so during migration,
           though) So the whole list needs to be checked again */
        if (postcopy_outgoing_check_all_ram_sent(s, NULL, 0) == 0) {
            return 0;
        }

        postcopy_outgoing_ram_all_sent(f, s);
        return 0;
    }

    DPRINTF("outgoing background state: %d\n", s->state);

    while (qemu_file_rate_limit(f) == 0) {
        if (ram_save_block(f) == 0) { /* no more blocks */
            assert(s->state == PO_STATE_ACTIVE);
            postcopy_outgoing_ram_all_sent(f, s);
            return 0;
        }
    }

    return 0;
}

/***************************************************************************
 * incoming part
 */

/* flags for incoming mode to modify the behavior.
   This is for benchmark/debug purpose */
#define INCOMING_FLAGS_FAULT_REQUEST            0x01


static void postcopy_incoming_umemd(void);

#define PIS_STATE_QUIT_RECEIVED         0x01
#define PIS_STATE_QUIT_QUEUED           0x02
#define PIS_STATE_QUIT_SENT             0x04

#define PIS_STATE_QUIT_MASK             (PIS_STATE_QUIT_RECEIVED | \
                                         PIS_STATE_QUIT_QUEUED | \
                                         PIS_STATE_QUIT_SENT)

struct PostcopyIncomingState {
    /* dest qemu state */
    uint32_t    state;

    int host_page_size;
    int host_page_shift;

    /* qemu side */
    int to_umemd_fd;
    QEMUFileNonblock *to_umemd;
#define MAX_FAULTED_PAGES       256
    struct umem_pages *faulted_pages;

    int from_umemd_fd;
    QEMUFile *from_umemd;
    int version_id;     /* save/load format version id */
};
typedef struct PostcopyIncomingState PostcopyIncomingState;


#define UMEM_STATE_EOS_RECEIVED         0x01    /* umem daemon <-> src qemu */
#define UMEM_STATE_EOC_SENT             0x02    /* umem daemon <-> src qemu */
#define UMEM_STATE_QUIT_RECEIVED        0x04    /* umem daemon <-> dst qemu */
#define UMEM_STATE_QUIT_QUEUED          0x08    /* umem daemon <-> dst qemu */
#define UMEM_STATE_QUIT_SENT            0x10    /* umem daemon <-> dst qemu */

#define UMEM_STATE_QUIT_MASK            (UMEM_STATE_QUIT_QUEUED | \
                                         UMEM_STATE_QUIT_SENT | \
                                         UMEM_STATE_QUIT_RECEIVED)
#define UMEM_STATE_END_MASK             (UMEM_STATE_EOS_RECEIVED | \
                                         UMEM_STATE_EOC_SENT | \
                                         UMEM_STATE_QUIT_MASK)

struct PostcopyIncomingUMemDaemon {
    /* umem daemon side */
    uint32_t state;

    int host_page_size;
    int host_page_shift;
    int nr_host_pages_per_target_page;
    int host_to_target_page_shift;
    int nr_target_pages_per_host_page;
    int target_to_host_page_shift;
    int version_id;     /* save/load format version id */

    int to_qemu_fd;
    QEMUFileNonblock *to_qemu;
    int from_qemu_fd;
    QEMUFile *from_qemu;

    int mig_read_fd;
    QEMUFile *mig_read;         /* qemu on source -> umem daemon */

    int mig_write_fd;
    QEMUFileNonblock *mig_write;        /* umem daemon -> qemu on source */

    /* = KVM_MAX_VCPUS * (ASYNC_PF_PER_VCPUS + 1) */
#define MAX_REQUESTS    (512 * (64 + 1))

    struct umem_pages *page_request;
    struct umem_pages *page_cached;

#define MAX_PRESENT_REQUESTS    MAX_FAULTED_PAGES
    struct umem_pages *present_request;

    uint64_t *target_pgoffs;

    /* bitmap indexed by target page offset */
    unsigned long *phys_requested;

    /* bitmap indexed by target page offset */
    unsigned long *phys_received;

    RAMBlock *last_block_read;  /* qemu on source -> umem daemon */
    RAMBlock *last_block_write; /* umem daemon -> qemu on source */
};
typedef struct PostcopyIncomingUMemDaemon PostcopyIncomingUMemDaemon;

static PostcopyIncomingState state = {
    .state = 0,
    .to_umemd_fd = -1,
    .to_umemd = NULL,
    .from_umemd_fd = -1,
    .from_umemd = NULL,
};

static PostcopyIncomingUMemDaemon umemd = {
    .state = 0,
    .to_qemu_fd = -1,
    .to_qemu = NULL,
    .from_qemu_fd = -1,
    .from_qemu = NULL,
    .mig_read_fd = -1,
    .mig_read = NULL,
    .mig_write_fd = -1,
    .mig_write = NULL,
};

void postcopy_incoming_ram_free(UMem *umem)
{
    umem_unmap(umem);
    umem_close(umem);
    umem_destroy(umem);
}

void postcopy_incoming_prepare(void)
{
    RAMBlock *block;

    if (!incoming_postcopy) {
        return;
    }

    state.state = 0;
    state.host_page_size = getpagesize();
    state.host_page_shift = ffs(state.host_page_size) - 1;
    state.version_id = RAM_SAVE_VERSION_ID; /* = save version of
                                               ram_save_live() */

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        block->umem = umem_new(block->host, block->length);
        block->flags |= RAM_POSTCOPY_UMEM_MASK;
    }
}

static int postcopy_incoming_ram_load_get64(QEMUFile *f,
                                            ram_addr_t *addr, int *flags)
{
    *addr = qemu_get_be64(f);
    *flags = *addr & ~TARGET_PAGE_MASK;
    *addr &= TARGET_PAGE_MASK;
    return qemu_file_get_error(f);
}

int postcopy_incoming_ram_load(QEMUFile *f, void *opaque, int version_id)
{
    ram_addr_t addr;
    int flags;
    int error;

    DPRINTF("incoming ram load\n");
    /*
     * RAM_SAVE_FLAGS_EOS or
     * RAM_SAVE_FLAGS_MEM_SIZE + mem size + RAM_SAVE_FLAGS_EOS
     * see postcopy_outgoing_ram_save_live()
     */

    if (version_id != RAM_SAVE_VERSION_ID) {
        DPRINTF("RAM_SAVE_VERSION_ID %d != %d\n",
                version_id, RAM_SAVE_VERSION_ID);
        return -EINVAL;
    }
    error = postcopy_incoming_ram_load_get64(f, &addr, &flags);
    DPRINTF("addr 0x%lx flags 0x%x\n", addr, flags);
    if (error) {
        DPRINTF("error %d\n", error);
        return error;
    }
    if (flags == RAM_SAVE_FLAG_EOS && addr == 0) {
        DPRINTF("EOS\n");
        return 0;
    }

    if (flags != RAM_SAVE_FLAG_MEM_SIZE) {
        DPRINTF("-EINVAL flags 0x%x\n", flags);
        return -EINVAL;
    }
    error = ram_load_mem_size(f, addr);
    if (error) {
        DPRINTF("addr 0x%lx error %d\n", addr, error);
        return error;
    }

    error = postcopy_incoming_ram_load_get64(f, &addr, &flags);
    if (error) {
        DPRINTF("addr 0x%lx flags 0x%x error %d\n", addr, flags, error);
        return error;
    }
    if (flags == RAM_SAVE_FLAG_EOS && addr == 0) {
        DPRINTF("done\n");
        return 0;
    }
    DPRINTF("-EINVAL\n");
    return -EINVAL;
}

static void postcopy_incoming_pipe_and_fork_umemd(int mig_read_fd,
                                                  QEMUFile *mig_read)
{
    int fds[2];
    RAMBlock *block;

    DPRINTF("fork\n");

    /* socketpair(AF_UNIX)? */

    if (qemu_pipe(fds) == -1) {
        perror("qemu_pipe");
        abort();
    }
    state.from_umemd_fd = fds[0];
    umemd.to_qemu_fd = fds[1];

    if (qemu_pipe(fds) == -1) {
        perror("qemu_pipe");
        abort();
    }
    umemd.from_qemu_fd = fds[0];
    state.to_umemd_fd = fds[1];

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        abort();
    }

    if (child == 0) {
        int mig_write_fd;

        fd_close(&state.to_umemd_fd);
        fd_close(&state.from_umemd_fd);
        umemd.host_page_size = state.host_page_size;
        umemd.host_page_shift = state.host_page_shift;

        umemd.nr_host_pages_per_target_page =
            TARGET_PAGE_SIZE / umemd.host_page_size;
        umemd.nr_target_pages_per_host_page =
            umemd.host_page_size / TARGET_PAGE_SIZE;

        umemd.target_to_host_page_shift =
            ffs(umemd.nr_host_pages_per_target_page) - 1;
        umemd.host_to_target_page_shift =
            ffs(umemd.nr_target_pages_per_host_page) - 1;

        umemd.state = 0;
        umemd.version_id = state.version_id;
        umemd.mig_read_fd = mig_read_fd;
        umemd.mig_read = mig_read;

        mig_write_fd = dup(mig_read_fd);
        if (mig_write_fd < 0) {
            perror("could not dup for writable socket \n");
            abort();
        }
        umemd.mig_write_fd = mig_write_fd;
        umemd.mig_write = qemu_fopen_nonblock(mig_write_fd);

        postcopy_incoming_umemd(); /* noreturn */
    }

    DPRINTF("qemu pid: %d daemon pid: %d\n", getpid(), child);
    fd_close(&umemd.to_qemu_fd);
    fd_close(&umemd.from_qemu_fd);
    state.faulted_pages = g_malloc(umem_pages_size(MAX_FAULTED_PAGES));
    state.faulted_pages->nr = 0;

    /* close all UMem.shmem_fd */
    QLIST_FOREACH(block, &ram_list.blocks, next) {
        umem_close_shmem(block->umem);
    }
    umem_qemu_wait_for_daemon(state.from_umemd_fd);
}

void postcopy_incoming_fork_umemd(QEMUFile *mig_read)
{
    int fd = qemu_file_fd(mig_read);
    assert((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);

    socket_set_nonblock(fd);
    postcopy_incoming_pipe_and_fork_umemd(fd, mig_read);
    /* now socket is disowned. So tell umem server that it's safe to use it */
    postcopy_incoming_qemu_ready();
}

static void postcopy_incoming_qemu_recv_quit(void)
{
    RAMBlock *block;
    if (state.state & PIS_STATE_QUIT_RECEIVED) {
        return;
    }

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (block->umem != NULL) {
            umem_destroy(block->umem);
            block->umem = NULL;
            block->flags &= ~RAM_POSTCOPY_UMEM_MASK;
        }
    }

    DPRINTF("|= PIS_STATE_QUIT_RECEIVED\n");
    state.state |= PIS_STATE_QUIT_RECEIVED;
    qemu_set_fd_handler(state.from_umemd_fd, NULL, NULL, NULL);
    qemu_fclose(state.from_umemd);
    state.from_umemd = NULL;
    fd_close(&state.from_umemd_fd);
}

static void postcopy_incoming_qemu_fflush_to_umemd_handler(void *opaque)
{
    assert(state.to_umemd != NULL);

    nonblock_fflush(state.to_umemd);
    if (nonblock_pending_size(state.to_umemd) > 0) {
        return;
    }

    qemu_set_fd_handler(state.to_umemd->fd, NULL, NULL, NULL);
    if (state.state & PIS_STATE_QUIT_QUEUED) {
        DPRINTF("|= PIS_STATE_QUIT_SENT\n");
        state.state |= PIS_STATE_QUIT_SENT;
        qemu_fclose(state.to_umemd->file);
        state.to_umemd = NULL;
        fd_close(&state.to_umemd_fd);
        g_free(state.faulted_pages);
        state.faulted_pages = NULL;
    }
}

static void postcopy_incoming_qemu_fflush_to_umemd(void)
{
    qemu_set_fd_handler(state.to_umemd->fd, NULL,
                        postcopy_incoming_qemu_fflush_to_umemd_handler, NULL);
    postcopy_incoming_qemu_fflush_to_umemd_handler(NULL);
}

static void postcopy_incoming_qemu_queue_quit(void)
{
    if (state.state & PIS_STATE_QUIT_QUEUED) {
        return;
    }

    DPRINTF("|= PIS_STATE_QUIT_QUEUED\n");
    umem_qemu_quit(state.to_umemd->file);
    state.state |= PIS_STATE_QUIT_QUEUED;
}

static void postcopy_incoming_qemu_send_pages_present(void)
{
    if (state.faulted_pages->nr > 0) {
        umem_qemu_send_pages_present(state.to_umemd->file,
                                     state.faulted_pages);
        state.faulted_pages->nr = 0;
    }
}

static void postcopy_incoming_qemu_faulted_pages(
    const struct umem_pages *pages)
{
    assert(pages->nr <= MAX_FAULTED_PAGES);
    assert(state.faulted_pages != NULL);

    if (state.faulted_pages->nr + pages->nr > MAX_FAULTED_PAGES) {
        postcopy_incoming_qemu_send_pages_present();
    }
    memcpy(&state.faulted_pages->pgoffs[state.faulted_pages->nr],
           &pages->pgoffs[0], sizeof(pages->pgoffs[0]) * pages->nr);
    state.faulted_pages->nr += pages->nr;
}

static void postcopy_incoming_qemu_cleanup_umem(void);

static int postcopy_incoming_qemu_handle_req_one(void)
{
    int offset = 0;
    int ret;
    uint8_t cmd;

    ret = qemu_peek_buffer(state.from_umemd, &cmd, sizeof(cmd), offset);
    offset += sizeof(cmd);
    if (ret != sizeof(cmd)) {
        return -EAGAIN;
    }
    DPRINTF("cmd %c\n", cmd);

    switch (cmd) {
    case UMEM_DAEMON_QUIT:
        postcopy_incoming_qemu_recv_quit();
        postcopy_incoming_qemu_queue_quit();
        postcopy_incoming_qemu_cleanup_umem();
        break;
    case UMEM_DAEMON_TRIGGER_PAGE_FAULT: {
        struct umem_pages *pages =
            umem_qemu_trigger_page_fault(state.from_umemd, &offset);
        if (pages == NULL) {
            return -EAGAIN;
        }
        if (state.to_umemd_fd >= 0 && !(state.state & PIS_STATE_QUIT_QUEUED)) {
            postcopy_incoming_qemu_faulted_pages(pages);
            g_free(pages);
        }
        break;
    }
    case UMEM_DAEMON_ERROR:
        /* umem daemon hit troubles, so it warned us to stop vm execution */
        vm_stop(RUN_STATE_IO_ERROR); /* or RUN_STATE_INTERNAL_ERROR */
        break;
    default:
        abort();
        break;
    }

    if (state.from_umemd != NULL) {
        qemu_file_skip(state.from_umemd, offset);
    }
    return 0;
}

static void postcopy_incoming_qemu_handle_req(void *opaque)
{
    do {
        int ret = postcopy_incoming_qemu_handle_req_one();
        if (ret == -EAGAIN) {
            break;
        }
    } while (state.from_umemd != NULL &&
             qemu_pending_size(state.from_umemd) > 0);

    if (state.to_umemd != NULL) {
        if (state.faulted_pages->nr > 0) {
            postcopy_incoming_qemu_send_pages_present();
        }
        postcopy_incoming_qemu_fflush_to_umemd();
    }
}

void postcopy_incoming_qemu_ready(void)
{
    umem_qemu_ready(state.to_umemd_fd);

    state.from_umemd = qemu_fopen_fd(state.from_umemd_fd);
    state.to_umemd = qemu_fopen_nonblock(state.to_umemd_fd);
    qemu_set_fd_handler(state.from_umemd_fd,
                        postcopy_incoming_qemu_handle_req, NULL, NULL);
}

static void postcopy_incoming_qemu_cleanup_umem(void)
{
    /* when qemu will quit before completing postcopy, tell umem daemon
       to tear down umem device and exit. */
    if (state.to_umemd_fd >= 0) {
        postcopy_incoming_qemu_queue_quit();
        postcopy_incoming_qemu_fflush_to_umemd();
    }
}

void postcopy_incoming_qemu_cleanup(void)
{
    postcopy_incoming_qemu_cleanup_umem();
    if (state.to_umemd != NULL) {
        nonblock_wait_for_flush(state.to_umemd);
    }
}

void postcopy_incoming_qemu_pages_unmapped(ram_addr_t addr, ram_addr_t size)
{
    uint64_t nr = DIV_ROUND_UP(size, state.host_page_size);
    size_t len = umem_pages_size(nr);
    ram_addr_t end = addr + size;
    struct umem_pages *pages;
    int i;

    if (state.to_umemd_fd < 0 || state.state & PIS_STATE_QUIT_QUEUED) {
        return;
    }
    pages = g_malloc(len);
    pages->nr = nr;
    for (i = 0; addr < end; addr += state.host_page_size, i++) {
        pages->pgoffs[i] = addr >> state.host_page_shift;
    }
    umem_qemu_send_pages_unmapped(state.to_umemd->file, pages);
    g_free(pages);
    assert(state.to_umemd != NULL);
    postcopy_incoming_qemu_fflush_to_umemd();
}

/**************************************************************************
 * incoming umem daemon
 */

static void postcopy_incoming_umem_recv_quit(void)
{
    if (umemd.state & UMEM_STATE_QUIT_RECEIVED) {
        return;
    }
    DPRINTF("|= UMEM_STATE_QUIT_RECEIVED\n");
    umemd.state |= UMEM_STATE_QUIT_RECEIVED;
    qemu_fclose(umemd.from_qemu);
    umemd.from_qemu = NULL;
    fd_close(&umemd.from_qemu_fd);
}

static void postcopy_incoming_umem_queue_quit(void)
{
    if (umemd.state & UMEM_STATE_QUIT_QUEUED) {
        return;
    }
    DPRINTF("|= UMEM_STATE_QUIT_QUEUED\n");
    umem_daemon_quit(umemd.to_qemu->file);
    umemd.state |= UMEM_STATE_QUIT_QUEUED;
}

static void postcopy_incoming_umem_send_eoc_req(void)
{
    struct qemu_umem_req req;

    if (umemd.state & UMEM_STATE_EOC_SENT) {
        return;
    }

    DPRINTF("|= UMEM_STATE_EOC_SENT\n");
    req.cmd = QEMU_UMEM_REQ_EOC;
    postcopy_incoming_send_req(umemd.mig_write->file, &req);
    umemd.state |= UMEM_STATE_EOC_SENT;
    qemu_fclose(umemd.mig_write->file);
    umemd.mig_write = NULL;
    fd_close(&umemd.mig_write_fd);
}

static void postcopy_incoming_umem_send_page_req(RAMBlock *block)
{
    struct qemu_umem_req req;
    int bit;
    uint64_t target_pgoff;
    int i;

    umemd.page_request->nr = MAX_REQUESTS;
    umem_get_page_request(block->umem, umemd.page_request);
    DPRINTF("id %s nr %"PRId64" offs 0x%"PRIx64" 0x%"PRIx64"\n",
            block->idstr, (uint64_t)umemd.page_request->nr,
            (uint64_t)umemd.page_request->pgoffs[0],
            (uint64_t)umemd.page_request->pgoffs[1]);

    if (umemd.last_block_write != block) {
        req.cmd = QEMU_UMEM_REQ_ON_DEMAND;
        req.idstr = block->idstr;
    } else {
        req.cmd = QEMU_UMEM_REQ_ON_DEMAND_CONT;
    }

    req.nr = 0;
    req.pgoffs = umemd.target_pgoffs;
    if (TARGET_PAGE_SIZE >= umemd.host_page_size) {
        for (i = 0; i < umemd.page_request->nr; i++) {
            target_pgoff = umemd.page_request->pgoffs[i] >>
                umemd.host_to_target_page_shift;
            bit = (block->offset >> TARGET_PAGE_BITS) + target_pgoff;

            if (!test_and_set_bit(bit, umemd.phys_requested)) {
                req.pgoffs[req.nr] = target_pgoff;
                req.nr++;
            }
        }
    } else {
        for (i = 0; i < umemd.page_request->nr; i++) {
            int j;
            target_pgoff = umemd.page_request->pgoffs[i] <<
                umemd.host_to_target_page_shift;
            bit = (block->offset >> TARGET_PAGE_BITS) + target_pgoff;

            for (j = 0; j < umemd.nr_target_pages_per_host_page; j++) {
                if (!test_and_set_bit(bit + j, umemd.phys_requested)) {
                    req.pgoffs[req.nr] = target_pgoff + j;
                    req.nr++;
                }
            }
        }
    }

    DPRINTF("id %s nr %d offs 0x%"PRIx64" 0x%"PRIx64"\n",
            block->idstr, req.nr, req.pgoffs[0], req.pgoffs[1]);
    if (req.nr > 0 && umemd.mig_write != NULL) {
        postcopy_incoming_send_req(umemd.mig_write->file, &req);
        umemd.last_block_write = block;
    }
}

static void postcopy_incoming_umem_send_pages_present(void)
{
    if (umemd.present_request->nr > 0) {
        umem_daemon_send_pages_present(umemd.to_qemu->file,
                                       umemd.present_request);
        umemd.present_request->nr = 0;
    }
}

static void postcopy_incoming_umem_pages_present_one(
    uint32_t nr, const uint64_t *pgoffs, uint64_t ramblock_pgoffset)
{
    uint32_t i;
    assert(nr <= MAX_PRESENT_REQUESTS);

    if (umemd.present_request->nr + nr > MAX_PRESENT_REQUESTS) {
        postcopy_incoming_umem_send_pages_present();
    }

    for (i = 0; i < nr; i++) {
        umemd.present_request->pgoffs[umemd.present_request->nr + i] =
            pgoffs[i] + ramblock_pgoffset;
    }
    umemd.present_request->nr += nr;
}

static void postcopy_incoming_umem_pages_present(
    const struct umem_pages *page_cached, uint64_t ramblock_pgoffset)
{
    uint32_t left = page_cached->nr;
    uint32_t offset = 0;

    while (left > 0) {
        uint32_t nr = MIN(left, MAX_PRESENT_REQUESTS);
        postcopy_incoming_umem_pages_present_one(
            nr, &page_cached->pgoffs[offset], ramblock_pgoffset);

        left -= nr;
        offset += nr;
    }
}

static int postcopy_incoming_umem_ram_load(void)
{
    ram_addr_t offset;
    int flags;

    int ret;
    size_t skip = 0;
    uint64_t be64;
    RAMBlock *block;

    void *shmem;
    int error;
    int i;
    int bit;

    if (umemd.version_id != RAM_SAVE_VERSION_ID) {
        return -EINVAL;
    }

    ret = qemu_peek_buffer(umemd.mig_read, (uint8_t*)&be64, sizeof(be64),
                           skip);
    skip += ret;
    if (ret != sizeof(be64)) {
        return -EAGAIN;
    }
    offset = be64_to_cpu(be64);

    flags = offset & ~TARGET_PAGE_MASK;
    offset &= TARGET_PAGE_MASK;

    assert(!(flags & RAM_SAVE_FLAG_MEM_SIZE));

    if (flags & RAM_SAVE_FLAG_EOS) {
        DPRINTF("RAM_SAVE_FLAG_EOS\n");
        postcopy_incoming_umem_send_eoc_req();

        qemu_fclose(umemd.mig_read);
        umemd.mig_read = NULL;
        fd_close(&umemd.mig_read_fd);
        umemd.state |= UMEM_STATE_EOS_RECEIVED;

        postcopy_incoming_umem_queue_quit();
        DPRINTF("|= UMEM_STATE_EOS_RECEIVED\n");
        return 0;
    }

    block = NULL;
    if (flags & RAM_SAVE_FLAG_CONTINUE) {
        block = umemd.last_block_read;
    } else {
        uint8_t len;
        char id[256];

        ret = qemu_peek_buffer(umemd.mig_read, &len, sizeof(len), skip);
        skip += ret;
        if (ret != sizeof(len)) {
            return -EAGAIN;
        }
        ret = qemu_peek_buffer(umemd.mig_read, (uint8_t*)id, len, skip);
        skip += ret;
        if (ret != len) {
            return -EAGAIN;
        }
        block = ram_find_block(id, len);
    }

    if (block == NULL) {
        return -EINVAL;
    }
    umemd.last_block_read = block;
    shmem = block->host + offset;

    if (flags & RAM_SAVE_FLAG_COMPRESS) {
        uint8_t ch;
        ret = qemu_peek_buffer(umemd.mig_read, &ch, sizeof(ch), skip);
        skip += ret;
        if (ret != sizeof(ch)) {
            return -EAGAIN;
        }
        memset(shmem, ch, TARGET_PAGE_SIZE);
    } else if (flags & RAM_SAVE_FLAG_PAGE) {
        ret = qemu_peek_buffer(umemd.mig_read, shmem, TARGET_PAGE_SIZE, skip);
        skip += ret;
        if (ret != TARGET_PAGE_SIZE){
            return -EAGAIN;
        }
    }
    qemu_file_skip(umemd.mig_read, skip);

    error = qemu_file_get_error(umemd.mig_read);
    if (error) {
        DPRINTF("error %d\n", error);
        return error;
    }

    qemu_madvise(shmem, TARGET_PAGE_SIZE, QEMU_MADV_DONTNEED);

    umemd.page_cached->nr = 0;
    bit = (umemd.last_block_read->offset + offset) >> TARGET_PAGE_BITS;
    if (!test_and_set_bit(bit, umemd.phys_received)) {
        if (TARGET_PAGE_SIZE >= umemd.host_page_size) {
            uint64_t pgoff = offset >> umemd.host_page_shift;
            for (i = 0; i < umemd.nr_host_pages_per_target_page; i++) {
                umemd.page_cached->pgoffs[umemd.page_cached->nr] = pgoff + i;
                umemd.page_cached->nr++;
            }
        } else {
            bool mark_cache = true;
            for (i = 0; i < umemd.nr_target_pages_per_host_page; i++) {
                if (!test_bit(bit + i, umemd.phys_received)) {
                    mark_cache = false;
                    break;
                }
            }
            if (mark_cache) {
                umemd.page_cached->pgoffs[0] = offset >> umemd.host_page_shift;
                umemd.page_cached->nr = 1;
            }
        }
    }

    if (umemd.page_cached->nr > 0) {
        umem_mark_page_cached(umemd.last_block_read->umem, umemd.page_cached);

        if (!(umemd.state & UMEM_STATE_QUIT_QUEUED) && umemd.to_qemu_fd >=0 &&
            (incoming_postcopy_flags & INCOMING_FLAGS_FAULT_REQUEST)) {
            uint64_t ramblock_pgoffset;

            ramblock_pgoffset =
                umemd.last_block_read->offset >> umemd.host_page_shift;
            postcopy_incoming_umem_pages_present(umemd.page_cached,
                                                 ramblock_pgoffset);
        }
    }

    return 0;
}

static bool postcopy_incoming_umem_check_umem_done(void)
{
    bool all_done = true;
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        UMem *umem = block->umem;
        if (umem != NULL && umem->nsets == umem->nbits) {
            umem_unmap_shmem(umem);
            umem_destroy(umem);
            block->umem = NULL;
        }
        if (block->umem != NULL) {
            all_done = false;
        }
    }
    return all_done;
}

static bool postcopy_incoming_umem_page_faulted(const struct umem_pages *pages)
{
    int i;

    for (i = 0; i < pages->nr; i++) {
        ram_addr_t addr = pages->pgoffs[i] << umemd.host_page_shift;
        RAMBlock *block = qemu_get_ram_block(addr);
        addr -= block->offset;
        umem_remove_shmem(block->umem, addr, umemd.host_page_size);
    }
    return postcopy_incoming_umem_check_umem_done();
}

static bool
postcopy_incoming_umem_page_unmapped(const struct umem_pages *pages)
{
    RAMBlock *block;
    ram_addr_t addr;
    int i;

    struct qemu_umem_req req = {
        .cmd = QEMU_UMEM_REQ_REMOVE,
        .nr = 0,
        .pgoffs = (uint64_t*)pages->pgoffs,
    };

    addr = pages->pgoffs[0] << umemd.host_page_shift;
    block = qemu_get_ram_block(addr);

    for (i = 0; i < pages->nr; i++)  {
        int pgoff;

        addr = pages->pgoffs[i] << umemd.host_page_shift;
        pgoff = addr >> TARGET_PAGE_BITS;
        if (!test_bit(pgoff, umemd.phys_received) &&
            !test_bit(pgoff, umemd.phys_requested)) {
            req.pgoffs[req.nr] = pgoff;
            req.nr++;
        }
        set_bit(pgoff, umemd.phys_received);
        set_bit(pgoff, umemd.phys_requested);

        umem_remove_shmem(block->umem,
                          addr - block->offset, umemd.host_page_size);
    }
    if (req.nr > 0 && umemd.mig_write != NULL) {
        req.idstr = block->idstr;
        postcopy_incoming_send_req(umemd.mig_write->file, &req);
    }

    return postcopy_incoming_umem_check_umem_done();
}

static void postcopy_incoming_umem_done(void)
{
    postcopy_incoming_umem_send_eoc_req();
    postcopy_incoming_umem_queue_quit();
}

static int postcopy_incoming_umem_handle_qemu(void)
{
    int ret;
    int offset = 0;
    uint8_t cmd;

    ret = qemu_peek_buffer(umemd.from_qemu, &cmd, sizeof(cmd), offset);
    offset += sizeof(cmd);
    if (ret != sizeof(cmd)) {
        return -EAGAIN;
    }
    DPRINTF("cmd %c\n", cmd);
    switch (cmd) {
    case UMEM_QEMU_QUIT:
        postcopy_incoming_umem_recv_quit();
        postcopy_incoming_umem_done();
        break;
    case UMEM_QEMU_PAGE_FAULTED: {
        struct umem_pages *pages = umem_recv_pages(umemd.from_qemu,
                                                   &offset);
        if (pages == NULL) {
            return -EAGAIN;
        }
        if (postcopy_incoming_umem_page_faulted(pages)){
            postcopy_incoming_umem_done();
        }
        g_free(pages);
        break;
    }
    case UMEM_QEMU_PAGE_UNMAPPED: {
        struct umem_pages *pages = umem_recv_pages(umemd.from_qemu,
                                                   &offset);
        if (pages == NULL) {
            return -EAGAIN;
        }
        if (postcopy_incoming_umem_page_unmapped(pages)){
            postcopy_incoming_umem_done();
        }
        g_free(pages);
        break;
    }
    default:
        abort();
        break;
    }
    if (umemd.from_qemu != NULL) {
        qemu_file_skip(umemd.from_qemu, offset);
    }
    return 0;
}

static void set_fd(int fd, fd_set *fds, int *nfds)
{
    FD_SET(fd, fds);
    if (fd > *nfds) {
        *nfds = fd;
    }
}

static int postcopy_incoming_umemd_main_loop(void)
{
    fd_set writefds;
    fd_set readfds;
    int nfds;
    RAMBlock *block;
    int ret;

    int pending_size;
    bool get_page_request;

    nfds = -1;
    FD_ZERO(&writefds);
    FD_ZERO(&readfds);

    if (umemd.mig_write != NULL) {
        pending_size = nonblock_pending_size(umemd.mig_write);
        if (pending_size > 0) {
            set_fd(umemd.mig_write_fd, &writefds, &nfds);
        }
    } else {
        pending_size = 0;
    }

#define PENDING_SIZE_MAX (MAX_REQUESTS * sizeof(uint64_t) * 2)
    /* If page request to the migration source is accumulated,
       suspend getting page fault request. */
    get_page_request = (pending_size <= PENDING_SIZE_MAX);

    if (get_page_request) {
        QLIST_FOREACH(block, &ram_list.blocks, next) {
            if (block->umem != NULL) {
                set_fd(block->umem->fd, &readfds, &nfds);
            }
        }
    }

    if (umemd.mig_read_fd >= 0) {
        set_fd(umemd.mig_read_fd, &readfds, &nfds);
    }

    if (umemd.to_qemu != NULL &&
        nonblock_pending_size(umemd.to_qemu) > 0) {
        set_fd(umemd.to_qemu_fd, &writefds, &nfds);
    }
    if (umemd.from_qemu_fd >= 0) {
        set_fd(umemd.from_qemu_fd, &readfds, &nfds);
    }

    ret = select(nfds + 1, &readfds, &writefds, NULL, NULL);
    if (ret == -1) {
        if (errno == EINTR) {
            return 0;
        }
        return ret;
    }

    if (umemd.mig_write_fd >= 0 && FD_ISSET(umemd.mig_write_fd, &writefds)) {
        nonblock_fflush(umemd.mig_write);
    }
    if (umemd.to_qemu_fd >= 0 && FD_ISSET(umemd.to_qemu_fd, &writefds)) {
        nonblock_fflush(umemd.to_qemu);
    }
    if (get_page_request) {
        QLIST_FOREACH(block, &ram_list.blocks, next) {
            if (block->umem != NULL && FD_ISSET(block->umem->fd, &readfds)) {
                postcopy_incoming_umem_send_page_req(block);
            }
        }
    }
    if (umemd.mig_read_fd >= 0 && FD_ISSET(umemd.mig_read_fd, &readfds)) {
        do {
            ret = postcopy_incoming_umem_ram_load();
            if (ret == -EAGAIN) {
                break;
            }
            if (ret < 0) {
                return ret;
            }
        } while (umemd.mig_read != NULL &&
                 qemu_pending_size(umemd.mig_read) > 0);
    }
    if (umemd.from_qemu_fd >= 0 && FD_ISSET(umemd.from_qemu_fd, &readfds)) {
        do {
            ret = postcopy_incoming_umem_handle_qemu();
            if (ret == -EAGAIN) {
                break;
            }
        } while (umemd.from_qemu != NULL &&
                 qemu_pending_size(umemd.from_qemu) > 0);
    }

    if (umemd.mig_write != NULL) {
        nonblock_fflush(umemd.mig_write);
    }
    if (umemd.to_qemu != NULL) {
        if (!(umemd.state & UMEM_STATE_QUIT_QUEUED)) {
            postcopy_incoming_umem_send_pages_present();
        }
        nonblock_fflush(umemd.to_qemu);
        if ((umemd.state & UMEM_STATE_QUIT_QUEUED) &&
            nonblock_pending_size(umemd.to_qemu) == 0) {
            DPRINTF("|= UMEM_STATE_QUIT_SENT\n");
            qemu_fclose(umemd.to_qemu->file);
            umemd.to_qemu = NULL;
            fd_close(&umemd.to_qemu_fd);
            umemd.state |= UMEM_STATE_QUIT_SENT;
        }
    }

    return (umemd.state & UMEM_STATE_END_MASK) == UMEM_STATE_END_MASK;
}

static void postcopy_incoming_umemd(void)
{
    ram_addr_t last_ram_offset;
    int nbits;
    RAMBlock *block;
    int ret;

    qemu_daemon(1, 1);
    signal(SIGPIPE, SIG_IGN);
    DPRINTF("daemon pid: %d\n", getpid());

    umemd.page_request = g_malloc(umem_pages_size(MAX_REQUESTS));

    umemd.page_cached = g_malloc(
        umem_pages_size(MAX_REQUESTS *
                        (TARGET_PAGE_SIZE >= umemd.host_page_size ?
                         1: umemd.nr_host_pages_per_target_page)));

    umemd.target_pgoffs =
        g_new(uint64_t, MAX_REQUESTS *
              MAX(umemd.nr_host_pages_per_target_page,
                  umemd.nr_target_pages_per_host_page));
    umemd.present_request = g_malloc(umem_pages_size(MAX_PRESENT_REQUESTS));
    umemd.present_request->nr = 0;

    last_ram_offset = qemu_last_ram_offset();
    nbits = last_ram_offset >> TARGET_PAGE_BITS;
    umemd.phys_requested = g_new0(unsigned long, BITS_TO_LONGS(nbits));
    umemd.phys_received = g_new0(unsigned long, BITS_TO_LONGS(nbits));
    umemd.last_block_read = NULL;
    umemd.last_block_write = NULL;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        UMem *umem = block->umem;
        umem->umem = NULL;      /* umem mapping area has VM_DONT_COPY flag,
                                   so we lost those mappings by fork */
        block->host = umem_map_shmem(umem);
        umem_close_shmem(umem);
    }
    umem_daemon_ready(umemd.to_qemu_fd);
    umemd.to_qemu = qemu_fopen_nonblock(umemd.to_qemu_fd);

    /* wait for qemu to disown migration_fd */
    umem_daemon_wait_for_qemu(umemd.from_qemu_fd);
    umemd.from_qemu = qemu_fopen_fd(umemd.from_qemu_fd);

    DPRINTF("entering umemd main loop\n");
    for (;;) {
        ret = postcopy_incoming_umemd_main_loop();
        if (ret != 0) {
            break;
        }
    }
    DPRINTF("exiting umemd main loop\n");

    /* This daemon forked from qemu and the parent qemu is still running.
     * Cleanups of linked libraries like SDL should not be triggered,
     * otherwise the parent qemu may use resources which was already freed.
     */
    fflush(stdout);
    fflush(stderr);
    _exit(ret < 0? EXIT_FAILURE: 0);
}
