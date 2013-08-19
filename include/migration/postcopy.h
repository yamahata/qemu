/*
 * migration-postcopy.c: postcopy livemigration
 *
 * Copyright (c) 2013
 * National Institute of Advanced Industrial Science and Technology
 *
 * https://sites.google.com/site/grivonhome/quick-kvm-migration
 * Author: Isaku Yamahata <isaku.yamahata at gmail com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MIGRATE_POSTCOPY_H
#define MIGRATE_POSTCOPY_H

#if defined(NEED_CPU_H)
#include "exec/cpu-all.h"
#else
#include "exec/cpu-common.h"
#endif

#include "qemu/queue.h"
#include "migration/umem.h"

/* incoming -> outgoing message */
#define QEMU_UMEM_REQ_EOC       0x01
#define QEMU_UMEM_REQ_PAGE      0x02
#define QEMU_UMEM_REQ_PAGE_CONT 0x03

struct QEMUUMemReq {
    int8_t cmd;
    uint8_t len;
    char idstr[256];    /* REQ_PAGE */
    uint32_t nr;        /* REQ_PAGE, REQ_PAGE_CONT */

    /* in target page size as qemu migration protocol */
    uint64_t *pgoffs;   /* REQ_PAGE, REQ_PAGE_CONT */
};
typedef struct QEMUUMemReq QEMUUMemReq;

uint64_t postcopy_bitmap_length(uint64_t length);
static inline uint64_t postcopy_bitmap_to_uint64(const unsigned long *bitmap)
{
#if HOST_LONG_BITS == 64
    return bitmap[0];
#elif HOST_LONG_BITS == 32
    return bitmap[0] | ((uint64_t)bitmap[1] << 32);
#else
# error "unsupported"
#endif
}
void postcopy_be64_to_bitmap(uint8_t *buffer, uint64_t length);

/* outgoing part */
enum POState {
    PO_STATE_ERROR_RECEIVE,
    PO_STATE_ACTIVE,
    PO_STATE_EOC_RECEIVED,
    PO_STATE_ALL_PAGES_SENT,
    PO_STATE_COMPLETED,
};
typedef enum POState POState;

#if !defined(CONFIG_USER_ONLY) && defined(NEED_CPU_H)
struct PostcopyOutgoingState {
    POState state;
    RAMBlock *last_block_read;
};
#endif

/* incoming */
QLIST_HEAD(UMemBlockHead, UMemBlock);
typedef struct UMemBlockHead UMemBlockHead;

#if !defined(CONFIG_USER_ONLY) && defined(NEED_CPU_H)
struct UMemBlock {
    UMem* umem;
    char idstr[256];
    ram_addr_t offset;
    ram_addr_t length;
    QLIST_ENTRY(UMemBlock) next;
    unsigned long *phys_requested;      /* thread to write to outgoing qemu
                                           in TARGET_PAGE_SIZE */
    unsigned long *phys_received;       /* thread to read from outgoing qemu
                                           in TARGET_PAGE_SIZE */
    unsigned long *clean_bitmap;
    unsigned long nr_pending_clean;     /* protected by pending_clean_mutex */
    unsigned long *pending_clean_bitmap;/* protected by pending_clean_mutex */

    /* for rdma */
    int block_index;                    /* index to RDMALocalBlcoks::block */
};
#endif
typedef struct UMemBlock UMemBlock;

int postcopy_incoming_prepare(UMemBlockHead **umem_blocks);
#if !defined(CONFIG_USER_ONLY) && defined(NEED_CPU_H)
int postcopy_incoming_umem_ram_loaded(UMemBlock *block, ram_addr_t offset);
#endif
void postcopy_incoming_umem_eos_received(void);
void postcopy_incoming_umem_req_eoc(void);
void postcopy_incoming_umemd_read_clean_bitmap_done(UMemBlock *block);

#endif /* MIGRATE_POSTCOPY_H */
