/*
 * umem.h: user process backed memory module for postcopy livemigration
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

#ifndef QEMU_UMEM_H
#define QEMU_UMEM_H

#include <linux/umem.h>

#include "qemu-common.h"

typedef struct UMemDev UMemDev;

struct UMem {
    void *umem;
    int fd;
    void *shmem;
    int shmem_fd;
    uint64_t size;

    /* indexed by host page size */
    int page_shift;
    int nbits;
    int nsets;
    unsigned long *faulted;
};

struct umem_pages {
    uint64_t nr;
    uint64_t pgoffs[0];
};

UMem *umem_new(void *hostp, size_t size);
void umem_destroy(UMem *umem);

/* umem device operations */
void umem_get_page_request(UMem *umem, struct umem_pages *page_request);
void umem_mark_page_cached(UMem *umem, struct umem_pages *page_cached);
void umem_unmap(UMem *umem);
void umem_close(UMem *umem);

/* umem shmem operations */
void *umem_map_shmem(UMem *umem);
void umem_unmap_shmem(UMem *umem);
void umem_remove_shmem(UMem *umem, size_t offset, size_t size);
void umem_close_shmem(UMem *umem);

/* qemu on source <-> umem daemon communication */

/* daemon -> qemu */
#define UMEM_DAEMON_READY               'R'
#define UMEM_DAEMON_QUIT                'Q'
#define UMEM_DAEMON_TRIGGER_PAGE_FAULT  'T'
#define UMEM_DAEMON_ERROR               'E'

/* qemu -> daemon */
#define UMEM_QEMU_READY                 'r'
#define UMEM_QEMU_QUIT                  'q'
#define UMEM_QEMU_PAGE_FAULTED          't'
#define UMEM_QEMU_PAGE_UNMAPPED         'u'

struct umem_pages *umem_recv_pages(QEMUFile *f, int *offset);
size_t umem_pages_size(uint64_t nr);

/* for umem daemon */
void umem_daemon_ready(int to_qemu_fd);
void umem_daemon_wait_for_qemu(int from_qemu_fd);
void umem_daemon_quit(QEMUFile *to_qemu);
void umem_daemon_send_pages_present(QEMUFile *to_qemu,
                                    struct umem_pages *pages);

/* for qemu */
void umem_qemu_wait_for_daemon(int from_umemd_fd);
void umem_qemu_ready(int to_umemd_fd);
void umem_qemu_quit(QEMUFile *to_umemd);
struct umem_pages *umem_qemu_trigger_page_fault(QEMUFile *from_umemd,
                                                int *offset);
void umem_qemu_send_pages_present(QEMUFile *to_umemd,
                                  const struct umem_pages *pages);
void umem_qemu_send_pages_unmapped(QEMUFile *to_umemd,
                                   const struct umem_pages *pages);

#endif /* QEMU_UMEM_H */
