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
typedef struct UMem UMem;

struct UMemPages {
    uint64_t nr;
    uint64_t pgoffs[0];
};
typedef struct UMemPages UMemPages;

int umem_new(void *hostp, size_t size, UMem** umemp);
void umem_destroy(UMem *umem);

/* umem device operations */
size_t umem_pages_size(uint64_t nr);
int umem_get_page_request(UMem *umem, UMemPages *page_request);
int umem_mark_page_cached(UMem *umem, const UMemPages *page_cached);
void umem_unmap(UMem *umem);
void umem_close(UMem *umem);

/* umem shmem operations */
int umem_map_shmem(UMem *umem);
void umem_unmap_shmem(UMem *umem);
void umem_remove_shmem(UMem *umem, size_t offset, size_t size);
bool umem_shmem_finished(const UMem *umem);
void umem_close_shmem(UMem *umem);

/* umem thread -> qemu main loop */
#define UMEM_DAEMON_READY               'R'
#define UMEM_DAEMON_QUIT                'Q'
#define UMEM_DAEMON_ERROR               'E'

/* qemu main loop -> umem thread */
#define UMEM_QEMU_READY                 'r'
#define UMEM_QEMU_QUIT                  'q'

/* for umem thread */
int umem_daemon_ready(int to_qemu_fd);
int umem_daemon_wait_for_qemu(int from_qemu_fd);
void umem_daemon_quit(QEMUFile *to_qemu);
void umem_daemon_error(QEMUFile *to_qemu);

/* for qemu main loop */
int umem_qemu_wait_for_daemon(int from_umemd_fd);
int umem_qemu_ready(int to_umemd_fd);
void umem_qemu_quit(QEMUFile *to_umemd);

#endif /* QEMU_UMEM_H */
