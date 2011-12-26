/*
 * umem.c: user process backed memory module for postcopy livemigration
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

#include <sys/ioctl.h>
#include <sys/mman.h>

#include "config-host.h"
#ifdef CONFIG_LINUX
#include <linux/uvmem.h>
#endif

#include "bitops.h"
#include "sysemu.h"
#include "hw/hw.h"
#include "umem.h"

#define DEBUG_UMEM
#ifdef DEBUG_UMEM
#include <sys/syscall.h>
#define DPRINTF(format, ...)                                            \
    do {                                                                \
        printf("%d:%ld %s:%d "format, getpid(), syscall(SYS_gettid),    \
               __func__, __LINE__, ## __VA_ARGS__);                     \
    } while (0)
#else
#define DPRINTF(format, ...)    do { } while (0)
#endif

#define DEV_UMEM        "/dev/uvmem"

UMem *umem_new(void *hostp, size_t size)
{
#ifdef CONFIG_LINUX
    struct uvmem_init uinit = {
        .size = size,
    };
    UMem *umem;

    assert((size % getpagesize()) == 0);
    umem = g_new(UMem, 1);
    umem->fd = open(DEV_UMEM, O_RDWR);
    if (umem->fd < 0) {
        perror("can't open "DEV_UMEM);
        abort();
    }

    if (ioctl(umem->fd, UVMEM_INIT, &uinit) < 0) {
        perror("UMEM_INIT");
        abort();
    }
    if (ftruncate(uinit.shmem_fd, uinit.size) < 0) {
        perror("truncate(\"shmem_fd\")");
        abort();
    }

    umem->nbits = 0;
    umem->nsets = 0;
    umem->faulted = NULL;
    umem->page_shift = ffs(getpagesize()) - 1;
    umem->shmem_fd = uinit.shmem_fd;
    umem->size = uinit.size;
    umem->umem = mmap(hostp, size, PROT_EXEC | PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED, umem->fd, 0);
    if (umem->umem == MAP_FAILED) {
        perror("mmap(UMem) failed");
        abort();
    }
    return umem;
#else
    perror("postcopy migration is not supported");
    abort();
    return NULL;
#endif
}

void umem_destroy(UMem *umem)
{
    if (umem->fd != -1) {
        close(umem->fd);
    }
    if (umem->shmem_fd != -1) {
        close(umem->shmem_fd);
    }
    g_free(umem->faulted);
    g_free(umem);
}

size_t umem_pages_size(uint64_t nr)
{
    return sizeof(struct umem_pages) + nr * sizeof(uint64_t);
}

void umem_get_page_request(UMem *umem, struct umem_pages *page_request)
{
    ssize_t ret = read(umem->fd, page_request->pgoffs,
                       page_request->nr * sizeof(page_request->pgoffs[0]));
    if (ret < 0) {
        perror("daemon: umem read");
        abort();
    }
    page_request->nr = ret / sizeof(page_request->pgoffs[0]);
}

void umem_mark_page_cached(UMem *umem, struct umem_pages *page_cached)
{
    const void *buf = page_cached->pgoffs;
    size_t size = page_cached->nr * sizeof(page_cached->pgoffs[0]);
    ssize_t ret;

    ret = qemu_write_full(umem->fd, buf, size);
    if (ret != size) {
        perror("daemon: umem write");
        abort();
    }
}

void umem_unmap(UMem *umem)
{
    munmap(umem->umem, umem->size);
    umem->umem = NULL;
}

void umem_close(UMem *umem)
{
    close(umem->fd);
    umem->fd = -1;
}

void umem_map_shmem(UMem *umem)
{
    umem->nbits = umem->size >> umem->page_shift;
    umem->nsets = 0;
    umem->faulted = g_new0(unsigned long, BITS_TO_LONGS(umem->nbits));

    umem->shmem = mmap(NULL, umem->size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       umem->shmem_fd, 0);
    if (umem->shmem == MAP_FAILED) {
        perror("daemon: mmap(\"shmem\")");
        abort();
    }
}

void umem_unmap_shmem(UMem *umem)
{
    if (umem->shmem) {
        munmap(umem->shmem, umem->size);
        umem->shmem = NULL;
    }
}

void umem_remove_shmem(UMem *umem, size_t offset, size_t size)
{
    size_t s = offset >> umem->page_shift;
    size_t e = (offset + size) >> umem->page_shift;
    size_t i;

    for (i = s; i < e; i++) {
        if (!test_and_set_bit(i, umem->faulted)) {
            umem->nsets++;
            qemu_madvise(umem->shmem + offset, size, QEMU_MADV_REMOVE);
        }
    }
}

bool umem_shmem_finished(const UMem *umem)
{
    return umem->nsets == umem->nbits;
}

void umem_close_shmem(UMem *umem)
{
    close(umem->shmem_fd);
    umem->shmem_fd = -1;
}

/***************************************************************************/
/* qemu main loop <-> umem thread communication */

static void umem_write_cmd(int fd, uint8_t cmd)
{
    ssize_t size;

    DPRINTF("write cmd %c\n", cmd);
    size = qemu_write_full(fd, &cmd, sizeof(cmd));
    if (size == 0) {
        if (errno == EPIPE) {
            perror("pipe");
            DPRINTF("write cmd %c %d: pipe is closed\n", cmd, errno);
            return;
        }

        perror("pipe");
        DPRINTF("write cmd %c %d\n", cmd, errno);
        abort();
    }
}

static void umem_read_cmd(int fd, uint8_t expect)
{
    ssize_t size;
    uint8_t cmd;

    size = qemu_read_full(fd, &cmd, sizeof(cmd));
    if (size == 0) {
        DPRINTF("read cmd %c: pipe is closed\n", cmd);
        abort();
    }

    DPRINTF("read cmd %c\n", cmd);
    if (cmd != expect) {
        DPRINTF("cmd %c expect %d\n", cmd, expect);
        abort();
    }
}

/* umem thread -> qemu main loop */
void umem_daemon_ready(int to_qemu_fd)
{
    umem_write_cmd(to_qemu_fd, UMEM_DAEMON_READY);
}

void umem_daemon_quit(QEMUFile *to_qemu)
{
    qemu_put_byte(to_qemu, UMEM_DAEMON_QUIT);
}

void umem_daemon_wait_for_qemu(int from_qemu_fd)
{
    umem_read_cmd(from_qemu_fd, UMEM_QEMU_READY);
}

/* qemu main loop -> umem thread */
void umem_qemu_wait_for_daemon(int from_umemd_fd)
{
    umem_read_cmd(from_umemd_fd, UMEM_DAEMON_READY);
}

void umem_qemu_ready(int to_umemd_fd)
{
    umem_write_cmd(to_umemd_fd, UMEM_QEMU_READY);
}

void umem_qemu_quit(QEMUFile *to_umemd)
{
    qemu_put_byte(to_umemd, UMEM_QEMU_QUIT);
}
