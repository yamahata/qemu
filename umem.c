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

#include <linux/umem.h>

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

#define DEV_UMEM        "/dev/umem"

UMem *umem_new(void *hostp, size_t size)
{
    struct umem_init uinit = {
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

    if (ioctl(umem->fd, UMEM_INIT, &uinit) < 0) {
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
    ssize_t left = page_cached->nr * sizeof(page_cached->pgoffs[0]);

    while (left > 0) {
        ssize_t ret = write(umem->fd, buf, left);
        if (ret == -1) {
            if (errno == EINTR)
                continue;

            perror("daemon: umem write");
            abort();
        }

        left -= ret;
        buf += ret;
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

void *umem_map_shmem(UMem *umem)
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
    return umem->shmem;
}

void umem_unmap_shmem(UMem *umem)
{
    munmap(umem->shmem, umem->size);
    umem->shmem = NULL;
}

void umem_remove_shmem(UMem *umem, size_t offset, size_t size)
{
    int s = offset >> umem->page_shift;
    int e = (offset + size) >> umem->page_shift;
    int i;

    for (i = s; i < e; i++) {
        if (!test_and_set_bit(i, umem->faulted)) {
            umem->nsets++;
#if defined(CONFIG_MADVISE) && defined(MADV_REMOVE)
            madvise(umem->shmem + offset, size, MADV_REMOVE);
#endif
        }
    }
}

void umem_close_shmem(UMem *umem)
{
    close(umem->shmem_fd);
    umem->shmem_fd = -1;
}

/***************************************************************************/
/* qemu <-> umem daemon communication */

size_t umem_pages_size(uint64_t nr)
{
    return sizeof(struct umem_pages) + nr * sizeof(uint64_t);
}

static void umem_write_cmd(int fd, uint8_t cmd)
{
    DPRINTF("write cmd %c\n", cmd);

    for (;;) {
        ssize_t ret = write(fd, &cmd, 1);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EPIPE) {
                perror("pipe");
                DPRINTF("write cmd %c %zd %d: pipe is closed\n",
                        cmd, ret, errno);
                break;
            }

            perror("pipe");
            DPRINTF("write cmd %c %zd %d\n", cmd, ret, errno);
            abort();
        }

        break;
    }
}

static void umem_read_cmd(int fd, uint8_t expect)
{
    uint8_t cmd;
    for (;;) {
        ssize_t ret = read(fd, &cmd, 1);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("pipe");
            DPRINTF("read error cmd %c %zd %d\n", cmd, ret, errno);
            abort();
        }

        if (ret == 0) {
            DPRINTF("read cmd %c %zd: pipe is closed\n", cmd, ret);
            abort();
        }

        break;
    }

    DPRINTF("read cmd %c\n", cmd);
    if (cmd != expect) {
        DPRINTF("cmd %c expect %d\n", cmd, expect);
        abort();
    }
}

struct umem_pages *umem_recv_pages(QEMUFile *f, int *offset)
{
    int ret;
    uint64_t nr;
    size_t size;
    struct umem_pages *pages;

    ret = qemu_peek_buffer(f, (uint8_t*)&nr, sizeof(nr), *offset);
    *offset += sizeof(nr);
    DPRINTF("ret %d nr %ld\n", ret, nr);
    if (ret != sizeof(nr) || nr == 0) {
        return NULL;
    }

    size = umem_pages_size(nr);
    pages = g_malloc(size);
    pages->nr = nr;
    size -= sizeof(pages->nr);

    ret = qemu_peek_buffer(f, (uint8_t*)pages->pgoffs, size, *offset);
    *offset += size;
    if (ret != size) {
        g_free(pages);
        return NULL;
    }
    return pages;
}

static void umem_send_pages(QEMUFile *f, const struct umem_pages *pages)
{
    size_t len = umem_pages_size(pages->nr);
    qemu_put_buffer(f, (const uint8_t*)pages, len);
}

/* umem daemon -> qemu */
void umem_daemon_ready(int to_qemu_fd)
{
    umem_write_cmd(to_qemu_fd, UMEM_DAEMON_READY);
}

void umem_daemon_quit(QEMUFile *to_qemu)
{
    qemu_put_byte(to_qemu, UMEM_DAEMON_QUIT);
}

void umem_daemon_send_pages_present(QEMUFile *to_qemu,
                                    struct umem_pages *pages)
{
    qemu_put_byte(to_qemu, UMEM_DAEMON_TRIGGER_PAGE_FAULT);
    umem_send_pages(to_qemu, pages);
}

void umem_daemon_wait_for_qemu(int from_qemu_fd)
{
    umem_read_cmd(from_qemu_fd, UMEM_QEMU_READY);
}

/* qemu -> umem daemon */
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

/* qemu side handler */
struct umem_pages *umem_qemu_trigger_page_fault(QEMUFile *from_umemd,
                                                int *offset)
{
    uint64_t i;
    int page_shift = ffs(getpagesize()) - 1;
    struct umem_pages *pages = umem_recv_pages(from_umemd, offset);
    if (pages == NULL) {
        return NULL;
    }

    for (i = 0; i < pages->nr; i++) {
        ram_addr_t addr = pages->pgoffs[i] << page_shift;

        /* make pages present by forcibly triggering page fault. */
        volatile uint8_t *ram = qemu_get_ram_ptr(addr);
        uint8_t dummy_read = ram[0];
        (void)dummy_read;   /* suppress unused variable warning */
    }

    /*
     * Very Linux implementation specific.
     * Make it sure that other thread doesn't fault on the above virtual
     * address. (More exactly other thread doesn't call fault handler with
     * the offset.)
     * the fault handler is called with mmap_sem read locked.
     * madvise() does down/up_write(mmap_sem)
     */
    qemu_madvise(NULL, 0, MADV_NORMAL);

    return pages;
}

void umem_qemu_send_pages_present(QEMUFile *to_umemd,
                                  const struct umem_pages *pages)
{
    qemu_put_byte(to_umemd, UMEM_QEMU_PAGE_FAULTED);
    umem_send_pages(to_umemd, pages);
}

void umem_qemu_send_pages_unmapped(QEMUFile *to_umemd,
                                   const struct umem_pages *pages)
{
    qemu_put_byte(to_umemd, UMEM_QEMU_PAGE_UNMAPPED);
    umem_send_pages(to_umemd, pages);
}
