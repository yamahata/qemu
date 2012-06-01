/*
 * QEMU buffered QEMUFile
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_BUFFERED_FILE_H
#define QEMU_BUFFERED_FILE_H

#include "hw/hw.h"

struct QEMUBuffer {
    uint8_t *buffer;
    size_t buffer_size;
    size_t buffer_capacity;
    bool freeze_output;
};
typedef struct QEMUBuffer QEMUBuffer;

struct QEMUFileBuf {
    QEMUFile *file;
    QEMUBuffer buf;
};
typedef struct QEMUFileBuf QEMUFileBuf;

QEMUFileBuf *qemu_fopen_buf_write(void);
/* This get the ownership of buf. */
QEMUFile *qemu_fopen_buf_read(uint8_t *buf, size_t size);

struct QEMUFileNonblock {
    int fd;
    QEMUFile *file;

    QEMUBuffer buf;
};
typedef struct QEMUFileNonblock QEMUFileNonblock;

QEMUFileNonblock *qemu_fopen_nonblock(int fd);
int nonblock_pending_size(QEMUFileNonblock *s);
void nonblock_fflush(QEMUFileNonblock *s);
void nonblock_wait_for_flush(QEMUFileNonblock *s);

typedef ssize_t (BufferedPutFunc)(void *opaque, const void *data, size_t size);
typedef void (BufferedPutReadyFunc)(void *opaque);
typedef void (BufferedWaitForUnfreezeFunc)(void *opaque);
typedef int (BufferedCloseFunc)(void *opaque);

QEMUFile *qemu_fopen_ops_buffered(void *opaque, size_t xfer_limit,
                                  BufferedPutFunc *put_buffer,
                                  BufferedPutReadyFunc *put_ready,
                                  BufferedWaitForUnfreezeFunc *wait_for_unfreeze,
                                  BufferedCloseFunc *close);
void qemu_buffered_file_drain_buffer(void *buffered_file);
void qemu_buffered_file_ready_buffer(void *buffered_file);

#endif
