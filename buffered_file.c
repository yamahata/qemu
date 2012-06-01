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
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "hw/hw.h"
#include "qemu-timer.h"
#include "qemu-char.h"
#include "buffered_file.h"

//#define DEBUG_BUFFERED_FILE
#ifdef DEBUG_BUFFERED_FILE
#define DPRINTF(fmt, ...) \
    do { printf("buffered-file: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif


/***************************************************************************
 * buffer management
 */

static void buffer_destroy(QEMUBuffer *s)
{
    g_free(s->buffer);
}

static void buffer_consume(QEMUBuffer *s, size_t offset)
{
    if (offset > 0) {
        assert(s->buffer_size >= offset);
        memmove(s->buffer, s->buffer + offset, s->buffer_size - offset);
        s->buffer_size -= offset;
    }
}

static void buffer_append(QEMUBuffer *s, const uint8_t *buf, size_t size)
{
#define BUF_SIZE_INC    (32 * 1024)     /* = IO_BUF_SIZE */
    int inc = size - (s->buffer_capacity - s->buffer_size);
    if (inc > 0) {
        s->buffer_capacity += DIV_ROUND_UP(inc, BUF_SIZE_INC) * BUF_SIZE_INC;
        s->buffer = g_realloc(s->buffer, s->buffer_capacity);
    }
    memcpy(s->buffer + s->buffer_size, buf, size);
    s->buffer_size += size;
}

typedef ssize_t (BufferPutBuf)(void *opaque, const void *data, size_t size);

static void buffer_flush(QEMUBuffer *buf, QEMUFile *file,
                         void *opaque, BufferPutBuf *put_buf)
{
    size_t offset = 0;
    int error;

    error = qemu_file_get_error(file);
    if (error != 0) {
        DPRINTF("flush when error, bailing: %s\n", strerror(-error));
        return;
    }

    DPRINTF("flushing %zu byte(s) of data\n", buf->buffer_size);

    while (offset < buf->buffer_size) {
        ssize_t ret;

        ret = put_buf(opaque, buf->buffer + offset, buf->buffer_size - offset);
        if (ret == -EINTR) {
            continue;
        } else if (ret == -EAGAIN) {
            DPRINTF("backend not ready, freezing\n");
            buf->freeze_output = true;
            break;
        }

        if (ret < 0) {
            DPRINTF("error flushing data, %zd\n", ret);
            qemu_file_set_error(file, ret);
            break;
        } else if (ret == 0) {
            DPRINTF("ret == 0\n");
            break;
        } else {
            DPRINTF("flushed %zd byte(s)\n", ret);
            offset += ret;
        }
    }

    DPRINTF("flushed %zu of %zu byte(s)\n", offset, buf->buffer_size);
    buffer_consume(buf, offset);
}


/***************************************************************************
 * read/write to buffer on memory
 */

static int buf_close(void *opaque)
{
    QEMUFileBuf *s = opaque;
    buffer_destroy(&s->buf);
    g_free(s);
    return 0;
}

static int buf_put_buffer(void *opaque,
                          const uint8_t *buf, int64_t pos, int size)
{
    QEMUFileBuf *s = opaque;
    buffer_append(&s->buf, buf, size);
    return size;
}

QEMUFileBuf *qemu_fopen_buf_write(void)
{
    QEMUFileBuf *s = g_malloc0(sizeof(*s));

    s->file = qemu_fopen_ops(s,  buf_put_buffer, NULL, buf_close,
                             NULL, NULL, NULL);
    return s;
}

static int buf_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    QEMUFileBuf *s = opaque;
    ssize_t len = MIN(size, s->buf.buffer_capacity - s->buf.buffer_size);
    memcpy(buf, s->buf.buffer + s->buf.buffer_size, len);
    s->buf.buffer_size += len;
    return len;
}

/* This get the ownership of buf. */
QEMUFile *qemu_fopen_buf_read(uint8_t *buf, size_t size)
{
    QEMUFileBuf *s = g_malloc0(sizeof(*s));
    s->buf.buffer = buf;
    s->buf.buffer_size = 0; /* this is used as index to read */
    s->buf.buffer_capacity = size;
    s->file = qemu_fopen_ops(s, NULL, buf_get_buffer, buf_close,
                             NULL, NULL, NULL);
    return s->file;
}

/***************************************************************************
 * Nonblocking write only file
 */
static ssize_t nonblock_flush_buffer_putbuf(void *opaque,
                                            const void *data, size_t size)
{
    QEMUFileNonblock *s = opaque;
    ssize_t ret = write(s->fd, data, size);
    if (ret == -1) {
        return -errno;
    }
    return ret;
}

static void nonblock_flush_buffer(QEMUFileNonblock *s)
{
    buffer_flush(&s->buf, s->file, s, &nonblock_flush_buffer_putbuf);

    if (s->buf.buffer_size > 0) {
        s->buf.freeze_output = true;
    }
}

static int nonblock_put_buffer(void *opaque,
                               const uint8_t *buf, int64_t pos, int size)
{
    QEMUFileNonblock *s = opaque;
    int error;
    ssize_t len = 0;

    error = qemu_file_get_error(s->file);
    if (error) {
        return error;
    }

    nonblock_flush_buffer(s);
    error = qemu_file_get_error(s->file);
    if (error) {
        return error;
    }

    while (!s->buf.freeze_output && size > 0) {
        ssize_t ret;
        assert(s->buf.buffer_size == 0);

        ret = write(s->fd, buf, size);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN) {
                s->buf.freeze_output = true;
            } else {
                qemu_file_set_error(s->file, errno);
            }
            break;
        }

        len += ret;
        buf += ret;
        size -= ret;
    }

    if (size > 0) {
        buffer_append(&s->buf, buf, size);
        len += size;
    }
    return len;
}

int nonblock_pending_size(QEMUFileNonblock *s)
{
    return qemu_pending_size(s->file) + s->buf.buffer_size;
}

void nonblock_fflush(QEMUFileNonblock *s)
{
    s->buf.freeze_output = false;
    nonblock_flush_buffer(s);
    if (!s->buf.freeze_output) {
        qemu_fflush(s->file);
    }
}

void nonblock_wait_for_flush(QEMUFileNonblock *s)
{
    while (nonblock_pending_size(s) > 0) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s->fd, &fds);
        select(s->fd + 1, NULL, &fds, NULL, NULL);

        nonblock_fflush(s);
    }
}

static int nonblock_close(void *opaque)
{
    QEMUFileNonblock *s = opaque;
    nonblock_wait_for_flush(s);
    buffer_destroy(&s->buf);
    g_free(s);
    return 0;
}

QEMUFileNonblock *qemu_fopen_nonblock(int fd)
{
    QEMUFileNonblock *s = g_malloc0(sizeof(*s));

    s->fd = fd;
    fcntl_setfl(fd, O_NONBLOCK);
    s->file = qemu_fopen_ops(s, nonblock_put_buffer, NULL, nonblock_close,
                             NULL, NULL, NULL);
    return s;
}

/***************************************************************************
 * Buffered File
 */

typedef struct QEMUFileBuffered
{
    BufferedPutFunc *put_buffer;
    BufferedPutReadyFunc *put_ready;
    BufferedWaitForUnfreezeFunc *wait_for_unfreeze;
    BufferedCloseFunc *close;
    void *opaque;
    QEMUFile *file;
    size_t bytes_xfer;
    size_t xfer_limit;
    QEMUTimer *timer;
    QEMUBuffer buf;
} QEMUFileBuffered;

static ssize_t buffered_flush_putbuf(void *opaque,
                                     const void *data, size_t size)
{
    QEMUFileBuffered *s = opaque;
    ssize_t ret = s->put_buffer(s->opaque, data, size);
    if (ret == 0) {
        DPRINTF("error flushing data, %zd\n", ret);
        qemu_file_set_error(s->file, ret);
    }
    return ret;
}

static void buffered_flush(QEMUFileBuffered *s)
{
    buffer_flush(&s->buf, s->file, s, buffered_flush_putbuf);
}

static int buffered_put_buffer(void *opaque, const uint8_t *buf, int64_t pos, int size)
{
    QEMUFileBuffered *s = opaque;
    int offset = 0, error;
    ssize_t ret;

    DPRINTF("putting %d bytes at %" PRId64 "\n", size, pos);

    error = qemu_file_get_error(s->file);
    if (error) {
        DPRINTF("flush when error, bailing: %s\n", strerror(-error));
        return error;
    }

    DPRINTF("unfreezing output\n");
    s->buf.freeze_output = false;

    buffered_flush(s);

    while (!s->buf.freeze_output && offset < size) {
        if (s->bytes_xfer > s->xfer_limit) {
            DPRINTF("transfer limit exceeded when putting\n");
            break;
        }

        ret = s->put_buffer(s->opaque, buf + offset, size - offset);
        if (ret == -EAGAIN) {
            DPRINTF("backend not ready, freezing\n");
            s->buf.freeze_output = true;
            break;
        }

        if (ret <= 0) {
            DPRINTF("error putting\n");
            qemu_file_set_error(s->file, ret);
            offset = -EINVAL;
            break;
        }

        DPRINTF("put %zd byte(s)\n", ret);
        offset += ret;
        s->bytes_xfer += ret;
    }

    if (offset >= 0) {
        DPRINTF("buffering %d bytes\n", size - offset);
        buffer_append(&s->buf, buf + offset, size - offset);
        offset = size;
    }

    if (pos == 0 && size == 0) {
        DPRINTF("file is ready\n");
        if (s->bytes_xfer <= s->xfer_limit) {
            DPRINTF("notifying client\n");
            s->put_ready(s->opaque);
        }
    }

    return offset;
}

static void buffered_drain(QEMUFileBuffered *s)
{
    while (!qemu_file_get_error(s->file) && s->buf.buffer_size) {
        buffered_flush(s);
        if (s->buf.freeze_output)
            s->wait_for_unfreeze(s->opaque);
    }
}

static int buffered_close(void *opaque)
{
    QEMUFileBuffered *s = opaque;
    int ret;

    DPRINTF("closing\n");

    buffered_drain(s);

    ret = s->close(s->opaque);

    qemu_del_timer(s->timer);
    qemu_free_timer(s->timer);
    buffer_destroy(&s->buf);
    g_free(s);

    return ret;
}

/*
 * The meaning of the return values is:
 *   0: We can continue sending
 *   1: Time to stop
 *   negative: There has been an error
 */
static int buffered_rate_limit(void *opaque)
{
    QEMUFileBuffered *s = opaque;
    int ret;

    ret = qemu_file_get_error(s->file);
    if (ret) {
        return ret;
    }
    if (s->buf.freeze_output)
        return 1;

    if (s->bytes_xfer > s->xfer_limit)
        return 1;

    return 0;
}

static int64_t buffered_set_rate_limit(void *opaque, int64_t new_rate)
{
    QEMUFileBuffered *s = opaque;
    if (qemu_file_get_error(s->file)) {
        goto out;
    }
    if (new_rate > SIZE_MAX) {
        new_rate = SIZE_MAX;
    }

    s->xfer_limit = new_rate / 10;
    
out:
    return s->xfer_limit;
}

static int64_t buffered_get_rate_limit(void *opaque)
{
    QEMUFileBuffered *s = opaque;
  
    return s->xfer_limit;
}

static void buffered_rate_tick(void *opaque)
{
    QEMUFileBuffered *s = opaque;

    if (qemu_file_get_error(s->file)) {
        buffered_close(s);
        return;
    }

    qemu_mod_timer(s->timer, qemu_get_clock_ms(rt_clock) + 100);

    if (s->buf.freeze_output)
        return;

    s->bytes_xfer = 0;

    buffered_flush(s);

    /* Add some checks around this */
    s->put_ready(s->opaque);
}

QEMUFile *qemu_fopen_ops_buffered(void *opaque,
                                  size_t bytes_per_sec,
                                  BufferedPutFunc *put_buffer,
                                  BufferedPutReadyFunc *put_ready,
                                  BufferedWaitForUnfreezeFunc *wait_for_unfreeze,
                                  BufferedCloseFunc *close)
{
    QEMUFileBuffered *s;

    s = g_malloc0(sizeof(*s));

    s->opaque = opaque;
    s->xfer_limit = bytes_per_sec / 10;
    s->put_buffer = put_buffer;
    s->put_ready = put_ready;
    s->wait_for_unfreeze = wait_for_unfreeze;
    s->close = close;

    s->file = qemu_fopen_ops(s, buffered_put_buffer, NULL,
                             buffered_close, buffered_rate_limit,
                             buffered_set_rate_limit,
			     buffered_get_rate_limit);

    s->timer = qemu_new_timer_ms(rt_clock, buffered_rate_tick, s);

    qemu_mod_timer(s->timer, qemu_get_clock_ms(rt_clock) + 100);

    return s->file;
}

void qemu_buffered_file_drain_buffer(void *buffered_file)
{
    buffered_drain(buffered_file);
}

void qemu_buffered_file_ready_buffer(void *buffered_file)
{
    QEMUFileBuffered *s = buffered_file;
    s->bytes_xfer = 0;
    if (!s->buf.freeze_output) {
        s->put_ready(s);
    }
}
