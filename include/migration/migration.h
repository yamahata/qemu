/*
 * QEMU live migration
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

#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

#include "qapi/qmp/qdict.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/notify.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "qapi-types.h"
#include "exec/cpu-common.h"

struct MigrationParams {
    bool blk;
    bool shared;
    int precopy_count;
    int64_t prefault_forward;
    int64_t prefault_backward;
};

typedef struct MigrationState MigrationState;
typedef struct PostcopyOutgoingState PostcopyOutgoingState;
typedef struct RDMAPostcopyOutgoing RDMAPostcopyOutgoing;

struct MigrationState
{
    int64_t bandwidth_limit;
    size_t bytes_xfer;
    size_t xfer_limit;
    QemuThread thread;
    QEMUBH *cleanup_bh;
    QEMUFile *file;

    int state;
    MigrationParams params;
    double mbps;
    int64_t total_time;
    int64_t downtime;
    int64_t expected_downtime;
    int64_t dirty_pages_rate;
    int64_t dirty_bytes_rate;
    bool enabled_capabilities[MIGRATION_CAPABILITY_MAX];
    int64_t xbzrle_cache_size;
    int64_t setup_time;

    /* for postcopy */
    int substate;              /* precopy or postcopy */
    QEMUFile *file_read;        /* connection from the detination */
    PostcopyOutgoingState *postcopy;
    int precopy_count;
    bool force_postcopy_phase;
    RDMAPostcopyOutgoing *rdma_outgoing;
};

struct MigrationRateLimitStat
{
    int64_t initial_time;       /* in mili-second */
    int64_t initial_bytes;
    int64_t max_size;
};
typedef struct MigrationRateLimitStat MigrationRateLimitStat;

void migration_update_rate_limit_stat(MigrationState *s,
                                      MigrationRateLimitStat *rlstat,
                                      int64_t current_time);
int64_t migration_sleep_time_ms(const MigrationRateLimitStat *rlstat,
                                int64_t current_time);


void process_incoming_migration(QEMUFile *f);

void qemu_start_incoming_migration(const char *uri, Error **errp);

uint64_t migrate_max_downtime(void);

void do_info_migrate_print(Monitor *mon, const QObject *data);

void do_info_migrate(Monitor *mon, QObject **ret_data);

void exec_start_incoming_migration(const char *host_port, Error **errp);

void exec_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void tcp_start_incoming_migration(const char *host_port, Error **errp);

void tcp_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void unix_start_incoming_migration(const char *path, Error **errp);

void unix_start_outgoing_migration(MigrationState *s, const char *path, Error **errp);

void fd_start_incoming_migration(const char *path, Error **errp);

void fd_start_outgoing_migration(MigrationState *s, const char *fdname, Error **errp);

void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp);

void rdma_start_incoming_migration(const char *host_port, Error **errp);

void migrate_fd_error(MigrationState *s);

void migrate_fd_connect(MigrationState *s);

int migrate_fd_close(MigrationState *s);

void add_migration_state_change_notifier(Notifier *notify);
void remove_migration_state_change_notifier(Notifier *notify);
bool migration_in_setup(MigrationState *);
bool migration_has_finished(MigrationState *);
bool migration_has_failed(MigrationState *);
MigrationState *migrate_get_current(void);
void migration_bitmap_init(void);
void migration_bitmap_free(void);
const unsigned long *migration_bitmap_get(void);
void migration_bitmap_sync(void);

bool ram_save_block(QEMUFile *f, bool disable_xbzrle, bool last_stage);
uint64_t ram_save_pending(QEMUFile *f, void *opaque, uint64_t max_size);
uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_transferred(void);
uint64_t ram_bytes_total(void);

void acct_update_position(QEMUFile *f, size_t size, bool zero);

extern SaveVMHandlers savevm_ram_handlers;

uint64_t dup_mig_bytes_transferred(void);
uint64_t dup_mig_pages_transferred(void);
uint64_t skipped_mig_bytes_transferred(void);
uint64_t skipped_mig_pages_transferred(void);
uint64_t norm_mig_bytes_transferred(void);
uint64_t norm_mig_pages_transferred(void);
uint64_t xbzrle_mig_bytes_transferred(void);
uint64_t xbzrle_mig_pages_transferred(void);
uint64_t xbzrle_mig_pages_overflow(void);
uint64_t xbzrle_mig_pages_cache_miss(void);

void ram_handle_compressed(void *host, uint8_t ch, uint64_t size);

/**
 * @migrate_add_blocker - prevent migration from proceeding
 *
 * @reason - an error to be returned whenever migration is attempted
 */
void migrate_add_blocker(Error *reason);

/**
 * @migrate_del_blocker - remove a blocking error from migration
 *
 * @reason - the error blocking migration
 */
void migrate_del_blocker(Error *reason);

bool migrate_postcopy_outgoing(void);
bool migrate_postcopy_outgoing_no_background(void);
bool migrate_postcopy_outgoing_move_background(void);
bool migrate_postcopy_outgoing_rdma_compress(void);

bool migrate_rdma_pin_all(void);
bool migrate_zero_blocks(void);

bool migrate_auto_converge(void);

int xbzrle_encode_buffer(uint8_t *old_buf, uint8_t *new_buf, int slen,
                         uint8_t *dst, int dlen);
int xbzrle_decode_buffer(uint8_t *src, int slen, uint8_t *dst, int dlen);

int migrate_use_xbzrle(void);
int64_t migrate_xbzrle_cache_size(void);

int64_t xbzrle_cache_resize(int64_t new_size);

/* For outgoing postcopy */
int postcopy_outgoing_create_read_socket(MigrationState *s, int fd);
void postcopy_outgoing_state_begin(QEMUFile *f, const MigrationParams *params);
void postcopy_outgoing_state_complete(
    QEMUFile *f, const uint8_t *buffer, size_t buffer_size);
int postcopy_outgoing_ram_save_iterate(QEMUFile *f, void *opaque);
int postcopy_outgoing_ram_save_complete(QEMUFile *f, void *opaque);
uint64_t postcopy_outgoing_ram_save_pending(QEMUFile *f, void *opaque,
                                            uint64_t max_size);

PostcopyOutgoingState *postcopy_outgoing_begin(MigrationState *s);
void postcopy_outgoing_cleanup(MigrationState *ms);
int postcopy_outgoing(MigrationState *s, MigrationRateLimitStat *rlstat);

/* For incoming postcopy */
int postcopy_incoming_loadvm_state(QEMUFile *f, QEMUFile **buf_file);
void postcopy_incoming_qemu_cleanup(void);
#if defined(NEED_CPU_H) && !defined(CONFIG_USER_ONLY)
void postcopy_incoming_ram_free(RAMBlock *ram_block);
#endif

void ram_control_before_iterate(QEMUFile *f, uint64_t flags);
void ram_control_after_iterate(QEMUFile *f, uint64_t flags);
void ram_control_load_hook(QEMUFile *f, uint64_t flags);

/* Whenever this is found in the data stream, the flags
 * will be passed to ram_control_load_hook in the incoming-migration
 * side. This lets before_ram_iterate/after_ram_iterate add
 * transport-specific sections to the RAM migration data.
 */
#define RAM_SAVE_FLAG_HOOK     0x80

#define RAM_SAVE_CONTROL_NOT_SUPP -1000
#define RAM_SAVE_CONTROL_DELAYED  -2000
#define RAM_SAVE_CONTROL_EAGAIN   -3000 /* This page isn't saved. try later */

#if !defined(CONFIG_USER_ONLY) && defined(NEED_CPU_H)
size_t ram_control_save_page(QEMUFile *f, ram_addr_t block_offset,
                             ram_addr_t offset, size_t size,
                             int *bytes_sent);
#endif

#endif
