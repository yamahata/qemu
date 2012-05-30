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

#include "qdict.h"
#include "qemu-common.h"
#include "notify.h"
#include "error.h"

struct MigrationParams {
    int blk;
    int shared;
    int postcopy;
    int movebg;
    int nobg;
    int64_t prefault_forward;
    int64_t prefault_backward;
};

typedef struct MigrationState MigrationState;

struct MigrationState
{
    int64_t bandwidth_limit;
    QEMUFile *file;
    int fd;
    int state;
    int (*get_error)(MigrationState *s);
    int (*close)(MigrationState *s);
    int (*write)(MigrationState *s, const void *buff, size_t size);
    void *opaque;
    MigrationParams params;

    /* for postcopy */
    int substate;              /* precopy or postcopy */
    int fd_read;
    QEMUFile *file_read;        /* connection from the detination */
    void *postcopy;
};

void process_incoming_migration(QEMUFile *f);

int qemu_start_incoming_migration(const char *uri, Error **errp);

uint64_t migrate_max_downtime(void);

void do_info_migrate_print(Monitor *mon, const QObject *data);

void do_info_migrate(Monitor *mon, QObject **ret_data);

int exec_start_incoming_migration(const char *host_port);

int exec_start_outgoing_migration(MigrationState *s, const char *host_port);

int tcp_start_incoming_migration(const char *host_port, Error **errp);

int tcp_start_outgoing_migration(MigrationState *s, const char *host_port,
                                 Error **errp);

int unix_start_incoming_migration(const char *path);

int unix_start_outgoing_migration(MigrationState *s, const char *path);

int fd_start_incoming_migration(const char *path);

int fd_start_outgoing_migration(MigrationState *s, const char *fdname);

int migrate_fd_cleanup(MigrationState *s);
void migrate_fd_error(MigrationState *s);
void migrate_fd_completed(MigrationState *s);

void migrate_fd_connect(MigrationState *s);

void add_migration_state_change_notifier(Notifier *notify);
void remove_migration_state_change_notifier(Notifier *notify);
bool migration_is_active(MigrationState *);
bool migration_has_finished(MigrationState *);
bool migration_has_failed(MigrationState *);

uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_transferred(void);
uint64_t ram_bytes_total(void);

void ram_save_set_params(const MigrationParams *params, void *opaque);
void sort_ram_list(void);
int ram_save_block(QEMUFile *f);
void ram_save_memory_set_dirty(void);
void ram_save_live_mem_size(QEMUFile *f);
int ram_save_live(QEMUFile *f, int stage, void *opaque);
int ram_load(QEMUFile *f, void *opaque, int version_id);

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

/* For outgoing postcopy */
int postcopy_outgoing_create_read_socket(MigrationState *s);
int postcopy_outgoing_ram_save_live(QEMUFile *f, int stage, void *opaque);
void *postcopy_outgoing_begin(MigrationState *s);
int postcopy_outgoing_ram_save_background(QEMUFile *f, void *postcopy);

/* For incoming postcopy */
extern bool incoming_postcopy;
extern unsigned long incoming_postcopy_flags;

void postcopy_incoming_ram_free(UMem *umem);
void postcopy_incoming_prepare(void);

int postcopy_incoming_ram_load(QEMUFile *f, void *opaque, int version_id);
void postcopy_incoming_fork_umemd(QEMUFile *mig_read);
void postcopy_incoming_qemu_ready(void);
void postcopy_incoming_qemu_cleanup(void);
#if defined(NEED_CPU_H) && !defined(CONFIG_USER_ONLY)
void postcopy_incoming_qemu_pages_unmapped(ram_addr_t addr, ram_addr_t size);
#endif

#endif
