/*
 * migration-postcopy-stub.c: postcopy livemigration
 *                            stub functions for non-supported hosts
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

#include "sysemu.h"
#include "migration.h"

int postcopy_outgoing_create_read_socket(MigrationState *s)
{
    return -ENOSYS;
}

int postcopy_outgoing_ram_save_live(Monitor *mon,
                                    QEMUFile *f, int stage, void *opaque)
{
    return -ENOSYS;
}

void *postcopy_outgoing_begin(MigrationState *ms)
{
    return NULL;
}

int postcopy_outgoing_ram_save_background(Monitor *mon, QEMUFile *f,
                                          void *postcopy)
{
    return -ENOSYS;
}

int postcopy_incoming_init(const char *incoming, bool incoming_postcopy)
{
    return -ENOSYS;
}

void postcopy_incoming_prepare(void)
{
}

int postcopy_incoming_ram_load(QEMUFile *f, void *opaque, int version_id)
{
    return -ENOSYS;
}

void postcopy_incoming_fork_umemd(QEMUFile *mig_read)
{
}

void postcopy_incoming_qemu_ready(void)
{
}

void postcopy_incoming_qemu_cleanup(void)
{
}

void postcopy_incoming_qemu_pages_unmapped(ram_addr_t addr, ram_addr_t size)
{
}
