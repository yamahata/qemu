#ifndef MIGRATION_RDMA_H
#define MIGRATION_RDMA_H
/*
 * migration/rdma.h: rdma postcopy live migration
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

#include "migration/migration.h"
#include "migration/postcopy.h"

/* rdma outgoing  */
int postcopy_rdma_outgoing(MigrationState *ms, MigrationRateLimitStat *rlstat);
void postcopy_rdma_outgoing_cleanup(RDMAPostcopyOutgoing *outgoing);
int postcopy_rdma_outgoing_loop(MigrationState *ms,
                                MigrationRateLimitStat *rlstat);


/* rdma incoming */
typedef struct RDMAPostcopyIncoming RDMAPostcopyIncoming;
struct RDMAPostcopyIncomingInit {
    UMemBlockHead *umem_blocks;
    bool precopy_enabled;
    struct rdma_event_channel *channel;
    struct rdma_cm_id *listen_id;
};
typedef struct RDMAPostcopyIncomingInit RDMAPostcopyIncomingInit;

void postcopy_rdma_incoming_prefork(QEMUFile *f,
                                    RDMAPostcopyIncomingInit *arg);
void postcopy_rdma_incoming_postfork_parent(RDMAPostcopyIncomingInit *arg);
RDMAPostcopyIncoming* postcopy_rdma_incoming_init(
    RDMAPostcopyIncomingInit *arg);
void postcopy_rdma_incoming_cleanup(RDMAPostcopyIncoming *rdma);
int postcopy_rdma_incoming_umemd_read_clean_bitmap(
    RDMAPostcopyIncoming *incoming, UMemBlockHead *umem_blocks);
int postcopy_rdma_incoming_send_req(RDMAPostcopyIncoming* incoming,
                                    const QEMUUMemReq *req,
                                    const UMemBlock *umem_block);
int postcopy_rdma_incoming_recv(RDMAPostcopyIncoming *incoming);

#endif /* MIGRATION_RDMA_H */
