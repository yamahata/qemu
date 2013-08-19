/*
 * migration-postcopy.c: postcopy livemigration
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

/***************************************************************************
 * stub functions for rdma-postcopy
 */
void postcopy_rdma_outgoing_cleanup(RDMAPostcopyOutgoing *outgoing)
{
}

int postcopy_rdma_outgoing(MigrationState *ms, MigrationRateLimitStat *rlstat)
{
    return -ENOSYS;
}

int postcopy_rdma_outgoing_loop(MigrationState *ms,
                                MigrationRateLimitStat *rlstat)
{
    return -ENOSYS;
}

int postcopy_rdma_incoming_send_req(RDMAPostcopyIncoming *incoming,
                                    const QEMUUMemReq *umem_req,
                                    const UMemBlock *umem_block)
{
    return -ENOSYS;
}

RDMAPostcopyIncoming*
postcopy_rdma_incoming_init(UMemBlockHead *umem_blocks, bool precopy_enabled)
{
    return NULL;
}

int postcopy_rdma_incoming_umemd_read_clean_bitmap(
    RDMAPostcopyIncoming *incoming, UMemBlockHead *umem_blocks)
{
    return -ENOSYS;
}

int postcopy_rdma_incoming_recv(RDMAPostcopyIncoming *incoming)
{
    return -ENOSYS;
}

void postcopy_rdma_incoming_cleanup(RDMAPostcopyIncoming *incoming)
{
}
