/*
 * User process backed memory.
 * This is mainly for KVM post copy.
 *
 * Copyright (c) 2011,
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

#ifndef __LINUX_UVMEM_H
#define __LINUX_UVMEM_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct uvmem_init {
	__u64 size;		/* in bytes */
	__s32 shmem_fd;
	__s32 padding;
};

#define UVMEMIO	0x1E

/* ioctl for uvmem fd */
#define UVMEM_INIT			_IOWR(UVMEMIO, 0x0, struct uvmem_init)

#endif /* __LINUX_UVMEM_H */
