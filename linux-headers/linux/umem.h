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

#ifndef __LINUX_UMEM_H
#define __LINUX_UMEM_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct umem_init {
	__u64 size;		/* in bytes */
	__s32 shmem_fd;
	__s32 padding;
};

#define UMEMIO	0x1E

/* ioctl for umem fd */
#define UMEM_INIT		_IOWR(UMEMIO, 0x0, struct umem_init)
#define UMEM_MAKE_VMA_ANONYMOUS	_IO  (UMEMIO, 0x1)

#endif /* __LINUX_UMEM_H */
