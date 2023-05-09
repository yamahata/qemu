/*
 * QEMU host private memfd memory backend
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Authors:
 *   Chao Peng <chao.p.peng@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "sysemu/hostmem.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qom/object.h"

#define TYPE_MEMORY_BACKEND_MEMFD_PRIVATE "memory-backend-memfd-private"

OBJECT_DECLARE_SIMPLE_TYPE(HostMemoryBackendPrivateMemfd,
                           MEMORY_BACKEND_MEMFD_PRIVATE)


struct HostMemoryBackendPrivateMemfd {
    HostMemoryBackend parent_obj;
    HostMemoryBackend *shmem;
    char *path;
};

static void
priv_memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(backend);
    int priv_fd;
    unsigned int flags;
    int mount_fd;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return;
    }

    if (!m->shmem) {
        error_setg(errp, "shmemdev must be specified for "TYPE_MEMORY_BACKEND_MEMFD_PRIVATE);
        return;
    }
    backend->mr = m->shmem->mr;

    flags = 0;
    mount_fd = -1;
    if (m->path) {
        flags = RMFD_USERMNT;
        mount_fd = open_tree(AT_FDCWD, m->path, OPEN_TREE_CLOEXEC);
        if (mount_fd == -1) {
            error_setg(errp, "open_tree() failed at %s: %s",
                       m->path, strerror(errno));
            return;
        }
    }
    priv_fd = qemu_memfd_restricted(backend->size, flags, mount_fd, errp);
    if (mount_fd >= 0) {
        close(mount_fd);
    }
    if (priv_fd == -1) {
        return;
    }

    memory_region_set_restricted_fd(backend->mr, priv_fd);
}

static char *priv_memfd_backend_get_path(Object *obj, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);

    return g_strdup(m->path);
}

static void priv_memfd_backend_set_path(Object *obj, const char *value, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);

    g_free(m->path);
    m->path = g_strdup(value);
}

static void
priv_memfd_backend_instance_init(Object *obj)
{
    MEMORY_BACKEND(obj)->reserve = false;
}

static void
priv_memfd_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = priv_memfd_backend_memory_alloc;

    object_class_property_add_str(oc, "path",
                                  priv_memfd_backend_get_path,
                                  priv_memfd_backend_set_path);
    object_class_property_set_description(oc, "path",
                                          "path to mount point of shmfs");
    object_class_property_add_link(oc,
                                   "shmemdev",
                                   TYPE_MEMORY_BACKEND,
                                   offsetof(HostMemoryBackendPrivateMemfd, shmem),
                                   object_property_allow_set_link,
                                   OBJ_PROP_LINK_STRONG);
    object_class_property_set_description(oc, "shmemdev",
                                          "memory backend for shared memory");
}

static const TypeInfo priv_memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD_PRIVATE,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = priv_memfd_backend_instance_init,
    .class_init = priv_memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendPrivateMemfd),
};

static void register_types(void)
{
    if (qemu_memfd_check(MFD_ALLOW_SEALING)) {
        type_register_static(&priv_memfd_backend_info);
    }
}

type_init(register_types);
