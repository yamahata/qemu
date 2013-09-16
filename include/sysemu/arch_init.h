#ifndef QEMU_ARCH_INIT_H
#define QEMU_ARCH_INIT_H

#include "qmp-commands.h"
#include "qemu/option.h"

enum {
    QEMU_ARCH_ALL = -1,
    QEMU_ARCH_ALPHA = 1,
    QEMU_ARCH_ARM = 2,
    QEMU_ARCH_CRIS = 4,
    QEMU_ARCH_I386 = 8,
    QEMU_ARCH_M68K = 16,
    QEMU_ARCH_LM32 = 32,
    QEMU_ARCH_MICROBLAZE = 64,
    QEMU_ARCH_MIPS = 128,
    QEMU_ARCH_PPC = 256,
    QEMU_ARCH_S390X = 512,
    QEMU_ARCH_SH4 = 1024,
    QEMU_ARCH_SPARC = 2048,
    QEMU_ARCH_XTENSA = 4096,
    QEMU_ARCH_OPENRISC = 8192,
    QEMU_ARCH_UNICORE32 = 0x4000,
    QEMU_ARCH_MOXIE = 0x8000,
};

extern const uint32_t arch_type;

void select_soundhw(const char *optarg);
void do_acpitable_option(const QemuOpts *opts);
void do_smbios_option(const char *optarg);
void cpudef_init(void);
void audio_init(void);
int tcg_available(void);
int kvm_available(void);
int xen_available(void);

CpuDefinitionInfoList *arch_query_cpu_definitions(Error **errp);

#define RAM_SAVE_FLAG_FULL     0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_COMPRESS 0x02
#define RAM_SAVE_FLAG_MEM_SIZE 0x04
#define RAM_SAVE_FLAG_PAGE     0x08
#define RAM_SAVE_FLAG_EOS      0x10
#define RAM_SAVE_FLAG_CONTINUE 0x20
#define RAM_SAVE_FLAG_XBZRLE   0x40
/* 0x80 is reserved in migration.h start with 0x100 next */

#define RAM_SAVE_VERSION_ID     4 /* currently version 4 */

void ram_save_page_reset(void);
int ram_load_page(QEMUFile *f, void *host, int flags);
int ram_save_iterate(QEMUFile *f);

#if defined(NEED_CPU_H) && !defined(CONFIG_USER_ONLY)
bool migration_bitmap_test_dirty(MemoryRegion *mr, ram_addr_t offset);
bool migration_bitmap_test_and_reset_dirty(MemoryRegion *mr, ram_addr_t offset);
void ram_save_bulk_stage_done(void);
void ram_save_set_last_seen_block(RAMBlock *block, ram_addr_t offset);
RAMBlock *ram_find_block(const char *id, uint8_t len);
void ram_save_page(QEMUFile *f, RAMBlock *block, ram_addr_t offset);
int ram_load_mem_size(QEMUFile *f, ram_addr_t total_ram_bytes);
int ram_load(QEMUFile *f, void *opaque, int version_id,
             void *(host_from_stream_offset_p)(QEMUFile *f,
                                               ram_addr_t offsset, int flags));
#endif

#endif
