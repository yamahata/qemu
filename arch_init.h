#ifndef QEMU_ARCH_INIT_H
#define QEMU_ARCH_INIT_H

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
};

extern const uint32_t arch_type;

void select_soundhw(const char *optarg);
void do_acpitable_option(const char *optarg);
void do_smbios_option(const char *optarg);
void cpudef_init(void);
int audio_available(void);
void audio_init(ISABus *isa_bus, PCIBus *pci_bus);
int tcg_available(void);
int kvm_available(void);
int xen_available(void);

#define RAM_SAVE_FLAG_FULL     0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_COMPRESS 0x02
#define RAM_SAVE_FLAG_MEM_SIZE 0x04
#define RAM_SAVE_FLAG_PAGE     0x08
#define RAM_SAVE_FLAG_EOS      0x10
#define RAM_SAVE_FLAG_CONTINUE 0x20

#define RAM_SAVE_VERSION_ID     4 /* currently version 4 */

#if defined(NEED_CPU_H) && !defined(CONFIG_USER_ONLY)
void ram_save_set_last_block(RAMBlock *block, ram_addr_t offset);
int ram_save_page(QEMUFile *f, RAMBlock *block, ram_addr_t offset);
RAMBlock *ram_find_block(const char *id, uint8_t len);
void *ram_load_host_from_stream_offset(QEMUFile *f,
                                       ram_addr_t offset,
                                       int flags,
                                       RAMBlock **last_blockp);
int ram_load_mem_size(QEMUFile *f, ram_addr_t total_ram_bytes);
#endif

#endif
