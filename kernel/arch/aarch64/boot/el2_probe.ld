/* Linker script for the aarch64 EL2 probe (kernel/arch/aarch64/boot/el2_probe.S).
 *
 * QEMU's `-M virt` loads direct-kernel ELFs at their LMA. The default
 * kernel load address for the virt machine is 0x40080000 (see QEMU
 * hw/arm/boot.c: arm_boot_info.loader_start + 0x80000). We place both
 * the entry point and all segments at that PA so QEMU can LOAD them
 * verbatim and jump straight into _start.
 */

ENTRY(_start)

SECTIONS {
    . = 0x40080000;
    .text : { *(.text._start) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
