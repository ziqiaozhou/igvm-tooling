import argparse
import logging
import subprocess

from ctypes import sizeof
from typing import List

import igvm.elf as elflib
from elftools.elf import *
from igvm.bootcstruct import *
from igvm.acpi import ACPI, ACPI_RSDP_ADDR, ACPI_END_ADDR
from igvm.igvmbase import IGVMBaseGenerator
from igvm.igvmfile import PGSIZE, ALIGN
from igvm.vmstate import ARCH

boot_params = struct_boot_params
setup_header = struct_setup_header

import ctypes
class struct_verismo_params(ctypes.Structure):
            pass

struct_verismo_params._pack_ = 1 # source:False
struct_verismo_params._fields_ = [
    ('cpu_count', ctypes.c_uint64),
    ('cpuid_page', ctypes.c_uint64),
    ('secret_page', ctypes.c_uint64),
    ('hv_param_page', ctypes.c_uint64),
    ('validated_entries', ctypes.c_uint64),
    ('validated_e820', struct_boot_e820_entry * 16),
    ('vmpl2_acpi', ctypes.c_uint64),
    ('vmpl2_acpi_size', ctypes.c_uint64),
    ('vmpl2_start', ctypes.c_uint64),
    ('vmpl2_kernel_size', ctypes.c_uint64),
    ('vmpl2_cmdline', ctypes.c_uint8 * 256),
    ('vmpl2_cmdline_len', ctypes.c_uint64),
]

verismo_params = struct_verismo_params

class IGVMVeriSMoGenerator(IGVMBaseGenerator):

    R = 1<<2
    W = 1<<1
    X = 1<<0
    BOOT_STACK_SIZE = 0x4000
    def __init__(self, **kwargs):
        # Parse BzImage header
        IGVMBaseGenerator.__init__(self, **kwargs)
        self.extra_validated_ram: List = []
        self._start = kwargs["start_addr"]

        acpi_dir = kwargs["acpi_dir"] if "acpi_dir" in kwargs else None
        self.acpidata: ACPI = ACPI(acpi_dir)

        self.elf = elflib.ELFObj(self.infile)
        self.cmdline = bytes(kwargs["append"] if "append" in kwargs else None, 'ascii') + bytes([0])

        in_path = self.infile.name
        bin_path = in_path + ".binary"
        subprocess.check_output(["objcopy", in_path, "-O", "binary", bin_path])
        with open(bin_path, "rb") as f:
            self._kernel: bytes = f.read()

        vmpl2_file: argparse.FileType = kwargs["vmpl2_kernel"] if "vmpl2_kernel" in kwargs else None
        self.pgtable_level: int = kwargs["pgtable_level"] if "pgtable_level" in kwargs else 2
        self.assign_stack: bool = True
        self._vmpl2_kernel: bytearray = bytearray(
            vmpl2_file.read()) if vmpl2_file else bytearray()
        # Create a setup_header for 32-bit

    @property
    def _vmpl2_header(self) -> setup_header:
        if not self._vmpl2_kernel:
            return None
        header = setup_header.from_buffer(self._vmpl2_kernel, 0x1f1)
        assert header.header.to_bytes(
            4, 'little') == b'HdrS', 'invalid setup_header'
        assert header.pref_address > 3 * 1024 * 1024, 'loading base cannot be below 3MB'
        assert header.xloadflags & 1, '64-bit entrypoint does not exist'
        assert header.pref_address % PGSIZE == 0
        assert header.init_size % PGSIZE == 0
        return header

    def setup_before_code(self):
        # [0-0xa0000] is reserved for BIOS
        # [0xe0000 - 0x200000] is for ACPI related data
        # load ACPI pages
        acpi_tables = self.acpidata
        sorted_gpa = sorted(acpi_tables.acpi.keys())
        # RAM for bios/bootloader
        self.state.seek(0xa0000)
        self.state.memory.allocate(acpi_tables.end_addr - 0xa0000)
        for gpa in sorted_gpa:
            self.state.memory.write(gpa, acpi_tables.acpi[gpa])
        self.state.seek(acpi_tables.end_addr)
        return sorted_gpa[0]

    def load_code(self):
        # Setup pgtable and boot stack after vmsa page but before code.
        if self.assign_stack:
            boot_stack_addr = self.state.memory.allocate(self.BOOT_STACK_SIZE, 16)
            print("assign_stack", boot_stack_addr)
            self.state.vmsa.rsp = boot_stack_addr + self.BOOT_STACK_SIZE
        else:
            boot_stack_addr = self.state.memory.allocate(0)

        self.cmdline_addr = self.state.memory.allocate(len(self.cmdline))
        self.state.memory.write(self.cmdline_addr, self.cmdline)

        self.state.setup_paging(paging_level = self.pgtable_level)

        self.monitor_params_addr = self.state.memory.allocate(
            sizeof(verismo_params))
        self.state.setup_gdt()
        addr = self.state.memory.allocate(0)
        self.extra_validated_ram.append((boot_stack_addr, addr - boot_stack_addr))

        # setup code
        self._start = ALIGN(addr, PGSIZE)
        self.state.seek(self._start)
        load_start_vaddr = -1
        segs = []
        rela_name = '.rela'
        rela = self.elf.elf.get_section_by_name(rela_name)
        for reloc in rela.iter_relocations():
            print('Relocation (%s)' % 'RELA' if reloc.is_RELA() else 'REL')
            # Relocation entry attributes are available through item lookup
            offset = reloc['r_offset'];
            r_addend = reloc['r_addend'];
            val = self._start + r_addend
            packed_u64 = bytes(ctypes.c_uint64(val))
            print("%x %x" %(offset, val))
            self._kernel = self._kernel[:offset] + packed_u64 + self._kernel[(offset + 8):]

        for i in range(self.elf.elf.num_segments()):
            seg = self.elf.elf.get_segment(i)
            header = seg.header
            if header.p_filesz:
                if load_start_vaddr == -1:
                    load_start_vaddr = header.p_vaddr
                    #break
                segs.append(seg)
        segs = sorted(segs, key = lambda x: (x.header.p_vaddr, x.header.p_filesz))
        prev_load_addr = 0
        load_addr = self._start + header.p_vaddr - load_start_vaddr
        self.state.memory.allocate(len(self._kernel))
        self.state.memory.write(load_addr, self._kernel)
        self.extra_validated_ram.append((load_addr, len(self._kernel)))
        entry_vaddr = self.elf.elf.header.e_entry
        print("entry_vaddr = %x, load_start_vaddr = %x"%(entry_vaddr, load_start_vaddr))
        return self._start + entry_vaddr - load_start_vaddr

    def load_vmpl2_kernel(self, vmpl2_addr: int):
        self.state.seek(vmpl2_addr)
        self.state.memory.allocate(len(self._vmpl2_kernel), PGSIZE)
        self.state.memory.write(vmpl2_addr, self._vmpl2_kernel)
        #self.extra_validated_ram.append((vmpl2_addr, len(self._vmpl2_kernel)))

    def setup_after_code(self, kernel_entry: int):
        # Skip all segments
        print("entry at %x"%(kernel_entry))
        entry_vaddr = self.elf.elf.header.e_entry
        monitor_end = 0
        for i in range(self.elf.elf.num_segments()):
            seg = self.elf.elf.get_segment(i).header
            monitor_end = max(monitor_end, seg.p_vaddr + seg.p_memsz - entry_vaddr + kernel_entry)
        print("monitor_end at %x"%(monitor_end))
        monitor_end =  ALIGN(monitor_end, PGSIZE)
    
        self.state.seek(monitor_end)

        # Setup other input data to security monitor
        vmpl2_kernel_addr = 0x3d00000
        self.state.vmsa.rip = kernel_entry
        self.state.vmsa.rsi = self.monitor_params_addr
        # Load VMPL2 kernel
        self.load_vmpl2_kernel(vmpl2_kernel_addr)

        # Define VMPL0 monitor's boot parameter
        monitor_params = verismo_params.from_buffer(
            self.state.memory, self.monitor_params_addr)
        monitor_params.cpuid_page = self.cpuid_page
        monitor_params.secret_page = self.secrets_page
        # TODO: Change to self.param_page + sizeof(IGVM_VHS_MEMORY_MAP_ENTRY)
        monitor_params.hv_param_page = self.param_page
        monitor_params.vmpl2_start = vmpl2_kernel_addr
        monitor_params.vmpl2_kernel_size = len(self._vmpl2_kernel)
        # filled later during booting.
        monitor_params.cpu_count = 0
        monitor_params.validated_entries = self._setup_e820_opt(monitor_params.validated_e820, vmpl2_kernel_addr)
        clen = len(self.cmdline)
        monitor_params.vmpl2_cmdline[0:(clen)] = self.cmdline
        monitor_params.vmpl2_cmdline_len = clen - 1
        monitor_params.vmpl2_acpi = ACPI_RSDP_ADDR
        monitor_params.vmpl2_acpi_size = ACPI_END_ADDR - ACPI_RSDP_ADDR
        del monitor_params

    def _setup_e820_opt(self, e820_table, vmpl2_kernel_addr):
        e820_table[0].addr = 0
        e820_table[0].size = 0
        e820_table[0].type = E820_TYPE_RAM
        e820_table[1].addr = 0xa0000
        e820_table[1].size = 0x100000 - 0xa0000
        e820_table[1].type = E820_TYPE_RESERVED
        e820_table[2].addr = 0x100000
        e820_table[2].size = self.acpidata.end_addr - 0x100000
        e820_table[2].type = E820_TYPE_ACPI
        e820_table[3].addr = self.SNP_CPUID_PAGE_ADDR
        e820_table[3].size = 4 * PGSIZE
        e820_table[3].type = E820_TYPE_RESERVED
        count = 4
        for addr, size in self.extra_validated_ram:
            e820_table[count].addr = addr
            e820_table[count].size = size
            e820_table[count].type = E820_TYPE_RESERVED
            count += 1
            print("extra table %x %x"%(addr, size))
        e820_table[count].addr = vmpl2_kernel_addr
        e820_table[count].size = len(self._vmpl2_kernel)
        e820_table[count].type = E820_TYPE_RAM
        print("table %x %x"%(vmpl2_kernel_addr, len(self._vmpl2_kernel)))
        count = count + 1
        for i in range(count):
            logging.debug("%x %x"%(e820_table[i].addr, e820_table[i].addr + e820_table[i].size))

        return count
