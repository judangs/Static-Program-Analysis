from disassembler.base import DisassemblerBase

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OPT_ON, CS_OP_IMM, CsInsn
#from capstone.x86 import *


import sys
from os.path import dirname, realpath

parent_dir = dirname(dirname(realpath(__file__)))
sys.path.append(parent_dir)

from source.parser.resources.elf import Elf

START = 0x0
END = 0x1

EXCUTABLE_FLAG = 0x1

class Disassembler(DisassemblerBase):

    def __init__(self, _io, parser, section_idx, section_addr):
        super().__init__(parser, section_idx, section_addr)

        if self.parser.header.machine == Elf.Machine.x86_64:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        else :
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        
        self.md.detail = CS_OPT_ON

        self._io = _io


    def ReadByte(self, offset: int, length: int)->bytearray:
        self._io.seek(offset, 0)
        return self._io.read(length)
    

    def IsExecutableAddr32(self, addr: int) -> bool:
        for phdr in self.parser.header.program_headers :
            if phdr.type != Elf.PhType.load :
                continue

            if phdr.vaddr <= addr and addr <= (phdr.vaddr + phdr.memsz) :
                if (phdr.flags32 & EXCUTABLE_FLAG) == True :
                    return True
        return False

    def IsExecutableAddr(self, addr: int) -> bool:
        if self.md._mode == CS_MODE_32:
            return self.IsExecutableAddr32(addr)
        
        for phdr in self.parser.header.program_headers :
            if phdr.type != Elf.PhType.load :
                continue

            if phdr.vaddr <= addr and addr <= (phdr.vaddr + phdr.memsz) :
                if (phdr.flags64 & EXCUTABLE_FLAG) == True :
                    return True
        return False

    def AddrSectionInfo(self, addr: int):
        for idx, section in enumerate(self.section_addr):
            if section[START] <= addr and addr <= section[END]:
                offset = addr - section[START]
                return idx, offset

        raise Exception('Invalid Address')

    # Find the distance of the current address from the section_entry.
    def DistanceOffset(self, addr):
        idx, offset = self.AddrSectionInfo(addr)
        return idx, (self.parser.header.section_headers[idx].ofs_body + offset)

    def GetCode(self, offset: int)-> bytearray:
        #exception:  offset + 0x10 => executable X
        return self.ReadByte(offset, 0x10)

    def ReadLine(self):
        # idx : section idx, offset : code offset
        idx, offset = self.DistanceOffset(self.ProgramCounter)
        code = self.GetCode(offset)
        insn = self.md.disasm(code, self.ProgramCounter, count=0x1).__next__()
        return insn

    def IsPltFunc(self, address:int):
        idx = self.section_idx['.plt']
        plt_entry = self.parser.header.section_headers[idx]
        plt_start = plt_entry.addr
        plt_end = plt_start + plt_entry.len_body

        return plt_start <= address and address <= plt_end
        

    def BranchAddr(self, insn: CsInsn):
        for operand in insn.operands :
            if operand.type == CS_OP_IMM :
                if self.IsPltFunc(operand.imm) == False:
                    return operand.imm
        return 0

    def FindBlockEntry(self, address: int):
        for basicblock in self.basicblocks:
            if basicblock.entry == address:
                return basicblock
        return None
    

    @classmethod
    def isVisit(cls, addr: int):
        for visit in cls.visitBranch:
            if addr == visit:
                return True
        return False
