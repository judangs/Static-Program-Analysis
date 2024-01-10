from disassembler.base import DisassemblerBase
from source.parser import ElfParser
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OPT_ON, CsInsn
from capstone.x86 import *

START = 0x0
END = 0x1

class Disassembler(DisassemblerBase):

    def __init__(self, elfparser:ElfParser):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = CS_OPT_ON

        self._io = elfparser._io
        super().__init__(elfparser.parser, elfparser.section_idx, elfparser.section_addr)

    def ReadByte(self, offset: int, length: int)->bytearray:
        self._io.seek(offset, 0)
        return self._io.read(length)

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

    def ReadLines(self, code: bytearray, addr: int, count: int):
        insn = self.md.disasm(code, addr, count=count).__next__()
        return insn

    def BranchAddr(self, insn: CsInsn):
        for operand in insn.operands :
            if operand.type == X86_OP_IMM :
                return operand.imm
        return 0

        # debug
        #print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))


    @classmethod
    def isVisit(cls, addr: int):
        for visit in cls.visitBranch:
            if addr == visit:
                return True
        return False
