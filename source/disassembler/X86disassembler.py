from .base import DisassemblerBase

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OPT_ON
from capstone.x86 import *

class Disassember(DisassemblerBase):

    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = CS_OPT_ON


    def ReadLine(self, code: bytearray, addr: int):
        insn = self.md.disasm(code, addr, count=0x1).__next__()
        return insn

        # debug
        #print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))


    @classmethod
    def isVisit(cls, addr: int):
        for visit in cls.visitBranch:
            if addr == visit:
                return True
        return False