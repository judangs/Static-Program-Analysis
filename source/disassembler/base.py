from typing import List
from abc import ABC, abstractmethod
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INVALID, CsInsn

class DisassemblerBase(ABC):
    DisasmList: List[int] = list()
    visitBranch: List[int] = list()

    @abstractmethod
    def ReadLine(self):
        ...

    @abstractmethod
    def isVisit(self, address: int):
        ...

    @classmethod
    def AddDisasList(cls, address: int):
        cls.DisasmList.append(address)

    @classmethod
    def linearSweepDisasm(cls, binary, start_address, end_address):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        for insn in md.disasm(binary, start_address):
            if insn.address >= end_address:
                break
            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    @classmethod
    def isJump(cls, insn: CsInsn):
        return insn.group(CS_GRP_JUMP)

    @classmethod
    def isRet(cls, insn: CsInsn):
        return insn.group(CS_GRP_RET)

    @classmethod
    def isCall(cls, insn: CsInsn):
        return insn.group(CS_GRP_CALL)

    @classmethod
    def isInvalid(cls, insn: CsInsn):
        return insn.group(CS_GRP_INVALID)


            

        
