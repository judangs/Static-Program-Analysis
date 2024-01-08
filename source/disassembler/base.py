from typing import List
from abc import ABC, abstractmethod

from capstone import CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INVALID, CsInsn


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
    
        
