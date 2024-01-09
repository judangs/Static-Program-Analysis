from typing import List, Deque, Set
from abc import ABC, abstractmethod
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INVALID, CsInsn, CS_OP_IMM, CS_OP_INVALID

from collections import deque

import sys
from os.path import dirname, realpath

parent_dir = dirname(dirname(realpath(__file__)))
sys.path.append(parent_dir)

from source.parser.resources.elf import Elf

class DisassemblerBase(ABC):
    
    DisasmList: List[int] = list()
    visitBranch: Set[int] = set()
    retStack: Deque[int] = deque()

    ProgramCounter:int = 0x0

    def __init__(self, parser:Elf, section_idx: tuple[int, int], section_addr: dict):
        self.parser = parser
        self.section_idx = section_idx
        self.section_addr = section_addr
        
    @abstractmethod
    def Arch(self):
        ...

    @abstractmethod
    def BranchAddr(self, insn: CsInsn):
        ...

    @abstractmethod
    def DistanceOffset(self, addr):
        ...

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
    
    # first Input = function start addr
def RecursiveDisasm(disasm: DisassemblerBase, branch_start_addr: int, size: int) :

    if disasm.isVisit(branch_start_addr):
        return

    disasm.ProgramCounter = branch_start_addr
    while disasm.ProgramCounter >= 0x0:
        insn = disasm.ReadLine()
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        disasm.ProgramCounter += insn.size
        size += insn.size

        #instruction is invalid or ret
        if disasm.isInvalid(insn) or disasm.isRet(insn):
            disasm.visitBranch.add(branch_start_addr)
            print()

            if disasm.retStack:
                disasm.ProgramCounter = disasm.retStack.pop()
                return
            else:
                disasm.ProgramCounter = -0x1
                return

        if disasm.isCall(insn):
            branch_addr = disasm.BranchAddr(insn)

            if branch_addr == CS_OP_IMM or branch_addr == CS_OP_INVALID:
                continue


            if disasm.isVisit(branch_addr) == False:
                disasm.visitBranch.add(branch_addr)

                disasm.retStack.append(disasm.ProgramCounter)
                disasm.ProgramCounter = branch_addr
                print()
                RecursiveDisasm(disasm, disasm.ProgramCounter, 0x0)

                branch_start_addr = disasm.ProgramCounter
                size = 0x0



def LinearSweepDisasm(disasm: DisassemblerBase, branch_start_addr: int, size: int):

    if disasm.isVisit(branch_start_addr):
        return

    disasm.ProgramCounter = branch_start_addr
    while disasm.ProgramCounter > 0x0:
        insn = disasm.ReadLine()
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        disasm.ProgramCounter += insn.size
        size += insn.size
        
        #instruction is invalid or ret
        if disasm.isInvalid(insn) or disasm.isRet(insn):
            disasm.visitBranch.add(branch_start_addr)
            print()

            if disasm.retStack:
                disasm.ProgramCounter = disasm.retStack.popleft()
                return
            else:
                disasm.ProgramCounter = -0x1
                return

        if disasm.isCall(insn):
            branch_addr = disasm.BranchAddr(insn)

            # (ex) call address type != 0x1000
            if branch_addr == CS_OP_IMM or branch_addr == CS_OP_INVALID:
                continue

            if disasm.isVisit(branch_addr) == False:
                disasm.visitBranch.add(branch_addr)
                disasm.retStack.append(branch_addr)

