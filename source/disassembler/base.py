from typing import List, Deque, Set, Dict, Any
from abc import ABC, abstractmethod
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INVALID, CsInsn, CS_OP_IMM, CS_OP_INVALID
from source.block.function import Function
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
    disasFunc : Dict[str, Function]

    ProgramCounter:int = 0x0

    def __init__(self, parser:Elf, section_idx: tuple[int, int], section_addr: dict):
        self.parser = parser
        self.section_idx = section_idx
        self.section_addr = section_addr
        self.RecursiveDisasm(parser.header.entry_point,0)
        
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
    
    @classmethod
    def addNewFunction(cls, insn: CsInsn):
        pass
    
    # first Input = function start addr
    def RecursiveDisasm(self, branch_start_addr: int, size: int, function_name: str = "start") :
        
        if self.isVisit(branch_start_addr):
            return

        self.ProgramCounter = branch_start_addr
        while self.ProgramCounter >= 0x0:
            insn = self.ReadLine()
            print("%s : 0x%x:\t%s\t%s" %(function_name, insn.address, insn.mnemonic, insn.op_str))
            #instruction is invalid or ret
            if self.isInvalid(insn) or self.isRet(insn):
                self.visitBranch.add(branch_start_addr)
                print()

                if self.retStack:
                    self.ProgramCounter = self.retStack.pop()
                    return
                else:
                    self.ProgramCounter = -0x1
                    return

            self.ProgramCounter += insn.size
            size += insn.size

            if self.isCall(insn):
                branch_addr = self.BranchAddr(insn)

                if branch_addr == CS_OP_IMM or branch_addr == CS_OP_INVALID:
                    continue


                if self.isVisit(branch_addr) == False:
                    function_name = "sub_" + hex(branch_addr)[2:]
                    print(function_name)
                    self.visitBranch.add(branch_addr)

                    self.retStack.append(self.ProgramCounter)
                    self.ProgramCounter = branch_addr
                    print()
                    self.RecursiveDisasm( self.ProgramCounter, 0x0,function_name)

                    branch_start_addr = self.ProgramCounter
                    size = 0x0