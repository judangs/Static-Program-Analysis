from typing import List, Deque, Set
from abc import ABC, abstractmethod
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INVALID, CsInsn, CS_OP_IMM, CS_OP_INVALID

from collections import deque

import sys
from os.path import dirname, realpath

parent_dir = dirname(dirname(realpath(__file__)))
sys.path.append(parent_dir)

PC_INVALID = 0x0

from source.parser.resources.elf import Elf
from .block.bb import BasicBlock

class DisassemblerBase(ABC):
    
    DisasmList: List[int] = list()
    visitBranch: Set[int] = set()
    retStack: Deque[int] = deque()
    basicblocks:List[BasicBlock] = list()
    ControlFlow: List[List[int]] = list()

    ProgramCounter:int = PC_INVALID

    def __init__(self, parser:Elf, section_idx: tuple[int, int], section_addr: dict):
        self.parser = parser
        self.section_idx = section_idx
        self.section_addr = section_addr
        

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

    @abstractmethod
    def FindBlockEntry(self, address: int):
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
    


def BuildControlFlow(disasm:DisassemblerBase) :
    
    NodeList: Deque[BasicBlock] = deque()
    visit: List[int] = list()

    for basicblock in disasm.basicblocks:
        current = basicblock
        visit.append(current.entry)

        # not empty()
        while current.next:
            for next in current.next:
                nextblock = disasm.FindBlockEntry(next)
                if nextblock == None:
                    continue

                current.successors.append(nextblock)
                if nextblock.entry not in visit:
                    NodeList.append(nextblock)
                    visit.append(nextblock.entry)

            if NodeList:
                current = NodeList.popleft()
            else:
                break

def CanReachableAddress(disasm: DisassemblerBase, address: int) :
    
    NodeList: Deque[BasicBlock] = deque()
    visit: List[int] = list()
    
    for basicblock in disasm.basicblocks:
        if basicblock.entry <= address and address <= basicblock.entry + basicblock.size:
            return True
        current = basicblock
        visit.append(current.entry)

        # not empty()
        while current.successors:
            for next in current.successors:
                if next.entry <= address and address <= next.entry + next.size:
                    return True
                else:
                    if next.entry not in visit:
                        NodeList.append(next)
                        visit.append(next.entry)


            if NodeList:
                current = NodeList.popleft()
            else:
                break


def CanReachable(disasm: DisassemblerBase, start: int, dest: int):

    NodeList: Deque[BasicBlock] = deque()
    visit: List[int] = list()

    current = disasm.FindBlockEntry(start)
    visit.append(current.entry)

    # while current.successors -> if entry block : ret (error)
    while True:
        for next in current.successors:
            if next.entry in visit:
                continue
            
            if next.entry <= dest and dest <= next.entry + next.size:
                return True
            else:
                if next.entry not in visit:
                    NodeList.append(next)
                    visit.append(next.entry)

        if NodeList:
            current = NodeList.popleft()
        else:
            break



def TraceControlFlow(disasm: DisassemblerBase, start: int, dest: int, path: List[int]):
    #Invalid address or Cannot
    if CanReachableAddress(disasm, dest) == "None" or CanReachable(disasm, start, dest) == "None":
        return False
    
    current_path = path
    current_path.append(start)
    print(current_path)
    currentbb = disasm.FindBlockEntry(start)

    if currentbb.entry <= dest and dest <= currentbb.entry + currentbb.size:
        disasm.ControlFlow.append(current_path)
        return True

    for basicblock in currentbb.successors:
        if basicblock.entry in path:
            continue

        if TraceControlFlow(disasm, basicblock.entry, dest, current_path) == True:
            return True
            


def PrintAssembleFlow(disasm: DisassemblerBase, idx: int):
    pass



def RecursiveDisasm(disasm: DisassemblerBase, branch_start_addr: int) :

    if disasm.isVisit(branch_start_addr):
        return

    disasm.ProgramCounter = branch_start_addr
    Currentbb = BasicBlock(branch_start_addr)
    while disasm.ProgramCounter >= PC_INVALID:
        insn = disasm.ReadLine()
        Currentbb.AddInsn(insn)

        disasm.ProgramCounter += insn.size

        #instruction is invalid or ret
        if disasm.isInvalid(insn) or disasm.isRet(insn):
            disasm.visitBranch.add(branch_start_addr)
            disasm.basicblocks.append(Currentbb)

            if disasm.retStack:
                disasm.ProgramCounter = disasm.retStack.pop()
                Currentbb.AddFlowAddr(disasm.ProgramCounter)
                Currentbb = BasicBlock(disasm.ProgramCounter)
            else:
                disasm.ProgramCounter = PC_INVALID
                return

        # instruction is call or jmp
        if disasm.isCall(insn) or disasm.isJump(insn):
            branch_addr = disasm.BranchAddr(insn)

            if branch_addr == CS_OP_IMM or branch_addr == CS_OP_INVALID:
                continue


            #flow : jmp addr(unconditional jmp type)
            Currentbb.AddFlowAddr(branch_addr)
            #flow : jmp addr(condition jmp type)
            Currentbb.AddFlowAddr(disasm.ProgramCounter) 

            #add basicblock
            disasm.basicblocks.append(Currentbb)

            if disasm.isVisit(branch_addr) == False:
                Currentbb = BasicBlock(branch_addr)
                disasm.visitBranch.add(branch_addr)
                disasm.retStack.append(disasm.ProgramCounter)

                disasm.ProgramCounter = branch_addr
                RecursiveDisasm(disasm, disasm.ProgramCounter)
            
            else:
                # prevent block duplicate
                Nextbb = disasm.FindBlockEntry(branch_addr)
                Nextbb.AddFlowAddr(disasm.ProgramCounter)

                Currentbb = BasicBlock(disasm.ProgramCounter)
                



def LinearSweepDisasm(disasm: DisassemblerBase, branch_start_addr: int):

    if disasm.isVisit(branch_start_addr):
        return

    disasm.ProgramCounter = branch_start_addr
    Currentbb = BasicBlock(branch_start_addr)
    while disasm.ProgramCounter > PC_INVALID:
        insn = disasm.ReadLine()
        Currentbb.AddInsn(insn)

        disasm.ProgramCounter += insn.size
        
        #instruction is invalid or ret
        if disasm.isInvalid(insn) or disasm.isRet(insn):
            disasm.visitBranch.add(branch_start_addr)
            disasm.basicblocks.append(Currentbb)


            if disasm.retStack:
                disasm.ProgramCounter = disasm.retStack.popleft()
                Currentbb.AddFlowAddr(disasm.ProgramCounter)
                Currentbb = BasicBlock(disasm.ProgramCounter)
            else:
                disasm.ProgramCounter = PC_INVALID
                return

        if disasm.isCall(insn) or disasm.isJump(insn):
            branch_addr = disasm.BranchAddr(insn)

            # (ex) call address type != 0x1000
            if branch_addr == CS_OP_IMM or branch_addr == CS_OP_INVALID:
                continue

            # flow : jmp addr(unconditional jmp type)
            Currentbb.AddFlowAddr(branch_addr)
            # flow : jmp addr(condition jmp type)
            Currentbb.AddFlowAddr(disasm.ProgramCounter)
            disasm.basicblocks.append(Currentbb)
            Currentbb = BasicBlock(disasm.ProgramCounter)

            if disasm.isVisit(branch_addr) == False:
                disasm.visitBranch.add(branch_addr)
                disasm.retStack.append(branch_addr)


            '''
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
            '''