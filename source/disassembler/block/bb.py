from capstone import CsInsn, CS_GRP_CALL, CS_OP_IMM
from parser.ElfParser import ElfParser
from linker.dynamicLinker import resolve_dynamic_symbol
class BasicBlock:
    def __init__(self, entry):
        self.entry = entry
        self.name = "sub_" + hex(self.entry)[2:]
        self.size = 0x0
        self.instructions:list[CsInsn] = list()
        self.next:list[int] = list()
        self.successors: list[BasicBlock] = list()
    
    def IsPltFunc(self, address:int, parser):
        idx = parser.section_idx['.plt']
        plt_entry = parser.parser.header.section_headers[idx]
        plt_start = plt_entry.addr
        plt_end = plt_start + plt_entry.len_body

        return plt_start <= address and address <= plt_end
    
    def BranchAddr(self, insn: CsInsn):
        for operand in insn.operands :
            if operand.type == CS_OP_IMM :
                if self.IsPltFunc(operand.imm) == True:
                    return operand.imm
        return 0

    def AddInsn(self, insn: CsInsn):
        self.size += insn.size
        self.instructions.append(insn)

    def PrintCode(self):
        for instruction in self.instructions:
            if hasattr(instruction,'plt'):
                print("%s : 0x%x:\t%s\tplt@%s" %(self.name, instruction.address, instruction.mnemonic, instruction.plt))
            else:
                print("%s : 0x%x:\t%s\t%s" %(self.name, instruction.address, instruction.mnemonic, instruction.op_str))

    def AddFlowAddr(self, address):
        self.next.append(address)
        
        

    

        
