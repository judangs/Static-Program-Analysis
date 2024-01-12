from capstone import CsInsn

class BasicBlock:
    def __init__(self, entry):
        self.entry = entry
        self.size = 0x0
        self.instructions:list[CsInsn] = list()
        self.next:list[int] = list()
        self.successors: list[BasicBlock] = list()


    def AddInsn(self, insn: CsInsn):
        self.size += insn.size
        self.instructions.append(insn)

    def PrintCode(self):
        for instruction in self.instructions:
            print("0x%x:\t%s\t%s" %(instruction.address, instruction.mnemonic, instruction.op_str))

    def AddFlowAddr(self, address):
        self.next.append(address)
        
        

    

        
