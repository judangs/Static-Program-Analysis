class Instruction:
    def __init__(self, address, mnemonic, op_str, size):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size

class BasicBlock:
    def __init__(self, entry):
        self.entry = entry
        self.size = 0x0
        self.instructions:list[Instruction] = list()
        self.next:set[int] = set()
        self.successors: list[BasicBlock] = list()


    def AddInsn(self, insn: Instruction):
        self.size += insn.size
        self.instructions.append(insn)

    def PrintCode(self):
        for instruction in self.instructions:
            print("0x%x:\t%s\t%s" %(instruction.address, instruction.mnemonic, instruction.op_str))

    def AddFlowAddr(self, address):
        self.next.add(address)
        
        

    

        
