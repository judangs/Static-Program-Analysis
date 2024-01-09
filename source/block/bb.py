from capstone import CsInsn, CS_GRP_JUMP, CS_GRP_CALL, CS_OP_IMM

class Instruction:
    def __init__(self, address, size, mnemonic, op_str):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.cs_insn = cs_insn #수정

    def is_branch(self):
        return self.cs_insn.group(CS_GRP_JUMP) or self.cs_insn.group(CS_GRP_CALL) 
    
    def get_branch_target_address(self): #추가
        #분기 명령어 -> 대상주소 계산
        if self.is_branch() and len(self.cs_insn.operands) > 0:
            if operand.type == CS_OP_IMM: #상대 주소..
                return operand.imm
        return None

class BasicBlock : 
    def parse_instructions(self, section): #추가
        self.md.detail = True
        code = section.body
        start_address = section.addr
        return [Instruction(i) for i in self.md.disasm(code, start_address)]


    def parse_basic_blocks(self): #추가
        for section in self.parser.header.section_headers:
            if section.flags_obj.alloc and section.flags_obj.exec_instr:
                instructions = self.parse_instructions(section)
                self.create_basic_blocks(instructions)

    def create_basic_blocks(self, instructions): #추가
        current_bb = BasicBlock(instructions[0].address)
        for instr in instructions:
            current_bb.instructions.append(instr)
            if instr.is_branch():
                target_address = instr.get_branch_target_address()
                current_bb.end_address = instr.address + instr.size
                self.basic_blocks.append(current_bb)
                if target_address:
                    current_bb = BasicBlock(target_address)
                else:
                    next_address = instr.address + instr.size
                    current_bb = BasicBlock(next_address)
        if current_bb.instructions:
            self.basic_blocks.append(current_bb)

    def connect_basic_blocks(self): #추가
        for bb in self.basic_blocks:
            last_instr = bb.instructions[-1]
            target_address = last_instr.get_branch_target_address()
            if target_address:
                target_bb = self.find_basic_block_by_adress(target_address)
                if target_bb:
                    bb.successors.append(target_bb)

    def find_basic_block_by_address(self, address): #추가
        for bb in self.basic_blocks:
            if bb.start_address <= address < bb.end_address:
                return bb
        return None


    def build_control_flow_graph(self): #추가
        self.parse_basic_blocks()
        self.connect_basic_blocks()