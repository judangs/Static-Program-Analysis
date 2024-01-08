from typing import Dict, Tuple

from .resources.elf import Elf
from .base import ParserBase

from kaitaistruct import KaitaiStream

class Instruction:
    def __init__(self, address, size, mnemonic, op_str):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.cs_insn = cs_insn #수정

    def is_branch(self):
        return self.cs_insn.group(CS_GRP_JUMP) or self.cs_insn.group(CS_GRP_CALL) #수정
        #return self.mnemonic.startswith('j') or self.mnemonic == 'call'
    
    def get_branch_target_address(self): #추가
        #분기 명령어 -> 대상주소 계산
        if self.is_branch() and len(self.cs_insn.operands) > 0:
            if operand.type == CS_OP_IMM: #상대 주소..
                return operand.imm
        return None

class BasicBlock:
    def __init__(self, start_address):
        self.start_address = start_address
        self.end_address = None #이 부분 끝 주소로 연결..!!(다시)
        self.instructions = []
        self.predecessors = []
        self.successors = []


class ElfParser(ParserBase) :
    

    def __init__(self, filename: str) :

        super().__init__()

        # section start addr, section end addr
        self.section_addr: Tuple[int, int] = tuple()

        self.Kstream = KaitaiStream(open(filename, 'rb'))
        self.parser = Elf(self.Kstream)

        self._ParseSectionInfo()

    def __del__(self) :
        pass
        #self.Kstream.close()

    def _ParseSectionInfo(self):
        
        section_addr = list()
        for idx, section in enumerate(self.parser.header.section_headers) :
            self.section_idx[section.name] = idx

            section_addr.append([section.addr, section.addr + section.len_body])

        self.section_addr = section_addr

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

    

    def FunctionList(self) -> dict :
        functionInfo : Dict[str] = dict()

        idx = self.section_idx['.symtab']

        for entry in self.parser.header.section_headers[idx].body.entries :
            functionInfo[entry.name] = entry.value

        return functionInfo
        
#추가                
elf_parser.build_control_flow_graph()

#CFG 출력.. 추가
for block in elf_parser.basic_blocks:
    print(f"Basic Block from {block.start_address} to {block.end_address}") #시작, 끝 주소
    print("Succesors:", [succ.start_address for succ in block.succesors]) #후임자
    print("Predecessors:", [pred.start_address for pred in block.predecessors]) #전임자
    print()
        



            
