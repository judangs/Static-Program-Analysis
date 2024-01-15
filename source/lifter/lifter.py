import llvmlite.ir as ir
import llvmlite.binding as llvm
from capstone import *
from capstone.x86 import *
from elf import Elf
from kaitaistruct import KaitaiStream
from io import BytesIO

class ELFDisassemblyDirector:
    def __init__(self, elf_file_path):
        self.elf_file_path = elf_file_path

    def execute(self):
        # use disassembler
        disassembler = ELFDisassembler(self.elf_file_path)
        instructions = disassembler.disassembled_instructions

        # create LLVM IR
        ir_generator = LLVMIRGenerator(instructions)
        llvm_ir_module = ir_generator.generate()

        return llvm_ir_module
    

class ELFDisassembler:
    def __init__(self, file_path):
        self.file_path = file_path
        self.elf = self._load_elf()
        self.disassembled_instructions = self._disassemble_text_section()

    def _load_elf(self):
        with open(self.file_path, 'rb') as file:
            return Elf(KaitaiStream(BytesIO(file.read())))

    def _disassemble_text_section(self):
        text_section = next((s for s in self.elf.header.section_headers if s.name == '.text'), None)
        if not text_section:
            raise ValueError("No .text section found in ELF file.")
       
        text_data = text_section.body
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        return list(md.disasm(text_data, text_section.addr))

class LLVMIRGenerator:
    REGISTERS_32 = {
        X86_REG_EAX: 'eax',
        X86_REG_EBX: 'ebx',
        X86_REG_ECX: 'ecx',
        X86_REG_EDX: 'edx',
        X86_REG_ESP: 'esp'
        # 다른 레지스터 더 추가하는 곳
    }

    def __init__(self, instructions):
        self.instructions = instructions
        self.module = ir.Module(name=__file__)
        self.function = self._create_function()
        self.builder = ir.IRBuilder(self.function.append_basic_block(name="entry"))
        self.registers = self._initialize_registers()
        self.stack_memory = self.builder.alloca(ir.ArrayType(ir.IntType(32), 1024), name="stack")

    def _create_function(self):
        func_type = ir.FunctionType(ir.VoidType(), [], var_arg=False)
        return ir.Function(self.module, func_type, name="disassembled_function")

    def _initialize_registers(self):
        registers = {reg: self.builder.alloca(ir.IntType(32), name=reg) for reg in self.REGISTERS_32.values()}
        # 스택 포인터 초기화
        esp = self.builder.const(ir.IntType(32), 1024)
        self.builder.store(esp, registers['esp'])
        return registers

    def generate(self):
        for ins in self.instructions:
            self._handle_instruction(ins)
        self.builder.ret_void()
        return self.module

    def _handle_instruction(self, instruction):
        handlers = {
            X86_INS_MOV: self._handle_mov,
            X86_INS_PUSH: self._handle_push,
        }
        handler = handlers.get(instruction.id)
        if handler:
            handler(instruction)

    def _handle_mov(self, instruction):
        operands = instruction.operands
        if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            reg_name = self.REGISTERS_32[operands[0].value.reg]
            immediate_value = operands[1].value.imm
            reg = self.registers[reg_name]
            self.builder.store(ir.Constant(ir.IntType(32), immediate_value), reg)

    def _handle_push(self, instruction):
        operands = instruction.operands
        if operands[0].type == X86_OP_REG:
            reg_name = self.REGISTERS_32[operands[0].value.reg]
            reg_value = self.builder.load(self.registers[reg_name])
            stack_ptr = self.registers['esp']
            current_stack_ptr = self.builder.load(stack_ptr)
            new_stack_ptr = self.builder.sub(current_stack_ptr, ir.Constant(ir.IntType(32), 4))
            self.builder.store(new_stack_ptr, stack_ptr)
            stack_slot = self.builder.gep(self.stack_memory, [ir.Constant(ir.IntType(32), 0), new_stack_ptr])
            self.builder.store(reg_value, stack_slot)

def main(elf_file_path):
    director = ELFDisassemblyDirector(elf_file_path)
    llvm_ir_module = director.execute()
    print(llvm_ir_module)

if __name__ == "__main__":
    elf_file_path = 'D:\SSL\miniweb'
    main(elf_file_path)