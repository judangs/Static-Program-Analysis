#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs

def main(arg: ParamSpecArgs):
    parse = parser.ElfParser(arg.file)
    disasm = disassembler.Disassembler(parse._io, parse, parse.section_idx, parse.section_addr)

    function = parse.FunctionList()
    
    for fname, address in function.items():
        if disasm.IsExecutableAddr(address):
            if disasm.isVisit(address) :
                continue
            disassembler.RecursiveDisasm(disasm, address)
            #disassembler.LinearSweepDisasm(disasm, address)

    disassembler.BuildControlFlow(disasm)  
    disasm.printBlock()
    print(disassembler.CanReachable(disasm, 0x40120e)) #True
    print(disassembler.CanReachable(disasm, 0x40120e)) #True
    print(disassembler.CanReachable(disasm, 0x401000)) #True
    print(disassembler.CanReachable(disasm, 0x40121b + 0x110)) #None
    
    for block in disasm.basicblocks:
        print("entry : 0x%x" %(block.entry))
        block.PrintCode()
        for idx, next in enumerate(block.next):
            print("\t%d: 0x%x" %(idx, next))
        print()
    
if __name__ == "__main__":
    arg = ArgumentParser()
    arg.add_argument("-f", "--file", type=str)
    args = arg.parse_args()
    ec = main(args)
    
#analyzer handler
    while True:
        print('(handler) ', end='')
        user_input = input()

        #(handler) function list
        if user_input.startswith("function list"):
            command_parts = user_input.split(' ')
            command = command_parts[0]
            print('(handler) function list')
            for idx, (fname, address) in enumerate(function.items(), start=1):
                print(f'\t{idx}: {fname} {hex(address)}')

        #(handler) function {name}
        elif user_input.startswith("function"):
            command_parts = user_input.split(' ')
            command = command_parts[0]
            function_name = command_parts[1]
            
            selected_function_address = function.get(function_name, None)
            if selected_function_address is not None:
                print(f'(handler) {function_name} {hex(selected_function_address)}')
            
                disassembler.LinearSweepDisasm(disasm, selected_function_address)
                

        # (handler) function {offset}
        elif user_input.startswith("function"):
            command_parts = user_input.split(' ')
            command = command_parts[0]
            function_offset = command_parts[1]

        if function_offset.startswith("0x") and all(c in string.hexdigits for c in function_offset[2:]):
            offset = int(function_offset, 16)
            print(f'Offset: {offset}')

            selected_function_address = function.get(offset, None)
            if selected_function_address is not None:
                print(f'(handler) function {hex(offset)}')
                disassembler.LinearSweepDisasm(disasm, selected_function_address)
            else:
                print(f'No function found at address {hex(offset)}')
        else:
            print(f'Invalid offset: {function_offset}')


