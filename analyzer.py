from source.linker import dynamicLinker
from source.parser import ElfParser
from source.disassembler import Disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def main(arg: ParamSpecArgs):
    parser = ElfParser(arg.file)
    dl = dynamicLinker(parser.parser, parser.section_idx, parser.section_addr)
    disasm = Disassembler()

    # Analysis Function List
    function = parser.FunctionList()
    print(function)

    for fname, address in function.items():
        if dl.IsPltSection(address):
            dl.AddFunction(fname, address)
            continue

        if dl.IsExecutableAddr(address):
            disasm.AddDisasList(address)

    for address in disasm.DisasmList:
        print(f"next function : 0x{address}")
        # linear sweep disassembly 수행
        end_address = address + 0x100 
        binary_file_path = '/home/khd/Static-Program-Analysis/miniweb'
        with open(binary_file_path, 'rb') as file:
            binary = file.read()

        Disassembler.linearSweepDisasm(binary, address, end_address)

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=str)
    args = parser.parse_args()
    ec = main(args)
    exit(ec)

