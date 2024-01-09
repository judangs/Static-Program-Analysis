#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs

def main(arg: ParamSpecArgs):
    parse = parser.ElfParser(arg.file)
    disasm = disassembler.Disassembler(parse._io, parse.parser, parse.section_idx, parse.section_addr)

    function = parse.FunctionList()
    
    
    '''
    Disasm Usage.
    for fname, address in function.items():
        if disasm.IsExecutableAddr(address):
            print("%s <0x%x>" %(fname, address))
            disassembler.RecursiveDisasm(disasm, address, 0x0)
            disassembler.LinearSweepDisasm(disasm, address, 0x0)
   '''

if __name__ == "__main__":
    arg = ArgumentParser()
    arg.add_argument("-f", "--file", type=str)
    args = arg.parse_args()
    ec = main(args)
    exit(ec)

