#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs

def main(arg: ParamSpecArgs):
    parse = parser.ElfParser(arg.file)
    disasm = disassembler.Disassembler(parse._io, parse.parser, parse.section_idx, parse.section_addr)

    function = parse.FunctionList()
    
    for fname, address in function.items():
        if disasm.IsExecutableAddr(address):
            if disasm.isVisit(address) :
                continue
            #disassembler.RecursiveDisasm(disasm, address)
            disassembler.LinearSweepDisasm(disasm, address)

    disassembler.BuildControlFlow(disasm)

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
    
    

    '''
    analyzer handler
    ex)
    while True:
        print('(handler) ', end='')
        intput()
        ...
    '''

    
    


if __name__ == "__main__":
    arg = ArgumentParser()
    arg.add_argument("-f", "--file", type=str)
    args = arg.parse_args()
    ec = main(args)
    exit(ec)

