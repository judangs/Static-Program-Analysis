from source.linker import dynamicLinker
from source.parser import ElfParser
from source.disassembler import Disassember, RecursiveDisasm

from argparse import ArgumentParser
from typing import ParamSpecArgs



def main(arg: ParamSpecArgs):
    
    parser = ElfParser(arg.file)
    dl = dynamicLinker(parser.parser, parser.section_idx, parser.section_addr)
    disasm = Disassember(parser._io, parser.parser, parser.section_idx, parser.section_addr)

    # Analysis Function List
    function = parser.FunctionList()
    for fname, address in function.items():

        

        if dl.IsPltSection(address):
            continue

        if dl.IsExecutableAddr(address) == True:
            print("%s\t<0x%x>" %(fname, address))
            RecursiveDisasm(disasm, address, 0x0)    
    

    


if __name__ == "__main__" :
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=str)
    args = parser.parse_args()
    ec = main(args)
    exit(ec)


