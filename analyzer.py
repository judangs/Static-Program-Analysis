from source.linker import dynamicLinker
from source.parser import ElfParser
from source.disassembler import Disassember

from argparse import ArgumentParser
from typing import ParamSpecArgs



def main(arg: ParamSpecArgs):
    
    parser = ElfParser(arg.file)
    dl = dynamicLinker(parser.parser, parser.section_idx, parser.section_addr)
    disasm = Disassember()

    # Analysis Function List
    function = parser.FunctionList()
    print(function)
    for fname, address in function.items():

        if dl.IsPltSection(address) :
            dl.AddFunction(fname, address)
            continue

        if dl.IsExecutableAddr(address) == True:
            disasm.AddDisasList(address)

    for address in disasm.DisasmList :
        print("next function : 0x%x" %(address))
            
    

    


if __name__ == "__main__" :
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=str)
    args = parser.parse_args()
    ec = main(args)
    exit(ec)


