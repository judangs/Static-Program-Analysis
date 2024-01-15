#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs

def main(arg: ParamSpecArgs):
    parse = parser.ElfParser(arg.file)
    disasm = disassembler.Disassembler(parse._io, parse, parse.section_idx, parse.section_addr)

    function = parse.FunctionList()
    
    for _, address in function.items():
        if disasm.IsExecutableAddr(address):
            if disasm.isVisit(address) :
                continue
            disassembler.RecursiveDisasm(disasm, address)
            #disassembler.LinearSweepDisasm(disasm, address)

    disassembler.BuildControlFlow(disasm)


    print(disassembler.CanReachable(disasm, function['_start'], 0x40120e)) #None
    print(disassembler.CanReachable(disasm, function['main'], 0x40120e)) #True
    print(disassembler.CanReachable(disasm, function['main'], 0x4011fd)) #True

    dest = 0x4011a5
    path = list()
    disassembler.TraceControlFlow(disasm, function['main'], dest, path)
    for controlflow in disasm.ControlFlow:
        for address in controlflow:
            print("0x%x" %(address), end=' -> ')
        print("0x%x" %(dest))

    

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

