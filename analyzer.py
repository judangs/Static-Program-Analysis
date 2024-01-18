#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs


def main(arg: ParamSpecArgs):
    parse = parser.ElfParser(arg.file)
    disasm = disassembler.Disassembler(parse._io, parse.parser, parse.section_idx, parse.section_addr)

    function = parse.FunctionList()
    
    for _, address in function.items():
        if disasm.IsExecutableAddr(address):
            if disasm.isVisit(address) :
                continue
            disassembler.RecursiveDisasm(disasm, address)
            #disassembler.LinearSweepDisasm(disasm, address)

    disassembler.BuildControlFlow(disasm)


    #analyzer handler (testing)
    while True:
        print('(handler) ', end='')
        user_input = input()

        if user_input.startswith("trace list"):
            if not disasm.ControlFlow:
                continue
            disassembler.ControlFlowList(disasm, dest)

        elif user_input.startswith("trace print"):
            if not disasm.ControlFlow:
                continue
            command_parts = user_input.split(' ')
            idx = int(command_parts[2], 16)
            disassembler.PrintAssembleFlow(disasm, idx)


        elif user_input.startswith("trace"):
            disasm.ControlFlow.clear()
            command_parts = user_input.split(' ')
            
            if len(command_parts) > 2:
                start = int(command_parts[1], 16)
                dest = int(command_parts[2], 16)
                path = list()
                disassembler.TraceControlFlow(disasm, start, dest, path)

            else:
                dest = int(command_parts[1], 16)

                path = list()
                for name, address in function.items():
                    if disasm.IsExecutableAddr(address):
                        disassembler.TraceControlFlow(disasm, function[name], dest, path)
                        path = list()
        



if __name__ == "__main__":
    arg = ArgumentParser()
    arg.add_argument("-f", "--file", type=str)
    args = arg.parse_args()
    ec = main(args)
    exit(ec)

