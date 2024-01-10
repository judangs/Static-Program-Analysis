from source.linker import dynamicLinker
from source.parser import ElfParser
from source.disassembler.x86disassembler import Disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def main(arg: ParamSpecArgs):
    Disassembler(ElfParser(arg.file))
   

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=str)
    args = parser.parse_args()
    ec = main(args)
    exit(ec)

