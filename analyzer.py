#from source.linker import dynamicLinker
from source import parser
from source import disassembler

from argparse import ArgumentParser
from typing import ParamSpecArgs

def main(arg: ParamSpecArgs):
    Disassembler(ElfParser(arg.file))
   

if __name__ == "__main__":
    arg = ArgumentParser()
    arg.add_argument("-f", "--file", type=str)
    args = arg.parse_args()
    ec = main(args)
    exit(ec)

