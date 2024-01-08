import sys
from os.path import dirname, realpath

parent_dir = dirname(dirname(realpath(__file__)))
sys.path.append(parent_dir)

from source.parser.resources.elf import Elf

EXCUTABLE_FLAG = 0x1

START = 0x0
END = 0x1

class dynamicLinker:

    functionList: dict = dict()

    def __init__(self, parser: Elf, section_idx: tuple[int, int], section_addr: dict) :
        self.parser = parser
        self.section_idx = section_idx
        self.section_addr = section_addr
        

    def IsExecutableAddr(self, addr: int) -> bool:
        for phdr in self.parser.header.program_headers :
            if phdr.type != Elf.PhType.load :
                continue

            if phdr.vaddr <= addr and addr <= (phdr.vaddr + phdr.memsz) :
                if (phdr.flags64 & EXCUTABLE_FLAG) == True :
                    return True
        return False
    
    def SectionIdx(self, section_name: str) -> int:
        return self.section_idx[section_name]
    

    def AddrSectionInfo(self, addr: int):
        for idx, section in enumerate(self.section_addr):
            if section[START] <= addr and addr <= section[END] :
                offset = addr - section[START]
                return idx, offset
    
        raise Exception('Invalid Address')
                 
    # Find the distance of the current address from the section_entry.
    def DistanceOffset(self, addr):
        idx, offset = self.AddrSectionInfo(addr)
        return self.parser.header.section_headers[idx].ofs_body + offset
    
    def IsPltSection(self, addr):
        idx = self.section_idx['.plt']
        plt_entry = self.parser.header.section_headers[idx]
        plt_start = plt_entry.addr
        plt_end = plt_start + plt_entry.len_body

        return plt_start <= addr and addr <= plt_end
    
    @classmethod
    def AddFunction(cls, fname: str, address: int):
        cls.functionList[fname] = address

        


        
        
    

        




