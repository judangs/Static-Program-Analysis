from typing import Dict, Tuple

from .resources.elf import Elf
from .base import ParserBase

from kaitaistruct import KaitaiStream



class ElfParser(ParserBase) :
    

    def __init__(self, filename: str) :

        super().__init__()

        # section start addr, section end addr
        self.section_addr: Tuple[int, int] = tuple()

        self.Kstream = KaitaiStream(open(filename, 'rb'))
        self.parser = Elf(self.Kstream)
            
        self._ParseSectionInfo()

    def __del__(self) :
        pass
        #self.Kstream.close()

    def _ParseSectionInfo(self):
        
        section_addr = list()
        for idx, section in enumerate(self.parser.header.section_headers) :
            self.section_idx[section.name] = idx

            section_addr.append([section.addr, section.addr + section.len_body])

        self.section_addr = section_addr


    def FunctionList(self) -> dict :
        functionInfo : Dict[str] = dict()

        idx = self.section_idx['.symtab']

        for entry in self.parser.header.section_headers[idx].body.entries :
            functionInfo[entry.name] = entry.value

        return functionInfo
        
                
    
    
        
        



            