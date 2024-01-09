from typing import Dict
from abc import ABC, abstractmethod
class ParserBase(ABC):

    def __init__(self) :
        self.section_idx: Dict[str, int] = dict()
        

    @abstractmethod
    def _ParseSectionInfo() :
        ...

    @abstractmethod
    def FunctionList() :
        ...