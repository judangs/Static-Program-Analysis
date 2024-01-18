from source.parser import ElfParser
from capstone import CS_MODE_32

def resolve_dynamic_symbol32(disasm, GTO: int) -> str:

    relaidx = disasm.section_idx['.rel.plt']
    symidx = disasm.section_idx['.dynsym']
    stridx = disasm.section_idx['.dynstr']
    idx = int(GTO / 8)

    function_str = ''
    
    dynsym_idx = disasm.parser.header.section_headers[relaidx].body.entries[idx].info >> 8
    dynstr_idx = disasm.parser.header.section_headers[symidx].body.entries[dynsym_idx].ofs_name
    for plt_func in disasm.parser.header.section_headers[stridx].body.entries:
        function_str += (plt_func) + ' '
    name = function_str[dynstr_idx:].split(' ')[0]
    return '<%s@plt>'%(name)
    
def resolve_dynamic_symbol(disasm, GTO : int) -> str:

    if disasm.md._mode == CS_MODE_32:
        return resolve_dynamic_symbol32(disasm, GTO)

    relaidx = disasm.section_idx['.rela.plt']
    symidx = disasm.section_idx['.dynsym']
    stridx = disasm.section_idx['.dynstr']
    
    if not relaidx:
        return None
    
    try:   
        r_info = disasm.parser.header.section_headers[relaidx].body.entries[GTO].info
        symbol_index = r_info >> 32

        sym = disasm.parser.header.section_headers[symidx].body.entries[symbol_index]
        string_index = sym.ofs_name
        str_entries = disasm.parser.header.section_headers[stridx].body.entries
        
        i = 0
        for st in str_entries:
            if i == string_index:
                return '<%s@plt>'%(st)
            i += len(st)+1
    except Exception as e:
        print(f"error occured in resolve symbol {e}")    