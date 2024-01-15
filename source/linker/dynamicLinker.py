from source.parser import ElfParser

def resolve_dynamic_symbol(parser : ElfParser, GTO : int) -> str:
    relaidx = parser.section_idx['.rela.plt']
    symidx = parser.section_idx['.dynsym']
    stridx = parser.section_idx['dynstr']
    
    if not relaidx:
        return None
    
    try:   
        r_info = parser.parser.header.section_headers[relaidx].body.entries[GTO].info
        symbol_index = r_info >> 32

        sym = parser.parser.header.section_headers[symidx].body.entries[symbol_index]
        string_index = sym.ofs_name
        str_entries = parser.parser.headersection_headers[stridx].body.entries
        
        i = 0
        for st in str_entries:
            if i == string_index:
                return st
            i += len(st)+1
    except Exception as e:
        print(f"error occured in resolve symbol {e}")    