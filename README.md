*static program analysis*
=============
While studying program static analysis, We have implemented a utility that can analyze programs and lift with LLVM IR using python3. The overall flow of the source code is as follows.

1. parsing x86 ELF header (32 / 64)
2. disassembly methodology
3. code pattern, basic block
4. control flow build, recovery
5. lift to LLVM IR (expected)


*directory*
-------------

* source
    * parser
    * disassembler
        * block : basic block
    * linker
    * lifter


*function*
-------------
* source.disassembler.base.RecursiveDisasm
* source.disassembler.base.LinearSweepDisasm
* source.disassembler.base.TraceControlFlow
* source.disassembler.base.CanReachable



*handler*
-------------
* trace
    * {optional: start}: trace flow start address
    * {end}: trace flow dest address

* trace list : print trace flow info

* trace print
    * {idx}: print assembly lines 

