import sys, struct, re
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *
from capstone.x86 import *

path = sys.argv[1]
want = sys.argv[2:]
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
img = pe.get_memory_mapped_image()
text = [s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tb = base + text.VirtualAddress
tdata = img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]

iat = {}
for mod in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in mod.imports:
        if imp.name:
            n = imp.name.decode()
            for w in want:
                if w.lower() in n.lower():
                    iat[imp.address] = (mod.dll.decode(), n)

# export map by rva for context
exp = {}
if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name and e.address: exp[base+e.address] = e.name.decode()

recent = {}
for insn in md.disasm(tdata, tb):
    a = insn.address
    for k in [k for k,(addr,v) in recent.items() if a-addr>64]: del recent[k]
    if insn.id == X86_INS_MOV and len(insn.operands)==2 and insn.operands[0].type==X86_OP_REG and insn.operands[1].type==X86_OP_IMM:
        recent[insn.reg_name(insn.operands[0].reg)] = (a, insn.operands[1].imm & 0xffffffffffffffff)
    if insn.id in (X86_INS_CALL,) and len(insn.operands)==1 and insn.operands[0].type==X86_OP_MEM and insn.operands[0].mem.base==X86_REG_RIP:
        tgt = a + insn.size + insn.operands[0].mem.disp
        if tgt in iat:
            dll, nm = iat[tgt]
            # nearest export <= a
            near = max((v for v in exp if v <= a and a-v < 0x2000), key=lambda x:x, default=None)
            print(f"{a:#x}  call {dll}!{nm[:70]}   (near export: {exp.get(near,'?')})")
            for reg in ('rdx','r8','rcx','r9'):
                if reg in recent:
                    addr, val = recent[reg]
                    if val < 0x100000000:
                        print(f"      {reg} = {val:#x} ({val})  @ {addr:#x}")
