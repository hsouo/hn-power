import sys, os, struct
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *
from capstone.x86 import *

path = sys.argv[1]
target = int(sys.argv[2], 16)  # VA of callee
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
all_image = pe.get_memory_mapped_image()
text = [s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tb = base + text.VirtualAddress
code = all_image[text.PointerToRawData*0 + text.VirtualAddress : text.VirtualAddress + text.Misc_VirtualSize]

# export name by RVA
exp_by_rva = {}
if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name: exp_by_rva[e.address] = e.name.decode()

# linear scan; track recent register imm loads per address window
recent = {}   # reg -> (addr, val)
funcs = []
for insn in md.disasm(code, tb):
    a = insn.address
    # clean old entries (>32 bytes before a)
    for k in [k for k,(addr,v) in recent.items() if a-addr>48]: del recent[k]
    if insn.id in (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVABS) and len(insn.operands)==2 and insn.operands[0].type==X86_OP_REG and insn.operands[1].type==X86_OP_IMM:
        recent[insn.reg_name(insn.operands[0].reg)] = (a, insn.operands[1].imm)
    if insn.id == X86_INS_CALL and len(insn.operands)==1 and insn.operands[0].type==X86_OP_IMM and insn.operands[0].imm == target:
        name = exp_by_rva.get(a-base, None) or [n for rva,n in exp_by_rva.items() if abs(rva-(a-base))<0x400]
        print(f"call {target:#x} at {a:#x} (enclosing export near: {exp_by_rva.get(a-base,'?')})")
        for reg in ('ecx','rdx','r8','r9'):
            if reg in recent:
                addr,val = recent[reg]
                print(f"    {reg} = {val:#x} (set at {addr:#x})")
