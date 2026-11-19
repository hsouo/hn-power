import sys, os, struct
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *
from capstone.x86 import *

path = sys.argv[1]
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# section map for RVA->offset
secs = [(s.VirtualAddress, s.VirtualAddress+s.Misc_VirtualSize, s.PointerToRawData) for s in pe.sections]
def rva2off(rva):
    for va, ve, po in secs:
        if va <= rva < ve: return po + (rva - va)
    return None

# IAT: import name -> (IAT VA, thunk)
iat_map = {}
for mod in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in mod.imports:
        if imp.name:
            iat_map[imp.name.decode()] = imp.address  # VA of IAT slot

# .pdata RUNTIME_FUNCTION entries for function bounds
pdata = None
for s in pe.sections:
    if s.Name.rstrip(b'\0') == b'.pdata':
        pdata = s
pf = []
if pdata:
    raw = pdata.get_data()
    for i in range(0, len(raw)-23, 12):
        begin, end, unk = struct.unpack('<III', raw[i:i+12])
        pf.append((base+begin, base+end))
pf.sort()

import bisect
def func_of(va):
    # find runtime function containing va
    lo = bisect.bisect_right([a for a,b in pf], va) - 1
    if lo >= 0 and pf[lo][0] <= va < pf[lo][1]:
        return pf[lo]
    return None

text = None
for s in pe.sections:
    if s.Name.rstrip(b'\0') == b'.text':
        text = s
text_base = base + text.VirtualAddress
text_data = text.get_data()

# find all rip-relative references to IAT slots
call_sites = {}  # func_start -> list of (call_va, import_name)
for insn in md.disasm(text_data, text_base):
    if insn.id == X86_INS_CALL and len(insn.operands) == 1 and insn.operands[0].type == X86_OP_MEM and insn.operands[0].mem.base == X86_REG_RIP:
        tgt = insn.address + insn.size + insn.operands[0].mem.disp
        for nm, slot in iat_map.items():
            if slot == tgt:
                f = func_of(insn.address)
                call_sites.setdefault((f[0], f[1], nm), []).append(insn.address)

# For each call to interesting imports, disasm the whole function and print,
# annotating: lea (string refs), mov edx/r9d immediates before DeviceIoControl calls,
# and string data at rdata refs.
# Build rdata string reader
all_image = pe.get_memory_mapped_image()
def read_cstr(va, wide=False):
    off = va - base
    try:
        if not wide:
            end = all_image.index(b'\0', off)
            return all_image[off:end].decode('latin1', 'replace')
        else:
            s = b''
            i = off
            while i+1 < len(all_image) and all_image[i:i+2] != b'\0\0':
                s += all_image[i:i+2]; i += 2
            return s.decode('utf-16le', 'replace')
    except Exception:
        return None

targets = set(sys.argv[2].split(',')) if len(sys.argv) > 2 else set(iat_map.keys())
for (fstart, fend, nm), sites in sorted(call_sites.items()):
    if nm not in targets: continue
    print("="*110)
    print(f"FUNCTION {fstart:#x}-{fend:#x}  (calls {nm}; call sites: {[hex(s) for s in sites]})")
    code = all_image[fstart - base : fstart - base + (fend-fstart)]
    lastimm = {}
    for insn in md.disasm(code, fstart):
        note = ""
        if insn.id == X86_INS_LEA and len(insn.operands)==2 and insn.operands[1].type == X86_OP_MEM and insn.operands[1].mem.base == X86_REG_RIP:
            tgt = insn.address + insn.size + insn.operands[1].mem.disp
            s = read_cstr(tgt)
            s2 = read_cstr(tgt, True) if not s or len(s)<2 else None
            if s2 and sum(32 <= ord(c) < 127 for c in s2)/max(1,len(s2)) > 0.9: s = s2
            if s and sum(32 <= ord(c) < 127 for c in s)/max(1,len(s)) > 0.85:
                note = f"   ; \"{s[:120]}\""
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}")
