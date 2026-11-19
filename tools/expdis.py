import sys, os, re, struct
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *

path = sys.argv[1]
pat = re.compile(sys.argv[2])
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
all_image = pe.get_memory_mapped_image()

# .pdata function bounds
pf = []
for s in pe.sections:
    if s.Name.rstrip(b'\0') == b'.pdata':
        raw = s.get_data()
        for i in range(0, len(raw)-23, 12):
            begin, end, unk = struct.unpack('<III', raw[i:i+12])
            pf.append((base+begin, base+end))
pf.sort()

import bisect
starts = [a for a,b in pf]
def func_of(va):
    lo = bisect.bisect_right(starts, va) - 1
    if lo >= 0 and pf[lo][0] <= va < pf[lo][1]:
        return pf[lo]
    return (va, va+0x400)

def read_cstr(va, wide=False):
    off = va - base
    try:
        if not wide:
            end = all_image.index(b'\0', off)
            return all_image[off:end].decode('latin1', 'replace')
        s = b''; i = off
        while i+1 < len(all_image) and all_image[i:i+2] != b'\0\0':
            s += all_image[i:i+2]; i += 2
        return s.decode('utf-16le', 'replace')
    except Exception:
        return None

# export map
syms = []
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name and pat.search(e.name.decode()):
        syms.append((base + e.address, e.name.decode()))
syms.sort()
print(f"### {len(syms)} exports matched in {os.path.basename(path)}")
seen = set()
for va, nm in syms:
    fs, fe = func_of(va)
    if fs in seen:
        print(f"\n@@@@ {nm}  == same func as above ({fs:#x})")
        continue
    seen.add(fs)
    print("="*110)
    print(f"### {nm}   func {fs:#x}-{fe:#x} ({fe-fs} bytes)")
    code = all_image[fs-base : fs-base + (fe-fs)]
    for insn in md.disasm(code, fs):
        note = ""
        if insn.mnemonic == 'lea' and 'rip + 0x' in insn.op_str:
            m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', insn.op_str)
            if m:
                tgt = insn.address + insn.size + int(m.group(1), 16)
                s = read_cstr(tgt)
                s2 = read_cstr(tgt, True) if not s or len(s) < 2 else None
                if s2 and sum(32 <= ord(c) < 127 for c in s2)/max(1,len(s2)) > 0.9: s = s2
                if s and sum(32 <= ord(c) < 127 for c in s)/max(1,len(s)) > 0.85:
                    note = f'   ; "{s[:110]}"'
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}")
