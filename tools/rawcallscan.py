import sys, os, re, struct
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *

path = sys.argv[1]
targets = set(sys.argv[2].split(','))  # import name substrings
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
all_image = pe.get_memory_mapped_image()

iat_map = {}  # name -> IAT slot VA
for mod in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in mod.imports:
        if imp.name:
            iat_map[mod.dll.decode() + '!' + imp.name.decode()] = imp.address

want = {va: nm for nm, va in iat_map.items() if any(t in nm for t in targets)}
print(f"### targets: {[ (va, hex(nm)) for nm,va in want.items() ]}")

text = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text'][0]
trva, tend, tpos = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize, text.PointerToRawData
raw = text.get_data()

# .pdata bounds
pf = []
for s in pe.sections:
    if s.Name.rstrip(b'\0') == b'.pdata':
        r = s.get_data()
        for i in range(0, len(r)-23, 12):
            b, e, u = struct.unpack('<III', r[i:i+12])
            pf.append((base+b, base+e))
pf.sort()
import bisect
starts = [a for a,_ in pf]
def func_of(va):
    lo = bisect.bisect_right(starts, va) - 1
    if lo >= 0 and pf[lo][0] <= va < pf[lo][1]:
        return pf[lo]
    return (va, va)

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

hits = {}  # func -> list of (site, name)
for i in range(len(raw) - 5):
    if raw[i] == 0xFF and raw[i+1] == 0x15:
        rel = struct.unpack('<i', raw[i+2:i+6])[0]
        site_rva = trva + i
        slot = base + site_rva + 6 + rel
        if slot in want:
            fva = base + site_rva
            fs, fe = func_of(fva)
            hits.setdefault((fs, fe, want[slot]), []).append(fva)

def dump(fs, fe, label):
    print("="*110)
    print(f"### {label}   func {fs:#x}-{fe:#x} ({fe-fs}B)")
    code = all_image[fs-base : fs-base + (fe-fs)]
    for insn in md.disasm(code, fs):
        note = ""
        if insn.mnemonic in ('lea','mov') and 'rip + 0x' in insn.op_str:
            m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', insn.op_str)
            if m:
                tgt = insn.address + insn.size + int(m.group(1), 16)
                s = read_cstr(tgt)
                s2 = read_cstr(tgt, True) if not s or len(s) < 2 else None
                if s2 and sum(32 <= ord(c) < 127 for c in s2)/max(1,len(s2)) > 0.9: s = s2
                if s and sum(32 <= ord(c) < 127 for c in s)/max(1,len(s)) > 0.85 and len(s)>1:
                    note = f'   ; "{s[:110]}"'
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}")

for (fs, fe, nm), sites in sorted(hits.items()):
    dump(fs, fe, f"calls {nm}  sites={[hex(s) for s in sites]}")
