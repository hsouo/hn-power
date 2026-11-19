import sys, os, re, struct, bisect
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *

path = sys.argv[1]
pats = sys.argv[2:]
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
img = pe.get_memory_mapped_image()
text = [s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
tb = base + text.VirtualAddress
tdata = img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]

pdata = [s for s in pe.sections if s.Name.rstrip(b'\0')==b'.pdata'][0]
praw = pdata.get_data()
pf = []
for i in range(0, len(praw)-23, 12):
    b,e,u = struct.unpack('<III', praw[i:i+12])
    pf.append((base+b, base+e))
pf.sort(); begins = [x[0] for x in pf]
def func_of(va):
    lo = bisect.bisect_right(begins, va)-1
    if lo>=0 and pf[lo][0]<=va<pf[lo][1]: return pf[lo]
    return None

targets = {}
for p in pats:
    for enc in ('latin1','utf-16le'):
        pb = p.encode(enc)
        for m in re.finditer(re.escape(pb), img):
            targets.setdefault(p, set()).add(base+m.start())

# raw lea scan
refs = {}
for i in range(len(tdata)-7):
    if tdata[i] in (0x48,0x4c) and tdata[i+1]==0x8D and (tdata[i+2] & 0xC7)==0x05:
        disp = struct.unpack('<i', tdata[i+3:i+7])[0]
        tva = tb + i + 7 + disp
        for p, vas in targets.items():
            if tva in vas:
                refs.setdefault(p, set()).add(tb+i)

def cstr(t, wide=False):
    try:
        if not wide:
            e = img.index(b'\0', t-base); return img[t-base:e].decode('latin1','replace')
        i2 = t-base
        while img[i2:i2+2] != b'\0\0': i2 += 2
        return img[t-base:i2].decode('utf-16le','replace')
    except: return None

def dumpfunc(fstart, fend, label):
    print("="*110)
    print(f"### {label}  func {fstart:#x}-{fend:#x}")
    for insn in md.disasm(img[fstart-base:fstart-base+(fend-fstart)], fstart):
        note = ""
        if insn.mnemonic=='lea' and '[rip' in insn.op_str:
            m = re.search(r'rip ([-+]) (0x[0-9a-f]+)', insn.op_str)
            if m:
                d = int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
                t = insn.address+insn.size+d
                s = cstr(t) or ""
                if len(s)<3: s = cstr(t, True) or ""
                if len(s)>2 and sum(32<=ord(c)<127 for c in s)/len(s)>0.85: note=f'   ; "{s[:110]}"'
        print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}")

found = False
for p, code_vas in refs.items():
    funcs = sorted({func_of(v) for v in code_vas if func_of(v)})
    if not funcs: continue
    found = True
    print(f"\n@@@@@ STRING {p!r} referenced from {len(code_vas)} sites in {len(funcs)} functions")
    for fs, fe in funcs[:5]:
        dumpfunc(fs, fe, p)
if not found: print("no refs found for:", pats)
