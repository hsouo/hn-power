import sys
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
from capstone import *
path = sys.argv[1]; start = int(sys.argv[2],16); end = int(sys.argv[3],16)
pe = pefile.PE(path); base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
img = pe.get_memory_mapped_image()
for insn in md.disasm(img[start-base:end-base], start):
    note = ""
    if insn.mnemonic == "lea" and "[rip" in insn.op_str:
        import re
        m = re.search(r'rip \+ (0x[0-9a-f]+)', insn.op_str)
        if m:
            t = insn.address + insn.size + int(m.group(1),16) - base
            try:
                s = img[t:img.index(b'\0',t)].decode('latin1')
                if sum(32<=ord(c)<127 for c in s)/max(1,len(s))>0.85 and len(s)>1: note = f'   ; "{s[:80]}"'
            except: pass
    print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}")
