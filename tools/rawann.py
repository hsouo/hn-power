import sys
sys.path.insert(0, r'C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages')
import pefile
from capstone import *
pe=pefile.PE(sys.argv[1]); base=pe.OPTIONAL_HEADER.ImageBase
img=pe.get_memory_mapped_image()
iat={}
for m in pe.DIRECTORY_ENTRY_IMPORT:
    for im in m.imports:
        iat[im.address]=(m.dll.decode(), im.name.decode() if im.name else 'ord')
def cstr(v,wide):
    o=v-base
    try:
        if not wide:
            e2=img.index(b'\0',o); return img[o:e2].decode('latin1','replace')
        i2=o
        while img[i2:i2+2]!=b'\0\0': i2+=2
        return img[o:i2].decode('utf-16le','replace')
    except: return None
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
va=int(sys.argv[2],16); size=int(sys.argv[3],16)
for insn in md.disasm(img[va-base:va+size-base], va):
    ann=''
    if 'rip +' in insn.op_str or 'rip -' in insn.op_str:
        for op in insn.operands:
            if op.type==3 and op.mem.base==41 and op.mem.index==0:
                t=insn.address+insn.size+op.mem.disp
                if t in iat: ann=' -> '+iat[t][0].replace('.dll','')+':'+iat[t][1][:70]
                else:
                    for w in (False,True):
                        s=cstr(t,w)
                        if s and len(s)>=2 and all(31<ord(c)<127 for c in s[:min(len(s),8)]):
                            ann='   >>> '+('W:' if w else 'S:')+repr(s[:70]); break
                break
    if ann or 'mov' in insn.mnemonic or insn.mnemonic in ('call','cmp','test','jmp','je','jne','lea'):
        print('%x %-7s %s%s'%(insn.address,insn.mnemonic,insn.op_str,ann))
