import sys, struct, bisect
sys.path.insert(0, r'C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages')
import pefile
from capstone import *
pe=pefile.PE(sys.argv[1]); base=pe.OPTIONAL_HEADER.ImageBase
img=pe.get_memory_mapped_image()
iat={}
for m in pe.DIRECTORY_ENTRY_IMPORT:
    for im in m.imports:
        iat[im.address]=(m.dll.decode(), im.name.decode() if im.name else 'ord')
pdata=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.pdata'][0]
praw=pdata.get_data(); pf=[]
for i in range(0,len(praw)-23,12):
    b,e,u=struct.unpack('<III', praw[i:i+12]); pf.append((base+b,base+e))
pf.sort(); begins=[a for a,b in pf]
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
import re as _re
exps={e.name.decode(): base+e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
for name in sys.argv[2].split(','):
    va=exps[name]
    lo=bisect.bisect_right(begins,va)-1
    fs,fe=pf[lo]
    print('========== %s  %s-%s (%d bytes)'%(name,hex(fs),hex(fe),fe-fs))
    for insn in md.disasm(img[fs-base:fe-base], fs):
        ann=''
        if 'rip +' in insn.op_str or 'rip -' in insn.op_str:
            for op in insn.operands:
                if op.type==3 and op.mem.base==41 and op.mem.index==0:
                    t=insn.address+insn.size+op.mem.disp
                    if t in iat: ann=' -> '+iat[t][0].replace('.dll','')+':'+iat[t][1][:70]
                    elif t in exps: ann=' ->EXP:'+name if False else ' ->EXP:'+[k for k,v in exps.items() if v==t][0][:60]
                    else:
                        for w in (False,True):
                            try:
                                s=cstr(t,w)
                            except Exception:
                                s=None
                            if s and len(s)>=2 and all(31<ord(c)<127 for c in s[:min(len(s),8)]):
                                ann='   >>> '+('W:' if w else 'S:')+repr(s[:70]); break
                    break
        print('%x %-7s %s%s'%(insn.address,insn.mnemonic,insn.op_str,ann))
