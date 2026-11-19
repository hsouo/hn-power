import sys
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile
pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
rows = []
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name and e.address:
        rows.append((e.address, e.name.decode()))
for rva, nm in sorted(rows):
    print(f"{base+rva:#x}  ordinal={next((o for o,nm2 in [(s.ordinal,s.name.decode() if s.name else '') for s in pe.DIRECTORY_ENTRY_EXPORT.symbols] if nm2==nm), None)}  {nm}")
