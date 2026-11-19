import sys, os
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile, re, json

def dump(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
    ])
    out = {"file": os.path.basename(path),
           "machine": hex(pe.FILE_HEADER.Machine),
           "timestamp": hex(pe.FILE_HEADER.TimeDateStamp),
           "exports": [], "imports": {}, "sections": [s.Name.rstrip(b'\0').decode('latin1') for s in pe.sections]}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            out["exports"].append([e.ordinal, e.name.decode('latin1') if e.name else None])
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            out["imports"][mod.dll.decode('latin1')] = [
                (imp.name.decode('latin1') if imp.name else f"#{imp.ordinal}") for imp in mod.imports]
    pe.close()
    return out

if __name__ == "__main__":
    d = sys.argv[1]
    for f in sorted(os.listdir(d)):
        if f.lower().endswith('.dll'):
            info = dump(os.path.join(d, f))
            print("="*100)
            print(f"FILE: {f}  machine={info['machine']}  timestamp={info['timestamp']}")
            print(f"SECTIONS: {', '.join(info['sections'])}")
            print(f"EXPORTS ({len(info['exports'])}):")
            for o, n in info["exports"]:
                print(f"  [{o}] {n}")
            print("IMPORTS:")
            for mod, funcs in info["imports"].items():
                print(f"  {mod}: {len(funcs)} funcs")
                print(f"     {', '.join(funcs[:60])}")
                if len(funcs) > 60: print(f"     ... (+{len(funcs)-60} more)")
