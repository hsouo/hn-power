import sys, os, re
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")

d = sys.argv[1]
outdir = os.path.join(d, "tools", "strings")
os.makedirs(outdir, exist_ok=True)

GUID_RE = re.compile(rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

def ascii_strings(data, minlen=5):
    out = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7f:
            cur.append(b)
        else:
            if len(cur) >= minlen: out.append(cur.decode('latin1'))
            cur = bytearray()
    if len(cur) >= minlen: out.append(cur.decode('latin1'))
    return out

def utf16_strings(data, minlen=5):
    out = []
    cur = []
    i = 0
    n = len(data) - 1
    while i < n:
        lo, hi = data[i], data[i+1]
        if hi == 0 and (0x20 <= lo < 0x7f):
            cur.append(chr(lo)); i += 2
        else:
            if len(cur) >= minlen: out.append(''.join(cur))
            cur = []
            i += 1
    if len(cur) >= minlen: out.append(''.join(cur))
    return out

for f in sorted(os.listdir(d)):
    if not f.lower().endswith(('.dll','.sys','.exe')): continue
    data = open(os.path.join(d, f), 'rb').read()
    a = ascii_strings(data)
    w = utf16_strings(data)
    guids = set(m.decode() for m in GUID_RE.findall(data))
    path = os.path.join(outdir, f + ".strings.txt")
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write("### ASCII strings (%d)\n" % len(a))
        for s in a: fh.write(s + "\n")
        fh.write("\n### UTF16 strings (%d)\n" % len(w))
        for s in w: fh.write(s + "\n")
        fh.write("\n### GUIDs found (%d)\n" % len(guids))
        for g in sorted(guids): fh.write(g + "\n")
    print(f, len(a), len(w), len(guids))
