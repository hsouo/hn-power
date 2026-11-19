import json, re, io
H = r'C:\Users\hs-desktop\code\dsh_test\honor'
d = json.load(open(H + r'\esif_primitive_ids.json'))
ind_lines = '\n'.join('    $m.Add("%s",%d)' % (k, v) for k, v in sorted(d.items(), key=lambda kv: kv[1]))
new_block = 'function Load-Ids {\n    if ($script:idmap) { return }\n    $p = Join-Path $PSScriptRoot \'esif_primitive_ids.json\'\n    if (Test-Path $p) {\n        $script:idmap = Get-Content $p -Raw | ConvertFrom-Json\n        return\n    }\n    $m = @{}\n' + ind_lines + '\n    $script:idmap = [pscustomobject]$m\n}'
old = open(H + r'\hn_esif.ps1', 'rb').read().decode('utf-8-sig')
pat = re.compile(r'function Load-Ids \{.*?\n\}', re.S)
assert pat.search(old), 'pattern not found'
out = pat.sub(lambda mm: new_block, old, count=1)
open(H + r'\hn_esif.ps1', 'wb').write(b'\xef\xbb\xbf' + out.encode('utf-8'))
print('rewritten, chars', len(out))
