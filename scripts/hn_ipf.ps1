# hn_ipf.ps1 v1.3 - Intel IPF CLI read-only probe (client mode against running ipfsvc)
# v1.3: fail branch dumps FULL about-output; v1.2: pure-ASCII (BOM-loss robust)
# Safety: client mode ONLY + read-only commands; aborts on connect failure; never starts server/shell.
# Run: laptop, elevated PowerShell. Output dir: .\acpi_hunt2\ipf\
$ErrorActionPreference = 'Continue'
$out = Join-Path (Get-Location) 'acpi_hunt2\ipf'
New-Item -ItemType Directory -Force $out | Out-Null
$log = Join-Path $out 'ipf_probe.txt'
function Log { param($m) Write-Host $m; $m | Out-File -Append -Encoding utf8 $log }

$fr = "$env:SystemRoot\System32\DriverStore\FileRepository"
$pkg = Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'ipf_cpu.inf_*' } | Sort-Object Name | Select-Object -Last 1
# prefer the exact package the running service uses (client/service SDK mismatch => rejected)
$ipl = ((reg query "HKLM\SYSTEM\CurrentControlSet\Services\ipfsvc" /v ImagePath 2>&1) -join ' ')
if ($ipl -match 'FileRepository\\(ipf_cpu\.inf_[a-f0-9_]+)\\') {
  $exact = Join-Path $fr $matches[1]
  if (Test-Path $exact) { $pkg = Get-Item $exact }
}
if (-not $pkg) { Log "!! ipf_cpu DriverStore package not found"; exit 1 }
$exe = Join-Path $pkg.FullName 'ipf_uf.exe'
Log ("== ipf_uf: " + $exe)

Log "--- [0] ipfsvc start args + UF named-pipe state ---"
Log ("  ImagePath: " + $ipl)
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match '14579667|18837DD8' }
if ($pipes) { Log ("  IPF pipe listening: " + ($pipes -join ', ')) } else { Log "  !! no IPF shell pipe (service may run without -i; client will fail to connect - expected, trying anyway)" }
# full pipe list (also locates MBA/PCManager/HunterCamp IPC servers)
[System.IO.Directory]::GetFiles('\\.\pipe\') | Sort-Object | Out-File -Encoding utf8 (Join-Path $out 'allpipes.txt')
Log ("  all named pipes: " + (Get-Content (Join-Path $out 'allpipes.txt')).Count + " -> allpipes.txt")

# copy PPM policy packages (.ppkg) for offline analysis (DISM on laptop rejects the extension)
$ppdst = Join-Path (Split-Path $out -Parent) 'ppkgs'
New-Item -ItemType Directory -Force $ppdst | Out-Null
Get-ChildItem $fr -Recurse -Filter '*.ppkg' -EA SilentlyContinue | Where-Object { $_.FullName -match 'ipf|dtt|ias_' } | ForEach-Object {
  Copy-Item $_.FullName (Join-Path $ppdst $_.Name) -Force -EA SilentlyContinue
}
Log ("  ppkg copies -> ppkgs\ {0}" -f (Get-ChildItem $ppdst -File).Count)

Set-Location $out   # DriverStore is read-only: all outputs land in $out; exe deps resolve from EXE dir, not cwd
function Run-Ipf { param($cmd, $file)
  Log ("  > " + $cmd)
  $fp = Join-Path $out $file
  $p = Start-Process -FilePath $exe -ArgumentList @('client','-c',$cmd) -NoNewWindow -PassThru -RedirectStandardOutput $fp -RedirectStandardError ($fp + '.err') -Wait -EA SilentlyContinue
  if ($null -eq $p) { Log "    start failed"; return $false }
  Log ("    exit=" + $p.ExitCode)
  $txt = (Get-Content $fp -Raw -EA SilentlyContinue)
  if ($txt) { $preview = ($txt -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 4) -join ' | '; Log ("    " + $preview.Substring(0,[Math]::Min(160,$preview.Length))) }
  $err = (Get-Content ($fp + '.err') -Raw -EA SilentlyContinue)
  if ($err) { Log ("    ERR: " + $err.Substring(0,[Math]::Min(200,$err.Length)).Trim()) }
  return ($p.ExitCode -eq 0)
}

Log "--- [1] handshake: client -c about ---"
$ok = Run-Ipf 'about' 'probe_about.txt'
$ptxt = (Get-Content (Join-Path $out 'probe_about.txt') -Raw -EA SilentlyContinue)
if ($ptxt -match '(?i)unable to connect|cannot|fail') { $ok = $false }   # exit code is unreliable; trust the text
if (-not $ok) {
  Log "!! client mode cannot reach the running framework. FULL about-output follows:"
  ($ptxt -split "`r?`n" | Where-Object { $_.Trim() }) | ForEach-Object { Log ("    | " + $_) }
  $pe = (Get-Content ((Join-Path $out 'probe_about.txt') + '.err') -Raw -EA SilentlyContinue)
  if ($pe) { Log "    STDERR:"; ($pe -split "`r?`n" | Where-Object { $_.Trim() }) | ForEach-Object { Log ("    ! " + $_) } }
  Log "!! next step (needs YOUR approval; reversible config change):"
  Log "!!   reg add ipfsvc ImagePath with trailing ' -i', Restart-Service ipfsvc, then re-run this script."
  Log "!!   (restore = drop the ' -i' and restart again)"
  Log "!! No changes were made. Exiting."
  exit 2
}

Log "--- [2] read-only command sweep ---"
$cmds = @(
  'info','sdk','participants','participantsk','domains','upes','apps','driversk','dspquery',
  'arbitrator help','config list','config files'
)
foreach ($c in $cmds) { $n = ($c -replace '[^a-z0-9]','_'); Run-Ipf $c ("cmd_" + $n + ".txt") | Out-Null }

Log "--- [3] participant details ---"
$partsTxt = Get-Content (Join-Path $out 'cmd_participants.txt') -EA SilentlyContinue
$ids = $partsTxt | ForEach-Object { if ($_ -match '0x([0-9a-fA-F]{6,16})') { $matches[1] } } | Sort-Object -Unique | Select-Object -First 16
Log ("  participant ids: " + ($ids -join ', '))
$k = 0
foreach ($id in $ids) { $k++; Run-Ipf ("participant 0x" + $id) ("part_{0:d2}.txt" -f $k) | Out-Null }

Log "--- [4] full DTT/IPF settings capture (XML) ---"
Run-Ipf 'capture overwrite ipf_settings_full.txt' 'cmd_capture.txt' | Out-Null
# relative capture filename lands in cwd (=$out)

Log "--- [5] outputs ---"
Get-ChildItem $out -File | Select-Object Name,Length | Format-Table -AutoSize | Out-String | ForEach-Object { Log $_ }
Log "Done. Pack acpi_hunt2\ipf (and ppkgs) back."
