# collect_dtt.ps1 v1.0 (曾用名 honor_dtt.ps1) — DTT/IPF 策略配置 + plugins 全家桶采集（纯只读/复制）
# 目标: 1) DPTF 策略 .config + PPM .ppkg  2) 关键策略DLL(PowerShare2/ITM3/ThirdPartyGraphics/upe_nvapi/Dptf)
#       3) HHAL.sys(第二条 MSR PL 路的驱动)  4) PCManager\plugins 全量清单+拷贝(性能中心真身)
# 运行: 管理员 PowerShell。产物 .\acpi_hunt2\
$ErrorActionPreference = 'Continue'
$out = Join-Path (Get-Location) 'acpi_hunt2'
New-Item -ItemType Directory -Force $out | Out-Null
function Say { param($m) Write-Host $m }

Say "[1/6] DTT/IPF 策略配置文件 -> configs\"
$c = Join-Path $out 'configs'; New-Item -ItemType Directory -Force $c | Out-Null
$fr = "$env:SystemRoot\System32\DriverStore\FileRepository"
foreach ($pkg in (Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'dtt_sw|ipfppm_sw|ipf_cpu|dtt_ext' })) {
  Get-ChildItem $pkg.FullName -Recurse -File -EA SilentlyContinue | Where-Object { $_.Extension -in '.config','.ppkg','.inf' -or $_.Name -match '\.dv$|\.ipd$' } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $c $($_.Name)) -Force } catch { Say ("  copy失败 " + $_.Name) }
  }
}
foreach ($pd in 'C:\ProgramData\Intel','C:\ProgramData\Intel Corporation') {
  Get-ChildItem $pd -Recurse -File -EA SilentlyContinue | Where-Object { $_.Extension -in '.config','.ppkg','.xml','.json' -and $_.FullName -match 'dtt|ipf|DPTF|thermal' } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $c ('pd_' + $_.Name)) -Force } catch {}
  }
}
# IPF 运行时策略库(C:\ProgramData\Intel\IPF\{dv,dsp,cmd,ui,log}) — 活的策略 vault, 全树拷贝
$ipf = 'C:\ProgramData\Intel\IPF'
if (Test-Path $ipf) {
  $ic = Join-Path $out 'ipf_progdata'; New-Item -ItemType Directory -Force $ic | Out-Null
  Get-ChildItem $ipf -Recurse -File -EA SilentlyContinue | Where-Object { $_.Length -lt 40MB } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $ic $($_.Name)) -Force } catch {}
  }
  Say ("  + Intel\IPF 树 -> ipf_progdata\ ({0} 个文件)" -f (Get-ChildItem $ic -File).Count)
}
Say ("  -> {0} 个文件" -f (Get-ChildItem $c -File).Count)

Say "[1b] DISM 解包 PPM 策略包 (WIM 容器)"
$xe = Join-Path $out 'ppm_extract'
New-Item -ItemType Directory -Force $xe | Out-Null
foreach ($pk in (Get-ChildItem $c -Filter '*.ppkg' -EA SilentlyContinue | Where-Object { $_.Name -match 'MTL' })) {
  $tmpwim = Join-Path $env:TEMP ('ppm_' + $pk.BaseName + '.wim')
  Copy-Item $pk.FullName $tmpwim -Force
  & dism /Apply-Image /ImageFile:$tmpwim /Index:1 /TargetDir:$xe 2>&1 | Select-Object -Last 3 | ForEach-Object { Say ("  " + $_) }
  Remove-Item $tmpwim -Force -EA SilentlyContinue
}
Say ("  -> ppm_extract\ {0} 个文件" -f (Get-ChildItem $xe -Recurse -File -EA SilentlyContinue).Count)

Say "[2/6] 关键策略/引擎 DLL -> ddlls\"
$d = Join-Path $out 'ddlls'; New-Item -ItemType Directory -Force $d | Out-Null
foreach ($pkg in (Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'dtt_sw|ipf_cpu' })) {
  Get-ChildItem $pkg.FullName -Recurse -File -EA SilentlyContinue | Where-Object { $_.Name -match 'Dptf\.dll|PowerShare|IntelligentThermalManagement3|ThirdPartyGraphics|upe_nvapi|AdaptivePerformance|PowerBoss' } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $d $($_.Name)) -Force } catch {}
  }
}
Say ("  -> {0} 个 DLL" -f (Get-ChildItem $d -File).Count)

Say "[3/6] HHAL.sys / HHAL 服务"
$hk = Join-Path $out 'hhal.txt'
"--- sc qc HHAL ---" | Out-File -Encoding utf8 $hk
$q = (sc.exe qc HHAL 2>&1) -join "`n"; $q | Out-File -Append -Encoding utf8 $hk
if ($q -match 'BINARY_PATH_NAME\s*:\s*(\S+)') {
  $bp = $matches[1] -replace '^\\\\\?\?\\','' -replace '^\\SystemRoot\\',$env:SystemRoot -replace '^\\\?\?\\',''
  Say ("  binary: " + $bp)
  if (Test-Path $bp) { try { Copy-Item $bp (Join-Path $out 'HHAL.sys') -Force; Say "  -> HHAL.sys 已复制" } catch { Say ("  copy失败: " + $_.Exception.Message) } }
} else { Say "  !! HHAL 服务不存在(未安装)——说明管家从未用过 SetCpuPl 路" }

Say "[4/6] PCManager 目录清单 + plugins 拷贝"
$p = Join-Path $out 'plugins'; New-Item -ItemType Directory -Force $p | Out-Null
foreach ($root in 'C:\Program Files\HONOR\PCManager','C:\Program Files\Honor\PCManager') {
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem $root -Recurse -File -EA SilentlyContinue |
    Select-Object @{n='Rel';e={$_.FullName.Substring($root.Length+1)}},Length,LastWriteTime |
    Format-Table -AutoSize | Out-String -Width 200 | Out-File -Append -Encoding utf8 (Join-Path $out 'pcmanager_manifest.txt')
  $pl = Join-Path $root 'plugins'
  if (-not (Test-Path $pl)) { continue }
  Get-ChildItem $pl -Recurse -File -EA SilentlyContinue | Where-Object { $_.Length -lt 30MB } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $p $($_.Name)) -Force } catch {}
  }
}
Say ("  -> plugins\ {0} 个文件, 共 {1:N1} MB" -f (Get-ChildItem $p -File).Count, (((Get-ChildItem $p -File | Measure-Object Length -Sum).Sum)/1MB))

Say "[5/6] PowerCenter 相关服务/进程运行状态"
$st = Join-Path $out 'runtime.txt'
"--- 进程 ---" | Out-File -Encoding utf8 $st
Get-Process -EA SilentlyContinue | Where-Object { $_.Path -like '*HONOR*' -or $_.Name -match 'Hn|PCManager|MBA|ipf' } | Select-Object Id,Name,Path | Format-Table -AutoSize | Out-String -Width 220 | Out-File -Append -Encoding utf8 $st
"--- DTT/IPF 服务全量 ---" | Out-File -Append -Encoding utf8 $st
Get-Service -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Innovation|Dynamic|Thermal|Intel' } | Select-Object Name,Status,StartType,DisplayName | Format-Table -AutoSize | Out-String -Width 220 | Out-File -Append -Encoding utf8 $st
"--- ipfsvc 命令行 ---" | Out-File -Append -Encoding utf8 $st
(reg query "HKLM\SYSTEM\CurrentControlSet\Services\ipfsvc" /v ImagePath 2>&1) -join ' ' | Out-File -Append -Encoding utf8 $st
(Get-CimInstance Win32_Process -Filter "Name like 'ipf%' or Name like '%dtt%' or Name like '%uf.exe'" -EA SilentlyContinue | Select-Object Name,CommandLine | Out-String) | Out-File -Append -Encoding utf8 $st
Say "  -> runtime.txt"

Say "[6/6] DTT/DPTF WMI 总线类枚举 (root\wmi INTC1042/IntelDTT*)"
$dw = Join-Path $out 'dtt_wmi.txt'
"--- root\wmi 类名过滤 (Get-CimClass; 桌面实测: IPF 无 DTT WMI 总线, 此处为笔记本复核) ---" | Out-File -Encoding utf8 $dw
try {
  $cls = Get-CimClass -Namespace root\wmi -EA Stop
  ("  总类数: " + $cls.Count) | Out-File -Append -Encoding utf8 $dw
  ($cls | Where-Object { $_.CimClassName -match 'Dtt|DTT|ESIF|IPF|IETM|INTC|Thermal|Participant|Cooling|Limit|Clip|Power' } | ForEach-Object { $_.CimClassName } | Sort-Object) -join "`n" | Out-File -Append -Encoding utf8 $dw
} catch { ("  list失败: " + $_.Exception.Message) | Out-File -Append -Encoding utf8 $dw }
"--- OemWMIMethod 方法参数 schema ---" | Out-File -Append -Encoding utf8 $dw
try {
  $om = Get-CimClass -Namespace root\wmi -ClassName OemWMIMethod -EA Stop
  foreach ($m in $om.CimClassMethods) {
    ("方法 " + $m.Name) | Out-File -Append -Encoding utf8 $dw
    $m.Parameters | ForEach-Object { ("  " + $_.Name + " : " + $_.CimType) | Out-File -Append -Encoding utf8 $dw }
  }
} catch { ("  oem失败: " + $_.Exception.Message) | Out-File -Append -Encoding utf8 $dw }
"--- 服务/进程含 dtt/Dptf ---" | Out-File -Append -Encoding utf8 $dw
(Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match 'dtt|Dptf|EPM|Thermal' } | Out-String) | Out-File -Append -Encoding utf8 $dw
(Get-Process -EA SilentlyContinue | Where-Object { $_.Name -match 'dtt|Dptf|ipf' } | Select-Object Id,Name,Path | Out-String) | Out-File -Append -Encoding utf8 $dw
Say "  -> dtt_wmi.txt"
Say ("完成。打包整个 {0} 带回。" -f $out)
