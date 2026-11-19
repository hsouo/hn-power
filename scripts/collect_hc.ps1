# collect_hc.ps1 v1.0 (曾用名 honor_hc.ps1) — HunterCamp 采集 + Esif WMI 实例 dump + 性能中心进程模块清单（全只读）
# 运行: 笔记本, 管理员 PowerShell。产物 .\acpi_hunt3\
$ErrorActionPreference = 'Continue'
$out = Join-Path (Get-Location) 'acpi_hunt3'
New-Item -ItemType Directory -Force $out | Out-Null
function Say { param($m) Write-Host $m }

Say "[1/4] root\wmi EsifDeviceInformation 实例 dump (IPF 内核 WMI 块)"
$e = Join-Path $out 'esif_wmi.txt'
try {
  $inst = Get-CimInstance -Namespace root\wmi -ClassName EsifDeviceInformation -EA Stop
  ("实例数: " + @($inst).Count) | Out-File -Encoding utf8 $e
  ($inst | Select-Object * -ExcludeProperty Cim* | Format-List | Out-String -Width 200) | Out-File -Append -Encoding utf8 $e
  $cls = Get-CimClass -Namespace root\wmi -ClassName EsifDeviceInformation -EA Stop
  "--- 属性 ---" | Out-File -Append -Encoding utf8 $e
  ($cls.CimClassProperties | ForEach-Object { $_.Name + " : " + $_.CimType }) -join "`n" | Out-File -Append -Encoding utf8 $e
  "--- 方法 ---" | Out-File -Append -Encoding utf8 $e
  ($cls.CimClassMethods | ForEach-Object { $_.Name }) -join "`n" | Out-File -Append -Encoding utf8 $e
} catch { ("FAIL: " + $_.Exception.Message) | Out-File -Encoding utf8 $e }
Get-Content $e -TotalCount 4 | ForEach-Object { Say ("  " + $_) }

Say "[2/4] EsifWmiEvent 快照(当前注册事件) + 3 秒被动监听样本"
try {
  Start-Job -Name esifsniff -ScriptBlock {
    Receive-Event -SourceIdentifier "esifjob" -ErrorAction SilentlyContinue | Out-Null
    Register-CimIndicationEvent -Namespace root\wmi -ClassName EsifWmiEvent -SourceIdentifier esifjob -EA SilentlyContinue
    $got = @()
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt 3) {
      try { $ev = Wait-Event -SourceIdentifier esifjob -Timeout 1; if ($ev) { $got += $ev.SourceArgs | Select-Object * -ExcludeProperty Cim*,*Property*; Remove-Event -EventIdentifier $ev.EventIdentifier } } catch {}
    }
    Unregister-Event -SourceIdentifier esifjob -EA SilentlyContinue
    $got
  } | Out-Null
  Wait-Job -Name esifsniff -Timeout 8 | Out-Null
  $res = Receive-Job -Name esifsniff -EA SilentlyContinue
  ("事件样本数: " + @($res).Count) | Out-File -Append -Encoding utf8 $e
  ($res | Format-List | Out-String -Width 200) | Out-File -Append -Encoding utf8 $e
  Say ("  -> 样本 " + @($res).Count + " 条 (若 0 条: 需配合模式切换才有事件)")
} catch { ("  evt FAIL: " + $_.Exception.Message) | Out-File -Append -Encoding utf8 $e }

Say "[3/4] HunterCamp 服务 + 目录清单 + 文件拷贝"
$h = Join-Path $out 'huntercamp'; New-Item -ItemType Directory -Force $h | Out-Null
$hc = Join-Path $out 'hc_services.txt'
(sc.exe qc HunterCampService 2>&1) -join "`n" | Out-File -Encoding utf8 $hc
foreach ($root in 'C:\Program Files\Honor\HunterCamp','C:\Program Files\HONOR\HunterCamp') {
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem $root -Recurse -File -EA SilentlyContinue |
    Select-Object @{n='Rel';e={$_.FullName.Substring($root.Length+1)}},Length,LastWriteTime |
    Format-Table -AutoSize | Out-String -Width 200 | Out-File -Append -Encoding utf8 $hc
  Get-ChildItem $root -Recurse -File -EA SilentlyContinue | Where-Object { $_.Length -lt 30MB -and $_.Extension -in '.dll','.exe','.xml','.json','.dat','.db','.config','.ini' } | ForEach-Object {
    try { Copy-Item $_.FullName (Join-Path $h $($_.Name)) -Force } catch {}
  }
}
Say ("  -> huntercamp\ {0} 个文件" -f (Get-ChildItem $h -File).Count)

Say "[4/4] 关键进程加载模块清单 (定位 GPU子模式 消息服务端/IPC注册者)"
$m = Join-Path $out 'proc_modules.txt'
"" | Out-File -Encoding utf8 $m
foreach ($pname in 'HnPerformanceCenter','HunterCampService','PCManagerMainService','MBAMainService','ipf_uf','LinkTurbo') {
  $proc = Get-Process -Name $pname -EA SilentlyContinue | Select-Object -First 1
  if (-not $proc) { ("### " + $pname + ": 未运行") | Out-File -Append -Encoding utf8 $m; continue }
  ("### " + $pname + " (pid " + $proc.Id + ")") | Out-File -Append -Encoding utf8 $m
  try {
    ($proc.Modules | ForEach-Object { $_.FileName }) -join "`n" | Out-File -Append -Encoding utf8 $m
  } catch { ("  modules FAIL: " + $_.Exception.Message) | Out-File -Append -Encoding utf8 $m }
  "" | Out-File -Append -Encoding utf8 $m
}
Say "  -> proc_modules.txt"
Say ("完成。打包 {0} 带回。" -f $out)
