# collect_acpi.ps1 v1.1 (曾用名 honor_acpi.ps1) — 荣耀本只读采集包
# v1.1: 修 GetSystemFirmwareTable(需启用 SeSystemEnvironmentPrivilege,管理员默认未启用)
#       修 WMI 类导出 -band 语法; 新增 [6]IPF策略配置采集 [7]HHAL/性能中心 exe 搜索复制 [8]服务注册表导出
# 全部只读(注册表导出/文件复制/查询), 不改任何设置。产物 .\acpi_hunt\
$ErrorActionPreference = 'Continue'
$out = Join-Path (Get-Location) 'acpi_hunt'
New-Item -ItemType Directory -Force $out | Out-Null
function Say { param($m) Write-Host $m }

function Enable-SysEnvPriv {
    if (-not ('HnPriv' -as [type])) {
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HnPriv {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValueW(string sys, string name, out long luid);
  [StructLayout(LayoutKind.Sequential)] struct TKP { public uint Count; public long Luid; public uint Attr; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool del, ref TKP np, uint len, IntPtr prev, IntPtr rel);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  const uint SE_PRIVILEGE_ENABLED = 2, TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8;
  public static bool Enable(string priv) {
    IntPtr tok; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok)) return false;
    long luid; if (!LookupPrivilegeValueW(null, priv, out luid)) return false;
    TKP p = new TKP(); p.Count = 1; p.Luid = luid; p.Attr = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(tok, false, ref p, 0, IntPtr.Zero, IntPtr.Zero);
  }
}
'@
    }
    return [HnPriv]::Enable('SeSystemEnvironmentPrivilege')
}

Say "[1/8] 启用 SeSystemEnvironmentPrivilege + ACPI 表转储 -> acpi_tables.bin"
$p = Enable-SysEnvPriv
Say ("  特权启用: {0}" -f $p)
if (-not ('ACPIDump' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.IO;
public static class ACPIDump {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern uint GetSystemFirmwareTable(uint provider, uint tableId, IntPtr buf, uint size);
  public static string Dump(string path) {
    const uint ACPI = 0x49435041;
    uint n = GetSystemFirmwareTable(ACPI, 0, IntPtr.Zero, 0);
    if (n == 0) return "枚举失败 err=" + Marshal.GetLastWin32Error();
    IntPtr list = Marshal.AllocHGlobal((int)n);
    try {
      if (GetSystemFirmwareTable(ACPI, 0, list, n) != n) return "枚举拷贝失败";
      using (var fs = new FileStream(path, FileMode.Create)) {
        byte[] hdr = new byte[8];
        for (int i = 0; i < n / 4; i++) {
          uint sig = (uint)Marshal.ReadInt32(list, i * 4);
          uint sz = GetSystemFirmwareTable(ACPI, sig, IntPtr.Zero, 0);
          if (sz == 0) continue;
          IntPtr tb = Marshal.AllocHGlobal((int)sz);
          try {
            if (GetSystemFirmwareTable(ACPI, sig, tb, sz) != sz) continue;
            byte[] bytes = new byte[sz];
            Marshal.Copy(tb, bytes, 0, (int)sz);
            Buffer.BlockCopy(BitConverter.GetBytes(sig), 0, hdr, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(sz), 0, hdr, 4, 4);
            fs.Write(hdr, 0, 8); fs.Write(bytes, 0, bytes.Length);
          } finally { Marshal.FreeHGlobal(tb); }
        }
      }
      return "OK";
    } finally { Marshal.FreeHGlobal(list); }
  }
}
'@
}
$r = [ACPIDump]::Dump((Join-Path $out 'acpi_tables.bin'))
Say ("  -> {0} ({1} bytes)" -f $r, (Get-Item (Join-Path $out 'acpi_tables.bin') -EA SilentlyContinue).Length)
if ($r -like '*失败*') { Say "  !! 若仍失败: 用管理员 cmd 先跑 powershell -ep bypass 再执行本脚本(特权段会重试)" }

Say "[2/8] WMI 类定义 (OemWMIMethod/OemWMIEvent)"
try {
  $cls = Get-CimClass -Namespace root/WMI -ClassName OemWMIMethod -ErrorAction Stop
  $sb = New-Object Text.StringBuilder
  [void]$sb.AppendLine("### class OemWMIMethod  ($($cls.CimClassProperties.Count) props, $($cls.CimClassMethods.Count) methods)")
  foreach ($c in $cls.CimClassProperties) {
    $qs = @(); foreach ($q in $c.Qualifiers) { $qs += "$($q.Name)=$($q.Value)" }
    [void]$sb.AppendLine("  prop $($c.Name) : $($c.CimType) qual: $($qs -join ',')")
  }
  foreach ($m in $cls.CimClassMethods) {
    $qi = @(); foreach ($q in $m.Qualifiers) { $qi += "$($q.Name)=$($q.Value)" }
    $pi = @(); $po = @()
    foreach ($par in $m.Parameters) {
      if ($par.Members -band 1) { $pi += "$($par.Name):$($par.CimType)" }
      if ($par.Members -band 2) { $po += "$($par.Name):$($par.CimType)" }
    }
    [void]$sb.AppendLine("  method $($m.Name) in[$($pi -join ';')] out[$($po -join ';')] qual: $($qi -join ',')")
  }
  $ev = Get-CimClass -Namespace root/WMI -ClassName OemWMIEvent -ErrorAction Stop
  [void]$sb.AppendLine("### class OemWMIEvent")
  foreach ($c in $ev.CimClassProperties) {
    $qs = @(); foreach ($q in $c.Qualifiers) { $qs += "$($q.Name)=$($q.Value)" }
    [void]$sb.AppendLine("  prop $($c.Name) : $($c.CimType) qual: $($qs -join ',')")
  }
  [void]$sb.AppendLine("### instances")
  foreach ($c in (Get-CimInstance -Namespace root/WMI -ClassName OemWMIMethod -EA SilentlyContinue)) {
    $vals = $c | Select-Object * -ExcludeProperty C* | Out-String
    [void]$sb.AppendLine("  $($c.__PATH)  $($vals -replace '\s+',' ')")
  }
  $sb.ToString() | Out-File -Encoding utf8 (Join-Path $out 'wmi_classes.txt')
  Say "  -> wmi_classes.txt"
} catch { Say ("  !! " + $_.Exception.Message) }

Say "[3/8] ACPI/NPCF 设备枚举 -> pnp_devices.txt"
Get-PnpDevice -PresentOnly -EA SilentlyContinue |
  Where-Object { $_.InstanceId -match 'ACPI|NVDA|PNP0C14|VEN_10DE' } |
  Select-Object FriendlyName, InstanceId, Status, Class, Service |
  Format-Table -AutoSize -Wrap | Out-String -Width 220 |
  Out-File -Encoding utf8 (Join-Path $out 'pnp_devices.txt')

Say "[4/8] 服务与驱动清单 -> services.txt"
$svcFile = Join-Path $out 'services.txt'
"--- Get-Service ---" | Out-File -Encoding utf8 $svcFile
Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match 'ipf|dtt|nv|HNOs|OS2SOC|MBA|Hn|Intel' } |
  Select-Object Name, Status, StartType, DisplayName | Format-Table -AutoSize | Out-String -Width 220 |
  Out-File -Append -Encoding utf8 $svcFile
"--- sc qc ---" | Out-File -Append -Encoding utf8 $svcFile
foreach ($s in 'ipfsvc','nvcontainer','NvContainerLocalSystem','OS2SOC','HNOs2ECx64','nvpcf','nvpower','ipf_ppm','ipf_uf') {
  $q = (sc.exe qc $s 2>&1) -join "`n"
  if ($q -notmatch '1060') { "### $s`n$q`n" | Out-File -Append -Encoding utf8 $svcFile }
}
"--- DriverStore (ipf|nvpcf|dtt|ias|ivpi|hsti|hwmi) 文件清单 ---" | Out-File -Append -Encoding utf8 $svcFile
foreach ($d in (Get-ChildItem "$env:SystemRoot\System32\DriverStore\FileRepository" -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'ipf|nvpcf|dtt|ias|ivpi|hsti|hwmi' })) {
  "### $($d.Name)" | Out-File -Append -Encoding utf8 $svcFile
  Get-ChildItem $d.FullName -Recurse -File -EA SilentlyContinue | ForEach-Object { "  $($_.FullName.Substring($d.FullName.Length+1))  $($_.Length)" } | Out-File -Append -Encoding utf8 $svcFile
}
Say "  -> services.txt"

Say "[5/8] 注册表 + 电源覆盖层"
$regFile = Join-Path $out 'registry.txt'
"--- HKU\.DEFAULT\Software\HONOR\PCManager\Performance ---" | Out-File -Encoding utf8 $regFile
(Get-ItemProperty 'HKU\.DEFAULT\Software\HONOR\PCManager\Performance' -EA SilentlyContinue | Out-String) | Out-File -Append -Encoding utf8 $regFile
"--- HKLM\SOFTWARE\PCManager\MBAPowerManager ---" | Out-File -Append -Encoding utf8 $regFile
(Get-ItemProperty 'HKLM:\SOFTWARE\PCManager\MBAPowerManager' -EA SilentlyContinue | Out-String) | Out-File -Append -Encoding utf8 $regFile
"--- WMI\Security 中含 abbc0f5b 的键 ---" | Out-File -Append -Encoding utf8 $regFile
$ws = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security' -EA SilentlyContinue
if ($ws) { $ws.GetValueNames() | Where-Object { $_ -match 'abbc0f5b' } | Out-File -Append -Encoding utf8 $regFile } else { "(无该键)" | Out-File -Append -Encoding utf8 $regFile }
"--- powercfg /overlayquery (Win11 电源模式滑条=IPF场景输入) ---" | Out-File -Append -Encoding utf8 $regFile
(& powercfg /overlayquery 2>&1) | Out-File -Append -Encoding utf8 $regFile
Say "  -> registry.txt"

Say "[6/8] IPF/IETM 策略配置采集 -> ipf_configs\"
$ic = Join-Path $out 'ipf_configs'
New-Item -ItemType Directory -Force $ic | Out-Null
$srcs = @()
$srcs += (Get-ChildItem "$env:SystemRoot\System32\DriverStore\FileRepository" -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'ipf|nvpcf' } | ForEach-Object { $_.FullName })
$srcs += 'C:\ProgramData\Intel\IPF','C:\Program Files\Intel\IPF','C:\Program Files (x86)\Intel\IPF','C:\ProgramData\Intel\DTT','C:\Program Files\Intel\DTT'
foreach ($s in $srcs) {
  if (-not (Test-Path $s)) { continue }
  Get-ChildItem $s -Recurse -File -EA SilentlyContinue | Where-Object { $_.Extension -match '^\.(xml|ipf|json|txt|csv|cfg|conf|reg|ipd|pdb)$' -and $_.Length -lt 20MB } | ForEach-Object {
    $dst = Join-Path $ic (($_.FullName -replace '[:*?"<>|]','_'))
    try { Copy-Item $_.FullName $dst -Force } catch {}
  }
}
Say ("  -> {0} 个配置文件" -f (Get-ChildItem $ic -File -EA SilentlyContinue).Count)

Say "[7/8] HHAL.dll / HnPerformanceCenter.exe 搜索复制 -> binaries\"
$bin = Join-Path $out 'binaries'
New-Item -ItemType Directory -Force $bin | Out-Null
foreach ($pat in 'HHAL.dll','HnPerformanceCenter.exe') {
  foreach ($root in 'C:\Program Files\HONOR','C:\Program Files\Honor','C:\Program Files (x86)\HONOR') {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -Filter $pat -EA SilentlyContinue | Select-Object -First 1 | ForEach-Object {
      Say ("  found: " + $_.FullName)
      try { Copy-Item $_.FullName (Join-Path $bin $pat) -Force } catch { Say ("  copy失败: " + $_.Exception.Message) }
    }
  }
}
Say "  -> binaries\ (若为空=未找到,请告知)"

Say "[8/8] 服务注册表参数导出 (nvpcf/ipf*)"
foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'nvpcf|ipf|OS2SOC|HNOs2EC' })) {
  $f = Join-Path $out ("svcreg_" + $k.PSChildName + ".txt")
  ("=== " + $k.PSChildName + " ===") | Out-File -Encoding utf8 $f
  Get-ChildItem $k.PSPath -Recurse -EA SilentlyContinue | ForEach-Object {
    "--- " + $_.Name | Out-File -Append -Encoding utf8 $f
    (Get-ItemProperty $_.PSPath -EA SilentlyContinue | Out-String) | Out-File -Append -Encoding utf8 $f
  }
}
Say "  -> svcreg_*.txt"
Say ("完成。打包整个 {0} 带回。" -f $out)
