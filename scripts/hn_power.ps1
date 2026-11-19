# hn_power.ps1 — 荣耀 MagicBook 只读功耗探针（不写任何寄存器/不设置任何模式）
# 用法（笔记本，管理员 PowerShell 5.1 x64）:
#   .\hn_power.ps1                 一次性全量采集 -> 控制台 + hn_power_report.txt
#   .\hn_power.ps1 -Loop           持续采样(默认5s) -> 控制台一行 + hn_power_log.csv
#   .\hn_power.ps1 -Loop -IntervalSec 2
# 依赖: 本目录放 OS2SOCService.dll (原厂已签名的服务DLL, 自含KERNEL32/ADVAPI32;
#       它会自动 OpenService/StartService 已安装的 OS2SOC 驱动服务; 若驱动服务不存在则相应段落自动跳过并提示)
param(
    [switch]$Loop,
    [int]$IntervalSec = 5,
    [switch]$NoWmi,        # 跳过 WMI 段
    [switch]$NoOs2Soc      # 跳过 OS2SOC 驱动段
)
$ErrorActionPreference = 'Continue'
$script:Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$report = Join-Path $script:Dir 'hn_power_report.txt'
$csv    = Join-Path $script:Dir 'hn_power_log.csv'
$outLines = New-Object System.Collections.Generic.List[string]
function Say($s) { $outLines.Add($s); Write-Host $s }

if (-not [Environment]::Is64BitProcess) { Write-Host "必须用 64 位 PowerShell" -ForegroundColor Red; exit 1 }

# ============ 1) WMI 传感器读取 (与 hn_wmi.ps1 v2 同路, 全部为读命令) ============
$script:HwmiInst = $null
function Get-HwmiInst {
    if ($script:HwmiInst) { return $script:HwmiInst }
    $all = @(Get-CimInstance -Namespace root/wmi -ClassName OemWMIMethod -ErrorAction Stop)
    if ($all.Count -eq 0) { throw "root/wmi OemWMIMethod 无实例" }
    $script:HwmiInst = ($all | Where-Object { $_.InstanceName -like '*HWMI_0' } | Select-Object -First 1)
    if (-not $script:HwmiInst) { $script:HwmiInst = $all[0] }
    return $script:HwmiInst
}
function Invoke-HwmiRaw([byte]$g, [byte]$c, [byte]$v) {
    $in = New-Object byte[] 64; $in[0]=$g; $in[1]=$c; $in[2]=$v
    $inst = Get-HwmiInst
    try {
        $r = Invoke-CimMethod -InputObject $inst -MethodName 'OemWMIfun' -Arguments @{ u8Input = $in } -ErrorAction Stop
    } catch {
        $u64 = [uint64]([int]$g -bor ([int]$c -shl 8) -bor ([int]$v -shl 16))
        $r = Invoke-CimMethod -InputObject $inst -MethodName 'OemWMIfunEx' -Arguments @{ u64Input = $u64 } -ErrorAction Stop
    }
    return [byte[]]$r.u8Output
}
$modeName = @{ 0='智能'; 1='高性能'; 3='猎人' }
function Read-WmiBlock {
    $o = @{}
    try {
        $r = Invoke-HwmiRaw 0x04 0x0E 0; $o.mode = if ($r[0] -eq 0) { [int]$r[1] } else { $null }
        $r = Invoke-HwmiRaw 0x02 0x02 0x00; $o.cpuT = if ($r[0] -eq 0) { [int]$r[2] } else { $null }
        $r = Invoke-HwmiRaw 0x02 0x02 0x0E; $o.zone0E = if ($r[0] -eq 0) { [int]$r[2] } else { $null }
        $r = Invoke-HwmiRaw 0x02 0x08 0;     $o.fan0 = if ($r[0] -eq 0) { [int]$r[1] + ([int]$r[2] -shl 8) } else { $null }; $o.fan0tgt = if ($r[0] -eq 0) { [int]$r[3] + ([int]$r[4] -shl 8) } else { $null }
        $r = Invoke-HwmiRaw 0x02 0x08 1;     $o.fan1 = if ($r[0] -eq 0) { [int]$r[1] + ([int]$r[2] -shl 8) } else { $null }; $o.fan1tgt = if ($r[0] -eq 0) { [int]$r[3] + ([int]$r[4] -shl 8) } else { $null }
        $r = Invoke-HwmiRaw 0x02 0x0C 0;     $o.noiseRead = ($r | Select-Object -First 6 | ForEach-Object { $_.ToString('X2') }) -join ' '
    } catch { $o.wmiErr = $_.Exception.Message }
    return $o
}

# ============ 2) OS2SOCService.dll P/Invoke (只读导出) ============
$script:Os2 = $null
if (-not $NoOs2Soc) {
    $dllPath = Join-Path $script:Dir 'OS2SOCService.dll'
    $svc = Get-Service -Name 'OS2SOC' -ErrorAction SilentlyContinue
    if (Test-Path $dllPath) {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class Os2Soc {
    [return: MarshalAs(UnmanagedType.I1)]
    [DllImport("__DLLPATH__", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool GetCurrentPlxByMSR(out uint pl1, out uint pl2);
    [return: MarshalAs(UnmanagedType.I1)]
    [DllImport("__DLLPATH__", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool GetCurrentPlxByMMIO(out uint pl1, out uint pl2);
    [DllImport("__DLLPATH__", CallingConvention = CallingConvention.Cdecl)]
    public static extern void GetCpuPower(out ulong pow64);
    [return: MarshalAs(UnmanagedType.I1)]
    [DllImport("__DLLPATH__", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool ReadIntelMsrReg(uint msr, out ulong value);
    [return: MarshalAs(UnmanagedType.I1)]
    [DllImport("__DLLPATH__", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool ReadIntelMMIO(uint offset, out ulong value);
}
'@
        $src = $src.Replace('__DLLPATH__', $dllPath.Replace('\','\\'))
        try { Add-Type -TypeDefinition $src -ErrorAction Stop; $script:Os2 = $true }
        catch { Say "[OS2SOC] Add-Type 失败: $($_.Exception.Message)" }
    } else {
        Say "[OS2SOC] 本目录无 OS2SOCService.dll, 跳过驱动读数 (把原厂 DLL 拷到脚本目录)"
    }
    if ($script:Os2 -and -not $svc) { Say "[OS2SOC] 注意: 未注册 OS2SOC 服务, 首次调用将尝试安装" }
    Say "[OS2SOC] 若打印 'The driver path incorrect': 按打印出的路径原样建目录并拷入 OS2SOC.sys (管理员)。该检查是文件存在性门; 服务若已注册, 拷贝的 sys 仅作凭证不会被内核加载"
}
function Read-Os2Block {
    $o = @{}
    if (-not $script:Os2) { return $o }
    try {
        $pl1=[uint32]0; $pl2=[uint32]0
        if ([Os2Soc]::GetCurrentPlxByMSR([ref]$pl1, [ref]$pl2)) { $o.plxMsr = @([int]$pl1, [int]$pl2) }
        $pl1=[uint32]0; $pl2=[uint32]0
        if ([Os2Soc]::GetCurrentPlxByMMIO([ref]$pl1, [ref]$pl2)) { $o.plxMmio = @([int]$pl1, [int]$pl2) }
        $pwr=[uint64]0; [Os2Soc]::GetCpuPower([ref]$pwr)
        $o.cpuPowRaw = $pwr
        $o.cpuPowDouble = [BitConverter]::ToDouble([BitConverter]::GetBytes($pwr), 0)
        $o.cpuPowU32 = @(($pwr -band 0xFFFFFFFF), ($pwr -shr 32))
        $msrs = [ordered]@{ 'PKG_POWER_LIMIT(610)'=0x610; 'PKG_ENERGY(611)'=0x611; 'PKG_POWER_INFO(614)'=0x614; 'PPM_POLICY(355)'=0x355; 'HWP_CAP(771)'=0x771; 'HWP_REQ_PKG(772)'=0x772; 'HWP_REQ(774)'=0x774 }
        $o.msr = [ordered]@{}
        foreach ($k in $msrs.Keys) {
            $v = [uint64]0
            if ([Os2Soc]::ReadIntelMsrReg([uint32]$msrs[$k], [ref]$v)) { $o.msr[$k] = $v } else { $o.msr[$k] = $null }
        }
    } catch { $o.os2Err = "$($_.Exception.Message) (LastWin32Error=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
    return $o
}

# ============ 3) MSR 字段解码 (SDM 客户端布局; 标记为启发式, 与实测对照) ============
function Decode-Msr([string]$name, [Nullable[uint64]]$v) {
    if ($null -eq $v) { return "$name = <不可读>" }
    switch -regex ($name) {
        '610' {
            $pl1w = (($v -band 0x7FFF) / 8.0)
            $pl1en = [bool](($v -shr 15) -band 1)
            $clamp = (($v -shr 16) -band 0x3F)
            $win = (($v -shr 24) -band 0x7F)
            $pl2w = ((($v -shr 37) -band 0x1FF) / 8.0)
            $pl2en = [bool](($v -shr 46) -band 1)
            return "610: PL1={0:N2}W(en={1}) win={2} clamp={3} PL2={4:N2}W(en={5})  raw=0x{6:X16}" -f $pl1w,$pl1en,$win,$clamp,$pl2w,$pl2en,$v
        }
        '614' {
            $spec=(($v -band 0x7FF)/8.0); $min=(((($v -shr 16)) -band 0x7FF)/8.0); $max=(((($v -shr 32)) -band 0x7FF)/8.0)
            return "614: ThermalSpec={0}W Min={1}W Max={2}W  raw=0x{3:X16}" -f $spec,$min,$max,$v
        }
        '771' {
            return "771 HWP_CAP: highest={0} guaranteed={1} nominal={2} lowest={3} (x100MHz)" -f ($v -band 0xFF),(($v -shr 8) -band 0xFF),(($v -shr 16) -band 0xFF),(($v -shr 24) -band 0xFF)
        }
        '772|774' {
            $max=($v -band 0xFF); $min=($v -shr 8 -band 0xFF); $des=($v -shr 16 -band 0xFF); $epp=($v -shr 24 -band 0xFF)
            $noTurbo=[bool]($v -shr 35 -band 1)
            $en = ($v -shr 32 -band 7)
            return "$($name): max={0} min={1} desired={2} EPP={3} enMask={4} noTurbo={5}  raw=0x{6:X16}" -f $max,$min,$des,$epp,$en,$noTurbo,$v
        }
        '355' {
            $plr=($v -band 0xFF)/4.0; $pl1=($v -shr 8 -band 0x7F)/4.0; $pl2=($v -shr 15 -band 0x7F)/4.0
            return "355 PPM_POLICY: PLR={0}% PL1={1}% PL2={2}%" -f $plr,$pl1,$pl2
        }
        default { return "$name = 0x{0:X16}" -f $v }
    }
}

# ============ 4) NVAPI GPU 功耗/DB 读数 (只读) ============
try {
    $nvasrc = @'
using System;
using System.Runtime.InteropServices;
public static class NvProbe {
    [DllImport("nvapi64.dll")] public static extern int NvAPI_Initialize();
    [DllImport("nvapi64.dll")] public static extern int NvAPI_EnumNvidiaDisplayHandle(int enumIndex, out IntPtr h);
    [DllImport("nvapi64.dll", EntryPoint="NvAPI_GPU_GetPhysicalGPUsFromDisplay")] public static extern int GetPhysFromDisp(IntPtr disp, out IntPtr physArray, ref uint count);
    [DllImport("nvapi64.dll", EntryPoint="NvAPI_GPU_GetAssociatedSystemType")] public static extern int GetGpuType(IntPtr phys, ref uint type, ref uint ibase);
    [DllImport("nvapi64.dll", EntryPoint="NvAPI_GPU_GetDynamicPStatesInfo")] public static extern int GetDynInfo(IntPtr phys, IntPtr pInfo);
    public static string NV_GPU_NAMES(int r) { return r.ToString(); }
}
'@
    Add-Type -TypeDefinition $nvasrc -ErrorAction Stop
    $script:NvOk = ($([NvProbe]::NvAPI_Initialize()) -eq 0)
} catch { $script:NvOk = $false; Say "[NVAPI] 加载失败: $($_.Exception.Message)" }
function Read-NvBlock {
    $o = @{}
    if ($script:NvOk) {
        try {
            $handles = @()
            for ($i=0; $i -lt 16; $i++) {
                $h = [IntPtr]::Zero
                if ([NvProbe]::NvAPI_EnumNvidiaDisplayHandle($i, [ref]$h) -ne 0) { break }
                $handles += $h
            }
            $physSeen = @{}
            $idx = 0
            foreach ($dh in $handles) {
                $cnt = [uint32]32; $pa = [IntPtr]::Zero
                if ([NvProbe]::GetPhysFromDisp($dh, [ref]$pa, [ref]$cnt) -ne 0) { continue }
                for ($j=0; $j -lt [int]$cnt; $j++) {
                    $pg = [Runtime.InteropServices.Marshal]::ReadIntPtr($pa, ($j*[IntPtr]::Size))
                    if ($null -eq $pg -or $physSeen.ContainsKey($pg)) { continue }
                    $physSeen[$pg] = $true
                    $info = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
                    try {
                        $best = $null
                        foreach ($ver in @(1,2)) {
                            $buf = New-Object byte[] 64
                            [BitConverter]::GetBytes([int](($ver -shl 16) -bor 40)).CopyTo($buf, 0)
                            [Runtime.InteropServices.Marshal]::Copy($buf, 0, $info, 64)
                            $rr = [NvProbe]::GetDynInfo($pg, $info)
                            if ($rr -eq 0) { $best = $ver; break }
                        }
                        if ($null -ne $best) {
                            $pow = [Runtime.InteropServices.Marshal]::ReadInt64($info, 24)
                            $cap = [Runtime.InteropServices.Marshal]::ReadInt64($info, 32)
                            $o["gpu$idx"] = [pscustomobject]@{ v=$best; power_mW=$pow; limit_mW=$cap }
                        }
                        $idx++
                    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($info) }
                }
            }
        } catch { $o.nvErr = $_.Exception.Message }
    }
    if ($o.Count -eq 0) {
        # nvidia-smi 回退 (循环内权威 GPU 读数; 行格式 "idx, drawW, limitW|N/A, pstate")
        try {
            $q = (& nvidia-smi --query-gpu=index,power.draw,power.limit,pstate --format=csv,nounits,noheader 2>$null)
            if ($q) {
                $gi = 0
                foreach ($ln in $q) {
                    $p = @($ln -split ',')
                    $pw = $null; $cap = $null
                    if ($p.Count -ge 2 -and $p[1].Trim() -match '^[\d.]+$') { $pw = [int]([double]$p[1].Trim()*1000) }
                    if ($p.Count -ge 3 -and $p[2].Trim() -match '^[\d.]+$') { $cap = [int]([double]$p[2].Trim()*1000) }
                    $o["gpu$gi"] = [pscustomobject]@{ v='smi'; power_mW=$pw; limit_mW=$cap; state=$(if ($p.Count -ge 4) { $p[3].Trim() } else { '' }) }
                    $gi++
                }
            }
        } catch { }
    }
    return $o
}
function Nv-SmiFallback {
    $smi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if (-not $smi) { return $null }
    try { (& nvidia-smi --query-gpu=power.draw,power.limit --format=csv,nounits,noheader 2>$null) } catch { $null }
}

# ============ 5) OS 策略侧只读信息 ============
function Read-OsBlock {
    $o = @{}
    try {
        $tmp = (& powercfg /getactivescheme) -join ' '
        if ($tmp -match '([0-9a-f-]{36}).*\((.+)\)') { $o.scheme = "$($matches[2]) $($matches[1].Substring(0,8))" }
        $o.subproc = @(& powercfg /q SUB_PROCESSOR 2>$null)
    } catch {}
    $o.svcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'OS2SOC|intel|dtt|ipf|nvcontainer|nvdisplay|MBA' } | ForEach-Object { "$($_.Status) $($_.Name)" })
    $o.procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'nvcontainer|PCCli|PCManager|MBA|Intel' } | ForEach-Object { "$($_.Id) $($_.Name)" })
    $o.reg = @()
    try { Get-ItemProperty 'HKLM:\SOFTWARE\PCManager\MBAPowerManager' -ErrorAction Stop | Select-Object * -ExcludeProperty PS* | ForEach-Object { $_.PSObject.Properties } | ForEach-Object { $o.reg += "HKLM MBAPowerManager\$($_.Name)=$($_.Value)" } } catch { $o.reg += "HKLM MBAPowerManager: $($_.Exception.Message)" }
    try { Get-ItemProperty 'Registry::HKEY_USERS\.DEFAULT\Software\HONOR\PCManager\Performance' -ErrorAction Stop | Select-Object * -ExcludeProperty PS* | ForEach-Object { $_.PSObject.Properties } | ForEach-Object { $o.reg += "\.DEFAULT Performance\$($_.Name)=$($_.Value)" } } catch { $o.reg += "\.DEFAULT Performance: $($_.Exception.Message)" }
    return $o
}

# ============ 6) 能量计数器 -> 实际封装功率 ============
$script:prevEnergy = $null; $script:prevTime = $null
function PkgWatts([Nullable[uint64]]$e64) {
    if ($null -eq $e64) { return $null }
    $e = [uint32]($e64 -band 0xFFFFFFFF)   # 32bit J = 61.035uJ
    $now = Get-Date
    $w = $null
    if ($null -ne $script:prevEnergy) {
        $de = if ($e -ge $script:prevEnergy) { $e - $script:prevEnergy } else { ([uint32]([double]4294967296 + $e - $script:prevEnergy)) }
        $dt = ($now - $script:prevTime).TotalSeconds
        if ($dt -gt 0.05) { $w = [math]::Round(($de * 61.03515625 / 1000000.0) / $dt, 2) }
    }
    $script:prevEnergy = $e; $script:prevTime = $now
    return $w
}

# ============ 5b) 电池/适配器 (v1.0.5: 验证电池补电/充电挤占) ============
function Read-Batt {
    $o = @{}
    try {
        $b = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop
        $o.pct  = $b.EstimatedChargeRemaining
        $o.rate = $b.ChargeRate          # A; 正=充电, 负=电池对外供电(补电实锤)
        $o.stat = $b.BatteryStatus       # 1未充电/2已插电/3充电中/4低电...
        $o.watt = if ($null -ne $b.Voltage -and $null -ne $b.ChargeRate) { [math]::Round($b.Voltage * $b.ChargeRate / 1000000.0, 1) } else { '' }  # V(mV)*A/1e6
    } catch { $o.pct='';$o.rate='';$o.stat='';$o.watt='' }
    return $o
}

# ============ 主流程 ============
Say ("hn_power 只读探针  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "  host=$env:COMPUTERNAME")
if ($Loop) {
    if (-not (Test-Path $csv)) { "time,mode,PL1msr_W,PL2msr_W,PL1mmio_W,PL2mmio_W,cpuPowRaw,cpuPowW611,plxUnitNote,EPPreq,maxReq,gpu0mW,gpu0capmW,gpu1mW,gpu1capmW,fan0,fan1,cpuT,610raw,battPct,chgRateA,battW(+=充-=补),battStatus" | Set-Content -Path $csv -Encoding UTF8 }
    Write-Host "Ctrl+C 停止; 采样写入 $csv" -ForegroundColor Yellow
    while ($true) {
        $w = if ($NoWmi) { @{} } else { Read-WmiBlock }
        $s = Read-Os2Block
        $nv = Read-NvBlock
        $pkgW = PkgWatts $s.msr['PKG_ENERGY(611)']
        $e10 = $s.msr['PKG_POWER_LIMIT(610)']
        $pl1msr = if ($null -ne $e10) { [math]::Round((($e10 -band 0x7FFF)/8.0),2) } else { '' }
        $pl2msr = if ($null -ne $e10) { [math]::Round((($e10 -shr 37 -band 0x1FF)/8.0),2) } else { '' }
        $h774 = $s.msr['HWP_REQ(774)']
        $epp  = if ($null -ne $h774) { [int]($h774 -shr 24 -band 0xFF) } else { '' }
        $mreq = if ($null -ne $h774) { [int]($h774 -band 0xFF) } else { '' }
        $pl1m = if ($s.plxMmio) { $s.plxMmio[0] } else { '' }
        $pl2m = if ($s.plxMmio) { $s.plxMmio[1] } else { '' }
        $g0 = $nv['gpu0']; $g1 = $nv['gpu1']
        $bt = Read-Batt
        $line = (Get-Date -Format 'HH:mm:ss') + "," + $w.mode + "," + $pl1msr + "," + $pl2msr + "," + $pl1m + "," + $pl2m + "," + $s.cpuPowRaw + "," + $pkgW + ",plxU=$($s.plxMsr[0])/$($s.plxMsr[1])," + $epp + "," + $mreq + "," + $(if($g0){$g0.power_mW}else{''}) + "," + $(if($g0){$g0.limit_mW}else{''}) + "," + $(if($g1){$g1.power_mW}else{''}) + "," + $(if($g1){$g1.limit_mW}else{''}) + "," + $w.fan0 + "," + $w.fan1 + "," + $w.cpuT + "," + $(if ($null -ne $e10) { '0x{0:X16}' -f $e10 } else { '' }) + "," + $bt.pct + "," + $bt.rate + "," + $bt.watt + "," + $bt.stat
        $line | Add-Content -Path $csv -Encoding UTF8
        Write-Host $line
        Start-Sleep -Seconds $IntervalSec
    }
    exit
}

# --- 一次性全量 ---
if (-not $NoWmi) {
    Say "`n===== [1] WMI 传感器 ====="
    $w = Read-WmiBlock
    if ($w.wmiErr) { Say "WMI 错误: $($w.wmiErr)" } else {
        Say ("电源模式      : {0} ({1})" -f $w.mode, $modeName[[int]$w.mode])
        Say ("温度 CPU(00)  : $($w.cpuT) C   zone0E: $($w.zone0E) C")
        Say ("风扇0         : 实际 $($w.fan0) / 目标 $($w.fan0tgt) RPM")
        Say ("风扇1         : 实际 $($w.fan1) / 目标 $($w.fan1tgt) RPM")
        Say ("噪声档读取(02 0C): $($w.noiseRead)  [语义待确认]")
    }
}
if (-not $NoOs2Soc) {
    Say "`n===== [2] OS2SOC 驱动读数 (只读) ====="
    $s = Read-Os2Block
    if ($s.os2Err) { Say "OS2SOC 调用失败: $($s.os2Err)" }
    if ($s.plxMsr)  { Say ("GetCurrentPlxByMSR  : pl1=$($s.plxMsr[0]) pl2=$($s.plxMsr[1])  [单位/编码待与610对照]" ) }
    if ($s.plxMmio) { Say ("GetCurrentPlxByMMIO : pl1=$($s.plxMmio[0]) pl2=$($s.plxMmio[1])" ) }
    if ($null -ne $s.cpuPowRaw) { Say ("GetCpuPower raw=0x{0:X16} 作为double={1:N2} 作为u32对={2},{3}" -f $s.cpuPowRaw, $s.cpuPowDouble, $s.cpuPowU32[0], $s.cpuPowU32[1]) }
    if ($s.msr) {
        Say "---- MSR (SDM 布局启发式解码, 待对照) ----"
        foreach ($k in $s.msr.Keys) { Say ("  " + (Decode-Msr $k $s.msr[$k])) }
        $null = PkgWatts $s.msr['PKG_ENERGY(611)']
        Start-Sleep -Milliseconds 800
        $v = [uint64]0
        if ($script:Os2 -and [Os2Soc]::ReadIntelMsrReg(0x611, [ref]$v)) {
            $pw = PkgWatts $v
            if ($null -ne $pw) { Say "  MSR611 能量计数器差分 => 实际封装功率 ≈ $pw W" }
        }
    }
}
Say "`n===== [3] NVAPI GPU (只读) ====="
$nv = Read-NvBlock
if ($nv.nvErr) { Say "NVAPI 错误: $($nv.nvErr)" }
$anyGpu = $false
foreach ($k in @('gpu0','gpu1')) {
    $g = $nv[$k]
    if ($null -ne $g) { $anyGpu = $true
        if ($null -ne $g.v) { Say ("  {0}: GetDynamicPStatesInfo v{1}: power={2} mW  limit={3} mW" -f $k, $g.v, $g.power_mW, $g.limit_mW) }
        else { Say ("  {0}: GetDynamicPStatesInfo 不支持/非活动" -f $k) }
    }
}
$smi = Nv-SmiFallback
if ($smi) { Say "  nvidia-smi: $($smi -join ' | ')" }
if (-not $anyGpu -and -not $smi) { Say "  (无 GPU 读数)" }
Say "`n===== [4] OS 策略侧 ====="
$o = Read-OsBlock
Say ("当前电源方案: " + $o.scheme)
$pp = @(); foreach ($l in $o.subproc) { if ($l -match '名称|Name|GUID|Alias|当前|Current|设置|Setting|分钟|分钟|Percent|percent' ) { $pp += $l.Trim() } }
$pp | Select-Object -First 120 | ForEach-Object { Say "  $_" }
Say ("相关服务: " + ($o.svcs -join '; '))
Say ("相关进程: " + ($o.procs -join '; '))
$o.reg | ForEach-Object { Say "  $_" }
Say "--- 电池/适配器 ---"
$bt = Read-Batt
if ($bt.pct -ne '') { Say ("  电量={0}%  ChargeRate={1}A  电池功率={2}W (正=正在充电,负=电池对外补电)  状态={3}" -f $bt.pct,$bt.rate,$bt.watt,$bt.stat) } else { Say "  (无电池读数)" }
$outLines | Set-Content -Path $report -Encoding UTF8
Write-Host "`n报告已保存: $report" -ForegroundColor Green
