# hn_epp.ps1 v1.0 — HWP Request Min/Max（0x774 [7:0]/[15:8]）逐核读改工具（经原厂 OS2SOC 驱动，非 WinRing0）
# 用法（管理员，脚本旁需有 OS2SOCService.dll；OS2SOC 驱动服务在笔记本已注册, DLL 会自动确保其运行）:
#   .\hn_epp.ps1 show                      # 只读: 逐核 0x770/0x771/0x772/0x773/0x774 解码
#   .\hn_epp.ps1 set 57 57 -Yes            # 写: 每核 0x774 min=57 max=57 (EPP/desired 位原样保留), 写前自动备份+写后回读
#   .\hn_epp.ps1 set 4 57 -Yes             # 恢复 TS 截图初始态
#   .\hn_epp.ps1 restore -Yes              # 按最近备份文件逐核写回
#   .\hn_epp.ps1 watch                     # 每2秒轮询 show 摘要(Ctrl+C 退出), 双烤时观察 OS/PEP 是否回头改写
# 恢复手段: ① restore ② 重启(MSR 复位到固件默认) ③ TS 写回。风险: HWP min 抬高→待机温度/风扇上升; 不改电压/频率上限, 不碰 PL/EC/BIOS。
param(
    [Parameter(Position=0)][string]$Action = 'show',
    [Parameter(Position=1)][int]$Min = -1,
    [Parameter(Position=2)][int]$Max = -1,
    [switch]$Yes
)
$ErrorActionPreference = 'Stop'
# ---------- 定位 DLL ----------
$dll = Join-Path $PSScriptRoot 'OS2SOCService.dll'
if (-not (Test-Path $dll)) { throw '本脚本旁需要 OS2SOCService.dll（与 hn_power.ps1 同一份）' }
# ---------- P/Invoke ----------
if (-not ('HnEppNative' -as [type])) {
$src = @'
using System;
using System.Runtime.InteropServices;
public static class HnEppNative {
    [DllImport("__DLLPATH__", CallingConvention=CallingConvention.Cdecl)]
    public static extern bool ReadIntelMsrReg(uint msr, out ulong value);
    [DllImport("__DLLPATH__", CallingConvention=CallingConvention.Cdecl)]
    public static extern void WriteIntelMsrReg(uint msr, ulong value);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] public static extern UIntPtr SetThreadAffinityMask(IntPtr h, UIntPtr mask);
    [DllImport("kernel32.dll")] public static extern uint GetActiveProcessorCount(ushort group); // 0xFFFF=ALL
    [DllImport("kernel32.dll")] public static extern uint GetLogicalProcessorInformation2(byte[] buf, ref uint len);
}
'@
$src = $src.Replace('__DLLPATH__', $dll.Replace('\','\\'))   # PS 单引号 '\'=1字符→'\\'=2字符(C# 转义)
Add-Type -TypeDefinition $src -Language CSharp
}
# ---------- 逻辑核列表 ----------
$procCount = [Environment]::ProcessorCount
function Get-CoreRaw([int]$core, [uint32]$msr) {
    $null = [HnEppNative]::SetThreadAffinityMask([HnEppNative]::GetCurrentThread(), [UIntPtr]([uint64]1 -shl $core))
    $v = [uint64]0
    $ok = [HnEppNative]::ReadIntelMsrReg($msr, [ref]$v)
    return @{ ok = $ok; val = $v }
}
function Set-CoreRaw([int]$core, [uint32]$msr, [uint64]$v) {
    $null = [HnEppNative]::SetThreadAffinityMask([HnEppNative]::GetCurrentThread(), [UIntPtr]([uint64]1 -shl $core))
    [HnEppNative]::WriteIntelMsrReg($msr, $v)
}
function Decode774([uint64]$v) {
    [pscustomobject]@{
        min = [int](($v -band 0xFF))
        max = [int](($v -shr 8 -band 0xFF))
        desired = [int](($v -shr 16 -band 0xFF))
        epp = [int](($v -shr 24 -band 0xFF))
        eppValid = [bool](($v -shr 28 -band 0x1) -eq 1)   # bit28 des_override? bit31? 保守: EPP 无独立 enable(bit42/45 在 pkg)
    }
}
function Show-Core([int]$core, [switch]$Verbose2) {
    $r770 = Get-CoreRaw $core 0x770; $r774 = Get-CoreRaw $core 0x774; $r771 = Get-CoreRaw $core 0x771
    if (-not $r774.ok) { "core {0,-3} 读取失败(驱动未就绪?)" -f $core; return $null }
    $d = Decode774 $r774.val
    $cap = if ($r771.ok) { 'cap=0x{0:X2}' -f [int]($r771.val -band 0xFF) } else { 'cap=?' }
    $lock = if ($r770.ok -and (($r770.val -shr 1) -band 1)) { ' LOCKED!' } else { '' }
    $s = "core {0,-3} 774: min={1,-3} max={2,-3} des={3,-3} epp={4,-3} {5}{6}  [raw=0x{7:X16}]" -f $core, $d.min, $d.max, $d.desired, $d.epp, $cap, $lock, $r774.val
    Write-Host $s
    return @{ core=$core; raw774=$r774.val; d=$d }
}
switch ($Action) {
    'show' {
        "逻辑核数: $procCount   (HWP cfg 0x770 / CAP 0x771 / REQUEST 0x774)"
        $res = @()
        for ($i = 0; $i -lt $procCount; $i++) { $r = Show-Core $i; if ($r) { $res += $r } }
        if ($res.Count -eq 0) { throw '全部读取失败: 确认管理员 + OS2SOC 服务(sc query OS2SOC) + DLL 路径门' }
        $uniq = $res | ForEach-Object { ('min={0} max={1} epp={2}' -f $_.d.min, $_.d.max, $_.d.epp) } | Sort-Object -Unique
        '核间差异汇总: ' + ($uniq -join ' | ')
        if ($res[0].d.min -lt 8) { '提示: min 处于低位(默认) —— 双烤时 CPU 可被压到很低性能档; TS 的 57 即把此下限拉满' }
    }
    'set' {
        if ($Min -lt 0 -or $Max -lt 0) { throw 'set <min> <max> [-Yes]' }
        if ($Min -gt 255 -or $Max -gt 255) { throw 'min/max 必须 0..255' }
        if ($Min -gt $Max) { throw "min($Min) 不能大于 max($Max)" }
        if (-not $Yes) { Write-Host "写实验需 -Yes 明确确认(这是你批准过的 HWP min/max 写入; 恢复=restore 或重启)。本次未做任何修改。"; return }
        # 预检 lock + 备份
        $bak = Join-Path $PSScriptRoot ("epp_backup_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        'core,raw774' | Set-Content -Path $bak -Encoding ascii
        for ($i = 0; $i -lt $procCount; $i++) {
            $r = Get-CoreRaw $i 0x774
            if (-not $r.ok) { throw "core $i 读 0x774 失败, 中止(未写入任何核)" }
            $c770 = Get-CoreRaw $i 0x770
            if ($c770.ok -and (($c770.val -shr 1) -band 1)) { throw "core $i HWP LOCKED(0x770.bit1), 中止" }
            "$i,$($r.val)" | Add-Content -Path $bak -Encoding ascii
        }
        "备份写入: $bak"
        for ($i = 0; $i -lt $procCount; $i++) {
            $r = Get-CoreRaw $i 0x774
            $nv = ($r.val -band -bnot 0xFFFF) -bor ([uint64]$Min) -bor ([uint64]$Max -shl 8)
            Set-CoreRaw $i 0x774 $nv
            $rb = Get-CoreRaw $i 0x774
            $ok = (($rb.val -band 0xFFFF) -eq (($Min) -bor ($Max -shl 8)))
            'core {0,-3} 写 0x{1:X16} 回读 min={2} max={3} epp={4} {5}' -f $i, $rb.val, [int]($rb.val -band 0xFF), [int]($rb.val -shr 8 -band 0xFF), [int]($rb.val -shr 24 -band 0xFF), $(if ($ok) {'OK'} else {'回读不符!'})
        }
        '完成。watch 可观察 OS 是否回头改写; 双烤验证功耗分配变化; 恢复: .\hn_epp.ps1 restore -Yes 或重启。'
    }
    'restore' {
        if (-not $Yes) { Write-Host 'restore 需要 -Yes 确认。本次未做任何修改。'; return }
        $bak = Get-ChildItem (Join-Path $PSScriptRoot 'epp_backup_*.csv') -EA SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $bak) { throw '找不到 epp_backup_*.csv（或直接用重启恢复出厂默认）' }
        "使用备份: $($bak.Name)"
        Import-Csv $bak.FullName | ForEach-Object {
            Set-CoreRaw ([int]$_.core) 0x774 ([uint64]$_.raw774)
            $rb = Get-CoreRaw ([int]$_.core) 0x774
            'core {0} 回写 0x{1:X16} {2}' -f $_.core, $rb.val, $(if ($rb.val -eq [uint64]$_.raw774) {'OK'} else {'不符'})
        }
    }
    'watch' {
        while ($true) {
            $line = @()
            for ($i = 0; $i -lt [Math]::Min($procCount, 8); $i++) {
                $r = Get-CoreRaw $i 0x774
                if ($r.ok) { $d = Decode774 $r.val; $line += ('{0}:mn{1}/mx{2}/e{3}' -f $i, $d.min, $d.max, $d.epp) } else { $line += "$i`:ERR" }
            }
            '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), ($line -join ' ')
            Start-Sleep -Seconds 2
        }
    }
    default { '动作: show | set <min> <max> -Yes | restore -Yes | watch' }
}
