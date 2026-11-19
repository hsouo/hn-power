# hn_wmi.ps1 v3 — 荣耀 BIOS WMI (OemWMIMethod) 控制工具
# v3: 新增原厂功耗再分配动作 setwatt/setgpu2cpu/setratio/raw2（来自 HNSDK.dll 逆向，
#     命令 03 17 / 03 0F，参数值域=原厂 UI 同款校验）。**写动作必须带 -Yes 才执行。**
# v2: Invoke-CimMethod + OemWMIfunEx(u64Input) 回退（兼容 PS5.1）。
# 用法：在荣耀笔记本上【以管理员身份】运行 PowerShell：
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\hn_wmi.ps1 status               # 读：模式/风扇/温度/电池阈值/背光（不变）
#   .\hn_wmi.ps1 setmode 1            # 0=智能 1=高性能 3=猎人（实机已验证）
#   .\hn_wmi.ps1 setwatt 105 87 100 -Yes   # GPU TGP=105W 温度墙87℃ TCP=100（需确认，实验）
#   .\hn_wmi.ps1 setgpu2cpu 300 -Yes       # GPU→CPU 最大供电档位(100/200/300/400/500)（实验）
#   .\hn_wmi.ps1 setratio 30 -Yes          # CPU/GPU 偏置 ratio（值域未定，谨慎）（实验）
#   .\hn_wmi.ps1 raw2 03 17 FF 69 57 64    # 任意字节序列（十六进制）
#   .\hn_wmi.ps1 events | grant | raw <g> <c> [v]
# 命令编码: u8Input[64] = 字节序列；应答 u8Output[0]==0 成功
# 恢复出厂默认：重启电脑（EC 侧 TGP 档位重启复位为默认协商值——此前 nvidia-smi 观察证实）

param(
    [Parameter(Position=0)][string]$Action = "status",
    [Parameter(Position=1)][string]$A1,
    [Parameter(Position=2)][string]$A2,
    [Parameter(Position=3)][string]$A3,
    [Parameter(Position=4)][string]$A4,
    [switch]$Yes
)

$script:HwmiInst = $null

function Get-HwmiInstance {
    if ($script:HwmiInst) { return $script:HwmiInst }
    $insts = @(Get-CimInstance -Namespace root/wmi -ClassName OemWMIMethod -ErrorAction Stop)
    if ($insts.Count -eq 0) { throw 'root\wmi 里没有 OemWMIMethod 实例（需管理员 / BIOS 不支持）' }
    $pref = $null
    $want = if ($env:HNWMI_INSTANCE) { $env:HNWMI_INSTANCE } else { 'HWMI_0$' }
    foreach ($i in $insts) { if ("$($i.InstanceName)" -match $want) { $pref = $i; break } }
    if (-not $pref) { $pref = $insts[0] }
    $script:HwmiInst = $pref
    return $pref
}

function Invoke-HwmiBytes([byte[]]$payload) {
    $inst = Get-HwmiInstance
    $in = New-Object byte[] 64
    [Array]::Copy($payload, 0, $in, 0, [Math]::Min($payload.Count, 64))
    $r = $null
    try {
        $r = Invoke-CimMethod -InputObject $inst -MethodName 'OemWMIfun' -Arguments @{ u8Input = [byte[]]$in } -ErrorAction Stop
    } catch {
        if ($payload.Count -ge 3 -and $payload.Count -le 5) {
            # 回退：OemWMIfunEx 走 u64Input（组|命令<<8|值<<16|byte3<<24）
            $u = [uint64]$payload[0]
            $u = $u -bor ([uint64]$payload[1] -shl 8)
            if ($payload.Count -ge 3) { $u = $u -bor ([uint64]$payload[2] -shl 16) }
            if ($payload.Count -ge 4) { $u = $u -bor ([uint64]$payload[3] -shl 24) }
            $r = Invoke-CimMethod -InputObject $inst -MethodName 'OemWMIfunEx' -Arguments @{ u64Input = $u } -ErrorAction Stop
        } else { throw }
    }
    if ($null -eq $r) { return $null }
    $outp = $r.u8Output
    if ($null -eq $outp) { return $null }
    $resp = @($outp)
    $b = New-Object byte[] $resp.Count
    for ($i = 0; $i -lt $resp.Count; $i++) { $b[$i] = [byte]$resp[$i] }
    return ,$b
}

function Invoke-Hwmi([byte]$group, [byte]$cmd, [byte]$val = 0) {
    return Invoke-HwmiBytes ([byte[]]@($group, $cmd, $val))
}

function Show-Resp([byte[]]$resp, [string]$label) {
    if ($null -eq $resp -or $resp.Count -eq 0) { Write-Host ("{0,-40} 无应答（方法返回里没有 u8Output？试试 raw 走 Ex 通道）" -f $label); return }
    $hex = ($resp | ForEach-Object { $_.ToString('X2') }) -join ' '
    if ($resp[0] -eq 0) { $ok = 'OK' } else { $ok = "FAIL(code=$($resp[0]))" }
    Write-Host ("{0,-40} {1} [{2}]" -f $label, $ok, $hex)
}

function Guard-Write([string]$desc) {
    if (-not $Yes) {
        Write-Host ("[需要确认] 这是功耗写入实验: {0}`n         核对参数后追加 -Yes 运行。恢复方法=重启。" -f $desc)
        exit 3
    }
}

switch ($Action) {
    'status' {
        $inst = Get-HwmiInstance
        Write-Host ("实例: {0}" -f $inst.InstanceName)
        $m = Invoke-Hwmi 0x04 0x0E
        if ($m -and $m[0] -eq 0 -and $m.Count -gt 1) {
            $modeName = @{0='智能/均衡';1='高性能';3='猎人(HUNTER)'}[[int]$m[1]]
            if (-not $modeName) { $modeName = "未知($($m[1]))" }
            Write-Host ("电源模式: {0}" -f $modeName)
        } else { Show-Resp $m '电源模式读取(04 0E)' }
        foreach ($z in 0x00, 0x0E) { Show-Resp (Invoke-Hwmi 0x02 0x02 $z) "温度 zone 0x$($z.ToString('X2')) (resp[2])" }
        foreach ($f in 0, 1)       { Show-Resp (Invoke-Hwmi 0x02 0x08 $f) "风扇 $f (resp[1..2]=实际 resp[3..4]=目标)" }
        Show-Resp (Invoke-Hwmi 0x03 0x11) '电池充电阈值 start/end'
        Show-Resp (Invoke-Hwmi 0x06 0x13) '键盘背光 (2灭 3低 4高)'
    }
    'setmode' {
        if ($A1 -notin '0','1','3') { throw 'mode 只能是 0(智能/退出性能) / 1(高性能) / 3(猎人)' }
        Show-Resp (Invoke-Hwmi 0x04 0x0F ([byte][int]$A1)) "设置电源模式=$A1"
    }
    'setwatt' {
        # HNSDK_SetGPUWattData(watt,temp,tcp): 03 17 FF watt temp tcp；原厂校验 watt60-115 temp75-87 tcp30-160
        if (-not $A1 -or -not $A2 -or -not $A3) { throw '用法: setwatt <watt 60-115> <temp 75-87> <tcp 30-160> -Yes' }
        $w=[int]$A1; $t=[int]$A2; $c=[int]$A3
        if ($w -lt 60 -or $w -gt 115) { throw "watt 必须 60..115（原厂校验域）" }
        if ($t -lt 75 -or $t -gt 87)  { throw "temp 必须 75..87" }
        if ($c -lt 30 -or $c -gt 160) { throw "tcp 必须 30..160" }
        Guard-Write ("GPU TGP=03 17 FF {0:X2} {1:X2} {2:X2} (watt={0} temp={1} tcp={2})" -f $w,$t,$c)
        Show-Resp (Invoke-HwmiBytes ([byte[]]@(0x03,0x17,0xFF,$w,$t,$c))) "SetGPUWatt watt=$w temp=$t tcp=$c"
    }
    'setgpu2cpu' {
        # HNSDK_SetGPUToCPUMaxPower: idx=W/100+6 (7..11)，报文 03 17 FF idx（byte4/5=0 与 setwatt 区分）
        if (-not $A1) { throw '用法: setgpu2cpu <100|200|300|400|500> -Yes' }
        $w=[int]$A1
        if ($w -notin 100,200,300,400,500) { throw '只接受 100/200/300/400/500（原厂步进阶梯）' }
        $idx=[byte]($w/100 + 6)
        Guard-Write ("GPU→CPU 最大供电档 03 17 FF {0:X2} (= {1}W 档)" -f $idx,$w)
        Show-Resp (Invoke-HwmiBytes ([byte[]]@(0x03,0x17,0xFF,$idx))) "SetGPUToCPUMaxPower=$w"
    }
    'setratio' {
        # HNSDK_SetCpuGpuRatio: 03 0F ratio 05；ratio 语义未定（0..255 原始值）
        if ($A1 -eq $null -or $A1 -eq '') { throw '用法: setratio <0-255> -Yes  （语义未定，先小步）' }
        $r=[int]$A1
        if ($r -lt 0 -or $r -gt 255) { throw 'ratio 0..255' }
        Guard-Write ("CPU/GPU 偏置 03 0F {0:X2} 05（ratio 语义未定，建议 0/10/20 小步试）" -f $r)
        Show-Resp (Invoke-HwmiBytes ([byte[]]@(0x03,0x0F,[byte]$r,0x05))) "SetCpuGpuRatio=$r"
    }
    'raw2' {
        $hexs = @($A1,$A2,$A3,$A4) | Where-Object { $_ }
        if ($hexs.Count -lt 2) { throw 'raw2 <b1> <b2> [...] 十六进制，例: raw2 03 17 FF 69 57 64' }
        $bs = [byte[]]($hexs | ForEach-Object { [convert]::ToInt32($_,16) })
        if ($bs[0] -eq 0x04 -and $bs[1] -eq 0x0E) { Show-Resp (Invoke-HwmiBytes $bs) 'raw2 (read)'; break }
        Guard-Write ("任意写 0x" + (($bs | ForEach-Object { $_.ToString('X2') }) -join ' '))
        Show-Resp (Invoke-HwmiBytes $bs) 'raw2'
    }
    'setnoise' {
        if ($A1 -notin '1','2','3') { throw 'noise 1..3（NoiseEventDealer 三档，报文 value=档-1）' }
        Show-Resp (Invoke-Hwmi 0x07 0x0C ([byte]([int]$A1 - 1))) "设置静音/噪音模式 档=$A1"
    }
    'events' {
        Write-Host '监听 OemWMIEvent 中（Ctrl+C 退出）——按 Fn+P 或切换模式试试'
        $null = Register-CimIndicationEvent -Namespace root\wmi -Query 'SELECT * FROM OemWMIEvent' -Action {
            $f = $Event.SourceEventArgs.NewEvent.Force
            $codes = @{0x2A0='退出高性能';0x2A1='进入高性能';0x2A6='热键切换(Fn+P)';0x2A8='猎人模式';0x287='麦克风静音键';0x288='摄像头键';0x2B1='背光灭';0x2B2='背光低';0x2B3='背光高'}
            $desc = $codes[[int]$f]
            if (-not $desc) { $desc = '' }
            Write-Host ("[{0}] Force=0x{1:X} {2}" -f (Get-Date -Format HH:mm:ss), $f, $desc)
        }
        while ($true) { Start-Sleep 1 }
    }
    'raw' {
        if (-not $A1 -or -not $A2) { throw 'raw <group> <cmd> [val]，例如: raw 04 0E' }
        $gv = [byte][convert]::ToInt32($A1,16)
        $cv = [byte][convert]::ToInt32($A2,16)
        $vv = 0
        if ($A3) { $vv = [byte][convert]::ToInt32($A3,0) }
        Show-Resp (Invoke-Hwmi $gv $cv $vv) "raw group=$A1 cmd=$A2 val=$A3"
    }
    'grant' {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security'
        $guid = '{abbc0f5b-8ea1-11d1-a000-c90629100000}'
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:(A;;0x1fffff;;;SY)(A;;0x1fffff;;;BA)(A;;0x2001f;;;$sid)")
        $bin = New-Object byte[] $sd.BinaryLength
        $sd.GetBinaryForm($bin, 0)
        Set-ItemProperty -Path $key -Name $guid -Value $bin -Type Binary
        Write-Host '已授权当前用户调用 OemWMIMethod (0x2001f)。恢复默认：删除该注册表值。'
    }
    default { Write-Host '动作: status | setmode | setwatt | setgpu2cpu | setratio | raw2 | setnoise | events | raw <g> <c> [v] | grant（写动作需 -Yes）' }
}
