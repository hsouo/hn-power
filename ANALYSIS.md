# 荣耀电脑管家电源模块逆向分析报告

分析对象：`honor/` 下 9 个 DLL（x64, MSVC C++，均从荣耀笔记本 `PCManager\mainframe\Plugins` 拷出）。
分析工具：pefile + capstone 自写脚本（`tools/peinfo.py`、`strings.py`、`disas.py`、`xrefdis.py`、`ioctlscan.py`、`ipcscan.py`），产物在 `tools/` 与 `tools/strings/`。

---

## 1. 结论（TL;DR）

**文件找对了。** 这 9 个 DLL 就是电脑管家的电源/性能控制栈本体，删掉它们管家确实失去控制能力。你自己写程序**不需要依赖这些 DLL**，因为真正的控制出口只有三类，都可以直接对接：

| 控制出口 | 位置 | 你需要什么 |
|---|---|---|
| **OS2SOC.sys 内核驱动**（读写 MSR/MMIO：PL1/PL2 功耗墙、EPP、Intel MMIO、AMD SMN） | `PCManager\mainframe\Plugins\OS2SOC.sys` | **必须再去笔记本上把这个 .sys 拷出来**（协议已 100% 解码，见 §3） |
| **BIOS WMI 接口**（风扇模式/静音/猎人模式/传感器/屏幕亮度请求） | 系统自带 `ROOT\WMI` → `OemWMI` 类，实例 `ACPI\PNP0C14\HWMI_0` | 不需要任何文件，PowerShell/C# 可直接调；**具体功能 ID 需在笔记本上抓一次**（见 §5） |
| **Windows 标准电源 API**（电源计划、亮度、睡眠超时等） | `POWRPROF.dll` 系统自带 | 直接调 `PowerWriteACValueIndex`/`PowerSetActiveScheme` 等 |

DLL 本身只是管家的**插件**（由 `MBAPluginsManager.dll` 插件框架加载，通过 `IPCMessage.dll` 总线和 UI 通信）。控制逻辑的"翻译层"价值已全部提炼进本报告。

---

## 2. 九个模块的分工

| 模块 | 大小 | 角色 |
|---|---|---|
| **PowerPolicyPlugin.dll** | 1.29M | 核心执行器：省电策略执行（`PowerPolicyExecutor::ExcutePowerPolicy`）、亮度（`SetMonitorBright` 用 PowerWriteAC/DCValueIndex + PowerSetActiveScheme）、杀/冻结进程、限 CPU 核数、`SetPowerLimit2`；加载 `\plugins\OS2SOCService.dll` 读写 PLX；内含 WMI 封装（`WMIInterface`、`VstInterface` 皮肤温度 WVST/GVNT）；`ctl*` 系列是 Intel GPU 控制库（`ControlLib%s.dll` 动态加载，`ctlPowerSetLimits`/`ctlFanSetSpeedTableMode`/`ctlOverclock*`）的转发 |
| **PerfCommonPlugin.dll** | 440K | **静音/性能/猎人模式就在这里**：`TurboMode.cpp`（`SetFanSpeed`、`CheckTurboModeStatus`、`OnUXQueryModeMessage`(IPC)、`StartMonitorTurboSwitch`、OemWMIEvent 回调"Callback Turbo Mode Changed,eventID="、`LoadHunterConfig`/`LoadFanSpeedConfig`）；`NoiseEventDealer::SetNoiseMode(int)`（噪音/静音模式）；`PowerSchemeFunction::InitPowerModeNotify`（Windows 电源模式通知→"Switch to balanced mode"）；EPP IPC 处理（"GetEpp recv msg failed"）；设备接口 GUID 枚举（`CM_Get_Device_Interface_List`，GUID `5EA0721E-9A8C-4281-B683-ED1B0E240D10`） |
| **OS2SOCService.dll** | 159K | **OS2SOC.sys 的用户态封装**，14 个 C 导出（见 §3），自动安装/启动驱动服务 |
| **MonPowerPlugin.dll** | 76K | 固件属性监控：`GetOriginPL1/PL2`、`GetCpuPower`、`GetPSysPower`、`GetPowerLimitScale`、`GetCpuTemperature`；`BiosWmi` + `StartCatchOemEvent`（WMI 事件回调 `GetWmiEventIDCallback`）；开盖开机/系统恢复设置 |
| **MonSysStatePlugin.dll** | 129K | 系统状态机：`RegisterPowerSettingNotification`、电源/电池/合盖状态汇总（`GetCurSysState`）广播 |
| **MonSysPerfPlugin.dll** | 430K | ETW + PDH 性能采样，JSON 上报含 "PL1"/"PL2" |
| **MonProcessPlugin.dll** | 102K | 进程 CPU 占用枚举 |
| **PerformanceDetectPlugin.dll** | 1.49M | 机型适配矩阵（`ProductAdapt`：GetEppSettingStatus/GetCpuPowerStatus…）、省电优化（会 `ChangeServiceConfigW`/`ControlService` 改 Windows 服务）、`DisplayConfigSetDeviceInfo` 改刷新率；"setepp"/"energystar" 只是配置 map 的键名（已反汇编确认，0x180007150） |
| **BlackMagic.dll** | 32K | **与电源无关**。管家主服务的 RPC 客户端（连 `OSDStaticRpcEndpoint`，NdrClientCall3），导出 BMStartProcess/BMRead·WriteRegistryValue/BMSetCamera/BMDataReport，是提权执行辅助库 |

机型代号出现在字符串中：GalileoF/N/G、HiggsF/E（Intel/AMD 平台族）。源路径 `D:\CDE_Patch9.0\workspace\common_compile\src\increment\sourcecode\PCManager\feature\PowerManager\...`。

各插件的 IPC 消息 ID **不是硬编码**（扫描无立即数），配置在 `mainframe\config\plugincfg.xml` 里。

---

## 3. OS2SOC.sys 驱动协议（已完整解码 ★ 最有价值的部分）

`OS2SOCService.dll` 工作函数 `0x180001390`：`ioctl(code, inbuf, insize, outbuf, outsize)`。每次调用先 `0x1800010d0` 确保服务已装并运行，然后 `CreateFileW("\\.\OS2SOC", GENERIC_READ|GENERIC_WRITE, share=3)`。`DeviceIoControl` 失败且 `GetLastError()==0x3E5`(IO_PENDING) 时 `WaitForSingleObject(event, 3000ms)`。

**服务安装**：`CreateServiceW("OS2SOC", "OS2SOC", type=1, start=3 手动, error=1, binaryPath="<dll所在目录>\..\PCManager\mainframe\Plugins\OS2SOC.sys")`；已存在则 `OpenServiceW` + 处于 STOPPED 时 `StartServiceW`。

全部 IOCTL 均为 **METHOD_BUFFERED，DeviceType 0x22**：

| IOCTL | 函数 | 入参 | 出参 |
|---|---|---|---|
| `0x224040` | GetCurrentPlxByMMIO | 无 | 8B = uint32 pl1, uint32 pl2 |
| `0x224044` | SetCurrentPlxByMMIO | 8B = pl1, pl2 | — |
| `0x224048` | GetPlatformInfo | 无 | 平台信息 |
| `0x22404C` | SetCurrentAMDPMFPara | AMD PMF 参数 | — |
| `0x224050` | GetCurrentPlxByMSR | 无 | 8B = pl1, pl2 |
| `0x224054` | SetAMDEPP | AMD EPP 值 | — |
| `0x224058` | GetCpuPower | 无 | CPU 功耗 |
| `0x22405C` | GetCpuResetStatus / ReadAMDSMNReg（两处调用点共用码值，存疑） | — | — |
| `0x224060` | SetCurrentPlxByMSR | 8B = pl1, pl2 | — |
| `0x224064` | WriteIntelMsrReg | MSR 写参数 | — |
| `0x224080` | ReadIntelMsrReg | MSR 地址 | 64 位值 |
| `0x224084` | ReadIntelMMIO | MMIO 地址 | 值 |
| `0x224088` | WriteIntelMMIO | MMIO 地址+值 | — |

导出 C 签名示例：`bool GetCurrentPlxByMSR(uint32_t* pl1, uint32_t* pl2)`、`bool SetCurrentPlxByMSR(uint32_t pl1, uint32_t pl2)`。
PL 值单位待真机确认（MSR 0x610 原生是 1/8W 桶或 1000mW 缩放编码；MonPower 有 `GetPowerLimitScale` 说明存在缩放）。

**自写程序接法**：把 `OS2SOC.sys` 拷到本机任意目录，用同样的 `CreateServiceW`+`StartServiceW` 装驱动（驱动有荣耀签名，Win10/11 x64 可加载），然后直接 `DeviceIoControl` 打上面的 IOCTL。风险：往 MSR 0x610/0x1AD 写错误值会即时改变供电行为，写太猛可能蓝屏/重启——先用 `Get*` 读，再小步 `Set*`。

---

## 4. BIOS WMI 接口（静音/性能/风扇的真正开关）

- 命名空间 `ROOT\WMI`，**类名 `OemWMIMethod`**（第三轮修正：`OemWMIfun`/`OemWMIfunEx` 是方法名，类名字符串在初始化函数 0x180005ee0 处 `mov r8d,0xc`+lea "OemWMIMethod" 全部编译期硬编码），实例路径拼接 `OemWMIMethod.InstanceName='ACPI\PNP0C14\HWMI_0'`（0x18004fd70 确认：base + ".InstanceName='" + 全局"ACPI\PNP0C14\HWMI_0" + "'"）。
- 方法：`OemWMIfun` / `OemWMIfunEx` / `OemWMIMethod`；输入属性 `u64Input`(VT_UI8) 或 `u8Input`(byte 数组)，输出 `u8Output`。
- 调用模式（PowerPolicyPlugin `0x18004fe20` BIOSPutUintContent 反汇编）：`Put("u64Input") → ExecMethod("OemWMIfunEx") → Get("u8Output")`；当 paramId==0x1020 时 SAFEARRAY 元素用 VT_I8，其余用 u8 数组。
- 事件：`SELECT * FROM OemWMIEvent`（BIOS→OS 主动通知：Fn+P 热键、模式变化、Turbo changed）。
- **TurboMode::SetFanSpeed(u8,u8)**（PerfCommon `0x18002b4c0`，TurboMode.cpp:269）：`u8Input[0..1]` = u16 LE **功能ID 0x0007**，`u8Input[2]=stoi(配置串@obj+0xB8)`，`u8Input[3]=stoi(配置串@obj+0xD8 按参数2格式化)`，调 `GetOutPutUIntEx(input, 64, out, 256)`，`out[0]==0` 成功。（GetOutPutUIntEx 是 **Util.dll 的 BiosWmi 包装类**，PerfCommon 从 Util.dll 导入 50-118 个函数，类/方法名常量在 Util.dll 里——和 PowerPolicyPlugin 内联的字面量同源。）
- **NoiseEventDealer::SetNoiseMode(int mode)**（PerfCommon `0x180022f30`）：mode∈{1,2,3}；`u8Input[0..1]` = u16 LE **功能ID 0x0C07 (3079)**（指令 `mov word ptr [rsp+0x100], 0xc07`），`u8Input[2] = mode-1`（0/1/2 三档），其余清零；同样 `GetOutPutUIntEx(in,64,out,256)`，`out[0]==0` 成功；成功后经 `0x180023340` 持久化到 **`HKU\.DEFAULT\Software\HONOR\PCManager\Performance`**（HKEY_USERS 伪句柄 0x80000003 + REG_DWORD，值名全局串）。发送前有机型门控 `[obj+0xD0]!=0 && [obj+0xD2]==0`（ProductAdapt 配置）。→ **静音/均衡/性能三档 = {07 0C 00/01/02}**（待真机验证档序）。
- 传感器（MonPower/PowerPolicy 字符串）：`eCPU_DTS, dGPU_DTS, SOC_NTC, GPU_NTC, TYPE_C_NTC, CHARGER_NTC, DDR_NTC, GDDR_NTC, Ambience_NTC, CPU_VR_NTC_Temp, GPU_VR_NTC_Temp, OPT_NTC_Temp, PerfMode, DGpuPower` —— 温度/功耗读取大概率也经 OemWMI 或 `MonPowerPlugin` 导出。
- 状态持久化注册表：`Software\PCManager\MBAPowerManager`（`PowerSafeManagerStatus/Mode`、`PowerManagerIntellMode`…）、`.DEFAULT\Software\HONOR\PCManager\Performance`、Turbo 相关 `SmartFanMode/SubSmartFanMode/MODE_AC`。

---

## 5. 需要在荣耀笔记本上做的事（下一步）

1. **提取文件**（管理员，从安装目录，通常在 `C:\Program Files\Honor\PCManager\` 或 `C:\Program Files (x86)\...`）：
   - `mainframe\Plugins\OS2SOC.sys` ← **最重要**
   - `mainframe\config\plugincfg.xml`、`config\DeviceFuncSwitchConf.xml`、`config\policy\*.xml`（模式定义/机型差异全在这）
   - `mainframe\IPCMessage.dll`、`MBAPluginsManager.dll` + 宿主服务 exe（若要复刻 UI 通信协议）
   - 如有 Intel 显卡模式控制：`ControlLib*.dll`
2. **抓 OemWMI 方法表**（PowerShell 管理员）：
   ```powershell
   Get-CimClass -Namespace root/wmi -ClassName OemWMI | Select-Object -Expand CimClassMethods
   Get-CimInstance -Namespace root/wmi -ClassName OemWMI   # 看实例和属性
   ```
3. **抓静音/性能切换的实际控制报文**（二选一或都做）：
   - Process Monitor（过滤进程 = 管家服务，Operation = IOCTL + WMIProv）在管家 UI 里切 静音↔性能↔猎人，记录 `OemWMIfun*` 的入参字节和 `\\.\OS2SOC` 的 IOCTL 序列；
   - 或常驻事件监听 `Register-CimIndicationEvent -Query "SELECT * FROM OemWMIEvent"` 看热键/模式事件 ID。
4. **对照注册表**：切换前后 dump `HKLM\SOFTWARE\PCManager\MBAPowerManager` 和 `HKU\.DEFAULT\Software\HONOR\PCManager\Performance`，确定模式→值的映射（如 SmartFanMode=0/1/2）。
5. `powercfg /q` 在切换前后对比，分离出哪些档走的是标准电源计划、哪些走 WMI/驱动。

---

## 6. 自写程序的分层建议

1. **第 1 层（零依赖，立刻可做）**：WMI `OemWMI` 读传感器、执行 §5 抓到的字节序列切模式——多数"静音/性能"表现（风扇曲线+模式指示）由这层完成。
2. **第 2 层（需 .sys）**：OS2SOC.sys 写 PL1/PL2/EPP，精细功耗墙控制（管家"性能模式"本质 = 提高 PL 墙 + 激进风扇表；"静音" = 降 PL + 保守风扇表）。
3. **第 3 层（标准 API）**：PowerSetActiveScheme/PowerWriteAC·DCValueIndex 管亮度、睡眠、Lid 行为；`PowerRegisterForEffectivePowerModeNotifications` 跟随 Windows 电源滑块。
4. Intel GPU 功率（若独显直连/集显功耗也想管）：复刻 `ctl*` 需 Intel GPU SDK（Level Zero/oneAPI Graphics Tools），不必用它的 DLL。

## 7. 风险与注意

- 写 MSR/MMIO 前务必备份当前 PL 值；错误值可致即时断电重启；驱动安装需管理员。
- OS2SOC.sys 是荣耀签名驱动，微软 HVCI/WDAC 环境可能拦截加载（普通家用 Win11 没问题）。
- `SetAMDEPP`/`SetCurrentAMDPMFPara` 仅 AMD 机型；Intel 机型走 MSR/MMIO 路径（GetPlatformInfo 可先判平台）。
- OemWMI 属 ACPI WMI，BIOS 版本不同可能改 ID 表——抓包结果绑定你这台机器的 BIOS 版本。

## 7.5 第二轮：新提取文件的分析（OS2SOC.sys / IPCMessage.dll / config，2026-11-19）

**OS2SOC.sys（46KB，已到手，FileVersion 1.0.0.19）**：
- KMDF 驱动；PDB `D:\work_directory\work_project\PC_Schedule\PLX_Code\gitLab\develop_branch\1.0.0.8_drv\plxdriver\Driver\x64\Release\OS2SOC.pdb`。
- 含 `chipsec_code$__a` 节区 + `hchipsec_` 标记 —— **基于 chipsec 开源驱动改造**（MmMapIoSpace/KeSetSystemAffinityThreadEx/KeDelayExecutionThread 等原语齐全），14 个 IOCTL 是在 chipsec 式 MSR/MMIO 原语上包的 PLX 语义。
- 设备 `\Device\OS2SOC` + `\DosDevices\OS2SOC`，`IoCreateDeviceSecure` DACL = `D:P(A;;GA;;;SY)(A;;GA;;;BA)` → **须管理员打开**；NoDisplayClass 隐藏于设备管理器；WHQL 签名（Microsoft Windows Hardware Compatibility Publisher，2023-08 时间戳）。

**IPCMessage.dll（825KB）= 命名管道总线**：
- 管道：`\\.\Pipe\iMateBookAssistant`（主）、`\\.\Pipe\PerformanceCenter`、`\\.\Pipe\MBADataMigration`，可 `SetPipeName` 自定义；服务端 `CreateNamedPipeW`+IOCP，客户端 `CreateFile`+`WaitNamedPipeW`，服务端 `GetNamedPipeClientProcessId` 校验来源。
- 消息 `TagIPCMessageItem`，序列化 `BasePacket`（`ConvertMessageToPacket`），大 payload 走 `HSharedMemory`（`ConvertMessageToPacketSharedMemory`）；API：`SendIPCMessage`（同步带回执）/`PostIPCMessage`/`PublishIPCMessage`/`RegisterMessageCallback(int msgId, fn)`。
- **消息 ID 配置：`.\config\local_config\performancecenter_module_ipc_cfg.json`（在笔记本上，尚未提取——要拿）**。
- MBAPluginsManager 经 `HnXMLDocument` 加载 `config\*.xml`，自身有 `RecvPublishMessage`。

**MBAPowerManager.reg**：仅 `PowerSafeManagerStatus=1`、`PowerSafeManagerMode=0`（省电管家开关；**电源模式不写这里**，静音模式写 `HKU\.DEFAULT\Software\HONOR\PCManager\Performance`——在笔记本上 `reg query "HKU\.DEFAULT\Software\HONOR\PCManager\Performance" /s` 应能看到历史值）。

**policy\ 目录**：rules.dat/triggers.dat/PowerAction.dat = 加密省电规则表（GBK 注释残迹"规则信息表/触发信息表/加优化进程设置表"）；tableconf.xml=sqlite schema（软件管控）；Reason.xml=亮屏/睡眠原因码。**不含风扇/静音参数**；风扇表在 `config\system\NLDFanSettings.dat` + HunterConfig（**尚未提取**，字符串证实 LoadHunterConfig/LoadFanSpeedConfig 读它们）。

**plugincfg.xml**：全是业务插件（账号/投屏/音频…），电源插件不在此——电源性能中心由独立进程+独立配置加载。

**WMI 类名修正（关键）**：用户真机 `Get-CimClass root/wmi -ClassName OemWMI` 报 0x80041002（类不存在）——但 `SELECT * FROM OemWMIEvent` 未报错（事件类存在）。反汇编证实模块初始化 0x180005ee0 把 12 字节 **"OemWMIMethod" 写入类名槽位**（同批：实例串 `ACPI\PNP0C14\HWMI_0`、方法名 `OemWMIfun`/`OemWMIfunEx`，全部编译期常量）→ **类名应为 `OemWMIMethod`**。待真机验证：
```powershell
Get-CimClass -Namespace root/wmi -ClassName OemWMIMethod | Select -Expand CimClassMethods
Get-CimInstance -Namespace root/wmi -ClassName OemWMIMethod | Format-List *
```
若存在，静音三档可直接 PowerShell 调用：`u8Input = [byte[]](0x07,0x0C,0|1|2)` → `Invoke-CimMethod -MethodName OemWMIfunEx`。

**SetNoiseMode 报文（新解码，PerfCommon 0x180022f30）**：`mov word ptr [rsp+0x100], 0xc07` → **u16 LE 功能ID 0x0C07(3079)**，`u8Input[2]=mode-1`（mode∈1..3）；`GetOutPutUIntEx(in,64,out,256)`，out[0]==0 成功；机型门控 `[obj+0xD0]!=0 && [obj+0xD2]==0`。TurboMode 同理 `u8Input[0..1]`=0x0007 小端 + 2 个 stoi 配置参数。

## 7.6 第三轮：接口最终确认 + 社区互证（2026-11-19，决定性）

**WMI 接口全貌（反汇编 + [Wintego/Honor-PC-Helper](https://github.com/Wintego/Honor-PC-Helper) 互证，该社区项目 hook 过 `IWbemServices::ExecMethod`@MBAMessageCenter.exe，确认 PC Manager 走的同款通道）**：
- 类：**`OemWMIMethod`**（root\wmi，此前"OemWMI"是误猜，DLL 里根本没有这个字符串→用户查不到属正常）。实例有 **HWMI_0 / HWMI_1 两个，管家固定用 HWMI_0**。
- 方法：**`OemWMIfun`**（数组命令走这个）/ `OemWMIfunEx`；输入 `u8Input` = **64 字节 [group, command, value, 0…]，输出 `u8Output`，`[0]==0` 成功**。
- 事件：`SELECT * FROM OemWMIEvent`（用户机器上已验证存在），事件属性 **`Force`**（DLL 字符串 8098 行吻合）低 16 位=事件码：0x2A0 退高性能 / 0x2A1 进高性能 / 0x2A6 热键切换(Fn+P) / 0x2A8 猎人模式 / 0x287 麦静音键 / 0x288 摄像头键 / 0x2B1-0x2B3 背光档位。
- **命令表**：`04 0E` 读电源模式（0=智能/均衡, 1=高性能, 3=猎人——**用户机型 MagicBook Pro 16 即社区实测的 HUNTER 机型**）｜`04 0F v` 设电源模式｜`02 02 zone` 读温度（zone 0x00/0x0E，应答 byte2）｜`02 08 idx` 读风扇（应答 byte1-2 实际 RPM LE、byte3-4 目标）｜`03 11` 读电池充电阈值｜`06 13` 读背光、`06 14/15/11` 设背光模式/自动亮度/超时｜**`07 0C (mode-1)` 静音/噪音三档**（本仓库反汇编 NoiseEventDealer::SetNoiseMode 独有发现，社区未覆盖；对应 TurboMode 也走 group 0x07，风扇命令/参数在 NLDFanSettings.dat 配置里）。
- **权限**：该 ACPI WMI 数据块 DACL 默认仅管理员。非管理员方案：写 `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security` 值 `{abbc0f5b-8ea1-11d1-a000-c90629100000}`，SDDL `O:BAG:BAD:(A;;0x1fffff;;;SY)(A;;0x1fffff;;;BA)(A;;0x2001f;;;<用户SID>)`（Honor-PC-Helper 的 GrantAccess 同款）。
- 交付工具：**`honor/hn_wmi.ps1`**（status/setmode/setnoise/events/raw/grant 六动作，UTF-8 BOM 防 PS5.1 中文乱码，已语法校验）。

**同类开源项目（少走弯路）**：Wintego/Honor-PC-Helper（C# 托盘工具，实测支持荣耀本性能模式/电池阈值/背光，直接可用作参照实现）；HelloZER0/HuaweiWmiControl；tutualican/matebook-control（华为系，性能模式+风扇+温度）；linux `huawei-wmi` 内核驱动（事件码出处）。

**剩余待取文件（次要）**：`mainframe\config\local_config\performancecenter_module_ipc_cfg.json`（IPC 消息 ID 表）、`mainframe\config\system\NLDFanSettings.dat`+HunterConfig（风扇表→group 0x07 的参数值）、`Util.dll`（BiosWmi 公共封装，内含更多 OemWMI 字面量）。

## 7.7 真机验证（MagicBook Pro 16, hs-pro16, 2026-11-19 09:08）

`hn_wmi.ps1 status` 全部命令 OK，实例选中 `ACPI\PNP0C14\HWMI_0`。实测解读：
- 04 0E：两次运行 resp[1]=0(智能)→1(高性能)，读路实锤；期间模式被切换（Fn+P 或 setmode，待用户确认写路）。
- 02 02：zone 0x00=CPU（70→74°C，切性能 +4°C），zone 0x0E=29/30°C（低负载区，似排气/表皮 NTC）。
- 02 08：风扇0 实际0x0C30=3120/目标0x0C1C=3100 RPM；风扇1 0x0B04=2820/0x0B54=2900。LE u16 解析与社区一致。
- 03 11：电池阈值两次 40-70% → 70-90%（管家充电保护档位变化被如实读出）。
- 06 13：背光 2(灭)→3(低)，与实际按键一致。

**结论：OemWMIMethod/OemWMIfun/[group,cmd,value] 协议在该机型完全成立。** 剩余：写路（setmode/setnoise）确证 + group 0x07 风扇子命令表。

## 7.8 写路验证（2026-11-19 09:16，写+事件双通道实锤）

`hn_wmi.ps1 setmode` 全部应答 OK，双窗口对照（一个 setmode，一个 events 监听）：
- `setmode 0` → 事件 `Force=0x2A0 退出高性能`
- `setmode 1` → 事件 `Force=0x2A1 进入高性能`
- `setmode 3` → 事件 `Force=0x2A8 猎人模式`
事件与命令一一对应，**读/写/事件订阅三通道全部在 MagicBook Pro 16 上验证成功**。电源模式（智能/高性能/猎人）可编程控制**彻底打通**。唯一未验证的是 `setnoise`(07 0C) 静音档（属风扇声学策略，另一条轴，与电源模式独立）。

## 8. 未决问题

- ~~静音/性能/猎人三档 WMI 字节序列~~ **已解决并真机验证**：性能模式=04 0F v（0智能/1高性能/3猎人），双窗口对照命令-事件一致（setmode 0/1/3 → 0x2A0/0x2A1/0x2A8）。
- 静音档 `setnoise`(07 0C, mode-1) 尚未真机验证具体档序映射（哪个 mode 对应 UI 的"静音"，可 `setnoise 1/2/3` 逐个听风扇+看是否触发 0x2A6 类事件）。
- ~~`0x22405C` 共用问题~~ **已解决（静态）**：GetCpuResetStatus 与 ReadAMDSMNReg 确实共用 `0x22405C`，驱动按 inSize 分派（inSize=0 → reset status, out 4B；inSize=4 → AMD SMn 寄存器读, in 4B/out 4B）。Intel 平台不受影响。
- PL 值缩放单位（如需直连驱动调 PL 再定；用 WMI 模式切换则无需关心）。
- group 0x07 TurboMode 风扇曲线细调命令（参数在 NLDFanSettings.dat；模式级切换已由 04 0F 覆盖，非必需）。
- 注：以上均为"锦上添花"，**核心目标（可编程切换静音/性能/猎人电源模式）已完全达成**。

---

# 第二阶段：CPU/GPU 自定义功耗分配（进行中）

> 机型 MagicBook Pro 16 HUNTER 2024（Core Ultra 5 125H + RTX 4060 Laptop）。单烤 CPU 70W+；双烤 CPU≈35W / GPU≈115W。目标：在保留原厂散热/温度/电流/供电保护的前提下，探索偏 CPU 的 45+105 / 55+95 分配。**150W 仅为实测和，未经证实为固件硬预算**——待真机数据验证预算是固定还是随温度/供电浮动。
> 本节所有结论严格标注证据级别：[静态]=二进制反汇编、[社区]=第三方互证、[实机]=本笔记本验证。

## 9. 功耗数据流与"35W 是谁限的"（静态分析结论）

### 9.1 管家的功耗读取链 [静态]
- `MonPowerPlugin.dll` 的 `FirmwarePropertyExecutor`（GetOriginPL1/PL2、GetCpuPower、GetPSysPower、GetPowerLimitScale…）**只是转发壳**：单例 ctor `0x1800026a0` → `InitMonProc 0x1800026d0` 里 `LoadLibrary("MonProcess.dll")`+`GetProcAddress` 构造真实对象存 `this+0x10`，每个 getter 导出都是 `mov rcx,[this+0x10]; jmp [vtbl+off]` 薄 thunk。**PL/Psys 的真实读取实现在 `MonProcess.dll`（未提取）**。
- `PowerPolicyPlugin` 经 IAT 直接导入 `MonPowerPlugin` 的 14 个 FirmwarePropertyExecutor 函数；`MonSysPerfPlugin` 导入其中 5 个。GPU 功耗读取 `NvGpuInfo::GetGpuPower/GetGpuFrequency` 来自 **`Util.dll`**（未提取，疑 NVAPI 包装）。
- 关键否定结论：把 PowerPolicy/MonPower/PerfCommon 三者的 WMI 命令字、寄存器写点全数枚举后，**管家侧不存在任何"把 CPU 钉在 35W"的固定逻辑或常量**；它对 CPU 功耗只做**读取+上报**（DataReport 遥测字段 CPUPower/POWERLIMIT1/dGPUTemp…@0x180004e60，周期上报器 PsysPL1 格式化器 @0x1800578e0）。[静态]
- 推论（未验证）：35W 更可能是 **平台级仲裁**——Intel DTT/IPF（Meteor Lake 的 DTT，桌面冒烟时本机即见 `ipfsvc/dttui/Platform License Manager` 在服务列表）、RAPL/MMIO Punit 限制、NVIDIA Dynamic Boost 的 CPU↔GPU 预算流转、或 EC 总预算，而非荣耀软件写死。[推断，待实机差分数据证实]

### 9.2 新解出的电源相关 WMI 命令字（均为 [静态]，未实机）
| 字节序列(g,c[,v]) | 出处 | 语义判断 |
|---|---|---|
| `04 0E` | PowerPolicy 主轮询函数 0x18001d940–0x18001e955 内 0x18001e15c | 读电源模式（0x0E04 已知：0智能/1高性能/3猎人） |
| `02 0C` | PowerPolicy 孪生函数 0x18002ff00/0x180030020 | 疑读噪声/风扇档回显（与写侧 07 0C 配对）——**待探针验证** |
| `03 D0, b3=(44-W)*8` | `PowerPolicyExecutor::SetPowerLimit2(byte)` @0x180013800 | **疑似"设 PL2 上限"的原厂高层入口**：44W 基准，步进 1/8W，写入 byte[3]。**高危假设未验证**；`GetPowerLimit2` 是恒返回 0 的桩(0x180009a90)→管家自己都不回读，说明该口可能已废或由 EC 决定 |
| `03 12` | `SetCpuCoreNumber(byte)` @0x180014ab0 | 设活跃核数（性能限制的粗粒度手段） |
| `06 1D/1E/2D/2E` | MonPower | 开盖开机/标志位读写（电源事件侧，非功耗） |
| `06 36/3C/0E/25/26/1B/34` | PowerPolicy 0x180030b4e… | 06 族=显示/背光家族，与功耗无关 |
- 策略 DSL：`ExcutePowerPolicy` 动作词表含 `powerlimit`、`socsetting`、`kill`、`frozen`（tools/strings/PowerPolicyPlugin…:7559）→ 原厂"智能模式"是按 XML 策略脚本执行的动作集合，功耗动作即 `powerlimit`→SetPowerLimit2(03 D0)。**这就是"优先寻找的原厂高层入口"候选**。[静态]

### 9.3 OS2SOC 读写 ABI 最终版（可直接 P/Invoke，[静态]）
- DLL 只依赖 KERNEL32+ADVAPI32，**可脱离管家直接加载**；每次调用自动确保 OS2SOC 服务在跑。签名见 `tools/os2soc_exports.txt`。
- 读：`GetCurrentPlxByMSR/GetCurrentPlxByMMIO(uint*pl1,uint*pl2)->bool`；`GetCpuPower(ulong*)`；`ReadIntelMsrReg(uint msr, ulong*out)`(0x224080)；`ReadIntelMMIO(uint off, ulong*out)`(0x224084)。
- 写：`SetCurrentPlxByMSR(pl1,pl2)`(0x224060)/`SetCurrentPlxByMMIO`(0x224044)；`WriteIntelMsrReg`(0x224064)/`WriteIntelMMIO`(0x224088)。
- 驱动侧：IoCreateDeviceSecure DACL 仅 SY/BA——**写入需管理员**，不扩权限即不可写（符合约束⑧，探针阶段全部只读）。
- ⚠️ 已知竞争者：管家插件与 DTT 周期性刷新 RAPL 时都会覆盖 0x610/0x615——**持续覆盖寄存器是错误路线**；正确路线=找原厂高层入口（03 D0 / powercfg / DTT 策略）或先测量出"谁在写"。

### 9.4 本阶段交付：`hn_power.ps1`（只读功耗探针，冒烟通过）
- 位置 `honor/hn_power.ps1`（UTF-8 BOM，本盒 PS5.1 PARSE OK + `-NoWmi -NoOs2Soc` 桌面实跑通过）。用法（笔记本，管理员）：
  - 拷 `OS2SOCService.dll` 到脚本同目录（它自己会拉起已装的 OS2SOC 服务；先 `sc query OS2SOC` 确认服务还在（PowerShell 里 `sc` 是 Set-Content 别名，要用 `sc.exe query` 或 `Get-Service`），若被删会由 DLL 重装）。
  - 一次性快照：`.\hn_power.ps1` → 控制台+`hn_power_report.txt`。
  - 双烤采样：`.\hn_power.ps1 -Loop -IntervalSec 2` → 同目录 CSV。
- 覆盖通道：[1] WMI 模式/温度/风扇/背光/02 0C 回显；[2] OS2SOC 读 MSR 0x610/0x611(能量计数器差分→实际封装瓦)/0x614(PCL)/0x355/0x771-0x774(HWP_CAP/EPP) + MMIO PL 双路；[3] GPU 功耗：优先 nvidia-smi（桌面实测 OK），NVAPI GetDynamicPStatesInfo 试探（单位存 mW，不确定，仅参考）；[4] OS 面：powercfg 方案/SUB_PROCESSOR、DTT/IPF 服务清单、管家注册表。
- 探针输出里 `PL1msr vs PL1mmio` 两列若背离 → 存在双头写者；`610raw` 列时间序列直接回答"双烤时 0x610 被谁、多久改一次"。
- 桌面冒烟即见 `ipfsvc / dttui / Intel Platform License Manager / IntelGraphicsSoftware` 在跑 → DTT(IPF) 仲裁者存在的旁证（台式机侧）。

### 9.5 仍需向用户索取的文件（荣耀本上，均为只读拷贝）
1. **`MonProcess.dll` + `Util.dll`**——在管家安装目录（与已提取 9 个 DLL 同级或其上层，形如 `...\PCManager\mainframe\` 或其 `Plugins\`；可用 `where /r "C:\Program Files\Honor" MonProcess.dll` 定位）。它们决定 GetOriginPL1/PSys/GpuPower 的真实数据源（DTT? EC WMI? PDH?），是"区分读数语义"的最后一块静态拼图。
2. （可选）`mainframe` 目录整体清单：`dir /s /b` 输出贴回即可，不必全拷。
3. （可选）`C:\Windows\System32\DriverStore\FileRepository` 中 `dtt*.inf`/`ipf*.inf` 目录名清单——确认 DTT 策略 XML 位置，后续可能从那里读原厂功耗预算。

### 9.7 真机首次快照（HS-PRO16, 2026-11-19 10:23）+ 修复
- 快照（高性能模式,接近待机）：CPU(00)=76°C / zone0E=31°C；风扇0 3240/目标3300、风扇1 3060/3100；nvidia-smi 功率=62.63W（限额 N/A）；服务面确认 **ipfsvc（Intel DTT/IPF）Running**、MBAMainService+PCManagerMainService 在跑。[实机]
- `02 0C` 回读=`00 46 00 00 00 00`（byte0=0 成功, byte1=0x46=70, 其余0）——若语义为噪声/风扇档位百分比,与风扇 3200+RPM 相符；**待对照 setnoise 后复测确认**。[实机读数,语义未定]
- 两个 bug 已修（v1.0.1）：① Add-Type 里 DLL 绝对路径的反斜杠未转义 → C# `"C:\Users\..."` 报"无法识别的转义序列"，OS2SOC 段整段失效；已改为 `$dllPath.Replace('\','\\')` 并本地编译验证 OK。② 用户侧 `sc query OS2SOC` 无输出 = PowerShell `sc` 是 Set-Content 别名，应使用 `sc.exe query OS2SOC` 或 `Get-Service OS2SOC`。
- 修复版需重新拷到笔记本再跑（段[2]上次为空是 bug①，不代表驱动不可用）。
- v1.0.2 修复：`$pl1=0u` 是 C# 字面量语法，PS5.1 把 `0u` 当命令名执行报"无法识别"→改 `[uint32]0`。本机（无驱动、非管理员）完整冒烟通过：Add-Type 编译+调用+优雅降级全链路 OK。v1.0.3：门路径提示文案更新。
- **文件门语义本机实锤（决定性）**：本机把 sys 放到打印路径后重跑 → 'driver path incorrect' 完全消失，进入服务分支（本机非管理员→服务安装失败，读数保持不可读，无副作用）。笔记本打印 `C:\Users\hs-pro16\..\PCManager\mainframe\Plugins\OS2SOC.sys`（..在中间）→ **归一化 = `C:\Users\PCManager\mainframe\Plugins\OS2SOC.sys`**（DLL 的 base 推导规则未完全解明，但不需要解——按它打印的原文建目录即可）。笔记本操作（管理员 cmd）：`mkdir C:\Users\PCManager\mainframe\Plugins` + 把 OS2SOC.sys 拷进去 + 管理员 PowerShell 重跑脚本（设备 DACL=SY/BA，读数本身也需要管理员）。
- 服务状态仍未直接确认（`sc query` 被别名吞了）；重跑时若段[2]仍不通，先 `Get-Service OS2SOC` 把结果发回。若服务不存在，DLL 会 CreateService 装载凭证路径下的 sys（就是真 WHQL 签名原件，合法路径）。
- 附带观察 [实机]：笔记本 `ipfsvc` Running、`Intel(R) Platform License Manager Service` Stopped、Intel_PIE_Service 进程在——Intel DTT/IPF 家族活着，"35W 仲裁者候选"名单得到实机旁证（NVIDIA 侧 NVDisplay.Container 也在跑，NvContainer 用户态未见=DB 可能由 Display Container 承载）。
- **新证据 [静态→本机实跑]**：OS2SOCService.dll 自带诊断——sys 不在 `<DLL自身目录>\..\PCManager\mainframe\Plugins\OS2SOC.sys` 时向 stdout 打印 `The driver path incorrect, is <完整路径>`，然后各导出返回 false，不崩溃。据此确认服务安装路径规则；笔记本上若 `Get-Service OS2SOC` 不存在，把 `OS2SOC.sys` 放到脚本目录旁的 DLL 所要求的相对位置即可（例：脚本在 `Desktop\power\` → sys 放 `Desktop\PCManager\mainframe\Plugins\OS2SOC.sys`）。

### 9.6 下一步计划（顺序固定，写操作全部另立方案待确认）1. 真机跑**修复版** `hn_power.ps1` 一次性快照（只读）→ 补齐上次缺失的段[2]（OS2SOC MSR/MMIO 读数），校准各通道语义与单位。
2. 真机 `-Loop` 三组：单烤 FPU、单烤 GPU(3DMark)、双烤 → CSV 差分 → 定位 35W 的限制源（RAPL PL1? DTT 封顶? EDP/供电? DB 流转?）——回答任务③。
3. 依据②结论再谈控制点选择（任务④⑤），任何写入前：备份原值(0x610 raw)+给出恢复命令+需用户确认。

## 9.8 真机烤机判决（hn_power_log.csv, 152行, 2026-11-19 11:07–11:12）[实机·决定性]

三段曲线（猎人模式,插电）：
| 阶段 | 时间 | CPU实际功率(611差分) | CPU温度 | PL1msr(0x610) | PL1mmio(实时PKI) | GPU(nvidia-smi一次性) |
|---|---|---|---|---|---|---|
| 单烤CPU | 11:07:18–11:09:02 | **67W 平台期** | 61→**100°C撞墙** | **85W 恒定** | 85→81 缓降 | (关) |
| 单烤GPU | 11:09:04–11:11:10 | 20–25W(空闲) | 回落至74 | **85W 恒定** | 80→**60 持续下降** | ~115W(用户口述,撞温度墙撑住) |
| 双烤 | 11:11:12–11:12:45 | 63W峰→11:11:43起**锁死36.0W**(方差<0.3) | 峰100→**89°C(不撞墙)** | **85W 恒定,610raw 全程一字未变** | 59→**54** | ~115W(口述) |

**判决链（35W 真凶）** [实机+推断，按证据分级]：
1. [实机] CPU 双烤被钉在 36W 时，温度 89°C（未撞墙）、MSR PL1=85W、MMIO 实时 PL1=54W——**全部高于 36W，PL 通道不是执行者**。0x610 全程无一次改写 → 不存在"谁在写 0x610"的问题，MSR 路线从始至终不是战场。
2. [实机] MMIO/PKI 侧 PL1 随 GPU 负载升高而单调下降（85→60→54），**存在活的仲裁者在动态预留 CPU 预算给 GPU**——但 54W 仍 >36W，说明还有更深一层钳制。
3. [推断·高置信] 36.0W ≈ 总预算 − GPU 115W ≈ 150−115：钳制发生在 **EC/Punit 平台总功率(EDP)层**——CPU+GPU 之和顶到 ~150W 联合包络，GPU 优先吃满，CPU 拿余数。这与用户实测(35+115)、89°C不撞墙、瞬间台阶(爬坡仅~30s)全部吻合。注意：这**不是**"固件硬编码 150W"的直接证据，包络值可能随温度/适配器浮动；但"CPU=总包络−GPU"的镜像关系是下一步实验的靶子。
4. [推断] 仲裁者身份：`ipfsvc`(Intel DTT/IPF) 与/或 EC 固件（荣耀侧）。管家软件本体已证实只读不写(§9.1静态+本次实测期间管家UI未操作)。

**由此导出的控制策略排序**（替代先前"改 PL"思路——改 PL 无效，因为 85W 根本没用满）：
- **首选（待用户批准写入实验）：压 GPU 侧，让 EC 把余量给 CPU**——双烤稳态后 `nvidia-smi -pl 105`（NVIDIA 官方机制，重启即复位，零原厂接口侵入）→ 若 CPU 从 36→~46W，"联合包络+GPU优先"实锤，且 **45+105 = 现成的 nvidia-smi -pl + 双烤自动平衡**，完全可逆可脚本化。再试 -pl 95 看 55+95。
- 次选：EC 层旋钮（HNOs2EcX64 驱动，见 §9.9；或 WMI 03 D0/04 0F 族）——需先拿到 HNOs2EC10x64.sys 静态解协议，风险高一档。
- DTT/IPF 策略面：ipfsvc 的配置在 DriverStore（策略XML/PTD），若 -pl 实验证明仲裁走 IPF，再研究合法改配置路径。
- 只读前置：`nvidia-smi --query-gpu=power.draw,power.limit,power.default_limit,power.max_limit,power.min_limit --format=csv` + `nvidia-smi -q -d POWER`（笔记本一次性，全只读）。

**已知读数盲区**：loop 内 GPU 列本次为空（v1.0.3 及以前 NVAPI 失败无回退）→ **v1.0.4 已修**（loop 内加 nvidia-smi 回退，PARSE OK+本机验证），下次实验前重新拷贝脚本。0x611 差分≈CPU封装功率与整机表现一致，此列可信。

## 9.9 MonProcess.dll 解剖（2026-11-19 11:22，用户提供 842,336B）[静态]
- 定位：`PCManager\sdk\Common\MonProcess\`（PDB 路径 `D:\CDE_ReSDK\...\MonProcess\MonProcExport.cpp / ProcDriver.cpp`）——就是 §9.1 说的"FirmwarePropertyExecutor 真实实现"，被 MonPowerPlugin `LoadLibrary("MonProcess.dll")` 加载。
- 导出 250 个（`MonProcExport::*` + `ProductAdapt::ProductFeature::*` 全家桶）；imports：Util.dll 39 函数（含 `WMI::GetOutPutUInt(u64,byte*,size)`、`WMI::GetAMDPowerLimit(AMDPowerWmiPara&)`、SmBiosHelper、Registry、HnXMLDocument）、HardwareSdk.dll 3（`Cpu::GetCputype`）、KERNEL32 含 **DeviceIoControl/CreateFileW/QueryDosDeviceW/LoadLibraryA**、ADVAPI32 含 **CreateServiceW/StartServiceW/ChangeServiceConfigW**（自带装服务逻辑）。
- **动态加载 `\plugins\OS2SOCService.dll`**：字符串 `QueryPl1Pl2`、`ReadIntelMsrReg`+失败消息 "Load os2soc.dll Failed_GetPSysPower" ⇒ `GetPSysPower/GetAvePSysPower(float,瓦)` 与 PL 读取最终走 OS2SOC 驱动（0x611 类差分，与 hn_power 的 611 通道同源）。
- **重大发现：第二个内核驱动 `HNOs2EC10x64.sys`**——服务名 `HNOs2ECx64`，设备 **`\\.\HNOs2EcX64`**（EC 嵌入式控制器直连通道）。MonProcess 内 9 个已用 IOCTL（METHOD_BUFFERED/0x22，disas 于 tools/mp_dev_calls.txt）：
  `0x224008`@0x18000c270、`0x22400C`@0x18000ca80、`0x224028`@0x1800073a2、`0x22402C`@0x18000cdb0、`0x224198`@0x18000d500、`0x22419C`@0x180008190、`0x2241A4`@0x18000d910、`0x2241A8`@0x18000dfd0、`0x2241C4`@0x18000dc70（各函数 0.9–0.7KB，语义需 .sys 侧解协议——**待用户提供 HNOs2EC10x64.sys**，找法：`where /r C:\ HNOs2EC10x64.sys` 或 `sc.exe qc HNOs2ECx64` 看 IMAGE_PATH）。
- 待查问题：双烤时 MMIO PL1 缓降(85→54)的写者是谁（IPF? EC?）——HNOs2EC10x64.sys 到手后看它的 0x2241xx 命令面是否含"设 CPU 预算"类写命令。

## 9.10 Util.dll 解剖（2026-11-19 12:0x）[静态]
- **`PowerLimit` 类导出（CPU PL 高层口）**：`SetCpuPl(uint)→bool` @0x1800e25b0（值域校验 `≤0x64`=**0..100W**，调 `GetProcAddress("SetCurrentPl1")`）；`GetCpuPl(uint&)` @0x1800e2280（`"GetCurrentPl1"`）；`ResetCpuPl()` @0x1800e28e0 = 读当前 PL，若非 0x2D 则 `SetCpuPl(45)`（`lea rdx,"-"`：字符串 "-" 字节 0x2D=45 的小技巧）——**原厂复位基线 CPU PL1=45W**。
- 后端模块：`PowerLimit` ctor @0x1800e21b4 → `LoadLibrary("<主目录>\plugins\HHAL.dll")`。**HHAL.dll 未提取（新待办）**——SetCurrentPl1/GetCurrentPl1 的实现体在里面（走 MSR/OS2SOC 还是 EC，待看）。注意 Util.dll 另有 `WMI::SetPL1(uint)/GetPL1(uint&/float&)` 导出 = WMI 路 PL1 口（疑似 03 D0 族的封装）。
- **NvGpuInfo 全为只读**：`NvGpuInit` @0x1800e0?? = LoadLibrary `C:\Windows\System32\nvml.dll`（nvmlInit/nvmlDeviceGetCount/HandleByIndex/**GetPowerUsage**）+ nvapi64 事件注册；`RegisterNvGPUPowerCallBack` @0x1800e0820 = 结构 {ver 0x100E0, interval 1000ms, 回调@obj+0x2b8} 经 `nvapi_pepQueryInterface` 注册 **DynamicBoost 功率分配回调（每秒）**。`nvapi64.dll` 与 **`nvpowerapi.dll`** 由同一 loader（0x180001190，按 GPU 类型二选一）经 `nvapi_QueryInterface` 按数字 ID 取函数。
- **结论：荣耀软件栈（9 DLL + Util + MonProcess）不存在任何 GPU 功率写入代码**——GPU 侧只有读功耗/频率/状态 + DB 回调。管家遥测字段 DGpuPower 亦只是读。

## 9.11 HNOs2Ec10x64.sys 解剖（2026-11-19 12:0x）[静态]
- WDM 驱动（非 KMDF），`\Device\HNOs2EcDevX64` + `\DosDevices\HNOs2EcX64`；**IoCreateDeviceSecure DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`（仅 SYSTEM/Admin）+ Exclusive 打开 + `IoValidateDeviceIoControlAccess` + 客户进程名白名单**：`PCManagerMainService.exe`（两个路径）、`MBAMessageCenter.exe`、`MBAMonitorService.exe`、`PCManager.exe`、`MBALogSampleService.exe`、**`HnPerformanceCenter.exe`**（=荣耀"性能中心"UI 存在实锤）。→ **第三方程序无法合法使用此设备**（白名单/权限绕过=违反约束⑧，不做）。
- 内核实现=**HWMI WMI 的内核代理**：`IoWMIOpenBlock(GUID ABBC0F5B-8EA1-11D1-A000-C90629100000)`——与用户态 OemWMIMethod 同一 WMI 数据块（社区 GrantAccess 的 GUID 相同）；`IoWMIQueryAllData`(0x206B 数据块)；`IoWMIExecuteMethod`(8B 输入, 方法ID取自数据块字段；输出 byte[0x55]=status 1..5→查表 {0x20000,0x40000,0x80000,0xC0000,0x100000}，bytes[0x56..0x59]=u32 LE（值域检查 6..0x100000，疑功率mW/频率kHz）) 两孪生 worker 0x140001000/0x1400012d4。
- 另有 `MmMapIoSpace`（EC/PMIO 直映射，第三 worker 0x1400015c4）、`ZwTerminateProcess`/`PsSuspendProcess`/`PsResumeProcess`（管家"冻结进程"功能底座）、`ZwCreateKey/ZwSetValueKey`（写服务配置）。
- 意义：EC 命令面与 WMI 命令面同源——**用户态已打通的 WMI 路就是官方允许第三方使用的等价通道**；EC 驱动不新增命令，只新增内核特权+白名单门。

## 9.12 GPU TGP 控制权归属判决（社区/web 互证 + 本机观察）[社区+推断]
- `nvidia-smi -pl 65` → "not supported in **current scope**" = RTX40 笔记本 TGP 不归 NVML/nvidia-smi 管：静态 default_limit=55W，115W=DB（Dynamic Boost 2.0）协商上限。
- 架构（NVIDIA open-gpu-kernel-modules issue #1162 等旁证）：**ACPI `\_SB.NPCF`（_HID `NVDA0820`，_DSM UUID `36b49710-2483-11e7-9598-0800200c9a66`）** 是平台↔NVIDIA 功率协商设备；Windows 上由 nvcontainer/NVIDIA 驱动内协商（Linux 对端是 nvidia-powerd）。OMEN 案例=OEM Hub 切档改 TGP（cTGP/PPAB）。
- 荣耀侧对应物：**HnPerformanceCenter.exe（白名单）+ EC/NPCF _DSM 提供的预算档表 + Intel IPF/DTT 平台预算参与**。→ 想"降 TGP 抬 CPU"，合法的第三方可见入口在 **ACPI 表（NPCF/EC _DSM 静态定义）与 HWMI WMI 命令空间**，不在 NVML。
- 采集工具已交付：`honor_acpi.ps1`（v1.0，5 步全只读：ACPI 全表转储(GetSystemFirmwareTable)/OemWMIMethod+OemWMIEvent 类定义 dump/PNP 设备(NVDA0820)/服务+DriverStore(ipf|dtt|ias|nvpcf)/注册表+WMI Security 键名清单）。产物 `acpi_hunt\` 文件夹带回即可本地解 DSDT+MOF。

## 9.13 「整机 TDP 墙」性质判定 + 电池补电（回应用户 m01112）[工程推断，待真机实测证伪]
用户问：电源 200W + 可从电池取电，能否提升 EC 整机 TDP 墙来拉高 CPU？用现有实测数据推理墙的真实性质：
- **墙不是电源（电）造成的**：实测 CPU+GPU 三相和最高仅 ~150W（log1 36+115；log2 峰值 ~140），远低于 200W 适配器 → 电有 ~50W 余量。适配器 oversized 是给瞬态 PL2/边充边放留头寸的。
- **墙≈整机散热的总排出能力**（关键旁证）：单烤 CPU=65W 撞 100℃（CPU 侧散热极限）；单烤 GPU=115W 撞温度墙（GPU 侧散热极限）；两者共享热管/风道 → 双烤总散热 < 65+115=180，实测稳定在 ~150。**双烤 CPU 在 40W/90℃(低于自身 65W@100℃)、GPU 在 96W 时总盘 ~136；GPU 抬到 115 时 CPU 被挤到 36、总盘 151——总盘随 GPU 走，符合"共享散热器饱和 + GPU-first 仲裁"，不是固定电预算**。
- **推论：单纯抬高 EC 总功率墙 = 无用**。因为约束是散热器排热(~150W)，不是电。把总电预算调到 >150W，热量无处可去 → 两颗都顶到 100℃ 后被 Punit/EC 强制回落，只是更热更吵、并蚕食原厂散热安全余量（不建议）。电池补电同理：只补电不补散热，对可持续总功率无帮助（仅稳瞬态）。
- **真正可行且热中性的杠杆 = 在同样 ~150W 总盘内做「再分配」**：把 GPU 份额/优先级降下来，CPU 拿回 45~55W（CPU 单烤能到 65W，故 45-55 在其能力内；GPU 让到 95-105 < 其 115 TGP）。总发热不变=安全，只改分配。**这正是用户最初诉求"降 TGP 抬 CPU"的物理正解**。
- 但再分配需要 GPU 侧写入口（把 GPU 从 GPU-first 的 115 拉低）：§9.10 已证荣耀软件无此口、`nvidia-smi -pl` 被 DB/NVPCF 禁；EC 总预算命令在 `HNOs2EcX64`（进程白名单+Exclusive+SY/BA，第三方不可合法使用，不绕过=约束⑧）。→ **再分配路径卡在 NVIDIA DB2.0/NVPCF 侧，待 §9.12 的 NPCF/ACPI 采集 + HHAL.dll 定位是否有合法档表切换命令**。
- 新增只读探针 `hn_power.ps1` **v1.0.5**：CSV 追加电池 4 列（battPct / chgRateA / 电池功率W[正=充电 负=对外补电] / battStatus）。真机跑一次即可判定：**若双烤满载时 chgRate 始终为正或零 → 电池没在帮忙 → 墙确实是散热/EC 策略而非电源；若满载且电池转负(放电) → 存在混合供电(hybrid power)，电才是限制，届时抬电预算/混合供电阈值才有意义**（本机无电池，输出空为正常）。
- 待决实验（读为主，写实验前需方案+确认）：①v1.0.5 双烤看电池列 + 总盘平台；②单烤 GPU 记录 GPU 温度——若 115W 时远低于其温度上限，说明散热未饱和、EC 电预算才是主墙（则该路还有救），若贴温度墙=散热极限（则该路无救，转纯再分配）。
  **[真机回信 m01144 判定] ②已答：单烤 GPU 已接近上限（散热极限）→ 总功率受散热而非供电限制，抬整机 TDP 墙无意义。用户决定不解锁 EC。方向锁定：散热盘内的 CPU/GPU 再分配。**

## 9.14 仲裁者架构 PnP 层实锤（honor_acpi v1.0 带回件分析，2026-11-19 12:5x）[实机观察]
`acpi_hunt\pnp_devices.txt`：
- `ACPI\INTC1042\IETM` = **Intel Innovation Platform Framework Manager**（driver `ipf_acpi`）——现代 DTT 继任者、平台功率/场景仲裁者
- `ACPI\INTC1062\SEN1..SEN8 + CHRG` = IPF Generic Participants（传感器+充电器参与者）
- `ACPI\NVDA0820\NPCF` = **NVIDIA Platform Controllers and Framework**（driver `nvpcf`）——DynamicBoost 平台预算接收端，与 §9.12 社区架构吻合（本机型驱动已装且状态 OK）
- `ACPI\PNP0C14\HWMI`（+DSARDEV/0X00/TESTDEV 其他 WMI 块）= 我们的 OemWMIMethod 通道宿主（driver `WmiAcpi`）
- `ACPI\INT340E\2`（老 DTT 设备）、`ACPI\THERMALZONE\TZ00`
→ **判决链：IETM(IPF) 按场景定总预算与参与者配额 → NVPCF 把预算喂给 NVIDIA 驱动 → GPU TGP/DB 在 NVIDIA 侧动态定；CPU 侧 IPF 同时管 PL 斜坡。荣耀 EC(WMI/HWMI) 提供模式档（04 0E/04 0F 影响整机墙与声学档）+ 电池策略。**
`acpi_hunt\services.txt`：
- `ipfsvc` Running/Auto，BinaryPath=`DriverStore\ipf_cpu.inf_amd64_fe2967a6eb0d3a7d\ipf_uf.exe`（IPF 用户态框架）
- DriverStore 实装包：`ipf_cpu.inf / ipf_acpi.inf / ipfppm_sw.inf / nvpcf.inf`（IPF PPM 软件包存在！配置采集目标）
- OS2SOC 服务仍注册（DEMAND_START，路径 `C:\Program Files\HONOR\PCManager\mainframe\Plugins\OS2SOC.sys` ✓与 DLL 内拼接路径一致）；HNOs2ECx64 AUTO_START（`PCManager\HNOs2EC10x64.sys`）
`acpi_hunt\registry.txt`：`.DEFAULT\Performance` 空（本机从未成功写过 NoiseMode——待验证）；MBAPowerManager 无 intell 值；WMI\Security 前40个 GUID 未见 abbc0f5b 自定义 DACL（社区提权路径在本机可能不需要/未做过）。
**未拿全的两件**：ACPI 表转储失败（GetSystemFirmwareTable err=1，即使管理员——真因=需要启用 `SeSystemEnvironmentPrivilege` 特权，v1.0 没做；v1.1 已修+新增 IPF 配置采集/HHAL/HnPerformanceCenter 自动搜索复制/svcreg 导出，桌面冒烟特权启用 True 通过）；OemWMIMethod 类定义（PS5.1 `-band` 简写语法 bug，已修）。→ **v1.1 待用户重跑。**

## 9.15 v1.1 带回件解剖 + HHAL.dll/HnPerformanceCenter 发现（2026-11-19 13:0x）[实机+静态]
- `wmi_classes.txt`[实机]：OemWMIMethod = 2 方法（OemWMIfun WmiMethodId=1 / OemWMIfunEx =2）+ Active/InstanceName；OemWMIEvent 仅 1 数据属性 **Force:UInt32(WmiDataId=1)**；实例确认 **HWMI_0 与 HWMI_1 并存**（与社区一致；管家与我们脚本都用 HWMI_0）。→ MOF 无参数元数据，**WMI 命令表只存在于 EC 固件+调用方 DLL，MOF 探新命令=死路（定案）**。
- `svcreg_nvpcf.txt`[实机]：nvpcf\Parameters 为空（只有 Wdf 版本）→ **注册表无旋钮，NPCF 预算表纯固件(_DSM)**；`WMI\Security` 无 abbc0f5b 自定义 DACL → 默认安全（管理员即可调用）。ACPI 转储 v1.1 仍 err=1（特权=True 下）——待办：换 NtQuerySystemInformation(76) 直读；优先级已降低（见 §9.16 主线转移）。
- **HHAL.dll**（149,600B）[静态]：PDB 与 OS2SOCService 同厂 `plxdll\Dll\Release\HHAL.pdb`；但打开 **`\\.\HHAL`**（自带 `\HHAL.sys`，CreateServiceW 自装）；导出仅 GetCurrentPl1/Pl2/Plx + SetCurrentPl1/Pl2/Plx + GetPlatformInfo；串 `[liyong0002]PL1 = 0X%x, PL2 = 0X%x`、`Read/Write msr failed!` → **Util.dll `PowerLimit::SetCpuPl` 的真实底层=第二套 MSR 驱动直写 0x610 族**（与 OS2SOC 0x224064 平行；管家有两套 MSR 写通道）。HHAL.sys 是否存在/路径 → honor_dtt.ps1 [3/6] 查（桌面冒烟：本机无 HHAL 服务=正常）。
- **HnPerformanceCenter.exe**（267,872B）[静态]：ASCII/UTF16 串显示它是 **MBAPluginsManager 宿主壳**（"HnPerformanceCenter PluginsInitialize"、基目录 `C:\Program Files\HONOR\PCManager`+`plugins\`、load Util.dll/MonProcess.dll/MBAPluginsManager.dll/HnDumpFile.dll、`runas` 自提权、CheckFileIntergrity.dat 完整性、三六零/奇安信签名链）→ **功能全在其 plugins\ 目录 DLL，honor_dtt.ps1 [4/6] 全量清单+拷贝**。
- [6/8] "0 个配置文件"根因=v1.1 扩展名过滤漏了 `.config`（Intel 用非标准后缀，内容=策略 XML，但**加密**见 §9.16）。

## 9.16 DTT/IPF 策略栈解剖 → **Intel IPF CLI 就是原厂策略入口**（2026-11-19 13:2x）[静态，桌面开发机 DriverStore 同版本文件本地解剖；版本一致性=实机哈希吻合]
桌面机 DriverStore 装有与笔记本**同哈希包**（`ipf_cpu.inf_amd64_fe2967a6eb0d3a7d`、`PPM-MTL-ARL-23H2-v1007.20241021.ppkg` 103,415B 同尺寸）→ 全栈可离线分析，产物中转 `honor/dtt1/`+`dtt1/tools/strings/`。
- 包清单：`dtt_sw`（Dptf.dll 3.5MB 核 + 16 个策略 DLL + configuration\*.config×10）、`ipfppm_sw`（**PPM-MTL ppkg=125H 平台功率策略包**）、`ipf_cpu`（ipf_uf.exe 服务 + ipfcore/ipfsrv/ipfipc + CoreProvider 1.6MB + **dsp.dv 666KB IPF DataVault** + ClientApiProxy/CoreApiProxy + upe_* 引擎，**含 upe_nvapi.dll**=IPF 侧 NVIDIA 引擎）、`nvpcf`。
- `.config` 文件**加密**（512B 块 ECB 重复密文头）→ 改配置文件路被 Intel 封死[实机文件+静态定案]；不解密（约束⑧）。
- **DptfPolicyPowerShare2.dll 串**：`Third Party Graphics Reserved TGP Changed to:`、`TPG TPP Limit changed for power source: [`、`/psh2_closed_loop_enabled`、`/psh2_gfx_perf_hint_disabled` + 全套参与者事件（电池阻抗/EPP 等）→ **§9.8 镜像模型的执行者=PowerShare2/TPG 策略**（GPU-first 配额的出处）[静态]。
- Dptf.dll：`DomainPowerControl_001::setPowerLimit / setPowerSharePolicyPower / setPowerShareEffectiveBias`、`power_limit_set`、`system_power_limit_set`；ThirdPartyGraphics.dll：PowerControl/PeakPowerControl/DynamicEpp facades。**全栈无 GPU 功率直写口**（GPU 配额经 NVPCF/DB，再次吻合 §9.12）。
- **决定性发现——ipf_uf.exe 内置官方管理台 "IPF CLI"**（banner: `IPF_UF [client | server | shell] [options]`、`-c command  Execute the specifed shell command at start.`、Copyright 2013-2024 Intel；PDB 路径 `dptf\Src\ESIF\Products\ESIF_UF\`）。`client` 模式经命名管道 `{14579667-532A-42C2-9200-FD0544E09B90}`/`{18837DD8-...}` 连**运行中的服务**（服务端需 `-i` 启动=“Start framework with client support (Server command only)”→ 可行性取决于 ipfsvc ImagePath 是否带 -i，honor_dtt.ps1 已采集）。命令集（节选）：
  - 只读：`about/info/participants/participant <id>/domains/upes/apps/driversk/dspquery/config list/config files/events`；**`capture [-overwrite] [filename]` = “Write all DPTF settings to .txt file in XML format”**（一键全量策略导出！）；原语 `getp/getp_pw`（mW 读功率）；遥测原语串 `GET_GT_CLIP_REASONS`（显卡被限功率的原因）/`GET_IA_CLIP_REASONS`。
  - 写侧（本阶段不碰，留作最终方案）：`setp_pw [part] <id> <qualifier> <instance> <power-mW>`、**`rstp` = “Resets/clears an override”（原厂恢复机制）**、`config gddv backup/reset/restore`。
- **策略结论（任务书④的答案）**：与其改加密 config/碰 EC/碰被禁的 NVML，正解=用 Intel 自带 IPF CLI 以 `client` 模式**读**参与者树+`capture` 导出荣耀实际策略，之后任何偏 CPU 的尝试走 `setp_pw`（对 dGPU/TPG 参与者设配额）+ `rstp` 恢复——原厂机制、可回滚、不越权。交付 **`hn_ipf.ps1` v1.0**（只读探针：诊断管道/ImagePath → client 握手 `about` → 失败即退（绝不另起 server/shell 与服务抢管道）→ 只读命令扫 → 每 participant 详情 → capture 全量 XML 导出）。
- 配套采集 `honor_dtt.ps1` v1.0 交付（6 步：DTT/IPF 配置+ppkg+dsp.dv / 关键策略 DLL / HHAL.sys 定位拷贝 / PCManager 全清单+plugins 拷贝 / 运行时状态+ipfsvc ImagePath / root\wmi DTT 类枚举）——桌面冒烟全绿。

## 9.17 三条路的实测判决 + IPF 落盘策略库定位（桌面实测轮，2026-11-19 13:4x）[实机(桌面)+静态]
- **DTT WMI 总线=死路**：桌面机 root\wmi 全量 1581 类（DTT/IPF 服务正在跑：dptftcs+ipf_uf+ipfsvc×2）**零个 Intel 热管理参与者类** → 现代 IPF 不再走 DPTF 时代的 WMI 总线。笔记本端由 honor_dtt.ps1 [6/6]（已修 Get-CimClass 语法+OemWMIMethod 参数 schema dump）复核。
- **IPF CLI client 依赖服务 `-i`**：桌面 ipfsvc ImagePath=`...\ipf_uf.exe`（无 `-i`）且 GUID 命名管道不存在；ipf_uf.exe 清单=**requireAdministrator**。→ 笔记本大概率同样连不上；hn_ipf.ps1 已按“握手失败即退零改动”设计，并把 client 的 exe 改为**按 ImagePath 匹配运行中版本**（版本不符会被 `ESIF_E_UNSUPPORTED_CLIENT_SDK` 拒）。若日后要 client 模式：给 ipfsvc ImagePath 加 `-i`+重启服务=可逆但改动原厂运行时，**须用户单独批准**（当前不做）。
- **PPM-MTL ppkg 已离线解包**（magic=**MSWIM**，普通 WIM 容器；桌面 7-Zip 免管理员解开：`tools/wimpeek.py` 定位 XML 资源被 LZMS 压缩挡住，7z 23.01 直接解）→ 57 文件/51 个 `*__Power_Policy.provxml`（MCSF 置备格式）。**内容判决：全是 Windows 电源方案+调度器置备（EPP×90 处、MaxFrequency、核心停车、HeteroPolicy 异构阈值、SchemePersonality=381b4222 电池子组×平衡/安静/高性能三方案）——无任何 PL1/PL2/TGP/EDP/温度旋钮** → PPM 包≠35W 限制出处[实机文件定案]；但它证明“方案级”参数本来就通过 powercfg 体系下发（我们 hn_power 已在读 SUB_PROCESSOR 同一体系）。customizations.xml(476KB) 亦零命中。
- **IPF 真正的活策略库定位**：ipf_uf.exe 内嵌路径宏 `DV=%DRVDATA%\Intel\IPF\dv`、`DSP=...\dsp`、`CMD=...\cmd`、`LOG=...\log` → **`C:\ProgramData\Intel\IPF\` 树=活的 DataVault(GDDV)仓库**，OEM/荣耀定制的最终落点。honor_dtt.ps1 [1] 已加全树拷贝 → 拿回后离线解析（magic 0x00941FE5+命名表，样例=包内 dsp.dv 666KB）或用 IPF CLI 文件命令读。
- 脚本修订：honor_dtt.ps1 → [1b] DISM 解 ppkg（笔记本管理员会话可用；本机已证 7-Zip 等效）、[1] + Intel\IPF 树、[6/6] 语法修复；hn_ipf.ps1 → DriverStore 不可写(输出全落 acpi_hunt2\ipf)、exe 版本匹配、capture 参数序修正。
- **本阶段静态/离线结论**：CPU/GPU 35/115 配额的“可读原厂策略源”收敛为三：①笔记本 `ProgramData\Intel\IPF` vault（待取，最高优先）②加密 `.config`（不解，违规）③荣耀 HWMI 未知命令空间（待 plugins 全套解剖）。写侧合规候选：IPF CLI `setp_pw`+`rstp`（需 -i 批准）> HWMI 新命令（需 plugins 逆向证据）。




---

*附：分析脚本在 `honor/tools/`，反汇编产物 `disas_os2soc.txt / perf_turbo.txt / perf_noise.txt / pp_wmi2.txt / pp_ipc.txt / pp_bright.txt / perfdetect_epp.txt`，字符串库 `tools/strings/*.strings.txt`。*


## 9.18 acpi_hunt2 带回件判读（honor_dtt v1.1, 2026-11-19 13:5x）[实机]
- `dtt_wmi.txt`：笔记本 root\wmi 1562 类中存在 **EsifDeviceInformation + EsifWmiEvent**（桌面开发机没有）= IPF 内核 WMI 信息块/事件块。OemWMIMethod schema 全量确认：`OemWMIfun(ID=1)/OemWMIfunEx(ID=2)`，参数 `u8Input:UInt8Array, u32Resrved:UInt32, u8Output:UInt8Array`；实例 HWMI_0+HWMI_1 双份。
- `runtime.txt`：**HnPerformanceCenter.exe 运行中(pid28376)**；**HunterCampService.exe 存在（C:\Program Files\Honor\HunterCamp\，猎人营中心）**；ipfsvc 实际二进制=dtt_sw.inf 包内 ipfsvc.exe（ipf_cpu 包另有 ipf_uf/ipf_helper）；无 dptftcs（纯 IPF 代际）。
- **[3] HHAL 服务不存在 → 管家从未调用过 SetCpuPl 路**（Util.dll PowerLimit→HHAL 写 PL1 通道在真机上从未启用；这条是"原厂自己都不用"的重要信号，也意味着我们用它=偏离原厂行为，风险加权）。
- 笔记本**无 C:\ProgramData\Intel\IPF 树**（无 ipf_progdata 拷贝行）→ GDDV 覆盖库为空，IPF 跑内置/驱动默认。
- [1b] DISM "指定的路径无效"×2=DISM 拒 `.ppkg` 扩展名（已在 v1.2 修复：先拷 %TEMP%\*.wim 再解；hn_ipf v1.1 改为直接拷 ppkg 回本地解）。

## 9.19 plugins\ 75 文件解剖 → **GPU 子模式 IPC 总线实锤**（2026-11-19 14:0x）[静态，高置信]
中转 honor\plg1\（9 文件先扫），产物 tools\peinfo_plg1.txt、plg1\tools\strings\、**tools\plg_ipc_calls.txt**。
- **UnderlyingOptimizationPlugin.dll 导出 `char __cdecl GetUXGPUSubMode(void)` @0x18000e280**（PDB feature\PerformanceManager\UnderlyingOptimization\…）——非 WMI、非驱动，是 **IPCMessage 命名管道总线调用**：
  - `IPCMessageClient` 构造：ctor(this, **edx=0x2560000**, bool,bool)——`??0IPCMessageClient@@QEAA@H_N0@Z`（IPCMessage.dll 导出确认）。
  - `SendIPCMessage(req, resp, u32 timeout)`：req@rsp+0x98 六 dword：[0]=**0x2470000**、[1]=[7]=-1(0xffffffff)、[3]=[5]=**0x244000b**、(0x9c/0xa8=-1)；timeout r9=**0x3e8=1000ms**。响应读回 u64≤**7** → **GPU 子模式 0..7（8 档）**。
  - 调用者 0x18000dfb0：日志 "The GPU mode is:" + 0/1 选择器。全 DLL 仅 1 个 SendIPCMessage 调用点=**只有 GET，SET 方在别处**——首选嫌疑人：**HunterCampService.exe / HnPerformanceCenter.exe**（猎人营 UI 的 GPU 档位滑条）。
- SmartChargePlugin：`PowerLimitingStatus` + `WMI::GetOutPutUInt(u64,byte*,u32)`（u64 命令式 WMI，又一族未解命令）。
- ProcessControlPlugin：GPUTopProcInfo/IGPU3DecodeLoad；PerfCommonPlugin：OnReceiveGpuModeProcessReStart（GPU 模式变更 IPC→重启进程）。

## 9.20 hn_ipf "全失败"根因 + IPC 服务端门禁（2026-11-19 14:1x）[实机+静态]
- probe_about.txt 实文 = `Starting program in client mode. Error: Unable to connect to server. Errorlevel Returned: 0` → **client 从未连上**；管道 `{18837DD8-…}` 在听但**不是 CLI shell 管道**（疑 ETWP 复用同 GUID 前缀）；**ipf_uf client 失败也返回 0**=脚本判定 bug。**hn_ipf.ps1 v1.1 修复**：probe 输出 grep 'Unable to connect'→fail；+allpipes.txt 全量命名管道清单；+ppkg 直接拷回（acpi_hunt2\ppkgs\）。**下一步若仍连不上**：给 ipfsvc 追加 `-i` 属可逆配置改动，**需用户单独批准**才动。
- **IPCMessage 服务端门禁链**：`IOCPServer::VerifyClientSignature(pid)` @0x18002fd70 = OpenProcess(0x410)+QueryFullProcessImageNameW → **`FileInfo::VerifyDigitalSignature(wchar_t* path, bool)` = HFileInfo.dll 导出**（工具产物 tools\ipc_vcs_full.txt）→ False→HandleIO 直接断开（日志 "IPCMessage HandleIO VerifyClientSignature False nPID:"）。
  - **HFileInfo.dll 未提取 → 验证策略未知**：若只要求"任何有效 Authenticode"，我们的 PowerShell/Microsoft 签名的宿主可过；若锁定 HONOR 发行者，第三方 IPC 直连关闭（不绕过，约束⑧）。
  - IPCMessage.dll 233 导出全确认（含 IPCMessageClient/SendIPCMessage/SetPipeName/SubscribeIPCMessage 等）→ 技术上 P/Invoke 可行，**唯一门槛=服务端签名策略**。

## 9.21 当前所需（第三轮文件请求）[行动清单]
1. 笔记本管理员重跑 **hn_ipf.ps1 v1.1**（假成功已修+全管道清单+ppkg 回带）→ acpi_hunt2\ipf + ppkgs。
2. 笔记本跑 **honor_hc.ps1 v1.0**（Esif 实例+3 秒事件监听、HunterCamp 服务/目录/文件拷贝、HnPerformanceCenter/HunterCampService/PCManagerMainService 等进程模块清单）→ acpi_hunt3。
3. 拷 **HFileInfo.dll**（`where /r "C:\Program Files\Honor" HFileInfo.dll`）——决定 IPC 总线对第三方是否可用。
4. （可选）HunterCamp 目录若 honor_hc 拷不到 >30MB 文件，手工列个清单即可。
**判定树**：HFileInfo 宽松 → 用 IPC GET/SET 消息走原厂通道（GPU 子模式 8 档=期望的 TGP 再分配杠杆）；HFileInfo 严格 → 回退 HWMI 未知命令族(02 0C/03 D0 只读探测)+ HunterCamp 自带 UI 的档位与 IPC 消息对应关系（从 HunterCamp 二进制逆向 SET 消息 ID）。

## 9.22 **HNSDK.dll 解剖 → 原厂 CPU/GPU 功耗再分配接口完整解码**（2026-11-19 14:3x）[静态·决定性]
HunterCamp(C:\Program Files\Honor\HunterCamp\) 的 SDK。中转 honor\hc1\；产物 tools\peinfo_hc1.txt、hc1\tools\strings\、tools\hnsdk_gpux_exports.txt、tools\hnsdk_setpower1.txt、tools\hnsdk_setpower2.txt、tools\hnsdk_wattbody.txt、tools\hnsdk_gpu2cpu.txt、tools\hfi_verify.txt、tools\hfi_core.txt。新增工具 **tools\fndump.py**（按导出名 dump 函数+IAT/字符串注释）、**tools\rawann.py**（任意 VA+长度线性反汇编+注释）。
- **HNSDK_SetGPUWattData(watt,temp,tcp)** @0x180038400 校验（原厂 UI 同源值域）：watt∈**[60,115]W**、temp∈**[75,87]℃**、tcp∈**[30,160]**（串 "maxTGP, tempLimit, targetTCP value out of range!"）→ 报文 **u8Input=[03,17,FF,watt,temp,tcp]** → ROOT\WMI GetOutPutUIntEx；out[0]!=0 失败（"SetGPUWatt WMI return ERROR!"）。**= HWMI 命令 03 17 = GPU TGP 三元组设置，正门在这里！**
- **HNSDK_SetGPUToCPUMaxPower(w)** @0x1800381c0：w∈{100..500 步进100}→idx=w/100+6(**7..11**)，经通用 sender 0x1800150f0(cl=3,dl=0x17)= 同一 03 17 族，报文 **[03,17,FF,idx,0,0]**（byte4/5=0 与 watt 区分，EC 侧语义待实测）；日志 "Get SetGPUToCPU Fail, outData[0] = %d"=有回读。串 "gpuToCpuDB value out of range!"=档位表校验。
- **HNSDK_SetCpuGpuRatio(ratio)** @0x180040ef0：报文 **[03,0F,ratio,05,0,0,0,0]**（inSize=8），失败日志带 GetOutPutUInt 错误码。**ratio 语义/值域未定**（UI 属性 Balance/IsSelectBalance 在 HUNTERCAMP.exe）。
- 同族确认 group03=**功耗预算族**：03 11 电池阈值/03 0F CpuGpuRatio/03 12 核心数/03 17 GPUwatt/03 D0 PowerLimit2(Util 路)。
- HUNTERCAMP.exe(.NET) 属性：MaxTGP/MaxTGPRange/GPUBase_MaxTGP/IsSetGpuPower/IsSetGpuTemp/Freq/Fan/Usage/Balance = 猎人营超频面板全量字段。
- **HNSDK_Set/GetNVCPPowerManagerMode = 进程内 std::map 查表**（[rip+0x8f7b0]，key=GPU id）非直通命令，忽略。
- ctlOverclockPowerLimitGet/Set(V2)+ctlPowerSetLimits 也在 HNSDK（Intel Arc GPU 路，本机 RTX 无关）。
- **交付 hn_wmi.ps1 v3**：新增 setwatt/setgpu2cpu/setratio/raw2；**所有写动作必须 -Yes**；带原厂值域校验；恢复方法=重启（TGP 非持久，前测已证）。setmode/setnoise/status 原样保留。

## 9.23 HFileInfo.dll 解剖 → **IPC 管道签名白名单实锤（IPC 直连路关闭）**（2026-11-19 14:3x）[静态·决定性]
honor\HFileInfo.dll(57,440B, PDB PCManager\sdk\Common\Util\FileInfo.cpp)。VerifyDigitalSignature(path,bool)→CORE 0x180003200：WinVerifyTrust→WTHelperProvDataFromStateData→Signer[0]/Cert→CertGetNameString→**wcsstr(名称, 白名单串)**。编译期内嵌白名单（W 串@0x180003448..0x1800036e5）：
`Honor Device Co., Ltd.`、`Zhuhai Kingsoft Office Software Co., Ltd.`、`Chengdu Qilu Technology Co. Ltd.`、`BeiJing IQIYI Science & Techonology Co.,Ltd`、`DingTalk Technology Co.,Ltd.`、`Beijing Yinxiang Biji Technologies Co. Ltd`。
→ **IPCMessage 管道客户端必须是上述六家之一的 Authenticode 签名进程**；powershell.exe(Microsoft)=拒。第三方走 IPC 总线=死路（不伪造签名，约束⑧）。**但 9.22 显示这些 IPC 消息的落点本来就是 HWMI WMI 命令——WMI 路管理员即可，无需签名**，此结论无害。
EsifDeviceInformation（acpi_hunt3\esif_wmi.txt）：**19 实例**=PCI\VEN_8086&DEV_7D03(PCH) 传感器阵列 _0.._18，Temperature 29-72℃ 活值、Ac0=67/Ac1=55 固定阈值、**_16 Power=55**；类方法=**EsifExecutePrimitive**（IPF 原语 WMI 入口，参数 schema 未 dump，桌面 DriverStore 命中 ipf_uf.exe/ipf_umdf2.dll 内含该类名——下轮从 Provider 二进制解 primitive 表）。桌面冒烟同轮修复：hn_ipf.ps1 BOM 回归（用户机报"鏈壘鍒?"乱码=无 BOM），已重加+PARSE OK。

## 9.24 写入实验方案（**待用户确认，任务书⑨**）
前置：AC 供电、猎人模式、开 hn_power.ps1 -Loop 采集 + nvidia-smi dmon 旁证。基线=双烤 CPU≈36/GPU≈115。
- **实验A（首选）**：`.\hn_wmi.ps1 setwatt 105 87 100 -Yes`（GPU TGP 105W，温度墙取原厂域上限 87，tcp=100 中性值）→ 双烤 60s 看 CPU 是否升到 ~45W。**风险**：tcp 语义未知（Target CPU Power? 平台项）；watt/temp 均在原厂 UI 域内=原厂允许状态。**恢复**：`setwatt 115 87 100 -Yes` 或**重启**（TGP 非持久）。
- 实验B（备选）：setgpu2cpu 500→400→300 阶梯 + 双烤观察（同 03 17 槽位，可能互踩，做完 A 再做）。
- 实验C（最后）：setratio 10/20/30 小步（语义未定，最低优先）。
每步：写后等 10s→双烤 60s→CSV 差分→异常（风扇满转不止/CPU>95℃ 不限速）立即重启。

## 9.25 ESIF 原语全表在 ipf_umdf2.dll 内嵌 → 仲裁只读观测+写侧镜像（2026-11-19 14:4x）[静态·决定性]
桌面 `ipf_cpu.inf_amd64_fe2967a6eb0d3a7d\ipf_umdf2.dll`（与笔记本同哈希包）扫出 **751 GET_* + 303 SET_/ENABLE_* 原语名**（esif_uf_primitive.c 内嵌名表；PDB C:\jenkins\workspace\dptf\Src\ESIF\…）。与本案直接相关的：
- 读：**GET_GPU_SPLIT_RATIO(_ACTIVE/_MAX/_AC_SUR/_DC_SUR)**（=DTT PowerShare 的 GPU 分割比，对应荣耀 03 0F/03 17 语义域）、**GET_PLATFORM_REST_OF_POWER**（平台总预算−其他参与者=CPU 剩余份额，36W 镜像的直接读出点）、**GET_NV_TGP_VALUE_AC/DC**（IPF 眼里当前的 NVIDIA TGP！）、GET_POWER_SHARE_POLICY_POWER/GET_POWER_SHARE_EFFECTIVE_BIAS/GET_POWER_SHARE_TEMPERATURE_THRESHOLD、GET_PLATFORM_POWER_LIMIT(_ENABLE/_TIME_WINDOW/_DUTY_CYCLE)、GET_EFFECTIVE_RAPL_POWER_LIMIT(+LOCK/_TIME_WINDOW/_MAX/_MIN)、GET_INSTANTANEOUS_POWER、GET_AC_PEAK_POWER、GET_ADAPTER_POWER_RATING、GET_PROC_THERMAL_DESIGN_POWER、GET_GT/IA_CLIP_REASONS、GET_INTELLIGENT_THERMAL_MANAGEMENT_TABLE、GET_POWER_BOSS_*_TABLE。
- 写：SET_GPU_SPLIT_RATIO(_MAX…)、SET_PLATFORM_REST_OF_POWER、SET_PLATFORM_POWER_LIMIT*、SET_POWER_SHARE_POLICY_POWER/EFFECTIVE_BIAS/TEMPERATURE_THRESHOLD、SET_NV_TGP_VALUE_SUR、SET_EFFECTIVE_RAPL_POWER_LIMIT(+_LOCK/_TIME_WINDOW) 等。
- 通道：`EsifDeviceInformation::EsifExecutePrimitive`（WMI 方法，笔记本存在/桌面不存在[本轮实测"找不到"]）；ipf_uf client 亦是同源（setp_pw/getp_pw mW）。**原语名→数字 ID 的映射表待从 ipf_umdf2 指针数组离线解析（下轮）**；方法参数 schema 需真机一行 dump：
  `(Get-CimClass root\wmi EsifDeviceInformation).CimClassMethods['EsifExecutePrimitive'].Parameters | Format-Table Name,CimType,Qualifiers -AutoSize`
- **层级判定实验设计（写完 03 17 后）**：读 GET_GPU_SPLIT_RATIO_ACTIVE 与 GET_NV_TGP_VALUE_AC——变=荣耀 HWMI 落 IPF/PowerShare 层（此后写走 IPF 原生=不竞争）；不变=HWMI 直通 EC/Punit（IPF 只是旁观者，写入需避让 DTT）。
- 教训固化：pwsh `>` 重定向产出 UTF-16 文件（hnsdk_setpower1.txt 读取需 [Text.Encoding]::Unicode）；`| Out-File -Encoding utf8` 才对。

## 9.26 setwatt 首测 FAIL(code=1) + ESIF 原语 ID 表离线解析成功 + 审计抓取方案（2026-11-19 14:5x）
- **[实机] 实验A 结果**：`setwatt 105 87 100 -Yes`（HWMI_0）→ 应答 `01 00...`= **EC 拒绝（out[0]=1）**，nvidia-smi 仍 115W cap，**系统状态无变化**（失败=无害拒绝）。可能原因（未定）：①EC 侧 gating（需猎人营"自定义"面板使能位/特定模式）；②03 17 仅特定机型开放（HNSDK 有 Is5070TiGpu 机型分叉）；③我们缺了原厂写入前的某条伴随命令；④实例应选 HWMI_1。
- **[静态·决定性] ESIF 原语 ID 表已离线解析**（ipf_umdf2.dll 单指针表 head=0x18011b838，16B stride，index=ID，GET/SET 混排 751 项）→ **tools\esif_primitive_ids.json**（751 条 name→id）。关键：GET_GPU_SPLIT_RATIO=**122**，_ACTIVE=**124**，_MAX=127，GET_NV_TGP_VALUE_AC=**189**，GET_PLATFORM_REST_OF_POWER=**245**，GET_PLATFORM_POWER_LIMIT=240，GET_POWER_SHARE_POLICY_POWER=**262**，GET_POWER_SHARE_EFFECTIVE_BIAS=**261**，GET_GT_CLIP_REASONS=132，GET_IA_CLIP_REASONS=148，GET_INSTANTANEOUS_POWER=156；SET_GPU_SPLIT_RATIO=**530**，SET_PLATFORM_POWER_LIMIT=603，SET_POWER_SHARE_EFFECTIVE_BIAS=619，SET_POWER_SHARE_POLICY_POWER=620。
- **EsifExecutePrimitive schema [实机]**：`inputData UInt8Array, instanceId UInt16, methodId UInt16, outputData(OUT), returnCode UInt32`。ipf_umdf2 dispatch=0x180045800（"Primitive result = %s"，工具产物 tools\esif_dispatch.txt）；**inputData 的序列化布局未解**（下一步从 0x180043dcc/0x1800413d0 继续或黑盒试错）。
- **[实机观察] ipf_uf.exe 有运行实例(pid 5768, 模块含 nvapi64)** = 某软件在跑 IPF 客户端/监视器；{18837DD8} 管道归属待定。
- **交付 honor_wmiact.ps1 v1.0**：OS 原生 WMIActivity 审计通道开→用户在猎人营 UI 点一次「应用 GPU 功率」→收集 ExecMethod 事件（实例名/方法名，不录参数）→自动关通道复原。零侵入抓原厂写入路径。
- hn_wmi.ps1 v3.1：`$env:HNWMI_INSTANCE='HWMI_1'` 可切实例重试。
- **下轮计划**：①用户看猎人营 UI 是否有 GPU 功率面板+值域（若 UI 可改成功→WMIActivity 抓原厂报文对比我们字节差；若 UI 无面板/灰→4060 机型固件未开放 03 17，转向 EsifExecutePrimitive 只读查询 DTT 内部值 124/189/245 判决 CPU 35W 的真实出处，再评估 SET_GPU_SPLIT_RATIO=530 写路径）②inputData 布局解析。

## 9.27 EC 层 03 17 判决关闭（4060 机型）+ B计划 IPF/DTT 层仪表交付（2026-11-19 15:1x）[实机+静态]
- **[实机] HWMI_1 同样 FAIL(code=1)** → 实例因素排除。
- **[实机] 猎人营 UI 无任何手动功率调节项**（用户确认+主页截图 huntercamp主页截图.png）：UI=智能/高能/狂战三档 tab + **五轴雷达(CPU/GPU/散热/静音/节能)=官方预设的功率偏置可视化** + 高刷新率/粘滞键/消息免打扰/逗逗陪玩/迅游/深度优化开关 + CPU/GPU 实时功率风扇温度表盘（19%/8%, 3840/3660RPM, 77/61℃——注意：表盘数据即 HNSDK 读取，证明其读通道活着）。
- **判决：03 17（EC TGP 三元组）在本机型被固件关门**（双实例拒 + 原厂 UI 无入口；HNSDK 代码路径服务的是 50 系等新机型, Is5070TiGpu 分叉佐证）。"降 TGP 抬 CPU"的 EC 正门 = 关闭，不尝试绕过。
- **B 计划（新战线）**：35W 钳制的执行层是 **DTT/IPF PowerShare 分割比**（§9.8 PL1mmio 85→54 单调降=PowerShare 手笔），而 IPF 侧 `SET_GPU_SPLIT_RATIO=530 / SET_POWER_SHARE_POLICY_POWER=620 / SET_POWER_SHARE_EFFECTIVE_BIAS=619` 是**另一层的原厂写入口**（不碰 EC/固件）。先建只读仪表验证可见性。
- **交付 hn_esif.ps1 v1.0（全只读）**：EsifExecutePrimitive(inputData,instanceId,methodId) 封装；原语表 **esif_primitive_ids.json**（751 项 name→id，脚本旁必须同拷）；动作 list/probe/get；**硬拒绝非 GET_* 原语**（call 动作禁用）。桌面冒烟：list OK、probe 正确报"无效类"（桌面该类不存在，笔记本存在）。
- ipf_umdf2 participant 管理串：`EsifUpPm_GetAvailableParticipantByInstanceLocked`（0x180043e96）→ **instanceId=participant 实例序号**，非 CIM 实例；19 个 CIM 实例只是 trip-point 数据行。probe 扫 0..47 找活 participant。
- 采集单（笔记本）：① `.\hn_esif.ps1 probe 2`（GET_ACTIVE_POWER_SCHEME）+ `probe PowerSharePolicy`（262）+ `probe 124` 结果全贴回；② honor_wmiact.ps1 改抓 **猎人营模式切换（智能↔狂战）** 的 WMI 事件（看原厂预设到底发哪些方法/实例）。
- 用户侧备忘：管家/猎人营臃肿带广告——待接口图完备后可整体卸载（HWMI WMI 通道独立于这些软件存活；仅 MSR 读数需保留 OS2SOC.sys 文件门路径）。

## 9.28 小更新（2026-11-19 15:2x）
- hn_esif.ps1 v1.1 **自含式**：751 原语 ID 表内嵌脚本（外部 json 可选覆盖），单文件可拷。桌面冒烟：list/probe 均走内嵌表（类缺失时正确报"无效类"）。
- WMIActivity 审计通道笔记本系统不存在（wevtutil 找不到信道）→ honor_wmiact.ps1 作废搁置；且用户判断确认：猎人营雷达图=展示层，模式 tab=我们已实现的 04 0F 三档 → **EC 预设写入面无遗漏，无新命令可抓**。B 计划唯一战线=IPF 原语（probe 三行见 §9.27 采集单）。

## 9.29 EsifExecutePrimitive 空数组拒绝根因（handler 反汇编定案）→ hn_esif v1.2（2026-11-19 15:3x）[静态·决定性]
provider 方法入口 = ipf_umdf2!0x180045800（tools\esif_dispatch.txt 全 130 行）：
- 参数解包：edx=instanceId(u32), r8=inputData CIM 数组, r9b=methodId(只取低字节→**methodId≤255?!**——表里 SET 原语 530+ 超界?待观察,GET 全部 <300 无碍), [rsp+0x110]=数据指针, [rsp+0x118]=OUT returnCode。
- **`test r8,r8 / je → edi=0x8FC`**：空数组被 WMI 框架传成 NULL → 立即"无效的参数"。**这解释了 probe 全灭**。
- 正常路径：0x180043dcc(instanceId)→participant（NULL→edi=0x898=instanceId 无效，**可用于扫活 participant**）→ 拼 6 字节头 `word[+0]=instanceId, word[+2]=inputData 长度, word[+4]=methodId` → 0x18003fd08(participant, &hdr, data, r9=4) 执行；日志 "Primitive result = %s"。
- **inputData 本身=纯 primitive payload**（无参 GET 用单字节 00 占位即可过 NULL 门）。
- hn_esif.ps1 v1.2：Invoke-Esif 空/缺省数据→强制 [byte[]](0x00)。probe 现在应返回 rc=0x898(死 inst)/0/其他错误码而非全 EXC。

### 9.29 补充：methodId 仅 8 位有效（hdr word[+4]=movzx r12d,r9b）→ id>255 原语（261/262/263 PowerShare 系）此 WMI 通道**截断禁用**，需 ipf_uf 管道；关键观测 122/124/127/132/148/156/189/240/242/245 全 ≤255 可用。hn_esif v1.2 加拦截；上一轮采集单中 probe 262 撤销，改 probe 245。

## 9.30 用户提供新杠杆：HWP Request Min/Max（TS Speed Shift）→ hn_epp.ps1 走原厂 OS2SOC 通道（2026-11-19 15:4x）
- User said (m01782 大意): ThrottleStop 把 Speed Shift min/max 都改成 57 可让功耗偏 CPU，但 TS 依赖的 WinRing0/throttlestop.sys 有漏洞报毒——要求研究 TS 实现后用**标准接口**自行实现。截图 throttlestop.png（TS Turbo Power Limits 页）。
- **[静态] TS 页面解码**：Speed Shift 行 Min 4 / Max 57 = **MSR 0x774 (IA32_HWP_REQUEST) bits[7:0]=MinPerf, [15:8]=MaxPerf**（非 EPP[31:24]）；SST Enabled=HWP 已启用(0x770[0])；**互证**：TS 显示 MSR PL1/PL2/Time=85/115/56、MMIO 75/115 —— 与 §9.7 真机 0x610 解码完全一致。
- **机制**：抬高 HWP min perf = CPU 常发高性能请求，Punit 预算器（§9.8 EDP 仲裁的上游请求方）向 CPU 倾斜；改的是"请求"不是"墙"，温度/电流保护链完整保留——与任务书④"不与控制器对抗"契合。用户实测有效 = 0x774 未被固件 lock 的实机证明。
- **实现（无 WinRing0）**：OS2SOCService.dll `ReadIntelMsrReg/WriteIntelMsrReg`（§9.3 ABI，IOCTL 0x224080/0x224064）= **管家自己的 MSR 驱动通道**，笔记本服务已在+路径门已过。交付 **hn_epp.ps1 v1.0**：
  * `show` 逐核(affinity 掩码轮 0..N-1)读 0x770/0x771/0x774 解码 min/max/des/epp+LOCKED 检测（只读）
  * `set <min> <max> -Yes`：预检逐核 HWP lock→备份全部原始 0x774→`epp_backup_ts.csv`→RMW 仅改 [15:0]（EPP/des 位保留）→逐核回读比对
  * `restore -Yes` 按最近备份写回；**重启=绝对恢复**（MSR 不持久）
  * `watch` 每2秒轮询前8核（看 OS/PEP 是否回头覆盖 min/max）
  * 桌面冒烟：Add-Type 编译过（修复 C# 路径反斜杠转义=`.Replace('\','\\')`，PS 单引号 `'\'`=1字符教训）；无驱动时正确走"读取失败"路径；无 -Yes 时零改动。
- **状态**：等笔记本 `show`（只读）→ 用户确认后 `set 57 57 -Yes` + hn_power -Loop 双烤对比 §9.8 基线（预期 CPU 镜像份额上升、GPU 回落；PL1mmio 动态下降是否缓解）。EsifExecutePrimitive 仪表(B计划仪表)因 WBEM_E_INVALID_PARAMETER(类路径 ExecMethod 待改)暂挂，EPP/HWP 路线优先。

## 9.31 HWP 直写被 PEP 覆写定案 → powercfg 官方属性路线 + hn_esif v1.3 类路径 ExecMethod（2026-11-19 16:0x）
- **[实机决定性] 0x774 直写不可保持**：用户 5 连 `set 57 57 -Yes`——每次被覆写的核**组合不同**、覆写值呈档位族 {min=07/0F/24/19, max=39/24/19}，= **Windows PEP/CPPC 按调度需求异步重算逐核 HWP_REQ**（非荣耀所为；用户 TS 同样锁不住、"以前可以现在不行"=Win11 PEP 行为变化）。EPP 位[31:24]=0x3F 全程未动。备份 csv 已在真机（restore -Yes 可用/重启复位）。
- **官方解法=改 PEP 的输入源（powercfg 电源属性，OS 自己写→永不回退）**，桌面已验证属性集（笔记本同）：
  * `893dee8e-2bef-41e0-89c6-b55d0929964c` = **最小处理器状态(CPMINPC)** → HWP min perf 来源
  * `36687f9e-e3a5-4dbf-b1dc-15eb381c6863/64/65` = **PERFEPP / PERFEPP1 / PERFEPP2** = 官方 EPP，**Class0/1/2 分开（P核/E核/LP-E 三档异类）**
  * `0cc5b647-...83/84` CPMINCORES1/2、`8baa4a8a-...` 处理器性能自主模式、`7f2f5cfa` 生效异类策略(iPPM)
- **hn_esif.ps1 v1.3**：Invoke-Esif 改 **System.Management 类路径 ExecMethod**（ManagementClass('root\wmi','EsifDeviceInformation').InvokeMethod + GetClassInstance 入参；ManagementScope.EnablePrivileges）——根因假设：Invoke-CimMethod 走 DMTF 宿主模式对该非标准 provider 报 0x80041008，类路径直激活 provider 可绕。错误输出带 WBEM 十六进制码。桌面冒烟正常（无类=预期错）。
- **[静态补] HNSDK_SetCpuGpuRatio(0x180040ef0)**：ratio 上限 **0x1F=31**（cmp rax,0x1f 双分支）；03 0F 命令 EC 侧是否接受=待测（03 17 被拒同组）。
- **ipf_uf 线复活**：hn_ipf v1.1（BOM 修好）从未真机跑过——若 client 管道通，`participants/getp_pw` 只读 + 官方写命令 `setp_pw/rstp` = 最正的 IPF 通道。
- 实验序列（发用户）：①restore -Yes 清基线 ②show→记 CPMINPC/PERFEPP* 原值(powercfg /q) ③setacvalueindex CPMINPC 80(AC)+PERFEPP 0 + setactive → watch 看 PEP 是否自写高 min ④hn_power -Loop 双烤对比 §9.8 基线 ⑤hn_esif v1.3 probe 2/124/245 ⑥hn_ipf v1.1 真机只读。

### 9.31 补充（2026-11-19 16:1x）：hn_ipf.ps1 v1.2 **纯 ASCII 重写**——用户笔记本上崩的仍是无 BOM 老拷贝(鏈壘鍒?乱码=GBK 误读 UTF-8)。教训固化：**分发链上 BOM 不可靠，脚本输出文本一律 ASCII 英文免灾**（hn_esif/hn_epp 等含中文脚本需提醒用户"整文件拷贝"而非剪贴板复制内容）。桌面冒烟：包装定位/管道清单/allpipes.txt 248条/ppkgs 7个 全通；ipf_uf.exe manifest=requireAdministrator（管理员运行 OK）。桌面 ipfsvc ImagePath 无 -i = 与笔记本预期同态 → 预判 client 连不上，[1] 失败分支已给 '-i 追加+重启服务' 的**待批准**修复步骤（可逆）。

### v1.4 修复（2026-11-19 16:2x）：hn_esif 真机报 ManagementClass 不含 GetClassInstance——**该方法在 ManagementClass 上不存在**（反射核实 False）；正确 API=**GetMethodParameters(String)**（反射确认存在）+ InvokeMethod(String,ManagementBaseObject,InvokeMethodOptions)（重载存在）。v1.4 已换+PARSE OK。真机 ipf 侧确认：管道 {18837DD8} 在听但非 client 端点、banner 后 Unable 被截流=预判一致，等 -i 实验。

## 9.32 ESIF 原语执行层解码（ipf_umdf2!0x18003fd08 = EsifUp_ExecuteSpecificActionPrimitive，rawann dump 0x340B）[静态·决定性]
调用链：handler 拼 tuple hdr {u16[0]=instanceId(=ESIF participant id), u16[2]=inputData len, u16[4]=methodId(=primitive id)} → 本函数：
- 三重 NULL 检查（participant/tuple/action selector）各自 → rc=**0x8FC(2300)**；
- 查 participant→[r13+0x10]=**DSP 指针**；NULL → 日志 "DSP is not found for participant %d" → rc=**0x961(2401)**；
- call [rip+0x946da](dsp, tuple) 按 hdr[0]/hdr[4] 匹配 (participantId,primitiveId)；未命中 → "The primitive id %d is not found in DSP"（rc 路径 0x961 附近）；
- 命中 → 原语 handler 执行，inputData 原样传给 handler（无额外头）。
**probe v1.4 返回码解读表**：rc=0 通；2300=participant 不存在（该 inst 死）或空参；2401=participant 活但无 DSP（PCH 传感器类实例，不服务原语）；其他值=进到原语层但 payload/权限拒。
participant 编号常识[社区]：0x01=FIVR? 实际以 2.0 probe 扫 0..47 结果为准，活者回非2300。
