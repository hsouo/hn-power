# hn-power — 荣耀 MagicBook 电源控制接口研究

> 对荣耀电脑管家（PCManager）/ 猎人营地（HunterCamp）电源管理组件的逆向研究成果，
> 以及基于原厂已签名组件的**自用**电源控制脚本集。
>
> 目标机型（已实机验证）：**MagicBook Pro 16 HUNTER 2024**（Core Ultra 5 125H + RTX 4060 Laptop）
> 同接口家族机型（华为/荣耀 MagicBook，HWMI WMI 数据块相同）大概率兼容，未逐一验证。
>
> 完整逆向过程、证据分级（静态 / 社区互证 / 实机验证）见 [ANALYSIS.md](ANALYSIS.md)。

## 目录

- [能力现状](#能力现状)
- [快速开始：切换电源模式](#快速开始切换电源模式)
- [脚本清单](#脚本清单)
- [依赖文件从哪里来](#依赖文件从哪里来)
- [接口原理速查](#接口原理速查)
- [目录结构](#目录结构)
- [安全与免责](#安全与免责)

---

## 能力现状

| 能力 | 状态 | 入口 |
|---|---|---|
| 读取电源模式（智能/高性能/猎人） | ✅ 实机验证 | `hn_wmi.ps1 status` |
| 设置电源模式 | ✅ 实机验证（含事件回读） | `hn_wmi.ps1 setmode` |
| 读温度 / 风扇转速 / 电池充电阈值 / 背光档位 | ✅ 实机验证 | `hn_wmi.ps1 status` |
| 监听原厂模式切换事件（FN+P 热键等） | ✅ 实机验证 | `hn_wmi.ps1 events` |
| 综合功耗监控（PL1/PL2、封装瓦数、GPU 瓦数、风扇） | ✅ 实机验证 | `hn_power.ps1` |
| 静音/性能档（噪声模式）设置 | ⚠️ 接口已定位，档位映射**未实机标定** | `hn_wmi.ps1 setnoise` |
| CPU/GPU 联合功耗再分配（偏 CPU 策略） | 🚧 研究中（EC 层已确认对第三方关闭，转 IPF/DTT 层） | `hn_esif.ps1` / `hn_ipf.ps1` |
| HWP Speed Shift min/max 直写 | ⛔ 已定案：被 Windows PEP 事件驱动覆写，暂停 | （历史见 ANALYSIS §9.31） |

**卸载电脑管家的影响**：WMI 通道（`OemWMIMethod`）由系统 ACPI 驱动提供，**与管家进程无关，卸载后依然可用**。
仅 `hn_power.ps1` 的 OS2SOC 段依赖原厂 `OS2SOCService.dll` + `OS2SOC.sys` 驱动（见下文）。

---

## 快速开始：切换电源模式

这是最核心的功能，**不需要任何依赖文件**，任何 PowerShell 直接可用。

### 1. 拷贝脚本

把 [`scripts/hn_wmi.ps1`](scripts/hn_wmi.ps1) 拷贝到目标笔记本的任意目录。

> ⚠️ **整文件拷贝**。脚本含中文注释（UTF-8 BOM 编码），如果通过剪贴板/聊天工具传"内容"，
> BOM 丢失会导致 PowerShell 5.1 报一堆假语法错误。

### 2. 以管理员身份打开 PowerShell

普通用户会因 WMI 数据块权限被拒。可选方案：

- 直接管理员 PowerShell；或
- 一次性给当前用户授权（脚本内置，管理员跑一次，重启后由 `WMI\Security` DACL 持久化）：

  ```powershell
  .\hn_wmi.ps1 grant
  ```

### 3. 使用

```powershell
# 查看当前状态：电源模式 / CPU与SOC温度 / 双风扇转速 / 电池充电阈值 / 背光档
.\hn_wmi.ps1 status

# 切换电源模式：0=智能均衡  1=高性能  3=猎人模式
.\hn_wmi.ps1 setmode 1
.\hn_wmi.ps1 setmode 3
.\hn_wmi.ps1 setmode 0

# 实时监听原厂模式事件（另一个窗口挂着它，按 FN+P 或在系统内切换都能看到）：
#   0x2A0=退出高性能  0x2A1=进入高性能  0x2A6=热键  0x2A8=猎人模式
.\hn_wmi.ps1 events

# 噪声/静音模式（1~3；⚠️ 档位与"静音/均衡/性能"声学的映射未实机标定，慎用）
.\hn_wmi.ps1 setnoise 1

# 原始命令通道（group + cmd + 可选值，全部十六进制）——用于探索未知命令
.\hn_wmi.ps1 raw 04 0E          # 例：读电源模式
.\hn_wmi.ps1 raw 02 08 00       # 例：读 0 号风扇
```

### 4. 硬件约束（原厂固件行为，脚本无法绕过）

- **高性能/猎人模式要求 AC 供电且电量 ≥ 20%**，电池供电时 `setmode 1/3` 会被固件拒绝；
- 猎人模式还会联动风扇激进曲线，属正常现象。

### 5. 在其他程序里调用（C# 最小示例）

```csharp
var scope = new ManagementScope(@"\\.\root\wmi");
scope.Connect();
// 实例：优先 HWMI_0（原厂管家也用它；部分机型另有 HWMI_1）
var inst = new ManagementObject(scope,
    new ManagementPath("OemWMIMethod=@\"ACPI\\PNP0C14\\HWMI_0\""), null);
var inParams = inst.GetMethodParameters("OemWMIfun");
var buf = new byte[64];
buf[0] = 0x04; buf[1] = 0x0F; buf[2] = 0x01;      // 设置高性能
inParams["u8Input"] = buf;
var outParams = inst.InvokeMethod("OemWMIfun", inParams, null);
var resp = (byte[])outParams["u8Output"];
bool ok = resp != null && resp.Length > 0 && resp[0] == 0;   // 0=成功
```

---

## 脚本清单

全部位于 [`scripts/`](scripts/)。所有脚本**默认只读**；写操作要么只写原厂定义的模式命令，要么显式 `-Yes` 门槛。

### 控制 / 观测

| 脚本 | 作用 | 依赖 | 权限 |
|---|---|---|---|
| `hn_wmi.ps1` | 电源模式读写、传感器、事件、grant | 无 | 管理员（或 grant 后的普通用户） |
| `hn_power.ps1` | 综合功耗探针：WMI 传感器 + OS2SOC MSR 读数（PL1/PL2、0x611 能量差分瓦数）+ nvidia-smi + powercfg。`-Loop [-IntervalSec N]` 出 CSV | 同目录放 `OS2SOCService.dll`（缺省自动跳过该段） | 管理员 |
| `hn_epp.ps1` | HWP 0x774 min/max 逐核读写（经 OS2SOC 驱动，非 WinRing0）。**实验性**：写会被 Windows PEP 覆写（ANALYSIS §9.31） | `OS2SOCService.dll` | 管理员 |
| `hn_esif.ps1` | Intel IPF/DTT `EsifExecutePrimitive` 只读探针（`list/probe/get`，硬拒非 GET 原语） | 无 | 管理员 |
| `hn_ipf.ps1` | 原厂 `ipf_uf.exe` 只读客户端探针（participants/capture 等） | 无（自动定位 DriverStore） | 管理员 |

`hn_power.ps1` / `hn_epp.ps1` 的 OS2SOC 说明：`OS2SOCService.dll` 内部按固定相对路径
`<dll所在目录>\..\PCManager\mainframe\Plugins\OS2SOC.sys` 自检驱动文件是否存在。
- **电脑管家正常安装时**：把 dll 放脚本旁即可，服务已注册，直接可用；
- **卸载/删除管家后**：需 `sc query OS2SOC` 确认服务仍在，并把 `OS2SOC.sys` 放到 dll 拼出的那个路径（或在同盘符建 `C:\Users\<任意用户名>\..\PCManager\mainframe\Plugins\OS2SOC.sys` 等价目录）；否则 dll 会打印 `The driver path incorrect` 并返回 false（无副作用，脚本自动跳过该段）。

### 采集（复现我的研究用）

| 脚本 | 作用 |
|---|---|
| `collect_acpi.ps1` | 5 步只读采集：ACPI 全表 / WMI 类 schema / PNP 设备 / 服务与驱动 / 注册表（v1.1，产物落 `.\acpi_hunt\`） |
| `collect_dtt.ps1` | DTT/IPF 配置 + PCManager plugins 目录快照采集（产物落 `.\acpi_hunt2\`） |
| `collect_hc.ps1` | HunterCamp 目录 + Esif WMI 实例 + 进程模块清单（产物落 `.\acpi_hunt3\`） |

> 曾用名映射：`honor_acpi.ps1`→`collect_acpi.ps1`，`honor_dtt.ps1`→`collect_dtt.ps1`，
> `honor_hc.ps1`→`collect_hc.ps1`；`honor_wmiact.ps1` 已删除（WMIActivity 审计通道在目标机不可用）。
> ANALYSIS.md 为历史日志，仍按旧名引用。

---

## 依赖文件从哪里来

本仓库**不包含也不分发任何荣耀/Intel 原厂二进制**（见 [.gitignore](.gitignore)）。
如需 `hn_power.ps1`/`hn_epp.ps1` 的完整功能，从你自己的笔记本拷贝：

| 文件 | 笔记本上的位置 |
|---|---|
| `OS2SOCService.dll` | `C:\Program Files\Honor\PCManager\mainframe\plugins\`（HunterCamp 另有一份新版，别混用） |
| `OS2SOC.sys` | `C:\Program Files\Honor\PCManager\mainframe\Plugins\` |

`hn_wmi.ps1`、`hn_esif.ps1`、`hn_ipf.ps1`、`collect_*.ps1` 无外部文件依赖。

---

## 接口原理速查

详细论证见 ANALYSIS.md（§7.6 命令表、§9.x 功耗架构）。核心事实：

- **WMI 通道**：`root\wmi` 的 `OemWMIMethod` 类（实例 `ACPI\PNP0C14\HWMI_0`，部分机型还有 `HWMI_1`），
  方法 `OemWMIfun`，入参 `u8Input` = 64 字节缓冲（`[0]=组 [1]=命令 [2]=值`，小端 16 位命令字），
  出参 `u8Output[0]==0` 为成功。命令族：`04` 电源模式、`02` 传感器、`06` 显示/背光、`11` 电池、`07/0C` 噪声、`03 D0` PL2 覆写（原厂内部）。
  数据块 GUID：`abbc0f5b-8ea1-11d1-a000-c90629100000`。
- **事件通道**：`OemWMIEvent`，属性 `Force` 低 16 位 = 事件码（模式切换/热键/背光/麦克风等）。
- **MSR 直读通道**：`OS2SOCService.dll` → `\\.\OS2SOC`（原厂 WHQL 驱动，chipsec 改造），
  IOCTL 见 ANALYSIS §9.3（`0x22404x–0x22408x`：PL1/PL2 读写、MSR/MMIO 读写）。DACL 仅 SYSTEM/Administrators。
- **已确认的控制边界**：CPU/GPU 联合功耗包络由 **EC+IPF(DTT) 仲裁**（§9.8：双烤 CPU≈总包络−GPU）；
  EC 侧的分配比例写入（`03 17` 等）对本机型固件关闭；GPU TGP 表在 BIOS/EC 的 ACPI `\_SB.NPCF`（NVPCF）里，
  `nvidia-smi -pl` 笔记本禁写。第三方合规路线=IPF/DTT 层 PowerShare 策略，仍在研究（`hn_esif.ps1`/`hn_ipf.ps1`）。

---

## 目录结构

```
hn-power/
├── README.md            本文件
├── ANALYSIS.md          逆向分析日志（按时间追加，含证据分级标注）
├── LICENSE              MIT（本仓库自产脚本与文档）
├── scripts/             控制/观测/采集 PowerShell 脚本（日常只需这一层）
├── tools/               逆向工具链（pefile+capstone 系列：peinfo/strings/disas/xrefdis/rawann/fndump…）
│   └── strings/         各 PE 的字符串提取产物
├── samples/             实机烤机 CSV / 报告样例、截图
├── data/                （.gitignore 排除）真机采集数据包：ACPI 表、plugins 快照、HunterCamp 快照等
└── vendored/            （.gitignore 排除）荣耀/Intel 原厂二进制存放处，不分发
```

---

## 安全与免责

- 本项目用于**自己拥有的设备**上的接口研究与学习。所有脚本默认只读；已实机验证的写操作仅限原厂定义的模式切换命令。
- 功耗/电压相关写操作可能触发保护（降频/关机）或影响硬件寿命。任何写实验前请确认散热环境，并知晓恢复手段（多数状态**重启即复位**）。
- 不绕过驱动白名单/DACL 等权限机制，不修改 BIOS/EC 固件，不引入未签名内核驱动——这是本研究的硬约束。
- 荣耀/Intel/NVIDIA 的商标、二进制与固件版权归各自所有者；本仓库仅包含自产脚本、分析与开源参考（`tools/ref_*.cs` 摘自社区项目 [Honor-PC-Helper](https://github.com/Wintego/Honor-PC-Helper)，MIT）。
- THE SOFTWARE IS PROVIDED "AS IS", SEE [LICENSE](LICENSE).
