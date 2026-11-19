# -*- coding: utf-8 -*-
# One-shot project reorganization: dedupe by hash, move binaries to vendored/,
# keep ANALYSIS-referenced research products under tools/ and data/.
import os, shutil, hashlib, sys

ROOT = r"C:\Users\hs-desktop\code\dsh_test\honor"
def p(*a): return os.path.join(ROOT, *a)

def md5(f):
    h = hashlib.md5()
    with open(f, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1<<20), b''):
            h.update(chunk)
    return h.hexdigest()

log = []
def move(src, dst, dedupe=True):
    """Move src->dst. If dst exists: same hash -> delete src (dedupe); else keep both (.alt suffix)."""
    s = p(src); d = p(dst)
    if not os.path.exists(s):
        log.append(f"SKIP(absent) {src}")
        return
    os.makedirs(os.path.dirname(d), exist_ok=True)
    if os.path.exists(d):
        if dedupe and md5(s) == md5(d):
            os.remove(s)
            log.append(f"DEDUP {src}  (identical to {dst})")
            return
        base, ext = os.path.splitext(d)
        i = 2
        while os.path.exists(f"{base}.alt{i}{ext}"): 
            if md5(s) == md5(f"{base}.alt{i}{ext}"):
                os.remove(s); log.append(f"DEDUP {src} (== alt{i})"); return
            i += 1
        d = f"{base}.alt{i}{ext}"
        shutil.move(s, d)
        log.append(f"MOVE(alt) {src} -> {d}")
        return
    shutil.move(s, d)
    log.append(f"MOVE {src} -> {dst}")

def rmtree(path, note=""):
    fp = p(path)
    if os.path.exists(fp):
        n = sum(len(fs) for _,_,fs in os.walk(fp))
        shutil.rmtree(fp)
        log.append(f"RMDIR {path} ({n} files) {note}")
    else:
        log.append(f"SKIP(absent) rmtree {path}")

def rm(path, note=""):
    fp = p(path)
    if os.path.exists(fp):
        os.remove(fp); log.append(f"DEL {path} {note}")
    else:
        log.append(f"SKIP(absent) {path}")

# ---------- 1. purge desktop smoke-test leftovers ----------
rmtree(r"_os2test", "smoke-test leftover")
rmtree(r"acpi_hunt_desktest", "smoke-test leftover")
rmtree(r"dtt_desktest", "smoke-test leftover")
rmtree(r"ipf_desktest", "smoke-test leftover")
rmtree(r"acpi_hunt2\ipf", "false-success ipf probe outputs (banner-only)")
rmtree(r"tools\__pycache__")
rm(r"tools\_probe64.ps1", "throwaway probe")
rm(r"tools\mp_strings_run.txt", "run log")
rm(r"tools\strings_hc1_run.txt", "run log")
rm(r"hn_wmiact.ps1", "abandoned: WMIActivity channel absent on target")

# ---------- 2. scripts ----------
for f in ["hn_wmi.ps1","hn_power.ps1","hn_esif.ps1","hn_ipf.ps1","hn_epp.ps1"]:
    move(f, os.path.join("scripts", f))
move("honor_acpi.ps1", r"scripts\collect_acpi.ps1")
move("honor_dtt.ps1",  r"scripts\collect_dtt.ps1")
move("honor_hc.ps1",   r"scripts\collect_hc.ps1")

# ---------- 3. samples ----------
move("hn_power_log.csv",  r"samples\stress_single_then_dual.csv")
move("hn_power_log2.csv", r"samples\stress_dual_lgc2400.csv")
move("hn_power_report.txt", r"samples\hn_power_once_report.txt")
move("throttlestop.png", r"samples\screenshot_throttlestop.png")
move("huntercamp主页截图.png", r"samples\screenshot_huntercamp_home.png")

# ---------- 4. vendored binaries (gitignored) ----------
BIN_EXT = ('.dll','.sys','.exe','.ppkg')
# 4a. root binaries -> vendored\pcmanager
ROOT_BINS = ["BlackMagic.dll","MonPowerPlugin.dll","MonProcessPlugin.dll","MonSysPerfPlugin.dll",
 "MonSysStatePlugin.dll","OS2SOCService.dll","PerfCommonPlugin.dll","PerformanceDetectPlugin.dll",
 "PowerPolicyPlugin.dll","MBAPluginsManager.dll","IPCMessage.dll","OS2SOC.sys","MonProcess.dll",
 "Util.dll","HHAL.dll","HNOs2EC10x64.sys","HFileInfo.dll","HnPerformanceCenter.exe"]
for f in ROOT_BINS:
    dst = r"vendored\huntercamp" if f in ("HFileInfo.dll",) else r"vendored\pcmanager"
    move(f, os.path.join(dst, f))
# 4b. plugin snapshot: whole dir keeps structure inside vendored; then dedupe files identical to pcmanager root
if os.path.isdir(p("acpi_hunt2\\plugins")):
    move("acpi_hunt2\\plugins", r"vendored\pcmanager\plugins")
    root_files = {f for f in os.listdir(p("vendored\\pcmanager")) if os.path.isfile(p("vendored\\pcmanager", f))}
    for f in list(root_files):
        a = p("vendored\\pcmanager", f)
        b = p("vendored\\pcmanager\\plugins", f)
        if os.path.isfile(b) and md5(a) == md5(b):
            os.remove(b); log.append(f"DEDUP plugins\\{f} (== pcmanager root copy)")
# 4c. DTT dlls: keep one set under vendored\dtt (acpi_hunt2\ddlls canonical, dtt1 dedupes against it)
for dirpath,_,files in os.walk(p("acpi_hunt2\\ddlls")):
    for f in files:
        src = os.path.relpath(os.path.join(dirpath,f), ROOT)
        move(src, os.path.join(r"vendored\dtt", f))
for dirpath,_,files in os.walk(p("dtt1")):
    if "ppm_x" in dirpath: continue
    for f in files:
        if f.lower().endswith(BIN_EXT):
            src = os.path.relpath(os.path.join(dirpath,f), ROOT)
            move(src, os.path.join(r"vendored\dtt", f))
# 4d. huntercamp snapshot binaries -> vendored\huntercamp
for dirpath,_,files in os.walk(p("acpi_hunt3\\huntercamp")):
    for f in files:
        if f.lower().endswith(BIN_EXT):
            src = os.path.relpath(os.path.join(dirpath,f), ROOT)
            move(src, os.path.join(r"vendored\huntercamp", f))
# 4e. hc1/hb1 staging binaries (mostly dup of huntercamp; hash-checked)
for stage in ["hc1","hb1"]:
    fp = p(stage)
    if os.path.isdir(fp):
        for f in os.listdir(fp):
            if f.lower().endswith(BIN_EXT):
                move(os.path.join(stage,f), os.path.join(r"vendored\huntercamp", f))
# staging dlls: mp1(MonProcess) util1(Util) ec1(EC sys) plg1(plugin snapshots)
for stage, dst in [("mp1", r"vendored\pcmanager"), ("util1", r"vendored\pcmanager"),
                   ("ec1", r"vendored\pcmanager"),
                   ("plg1", r"vendored\pcmanager\plugins")]:
    fp = p(stage)
    if os.path.isdir(fp):
        for f in os.listdir(fp):
            if f.lower().endswith(BIN_EXT):
                move(os.path.join(stage,f), os.path.join(dst, f))
# acpi_hunt\binaries (HHAL/HnPerformanceCenter copies)
for dirpath,_,files in os.walk(p("acpi_hunt\\binaries")):
    for f in files:
        src = os.path.relpath(os.path.join(dirpath,f), ROOT)
        move(src, os.path.join(r"vendored\pcmanager", f))

# ---------- 5. staging strings -> canonical tools\strings ----------
for stage in ["mp1","ec1","util1","hb1","hc1","plg1","dtt1"]:
    sd = p(stage, "tools", "strings")
    if os.path.isdir(sd):
        # rename map to disambiguate known alternate-version copies
        for f in os.listdir(sd):
            newname = f
            if stage in ("hc1","hb1"):
                newname = f.replace(".dll.strings.txt", ".huntercamp.dll.strings.txt").replace(".exe.strings.txt", ".huntercamp.exe.strings.txt")
                if f == "HFileInfo.dll.strings.txt": newname = "HFileInfo.huntercamp.dll.strings.txt"
            if stage == "plg1":
                pass
            move(os.path.join(stage,"tools","strings",f), os.path.join(r"tools\strings", newname))
# canonicalize: for each .altN stub pair under tools\strings, keep the LARGEST as canonical
import re as _re
sd = p("tools","strings")
groups = {}
for f in os.listdir(sd):
    stem = _re.sub(r"\.alt\d+", "", f)
    groups.setdefault(stem, []).append(f)
for stem, names in groups.items():
    if stem in names and len(names) > 1:
        biggest = max(names, key=lambda n: os.path.getsize(p("tools","strings",n)))
        if biggest != stem:
            os.remove(p("tools","strings",stem)); log.append(f"DEL stub tools\\strings\\{stem}")
            os.rename(p("tools","strings",biggest), p("tools","strings",stem))
            log.append(f"CANON tools\\strings\\{stem} <- {biggest}")
# tools\strings\MonProcess.dll.strings.txt currently a stale truncated stub -> replace from mp1 unless hash-equal handled
# (staging move above: mp1 copy went to tools\strings\MonProcess.dll.strings.txt -> name clash handled as .alt2. Fix: prefer the big one.)
import glob as _g
for cand in _g.glob(p("tools","strings","MonProcess.dll.alt*.strings.txt")) + _g.glob(p("tools","strings","MonProcess.dll.strings.alt*")):
    pass  # handled below in a manual step if needed

# ---------- 6. data ----------
move(r"policy", r"data\config\policy")
for f in ["plugincfg.xml","DeviceFuncSwitchConf.xml","MBAPowerManager.reg","命令记录.txt"]:
    move(f, os.path.join(r"data\config", f))
for d in ["acpi_hunt","acpi_hunt2","acpi_hunt3"]:
    if os.path.exists(p(d)):
        move(d, os.path.join("data", d))
move(r"dtt1\ppm_x", r"data\ppm_x")

# leftovers of staging dirs
for stage in ["mp1","ec1","util1","hb1","hc1","plg1","dtt1"]:
    rmtree(stage, "staging leftover")

# ---------- report ----------
rep = p("tools","reorganize_report.txt")
with open(rep, "w", encoding="utf-8") as fh:
    fh.write("\n".join(log))
print(f"done, {len(log)} actions, report: {rep}")
