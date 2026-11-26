"""Watcher for the FULL40 Qwen3.5 sweep (overnight, reap-resistant).
Called every ~15 min by a cron. Autonomous ops only (no user interaction):
  - count done report.json (target 240)
  - if a live meeting (Zoom CptHost) is active -> PAUSE: kill sweep + unload model, don't resume
  - elif sweep process dead and not done -> free RAM + relaunch sweep DETACHED (resume, skip-done)
  - if 240/240 done -> build final report, print DONE (cron then sends file + self-deletes)
Prints ONE status line the cron invocation can relay. Never touches Chrome/VSCode/meeting/system procs.
Usage: python eval/watch_full40.py"""
import os, sys, subprocess, glob, urllib.request, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
TARGET = 240
OUT = ROOT / "runs" / "_full40_sweep.out.log"
ERR = ROOT / "runs" / "_full40_sweep.err.log"
DONE_MARK = ROOT / "runs" / "_full40_DONE.txt"


def ps(cmd):
    try:
        return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                              capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception:
        return ""


def sweep_alive():
    # NB: match ANY interpreter (python.exe OR pythonw.exe). Launching via pythonw
    # propagates sys.executable=pythonw to the runner; filtering Name='python.exe'
    # missed it -> watcher kept relaunching -> stacked runners (fixed 2026-10-29).
    out = ps("(Get-CimInstance Win32_Process | "
             "Where-Object { $_.CommandLine -like '*run_full40_q35*' } | Measure-Object).Count")
    return out.strip().startswith(("1", "2", "3", "4", "5"))


def meeting_active():                           # Zoom in-call spawns CptHost.exe
    out = ps("(Get-Process CptHost -ErrorAction SilentlyContinue | Measure-Object).Count")
    return out.strip().startswith(("1", "2", "3"))


def unload_model():
    try:
        req = urllib.request.Request("http://localhost:11434/api/generate",
                                     data=json.dumps({"model": "qwen3.5:latest", "keep_alive": 0}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass


def free_ram():                                 # only clearly-idle, non-work apps (per standing authz)
    # NB: Chrome / VSCode / Zoom-meeting / OS procs sengaja TIDAK disentuh.
    for name in ("PhoneExperienceHost.exe", "CrossDeviceService.exe", "msedge.exe",
                 "msedgewebview2.exe", "ChatGPT.exe", "codex.exe"):
        subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)


def kill_sweep():
    out = ps("Get-CimInstance Win32_Process | "
             "Where-Object { $_.CommandLine -like '*run_full40_q35*' } | "
             "ForEach-Object { $_.ProcessId }")
    for pid in out.split():
        if pid.strip().isdigit():
            subprocess.run(["taskkill", "/F", "/PID", pid.strip()], capture_output=True)


def relaunch():
    DETACHED = 0x00000008 | 0x00000200          # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    with open(OUT, "a") as o, open(ERR, "a") as e:
        subprocess.Popen([sys.executable, str(ROOT / "eval" / "run_full40_q35.py")],
                         cwd=str(ROOT), stdout=o, stderr=e, creationflags=DETACHED, close_fds=True)


def main():
    done = len(glob.glob(str(ROOT / "runs" / "f40-*" / "report.json")))
    if done >= TARGET:
        # build final report
        r = subprocess.run([sys.executable, str(ROOT / "eval" / "build_fullsystem_report.py")],
                          cwd=str(ROOT), capture_output=True, text=True, timeout=600)
        DONE_MARK.write_text("done %d/%d\n%s" % (done, TARGET, r.stdout[-500:]), encoding="utf-8")
        print("DONE %d/%d report-built" % (done, TARGET)); return
    if meeting_active():
        kill_sweep(); unload_model()
        print("PAUSED-MEETING %d/%d (sweep dihentikan sementara, akan resume setelah meeting)" % (done, TARGET)); return
    if not sweep_alive():
        unload_model(); free_ram(); relaunch()
        print("RESUMED %d/%d (sweep mati -> RAM dibebasin -> relaunch detached)" % (done, TARGET)); return
    print("RUNNING %d/%d (sweep sehat)" % (done, TARGET))


if __name__ == "__main__":
    main()
