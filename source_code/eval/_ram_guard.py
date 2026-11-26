"""Proactive RAM guard for the FULL40 Qwen3.5 sweep (user-authorized, 2026-10-28).

Why this exists: watch_full40 only frees RAM *reactively* (after a reap already
killed the sweep). On a 24GB box the 11.5GB model leaves a thin margin, so a reap
can hit mid-run and waste ~20 min. This guard frees RAM *proactively* on a tight
2-min cadence, BEFORE pressure triggers a reap -> fewer lost runs, faster sweep.

Scope (user authz 2026-10-28, session-scoped): close ALL non-essential apps
INCLUDING Chrome/browsers -> free max RAM for Claude + the training. The standing
"never touch Chrome" rule is overridden only for this training session.
NEVER touched (hard allowlist by denylist-avoidance): the sweep (python
run_full40/one_run_seed), ollama / ollama app, llama-server (model + embedding),
this RAM guard, the Claude Code session (node/claude + its shell), and all OS /
shell / security procs (explorer, dwm, csrss, winlogon, services, System,
MsMpEng, SearchHost). Detached: survives the Claude session. Stops at 240/240.

Usage (launch detached):
  pythonw eval/_ram_guard.py
"""
import time, glob, subprocess, datetime
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
LOG = ROOT / "runs" / "_ram_guard.log"
DONE_MARK = ROOT / "runs" / "_full40_DONE.txt"
TARGET = 240

TRIGGER_GB = 2.6          # act early: keep a fat buffer above the ~1.2GB zone
                          # where mid-run reaps hit D's chromium (Playwright) spikes
PERIOD_S = 60             # 1-min cadence: catch pressure bursts before they kill a run
MAX_TICKS = 2500          # ~83h ceiling, far beyond any realistic sweep

# Non-essential apps to close (session authz: browsers incl. Chrome ARE closed).
# Deliberately excludes: training stack, ollama, llama-server, this guard, the
# Claude session + shell, IDEs the user may be coding in, and all OS/security procs.
SAFE = ["chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
        "brave.exe", "opera.exe", "PhoneExperienceHost.exe", "CrossDeviceService.exe",
        "WidgetService.exe", "Widgets.exe", "ChatGPT.exe", "codex.exe", "Copilot.exe",
        "GameBar.exe", "GameBarFTServer.exe", "Clipchamp.exe", "Teams.exe",
        "OUTLOOK.EXE", "Spotify.exe", "Discord.exe", "Slack.exe", "WhatsApp.exe",
        "Telegram.exe", "Notion.exe", "Acrobat.exe", "AcroRd32.exe"]


def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m))


def free_ram_gb():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"],
            capture_output=True, text=True, timeout=30).stdout.strip()
        return float(out) / 1024 / 1024
    except Exception as e:
        log("free_ram read error: %r" % e); return 99.0


def done_count():
    return len(glob.glob(str(ROOT / "runs" / "f40-*" / "report.json")))


def reclaim():
    killed = []
    for name in SAFE:
        r = subprocess.run(["taskkill", "/F", "/IM", name],
                           capture_output=True, text=True)
        if "SUCCESS" in (r.stdout or ""):
            killed.append(name.replace(".exe", ""))
    return killed


def main():
    log("ram-guard START (trigger<%.1fGB, every %ds, detached)" % (TRIGGER_GB, PERIOD_S))
    last_done = -1
    for _ in range(MAX_TICKS):
        if DONE_MARK.exists():
            log("DONE mark present -> ram-guard stop"); break
        done = done_count()
        if done >= TARGET:
            log("240/240 reached -> ram-guard stop"); break
        free = free_ram_gb()
        if free < TRIGGER_GB:
            killed = reclaim()
            time.sleep(2)
            after = free_ram_gb()
            log("CRITICAL %.2fGB -> freed %s -> %.2fGB  [%d/%d]"
                % (free, (killed or "nothing-idle"), after, done, TARGET))
        elif done != last_done:
            log("ok %.2fGB free  [%d/%d]" % (free, done, TARGET)); last_done = done
        time.sleep(PERIOD_S)
    log("ram-guard EXIT")


if __name__ == "__main__":
    main()
