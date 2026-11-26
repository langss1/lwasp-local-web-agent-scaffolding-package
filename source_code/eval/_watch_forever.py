"""Detached 15-min watcher loop.
Dilepas via Start-Process (hidden) -> BUKAN shell yang dikelola Claude Code,
jadi tidak ikut di-reap saat RAM sesak dan tetap hidup walau sesi Claude berakhir.
Berhenti sendiri saat 240/240 (watch_full40 menulis _full40_DONE.txt)."""
import time, subprocess, sys, datetime
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
PY = sys.executable
LOG = ROOT / "runs" / "_watch_forever.log"


def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m))


log("forever-watcher START (detached, 15-min)")
for i in range(400):                                   # 400 x 15 mnt ~ 4 hari, cukup
    try:
        subprocess.run([PY, str(ROOT / "eval" / "watch_full40.py")],
                       cwd=str(ROOT), timeout=700)
    except Exception as e:
        log("watch error: %r" % e)
    if (ROOT / "runs" / "_full40_DONE.txt").exists():
        log("DONE terdeteksi -> loop berhenti")
        break
    time.sleep(900)
log("forever-watcher EXIT")
