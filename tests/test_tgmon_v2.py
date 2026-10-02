#!/usr/bin/env python3
"""
tests/test_tgmon_v2.py
───────────────────────────────────────────────────────────────────────────────
Тесты v2 генератора _install_monitor_cron (chimera/modules/tg_bot.py).

Инцидент 02.10.2026 (спам cert-алертами каждые 5 минут при выключенных
событиях, до 288 алертов/сутки) — v2-монитор обязан:

Проверяет:
  1. bash -n сгенерированного скрипта
  2. python-код send компилируется
  3. send уважает events.<event> (cert_expire выкл / xray_down выкл)
  4. {H} → [host | ip], \n → newline
  5. cert-часть содержит анти-спам TAG/stamp + сброс при продлении
  6. токен/chat_id НЕ запечены в скрипт (читаются из telegram.json)
"""
from __future__ import annotations

import sys
import types
import subprocess
import json
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

OUT = Path("/tmp/test-tgmon")
OUT.mkdir(parents=True, exist_ok=True)

# ── Импорт тестируемого модуля ───────────────────────────────────────────────
import chimera.modules.tg_bot as tg_bot  # noqa: E402

# Мок окружения: конфиг и cron-файл — в тестовую директорию
# (оригиналы сохраняем — восстановим в конце для общих прогонов pytest)
_saved_notif = tg_bot._NOTIF_FILE
_saved_svc = tg_bot._MONITOR_SVC
tg_bot._NOTIF_FILE = OUT / "telegram.json"
tg_bot._MONITOR_SVC = OUT / "xray-tg-monitor.cron"

cfg = {"token": "TESTTOKEN", "chat_id": "12345",
       "server_ip": "203.0.113.103",
       "events": {"xray_down": True, "xray_up": True, "cert_expire": True}}
(OUT / "telegram.json").write_text(json.dumps(cfg))

# Скрипт пишется по абсолютному пути /usr/local/bin/xray-tg-monitor.sh —
# перехватываем Path.write_text для этого пути (реальная ФС не трогается).
real_write_text = Path.write_text
captured = {}


def spy_write_text(self, data, *a, **kw):
    if str(self) == "/usr/local/bin/xray-tg-monitor.sh":
        captured[str(self)] = data
        (OUT / "xray-tg-monitor.sh").write_text(data)
        return len(data)
    return real_write_text(self, data, *a, **kw)


Path.write_text = spy_write_text
try:
    tg_bot._install_monitor_cron()
finally:
    Path.write_text = real_write_text

sh = (OUT / "xray-tg-monitor.sh").read_text()
cron = (OUT / "xray-tg-monitor.cron").read_text()
print("CRON:", cron.strip())
print("=" * 70)

# 1. bash -n
r = subprocess.run(["bash", "-n", str(OUT / "xray-tg-monitor.sh")],
                   capture_output=True, text=True)
assert r.returncode == 0, f"bash -n FAILED:\n{r.stderr}"
print("[PASS] bash -n OK")

# 2. python-код send компилируется
m = re.search(r"python3 -c '\n(.*?)' \"\$1\" \"\$2\"", sh, re.DOTALL)
assert m, "python-блок send не найден"
py_code = m.group(1)
compile(py_code, "<send>", "exec")
print("[PASS] python-код send компилируется")

# 3. Юнит-тест send: проверка events
test_calls = []


def patched_run(cmd, **kw):
    test_calls.append(cmd)
    return subprocess.CompletedProcess(cmd, 0, "", "")


fake_subprocess = types.ModuleType("subprocess")
fake_subprocess.run = patched_run
fake_subprocess.CompletedProcess = subprocess.CompletedProcess
real_subprocess = sys.modules.get("subprocess")


def run_send(event, msg, events_cfg):
    (OUT / "telegram.json").write_text(json.dumps(events_cfg))
    code = py_code.replace("/var/lib/xray-installer/telegram.json",
                           str(OUT / "telegram.json"))
    sys.modules["subprocess"] = fake_subprocess
    sys.argv = ["send", event, msg]
    try:
        exec(code, {"__name__": "send_test"})
    except SystemExit:
        pass
    finally:
        sys.modules["subprocess"] = real_subprocess
        sys.argv = ["test"]


base = {"token": "T", "chat_id": "C", "server_ip": "1.2.3.4"}

# cert_expire выкл → нет curl
test_calls.clear()
run_send("cert_expire", "🔒 <b>{H}</b> тест", {**base, "events": {"cert_expire": False}})
assert not test_calls, f"curl при выключенном cert_expire: {test_calls}"
print("[PASS] events.cert_expire=false → отправки нет")

# xray_down выкл, но cert_expire вкл → cert уходит
test_calls.clear()
run_send("cert_expire", "🔒 <b>{H}</b> тест", {**base, "events": {"cert_expire": True, "xray_down": False}})
assert test_calls, "curl НЕ вызван при включённом cert_expire"
text_arg = [a for a in test_calls[0] if a.startswith("text=")][0]
assert "[host" not in text_arg  # header подставляется реальный hostname
assert "1.2.3.4" in text_arg, f"server_ip не в header: {text_arg}"
print("[PASS] events.cert_expire=true → curl, header содержит server_ip")

# xray_down выкл → xray_down не уходит
test_calls.clear()
run_send("xray_down", "🔴 тест", {**base, "events": {"xray_down": False}})
assert not test_calls, f"curl при выключенном xray_down: {test_calls}"
print("[PASS] events.xray_down=false → отправки нет")

# \n → newline, {H} → header
test_calls.clear()
run_send("cert_expire", "line1\\nline2 {H}", {**base, "events": {"cert_expire": True}})
text_arg = [a for a in test_calls[0] if a.startswith("text=")][0]
assert "line1\nline2" in text_arg and "{H}" not in text_arg, f"\\n/H не обработаны: {repr(text_arg)}"
print("[PASS] \\n → newline, {H} → header")

# 4. Анти-спам cert-части в bash
assert 'TAG="$(date ' in sh and "$STAMP_CERT" in sh, "нет stamp-логики"
assert 'rm -f "$STAMP_CERT"' in sh, "нет сброса stamp при продлении"
print("[PASS] cert-часть: TAG + stamp + сброс")

# 5. Токен не запечён
assert "TESTTOKEN" not in sh, "ТОКЕН ЗАПЕЧЁН В СКРИПТ!"
print("[PASS] токен не запечён в скрипт")

print("\nВСЕ ТЕСТЫ ПРОШЛИ")

# ── Восстановление глобального состояния (общие прогоны pytest) ──────────
tg_bot._NOTIF_FILE = _saved_notif
tg_bot._MONITOR_SVC = _saved_svc
print("[CLEANUP] _NOTIF_FILE/_MONITOR_SVC восстановлены")
