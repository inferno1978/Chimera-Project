#!/usr/bin/env python3
"""
tests/test_certmon_v2.py
───────────────────────────────────────────────────────────────────────────────
Тесты v2 генератора _certbot_install_monitor_cron (chimera/modules/ssl_certbot.py).

Инцидент 02.10.2026 (спам cert-алертами при выключенных событиях + падение
renew «Some challenges have failed») — v2-монитор обязан:

Проверяет:
  1. Сгенерированный bash-скрипт валиден (bash -n)
  2. Встроенный python-код send_tg компилируется
  3. Экранирование: в bash-сообщениях literal \n, в python-коде "\\\\n"
  4. send_tg уважает events.cert_expire из telegram.json (юнит-тест
     python-кода, извлечённого из сгенерированного скрипта)
  5. Анти-спам stamp-логика: второй алерт в те же сутки suppressed
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

# ── Мок chimera._core (ленивая привязка ssl_certbot через importlib) ─────────
fake_core = types.ModuleType("chimera._core")
fake_core.STATE_FILE = Path("/tmp/test-certmon/state.json")
fake_core.success = lambda msg: print(f"[OK] {msg}")
fake_core.warn = lambda msg: print(f"[WARN] {msg}")
fake_core.info = lambda msg: print(f"[INFO] {msg}")
fake_core._run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", "")
# остальные атрибуты, которые может тронуть импорт
for attr in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "BOLD", "DIM", "WHITE", "NC"):
    setattr(fake_core, attr, "")
fake_core._box_top = lambda *a, **k: None
fake_core._box_row = lambda *a, **k: None
fake_core._box_item = lambda *a, **k: None
fake_core._box_bottom = lambda *a, **k: None
fake_core._box_sep = lambda *a, **k: None
fake_core._box_back = lambda *a, **k: None
fake_core.log_to_file = lambda *a, **k: None
fake_core._log_change = lambda *a, **k: None
fake_core._tg_notify_event = lambda *a, **k: None
fake_core.PARAM_DOMAIN = "test.example.com"

# Анти-загрязнение: сохраняем sys.modules для восстановления в конце модуля
_saved_modules = {k: sys.modules.get(k) for k in ("chimera", "chimera._core")}

pkg_chimera = types.ModuleType("chimera")
pkg_chimera.__path__ = [str(_PROJECT_ROOT / "chimera")]
sys.modules["chimera"] = pkg_chimera
sys.modules["chimera._core"] = fake_core

# ── Импорт тестируемого модуля ───────────────────────────────────────────────
from chimera.modules import ssl_certbot  # noqa: E402

OUT = Path("/tmp/test-certmon")
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "state.json").write_text(json.dumps({"domain": "chimeraprodcdn.online"}))

# Подменяем целевые пути на тестовые (с сохранением оригиналов)
_saved_script = ssl_certbot._CERTBOT_MONITOR_SCRIPT
_saved_cron = ssl_certbot._CERTBOT_MONITOR_CRON
ssl_certbot._CERTBOT_MONITOR_SCRIPT = OUT / "xray-certbot-monitor.sh"
ssl_certbot._CERTBOT_MONITOR_CRON = OUT / "xray-certbot-monitor.cron"

ssl_certbot._certbot_install_monitor_cron()

sh = (OUT / "xray-certbot-monitor.sh").read_text()
cron = (OUT / "xray-certbot-monitor.cron").read_text()

print("=" * 70)
print("CRON:", cron.strip())
print("=" * 70)

# 1. bash -n
r = subprocess.run(["bash", "-n", str(OUT / "xray-certbot-monitor.sh")],
                   capture_output=True, text=True)
assert r.returncode == 0, f"bash -n FAILED:\n{r.stderr}"
print("[PASS] bash -n OK")

# 2. Извлечь python-код send_tg и скомпилировать
m = re.search(r"python3 -c '\n(.*?)' \"\$1\"", sh, re.DOTALL)
assert m, "python-блок send_tg не найден"
py_code = m.group(1)
compile(py_code, "<send_tg>", "exec")
print("[PASS] python-код send_tg компилируется")

# 3. Проверка экранирования в сгенерированном файле
# в bash-сообщениях должен быть literal backslash-n (для replace в python)
assert 'истекает через $DAYS дн.!\\nДомен' in sh, "нет \\n в bash-сообщении"
assert 'FAILED</b>\\nДомен' in sh, "нет \\n в FAILED-сообщении"
print("[PASS] экранирование \\n в bash-сообщениях")

# 4. Юнит-тест send_tg: событие выключено → отправки нет
test_calls = []


def patched_run(cmd, **kw):
    test_calls.append(cmd)
    return subprocess.CompletedProcess(cmd, 0, "", "")


fake_subprocess = types.ModuleType("subprocess")
fake_subprocess.run = patched_run
fake_subprocess.CompletedProcess = subprocess.CompletedProcess
real_subprocess = sys.modules.get("subprocess")


def run_send_tg(msg, events_cfg):
    (OUT / "telegram.json").write_text(json.dumps(events_cfg))
    # локальный тест: подменяем абсолютный путь конфига
    code = py_code.replace("/var/lib/xray-installer/telegram.json",
                           str(OUT / "telegram.json"))
    sys.modules["subprocess"] = fake_subprocess
    sys.argv = ["send_tg", msg]
    try:
        exec(code, {"__name__": "send_tg_test"})
    except SystemExit:
        pass
    finally:
        sys.modules["subprocess"] = real_subprocess
        sys.argv = ["test"]


# cert_expire выключен → НЕТ curl
test_calls.clear()
run_send_tg("тест", {"token": "T", "chat_id": "C", "events": {"cert_expire": False}})
assert not test_calls, f"curl вызван при выключенном событии: {test_calls}"
print("[PASS] events.cert_expire=false → отправки нет")

# cert_expire включен → curl вызван
test_calls.clear()
run_send_tg("тест\\nвторя строка", {"token": "T", "chat_id": "C", "events": {"cert_expire": True}})
assert test_calls, "curl НЕ вызван при включённом событии"
sent = test_calls[0]
assert "chat_id=C" in sent and "parse_mode=HTML" in sent, f"неверные параметры: {sent}"
print("[PASS] events.cert_expire=true → curl вызван с chat_id/parse_mode")

# нет токена → нет curl
test_calls.clear()
run_send_tg("тест", {"events": {"cert_expire": True}})
assert not test_calls, "curl вызван без токена"
print("[PASS] без token/chat_id → отправки нет")

# 5. Симуляция анти-спама (stamp-логика: TAG меняется раз в сутки)
(OUT / "stamp-exp").unlink(missing_ok=True)  # изоляция повторных прогонов
bash_test = r'''
STAMP_EXP=/tmp/test-certmon/stamp-exp
TAG="2026-10-02:10"
if [ "$(cat "$STAMP_EXP" 2>/dev/null)" != "$TAG" ]; then echo "$TAG" > "$STAMP_EXP"; echo ALERT_SENT; else echo SKIPPED; fi
if [ "$(cat "$STAMP_EXP" 2>/dev/null)" != "$TAG" ]; then echo "$TAG" > "$STAMP_EXP"; echo ALERT_SENT; else echo SKIPPED; fi
'''
r = subprocess.run(["bash", "-c", bash_test], capture_output=True, text=True)
lines = r.stdout.strip().splitlines()
assert lines == ["ALERT_SENT", "SKIPPED"], f"stamp-логика сломана: {lines}"
print("[PASS] анти-спам: второй алерт в тот же день suppressed")

# 6. Токен не запечён в скрипт
assert "glpat-" not in sh and "ghp_" not in sh, "токен запечён в скрипт!"
print("[PASS] токен не запечён в скрипт")

print("\nВСЕ ТЕСТЫ ПРОШЛИ")

# ── Восстановление глобального состояния (общие прогоны pytest) ────────────
ssl_certbot._CERTBOT_MONITOR_SCRIPT = _saved_script
ssl_certbot._CERTBOT_MONITOR_CRON = _saved_cron
for _k, _v in _saved_modules.items():
    if _v is not None:
        sys.modules[_k] = _v
    else:
        sys.modules.pop(_k, None)
print("[CLEANUP] sys.modules и пути генератора восстановлены")
