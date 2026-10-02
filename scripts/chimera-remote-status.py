#!/usr/bin/env python3
"""chimera-remote-status.py — собирает статус Chimera-сервера как JSON.

Устанавливается на каждый Chimera-сервер в /usr/local/bin/chimera-remote-status.py
(chimera деплоит его при установке; см. docs/faq/TG_BOTS_FAQ.md).
Вызывается по SSH admin-ботом (на primary) для агрегации /status по каскаду.

v2 (03.10.2026): + mieru-каскад — mita, Exit-ы (healthy/total), живость
health-тика. Поля добавляются ТОЛЬКО при настроенном каскаде (роль entry
с включёнными Exit-ами) — старые форматы вывода не меняются; бот
показывает сегмент 🧅 Mieru только при наличии ключа.

Output: single JSON line on stdout:
  {"host":..., "xray":..., "proto":..., "port":..., "mode":..., "uptime":...,
   "mieru": {"ok":N, "total":M, "mita":"active", "stalled":false}}

Exit codes: 0 — статус собран; 1 — ошибка (редко; обычно нет state.json).
"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

STATE_FILE = '/var/lib/xray-installer/state.json'
MIERU_STATE = '/var/lib/xray-installer/mieru_cascade.json'
STALL_AFTER = 300   # сек без свежего last_check = health-тик умер

# Load state.json ( Chimera state — domain, protocol, port, mode, etc )
try:
    with open(STATE_FILE) as f:
        st = json.load(f)
except Exception:
    st = {}

# Collect hostname
try:
    host = subprocess.check_output(['hostname', '-s'], text=True).strip()
except Exception:
    host = '?'

# Check Xray service status
try:
    r = subprocess.run(['systemctl', 'is-active', 'xray'],
                       capture_output=True, text=True, timeout=5)
    xs = r.stdout.strip()
except Exception:
    xs = 'unknown'

# Get uptime
try:
    up = subprocess.check_output(['uptime', '-p'], text=True,
                                 stderr=subprocess.DEVNULL).strip()
except Exception:
    up = ''

out = {
    'host': host,
    'xray': xs,
    'proto': st.get('protocol_mode', '?'),
    'port': st.get('server_port', '?'),
    'mode': st.get('install_mode', '?'),
    'uptime': up,
}

# ── Mieru-каскад (v2): только при настроенном entry-каскаде ──────────────────
try:
    mcs = json.loads(Path(MIERU_STATE).read_text())
    exits = [e for e in mcs.get('exits', []) if e.get('enabled', True)]
    if mcs.get('role') == 'entry' and exits:
        n_ok = sum(1 for e in exits if e.get('healthy'))
        try:
            r2 = subprocess.run(['systemctl', 'is-active', 'mita'],
                                capture_output=True, text=True, timeout=5)
            mita = (r2.stdout or '').strip() or 'unknown'
        except Exception:
            mita = 'unknown'
        newest = 0.0
        for e in exits:
            v = e.get('last_check', '')
            try:
                ts = datetime.strptime(str(v), '%Y-%m-%d %H:%M:%S').timestamp()
                newest = max(newest, ts)
            except Exception:
                pass
        stalled = bool(newest) and (datetime.now().timestamp() - newest > STALL_AFTER)
        out['mieru'] = {
            'ok': n_ok, 'total': len(exits),
            'mita': mita, 'stalled': stalled,
        }
except Exception:
    pass   # каскад не настроен / файл не читается — поле не добавляем

# Print JSON to stdout (single line, no extra output)
print(json.dumps(out))
sys.exit(0)
