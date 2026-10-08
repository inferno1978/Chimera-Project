#!/usr/bin/env python3
"""chimera-remote-status.py — собирает статус Chimera-сервера как JSON.

Устанавливается на каждый Chimera-сервер в /usr/local/bin/chimera-remote-status.py
(chimera деплоит его при установке; см. docs/faq/TG_BOTS_FAQ.md).
Вызывается по SSH admin-ботом (на primary) для агрегации /status по каскаду.

v2 (03.10.2026): + mieru-каскад — mita, Exit-ы (healthy/total), живость
health-тика. Поля добавляются ТОЛЬКО при настроенном каскаде (роль entry
с включёнными Exit-ами) — старые форматы вывода не меняются; бот
показывает сегмент 🧅 Mieru только при наличии ключа.

v3 (08.10.2026): + AWG-каскад — роль (entry/exit), туннель awg1 и
routing-юнит, свежесть handshake (минимальный возраст по слотам
awg1..awgN), состав экзитов; в LB-режиме — стратегия, число слотов и
живых (state['lb']['alive'], пишет health-тик раз в минуту). Поле awg
добавляется ТОЛЬКО при настроенном каскаде (cascade_role в
awg_standalone_state.json) — старые форматы не меняются; бот показывает
сегмент 🛡 AWG только при наличии ключа.

Output: single JSON line on stdout:
  {"host":..., "xray":..., "proto":..., "port":..., "mode":..., "uptime":...,
   "mieru": {"ok":N, "total":M, "mita":"active", "stalled":false},
   "awg": {"role":"entry", "awg1":true, "routing":true, "hs":70,
            "exits":5, "lb":true, "strategy":"smart", "slots":5,
            "alive":5}}

Exit codes: 0 — статус собран; 1 — ошибка (редко; обычно нет state.json).
"""
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

STATE_FILE = '/var/lib/xray-installer/state.json'
MIERU_STATE = '/var/lib/xray-installer/mieru_cascade.json'
AWG_STATE = '/var/lib/xray-installer/awg_standalone_state.json'
STALL_AFTER = 300   # сек без свежего last_check = health-тик умер
LB_MAX_SLOTS = 10   # защитный потолок перебора awg1..awgN (как AWGS_LB_MAX_SLOTS)

# ── Хелперы (v3) ─────────────────────────────────────────────────────────────
def _svc_active(unit):
    """systemctl is-active <unit> → bool (False при любой ошибке)."""
    try:
        r = subprocess.run(['systemctl', 'is-active', unit],
                           capture_output=True, text=True, timeout=5)
        return (r.stdout or '').strip() == 'active'
    except Exception:
        return False


def _hs_age(text):
    """Парсит 'latest handshake: 1 minute, 10 seconds ago' → 70 (сек).

    Зеркало awg_cascade._awgs_cascade_parse_handshake_age (та же
    грамматика вывода `awg show`). Нет строки handshake → None.
    Чистая функция (тестируется без сервера).
    """
    m = re.search(r'latest handshake:\s*(.+?)\s+ago', text or '')
    if not m:
        return None
    total, found = 0, False
    for part in m.group(1).split(','):
        pm = re.match(r'(\d+)\s+(second|minute|hour|day|week)s?',
                      part.strip())
        if pm:
            found = True
            mult = {'second': 1, 'minute': 60, 'hour': 3600,
                    'day': 86400, 'week': 604800}[pm.group(2)]
            total += int(pm.group(1)) * mult
    return total if found else None


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

# ── AWG-каскад (v3): только при настроенной роли (entry/exit) ────────────────
try:
    awst = json.loads(Path(AWG_STATE).read_text())
    arole = awst.get('cascade_role', '')
    if arole == 'entry':
        all_exits = awst.get('cascade_exits') or []
        # Эффективный состав: LB-фильтр lb_exits (пусто = все)
        sel = awst.get('lb_exits') or None
        eff = [e for e in all_exits if (not sel or e.get('name') in sel)]
        n_eff = min(len(eff), LB_MAX_SLOTS)
        # Свежий handshake по слотам awg1..awgN (LB) или awg1 (single)
        hs = None
        for i in range(1, n_eff + 1):
            try:
                r = subprocess.run(['awg', 'show', 'awg%d' % i],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    age = _hs_age(r.stdout or '')
                    if age is not None and (hs is None or age < hs):
                        hs = age
            except Exception:
                pass
        awg = {
            'role': 'entry',
            'awg1': _svc_active('awg-quick@awg1'),
            'routing': _svc_active('awg-cascade-routing'),
            'hs': hs,
            'exits': len(all_exits),
        }
        if awst.get('lb_mode') and n_eff >= 2:
            alive = awst.get('lb', {}).get('alive') or []
            eff_names = {e.get('name') for e in eff}
            awg['lb'] = True
            awg['strategy'] = awst.get('lb_strategy', '')
            awg['slots'] = n_eff
            awg['alive'] = len([a for a in alive if a in eff_names])
        else:
            awg['active'] = awst.get('cascade_active_exit', '')
        out['awg'] = awg
    elif arole == 'exit':
        out['awg'] = {
            'role': 'exit',
            'awg0': _svc_active('awg-quick@awg0'),
        }
except Exception:
    pass   # AWG не настроен / файл не читается — поле не добавляем

# Print JSON to stdout (single line, no extra output)
print(json.dumps(out))
sys.exit(0)
