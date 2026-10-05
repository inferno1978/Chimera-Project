"""
chimera/modules/awg_cascade_lb.py
───────────────────────────────────────────────────────────────────────────────
Балансировка мульти-exit каскада AmneziaWG (порт mieru_cascade, 05.10).

До этого каскад держал ОДИН активный туннель awg1 (failover: смерть
активного → перезапись awg1.conf на следующий exit). LB-режим поднимает
ВСЕ туннели одновременно — awg1..awgN, слот = позиция exit в
cascade_exits — и распределяет НОВЫЕ соединения между ними:

  • ядерные (распределяет iptables, пересчёт не нужен):
      prio      — active-backup, только первый живой слот (аналог
                   нынешнего failover, но без перезаписи конфигов)
      rr        — statistic nth, по очереди на соединение
      random    — statistic random, равномерно случайно на соединение
      clienthash— HMARK по src-IP: клиент прилипает к «своему» слоту
                   (все сессии одного WAN-IP через один exit — лечит
                   WAN-affinity; аналог глобального пиннинга Mieru, но
                   per-КЛИЕНТ). Ядро без xt_HMARK → warn + fallback
                   random. Мёртвые слоты не исключаются в ядре (HMARK
                   не знает живости) — соединения на них умирают и
                   переподключаются, компромисс задокументирован.
  • весовые (доли ∝ 1/метрика, weighted random; пересчёт в health-тике
    раз в минуту; живые слоты остаются в ротации — агрегация каналов):
      leastping — доли ∝ 1/RTT (ping -I awgN шлюза exit)
      leastload — доли ∝ 1/(1+tx_rate) (скорость интерфейса за тик)
      smart     — доли ∝ 1/score (RTT + потери + нагрузка) ★ как VLESS;
                   TTFB-плечо заменено потерями: проба HTTP через туннель
                   невозможна (Table=off — нет main-маршрута), веса те же
  • закрепление (порт pinned Mieru): весь NEW → выбранный exit; при
    падении — временно первый живой (фаза fallback + TG-уведомление),
    при восстановлении — автоматический возврат.

Пер-exit инфраструктура:
  марка  0x8200|slot  (0x8201..0x8210; бит 0x8000 b4-exempt в каждой —
                       критично для сосуществования с b4 на entry)
  таблица 2000+slot   (on-link подсеть + default via base.1)
  ip rule fwmark 0x8200|slot lookup 2000+slot
  nat POSTROUTING -o awgN MASQUERADE; FORWARD; TCPMSS 1240/1220 (v4/v6)

Диспетчер awg_lb (mangle PREROUTING; hook = прежнее каскадное mark-правило
-i awg0 + исключения RU/сплит; save-правило — следующим в PREROUTING):
  1) connmark-«наш» (0x8200/0xFF00) → CONNMARK --restore-mark (0xFFFF —
     номер слота в младших битах обязан попадать в ctmark, иначе restore
     терял бы слот ≥16)
  2) meta mark «наш» → RETURN — устоявшееся соединение не трогаем
  3) NEW: statistic-хвост по стратегии — ПАРЫ MARK/RETURN (MARK не
     терминирующий таргет: без RETURN следующий statistic перезаписал
     бы марку и сломал распределение)
  4) возврат в PREROUTING → -i awg0 CONNMARK --save-mark (0xFFFF):
     следующий пакет того же соединения узнаётся ветками 1-2 и НЕ
     перераспределяется. Отличие от Mieru: там statistic в nat (REDIRECT
     терминирует, коннтрек кэширует сам) — здесь mangle зовётся на
     КАЖДОМ пакете, без save/restore statistic рвал бы TCP-поток между
     exit'ами посреди соединения (главная ловушка порта).

B4-сплит: хук наследует исключение ! --match-set awg_b4_direct dst
(mark_rule_exclusion awg_b4_split) — сплит-домены идут в direct-плечо
минуя диспетчер; blanket awg_b4exempt расширяется на awg2..awgN
(lb_extra_ifaces в awg_b4_split) — b4-exempt бит на inner-пакеты всех
туннелей. Exit-ноды не меняются ВООБЩЕ: их пиры cascade_entry_* уже
зарегистрированы (боксы «Настроить как AWG1»). Деплой = код на entry.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from .awg_constants import (
    AWGS_CASCADE_FWMARK,
    AWGS_B4_EXEMPT_BIT,
    AWGS_IPSET_NAME,
    AWGS_DEFAULT_SUBNET,
    AWGS_LB_STRATEGIES,
    AWGS_LB_METRIC_STRATEGIES,
    AWGS_LB_DEFAULT_STRATEGY,
    AWGS_LB_MAX_SLOTS,
    AWGS_LB_TABLE_BASE,
    AWGS_LB_CHAIN,
    AWGS_LB_CHAIN6,
    AWGS_LB_W_LATENCY,
    AWGS_LB_W_TTFB,
    AWGS_LB_W_LOAD,
    AWGS_LB_NORM_LAT_MS,
    AWGS_LB_NORM_LOAD,
    AWGS_LB_NORM_LOSS_PCT,
    AWGS_LB_SHARE_FLOOR,
    AWGS_LB_SCORE_FLOOR,
    AWGS_LB_EMA_ALPHA,
    AWGS_LB_WEIGHTS_HYSTERESIS,
)
from .awg_state import awgs_state_load, awgs_state_save

# «наш»-маски: матч connmark/mark по старшему байту 0x82 (0xFF00);
# save/restore ПОЛНОЙ марки 0xFFFF — номер слота в младших битах.
_OUR_MASK_CT = 0xFF00
_OUR_MASK_FULL = 0xFFFF
_OUR_VALUE = AWGS_CASCADE_FWMARK & _OUR_MASK_CT      # 0x8200


def _core_module():
    """Ленивый импорт _core (как во всех модулях проекта)."""
    import importlib
    return importlib.import_module("chimera._core")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(level: str, msg: str) -> None:
    try:
        _core_module().log_to_file(level, f"awg-lb: {msg}")
    except Exception:
        pass


def _info(msg):  _log("INFO", msg)
def _warn(msg):  _log("WARN", msg)
def _err(msg):   _log("ERROR", msg)


# ══════════════════════════════════════════════════════════════════════════════
#  STATE / СЛОТЫ
# ══════════════════════════════════════════════════════════════════════════════

def lb_is_on(state: Optional[dict] = None) -> bool:
    """LB-режим активен и есть чем балансировать (≥2 exit'ов)."""
    if state is None:
        state = awgs_state_load()
    if not state.get("lb_mode"):
        return False
    return len(state.get("cascade_exits") or []) >= 2


def lb_slot_map(state: Optional[dict] = None) -> dict:
    """Слот = позиция exit в cascade_exits (1-based).

    → {name: {slot, mark, table, iface, subnet, box}}. Чистая функция
    (тестируется без сервера). Слоты > AWGS_LB_MAX_SLOTS не выдаётся.
    """
    if state is None:
        state = awgs_state_load()
    exits = state.get("cascade_exits") or []
    out: dict = {}
    for i, box in enumerate(exits[:AWGS_LB_MAX_SLOTS], 1):
        name = box.get("name") or f"exit-{i}"
        out[name] = {
            "slot": i,
            "mark": AWGS_CASCADE_FWMARK | i,
            "table": AWGS_LB_TABLE_BASE + i,
            "iface": f"awg{i}",
            "subnet": box.get("subnet") or AWGS_DEFAULT_SUBNET,
            "box": box,
        }
    return out


def _lb_tree(state: dict) -> dict:
    """Поддерево state['lb'] (создаёт по требованию, НЕ сохраняет)."""
    lb = state.get("lb")
    if not isinstance(lb, dict):
        lb = {}
        state["lb"] = lb
    return lb


def lb_strategy(state: Optional[dict] = None) -> str:
    if state is None:
        state = awgs_state_load()
    s = (state.get("lb_strategy") or AWGS_LB_DEFAULT_STRATEGY).lower()
    return s if s in AWGS_LB_STRATEGIES else AWGS_LB_DEFAULT_STRATEGY


def _base_of(subnet: str) -> str:
    """'172.16.91.0/24' → '172.16.91'."""
    return (subnet or AWGS_DEFAULT_SUBNET).split("/")[0].rsplit(".", 1)[0]


# ══════════════════════════════════════════════════════════════════════════════
#  ДИСПЕТЧЕР: чистые spec-функции (тестируются без сервера)
# ══════════════════════════════════════════════════════════════════════════════

def _split_excl() -> list:
    """Исключение B4-сплита для хука в argv-виде (list).

    mark_rule_exclusion возвращает СТРОКУ argv ('-m set ! --match-set
    awg_b4_direct dst' или '') — здесь в shlex-список.
    """
    try:
        import shlex
        from . import awg_b4_split
        s = awg_b4_split.mark_rule_exclusion() or ""
        return shlex.split(s) if s.strip() else []
    except Exception:
        return []


def lb_hook_argv(v6: bool = False) -> list:
    """Хук-правило диспетчера в mangle PREROUTING (полный argv).

    Наследует исключения прежнего каскадного mark-правила: RU-сети
    (awg_ru_networks) всегда; awg_b4_direct — при активном B4-сплите.
    v6 — БЕЗ set-матчей: awg_ru_networks/awg_b4_direct — inet-сеты,
    в ip6tables их матчить нельзя (ошибка применения). Форма зеркалит
    оригинальный v6-MARK каскада (apply_iptables: -i awg0 -j MARK
    без исключений — весь v6 от awg0 идёт через каскад).
    """
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    if v6:
        return [ipt, "-t", "mangle", "-A", "PREROUTING",
                "-i", "awg0", "-j", chain]
    spec = ["-i", "awg0", "-m", "set", "!", "--match-set",
            AWGS_IPSET_NAME, "dst"] + _split_excl()
    return [ipt, "-t", "mangle", "-A", "PREROUTING"] + spec + ["-j", chain]


def lb_save_argv(v6: bool = False) -> list:
    """Правило записи ctmark (в PREROUTING, СРАЗУ ПОСЛЕ хука).

    -i awg0 без исключений: сплит/RU-пакеты получат в ctmark текущую
    meta-марку (0x8000 от nft-blanket или 0) — не «наша», restore её
    не подхватит, диспетчер их не трогает. Безопасно.
    """
    ipt = "ip6tables" if v6 else "iptables"
    return [ipt, "-t", "mangle", "-A", "PREROUTING", "-i", "awg0",
            "-j", "CONNMARK", "--save-mark",
            "--nfmask", f"{_OUR_MASK_FULL:#x}",
            "--ctmask", f"{_OUR_MASK_FULL:#x}"]


def lb_head_specs(v6: bool = False) -> list:
    """Голова диспетчер-цепочки (ставится один раз, не переписывается).

    1) connmark-«наш» → restore (маска 0xFFFF: номер слота в ctmark)
    2) meta mark «наш» → RETURN — устоявшееся соединение сразу вылетает
    Каждый элемент — полный argv (iptables/ip6tables -t mangle -A awg_lb).
    """
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    our = f"{_OUR_VALUE:#x}/{_OUR_MASK_CT:#x}"
    full = f"{_OUR_MASK_FULL:#x}"
    return [
        [ipt, "-t", "mangle", "-A", chain,
         "-m", "connmark", "--mark", our,
         "-j", "CONNMARK", "--restore-mark",
         "--nfmask", full, "--ctmask", full],
        [ipt, "-t", "mangle", "-A", chain,
         "-m", "mark", "--mark", our, "-j", "RETURN"],
    ]


def _prob_str(p: float) -> str:
    """Единый формат вероятности iptables statistic (порт mieru_cascade).

    Один helper для создания, хранения (applied) и зачистки — строки
    идентичны, -D совпадает байт-в-байт."""
    p = max(min(p, 1.0), 0.0001)
    return f"{p:.4f}"


def _hmark_argv(n: int, v6: bool = False) -> list:
    """clienthash: mark = hash(srcIP) % n + 0x8201 → слоты 1..n подряд.

    Синтаксис xt_HMARK уточняется при apply (проба в _hmark_available);
    при недоступности модуля — fallback random (caller: health-тик)."""
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    src = "ip6" if v6 else "ip"
    return [ipt, "-t", "mangle", "-A", chain,
            "-j", "HMARK", "--hmark-src", src,
            "--hmark-mod", str(n),
            "--hmark-offset", str(AWGS_CASCADE_FWMARK | 1)]


def lb_tail_specs(strategy: str, slots: dict, alive: list,
                   shares: Optional[dict] = None,
                   pinned: str = "",
                   hmark: bool = True,
                   v6: bool = False) -> list:
    """Хвост распределения NEW-соединений (переписывается тиком).

    slots — карта lb_slot_map; alive — имена живых слотов (порядок
    списка = приоритет для prio / порядок ротации rr-random);
    shares — имя→доля (взвешенные); pinned — имя закреплённого слота
    (fallback-слот caller подаёт уже живым); hmark=False — ядру не
    доступен xt_HMARK (clienthash → caller переключает на random).

    Возвращает список ПОЛНЫХ argv (iptables -t mangle -A awg_lb ...):
    пары MARK/RETURN — MARK не терминирующий таргет, без RETURN
    следующий statistic перезаписал бы марку. Последний слот —
    catch-all без statistic (остаток, как REDIRECT-хвост Mieru).
    """
    strategy = (strategy or "").lower()
    if strategy not in AWGS_LB_STRATEGIES:
        strategy = AWGS_LB_DEFAULT_STRATEGY
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN

    def _pair(mark: int, pre: list) -> list:
        ms = f"{mark:#x}"
        return [
            [ipt, "-t", "mangle", "-A", chain] + pre +
            ["-j", "MARK", "--set-mark", ms],
            [ipt, "-t", "mangle", "-A", chain,
             "-m", "mark", "--mark", ms, "-j", "RETURN"],
        ]

    def _mark_of(name: str) -> int:
        info = slots.get(name) or {}
        return int(info.get("mark") or 0)

    # Закрепление: весь NEW → выбранный слот (fallback-живой от caller)
    if pinned and pinned in slots and pinned in (alive or [pinned]):
        m = _mark_of(pinned)
        if m:
            return _pair(m, [])

    act = [nm for nm in alive if nm in slots]
    n = len(act)
    if n == 0:
        return []

    if strategy == "clienthash":
        if not hmark:
            strategy = "random"            # fallback: ядро без xt_HMARK
        else:
            hm = _hmark_argv(n, v6=v6)
            our = f"{_OUR_VALUE:#x}/{_OUR_MASK_CT:#x}"
            return [hm, [ipt, "-t", "mangle", "-A", chain,
                         "-m", "mark", "--mark", our, "-j", "RETURN"]]

    sh = {}
    if strategy in AWGS_LB_METRIC_STRATEGIES:
        sh = dict(shares or {})
        # порядок по убыванию доли (численно устойчивые вероятности)
        act = sorted(act, key=lambda nm: (-sh.get(nm, 0.0), nm))
        # floor: вне ротации — ИСКЛЮЧАЕМ ДО раздачи (иначе слот с
        # крошечной долей получил бы catch-all — баг 05.10, тест ловит).
        # Если после фильтра пусто (деградация) — оставляем всех.
        kept = [nm for nm in act if sh.get(nm, 0.0) >= AWGS_LB_SHARE_FLOOR]
        if kept:
            act = kept
        sh = {k: v for k, v in sh.items() if k in act}

    specs: list = []
    tail = 0.0
    for i, nm in enumerate(act):
        m = _mark_of(nm)
        if not m:
            continue
        is_last = (i == n - 1)
        pre: list = []
        if strategy == "prio":
            if i > 0:
                continue                   # active-backup: только первый
        elif strategy == "rr" and not is_last:
            pre = ["-m", "statistic", "--mode", "nth",
                   "--every", str(n - i), "--packet", "0"]
        elif strategy == "random" and not is_last:
            pre = ["-m", "statistic", "--mode", "random",
                   "--probability", _prob_str(1.0 / (n - i))]
        elif strategy in AWGS_LB_METRIC_STRATEGIES:
            q = sh.get(nm, 0.0)
            if not is_last:
                if q < AWGS_LB_SHARE_FLOOR:
                    continue               # вне ротации
                p = q / max(1.0 - tail, 0.01)
                pre = ["-m", "statistic", "--mode", "random",
                       "--probability", _prob_str(p)]
        specs.extend(_pair(m, pre))
        tail += sh.get(nm, 0.0)
    return specs


# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ: run-обёртки
# ══════════════════════════════════════════════════════════════════════════════

def _run(argv: list, capture: bool = False, check: bool = False):
    """Единый run (как в awg_b4_split) — мок-тестируемость."""
    import subprocess
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(argv, **kw)


def _argv_del(spec: list) -> list:
    """argv-копия с -A→-D (байт-в-байт для зачистки по applied)."""
    out = list(spec)
    for i, a in enumerate(out):
        if a == "-A":
            out[i] = "-D"
            break
    return out


def _check_or_add(spec: list) -> bool:
    """Идемпотентное правило: -C || -A (как _awgs_cascade_apply_iptables)."""
    chk = list(spec)
    for i, a in enumerate(chk):
        if a == "-A":
            chk[i] = "-C"
            break
    r = _run(["bash", "-c", " ".join(map(_shquote, chk)) + " 2>/dev/null || "
              + " ".join(map(_shquote, spec))],
             capture=True)
    return r.returncode == 0


def _shquote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _while_del(spec: list) -> None:
    """Цикличное удаление правила (все копии), тихое."""
    d = " ".join(map(_shquote, _argv_del(spec)))
    _run(["bash", "-c", f"while {d} 2>/dev/null; do :; done"])


# ══════════════════════════════════════════════════════════════════════════════
#  ДИСПЕТЧЕР: install/remove
# ══════════════════════════════════════════════════════════════════════════════

def _hook_variants(v6: bool = False) -> list:
    """Хук в вариантах (сплит вкл/выкл) + v6 — для зачистки/синка."""
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    base = ["-i", "awg0", "-m", "set", "!", "--match-set",
            AWGS_IPSET_NAME, "dst"]
    out = []
    for excl in (_split_excl(), []):
        out.append([ipt, "-t", "mangle", "-A", "PREROUTING"]
                   + base + excl + ["-j", chain])
    if v6:
        out.append([ipt, "-t", "mangle", "-A", "PREROUTING",
                    "-i", "awg0", "-j", chain])
    return out


def lb_dispatcher_install(state: Optional[dict] = None) -> bool:
    """Полная установка диспетчера + пер-exit инфраструктуры (v4+v6).

    Идемпотентен (safe при повторах и self-heal тика):
      1. снять каскадный MARK-путь (все формы, v4/v6, легаси)
      2. снять старый хук/save/хвост (по applied + варианты хука)
      3. цепочки awg_lb/awg_lb6: голова (restore/RETURN) + хвост
         по стратегии (доли из state, живость из state['lb']['alive'])
      4. хук → save (порядок в PREROUTING критичен: хук РАНЬШЕ save)
      5. per-slot: таблицы/маршруты/ip rule + MASQUERADE + FORWARD
         + TCPMSS (v4/v6); RU-FORWARD общий
      6. слоты > n: ip rule/таблицы зачистить
    Возвращает True при успехе (частичность — False + WARN).
    """
    if state is None:
        state = awgs_state_load()
    if not lb_is_on(state):
        return False
    slots = lb_slot_map(state)
    if not slots:
        return False
    lb = _lb_tree(state)
    strategy = lb_strategy(state)
    shares = ((lb.get("balance") or {}).get("shares")) or {}
    alive = lb.get("alive") or list(slots.keys())
    pinned = state.get("lb_pinned") or ""
    hmark = lb.get("hmark_available", True)
    v6_on = bool(state.get("allow_ipv6_tunnel")) and bool(
        lb.get("v6_slots_on", True))

    # 1. каскадный MARK-путь (все формы) — как в apply_iptables
    _remove_cascade_mark_path()

    # 2. старый хук (оба варианта, v4/v6) + save + хвост по applied
    for v6 in (False, True):
        for h in _hook_variants(v6):
            _while_del(h)
        _while_del(lb_save_argv(v6))
        for spec in (lb.get("applied_v6" if v6 else "applied") or []):
            try:
                _while_del(spec)
            except Exception:
                pass

    ok = True
    # 3. цепочки: голова + хвост
    for v6 in (False, True):
        ipt = "ip6tables" if v6 else "iptables"
        chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
        _run([ipt, "-t", "mangle", "-N", chain])
        _run([ipt, "-t", "mangle", "-F", chain])
        for spec in lb_head_specs(v6):
            if not _check_or_add(spec):
                ok = False
                _warn(f"head rule failed: {spec}")
        use_v6 = v6_on if v6 else True
        if not use_v6:
            continue
        tail = lb_tail_specs(strategy, slots, alive, shares, pinned,
                             hmark=hmark, v6=v6)
        applied_key = "applied_v6" if v6 else "applied"
        applied: list = []
        for spec in tail:
            r = _run(spec)
            if r.returncode == 0:
                applied.append(spec)
            else:
                ok = False
                _warn(f"tail rule failed ({strategy}): {spec}")
        lb[applied_key] = applied

    # 4. хук → save (рядом, хук первым)
    for v6 in (False, True):
        use_v6 = v6_on if v6 else True
        if not use_v6:
            continue
        if not _check_or_add(lb_hook_argv(v6)):
            ok = False
            _warn("hook rule failed")
        if not _check_or_add(lb_save_argv(v6)):
            ok = False
            _warn("save rule failed")

    # 5. per-slot инфраструктура
    for name, info in slots.items():
        iface = info["iface"]
        mark = info["mark"]
        table = info["table"]
        base = _base_of(info["subnet"])
        # v4: on-link + default via base.1 (как каскад, фикс invalid gw)
        _run(["ip", "route", "replace", f"{base}.0/24", "dev", iface,
              "table", str(table)])
        _run(["ip", "route", "replace", "default", "via", f"{base}.1",
              "dev", iface, "table", str(table)])
        _run(["bash", "-c",
              f"while ip rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
              f"ip rule add fwmark {mark:#x} lookup {table}"])
        for spec in (
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface,
             "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-i", "awg0", "-o", iface,
             "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-i", iface, "-o", "awg0",
             "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
             "-j", "ACCEPT"],
            ["iptables", "-t", "mangle", "-A", "FORWARD", "-i", "awg0",
             "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1240"],
            ["iptables", "-t", "mangle", "-A", "FORWARD", "-i", iface,
             "-o", "awg0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1240"],
        ):
            if not _check_or_add(spec):
                ok = False
                _warn(f"per-slot rule failed ({name}): {spec}")
        if v6_on:
            for spec in (
                ["ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", iface,
                 "-j", "MASQUERADE"],
                ["ip6tables", "-A", "FORWARD", "-i", "awg0", "-o", iface,
                 "-j", "ACCEPT"],
                ["ip6tables", "-A", "FORWARD", "-i", iface, "-o", "awg0",
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                 "-j", "ACCEPT"],
                ["ip6tables", "-t", "mangle", "-A", "FORWARD", "-i", "awg0",
                 "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                 "-j", "TCPMSS", "--set-mss", "1220"],
                ["ip6tables", "-t", "mangle", "-A", "FORWARD", "-i", iface,
                 "-o", "awg0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                 "-j", "TCPMSS", "--set-mss", "1220"],
            ):
                if not _check_or_add(spec):
                    ok = False
                    _warn(f"per-slot v6 rule failed ({name}): {spec}")
            _run(["ip", "-6", "route", "replace", "default", "dev", iface,
                  "table", str(table)])
            _run(["bash", "-c",
                  f"while ip -6 rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
                  f"ip -6 rule add fwmark {mark:#x} lookup {table}"])

    # RU-сети — forward напрямую (общий с каскадом, v4)
    _check_or_add(["iptables", "-A", "FORWARD", "-i", "awg0",
                   "-m", "set", "--match-set", AWGS_IPSET_NAME, "dst",
                   "-j", "ACCEPT"])

    # 6. лишние слоты (сдвиг списка при удалении exit'ов)
    n = len(slots)
    for slot in range(n + 1, AWGS_LB_MAX_SLOTS + 1):
        mark = AWGS_CASCADE_FWMARK | slot
        table = AWGS_LB_TABLE_BASE + slot
        _run(["bash", "-c",
              f"while ip rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
              f"ip route flush table {table} 2>/dev/null; "
              f"while ip -6 rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
              f"ip -6 route flush table {table} 2>/dev/null; true"])

    lb["slots_snapshot"] = {k: v["slot"] for k, v in slots.items()}
    lb["ts_last_install"] = _now_iso()
    awgs_state_save(state)
    return ok


def _remove_cascade_mark_path() -> None:
    """Снять каскадный MARK-путь (v4/v6, все формы/легаси) — порт из
    _awgs_cascade_apply_iptables (те же строки, чтобы зачистка была
    полной и после старых установок)."""
    from .awg_b4_split import mark_rule_exclusion
    b4x = (mark_rule_exclusion() or "").strip()   # str-argv ('' если сплит выкл)
    fwm = f"{AWGS_CASCADE_FWMARK:#x}"
    fwml = f"{(AWGS_CASCADE_FWMARK & ~AWGS_B4_EXEMPT_BIT):#x}"
    ipset = AWGS_IPSET_NAME
    base = f"-i awg0 -m set ! --match-set {ipset} dst"
    parts = [
        f"while iptables -t mangle -D FORWARD {base} -j MARK --set-mark {fwm} 2>/dev/null; do :; done;",
        f"while iptables -t mangle -D PREROUTING {base} -j MARK --set-mark {fwm} 2>/dev/null; do :; done;",
        f"while iptables -t mangle -D PREROUTING {base} -m set ! --match-set awg_b4_direct dst -j MARK --set-mark {fwm} 2>/dev/null; do :; done;",
    ]
    if b4x:
        parts.append(f"while iptables -t mangle -D PREROUTING {base} {b4x} "
                      f"-j MARK --set-mark {fwm} 2>/dev/null; do :; done;")
    parts += [
        f"while iptables -t mangle -D PREROUTING {base} -j MARK --set-mark {fwml} 2>/dev/null; do :; done;",
        f"while iptables -t mangle -D FORWARD {base} -j MARK --set-mark {fwml} 2>/dev/null; do :; done;",
        f"while iptables -t mangle -D PREROUTING -i awg0 -j MARK --set-mark {fwm} 2>/dev/null; do :; done;",
        f"while ip6tables -t mangle -D PREROUTING -i awg0 -j MARK --set-mark {fwm} 2>/dev/null; do :; done;",
        f"while ip6tables -t mangle -D PREROUTING -i awg0 -j MARK --set-mark {fwml} 2>/dev/null; do :; done;",
        "true",
    ]
    _run(["bash", "-c", " ".join(parts)])


def lb_dispatcher_remove() -> bool:
    """Снять ВЕСЬ LB: хук/save/хвосты/цепочки/пер-exit/таблицы (v4/v6).

    Вызывается из lb_deactivate (state lb_mode уже False — порядок
    урока deactivate: state ПЕРВЫМ, скрипты ПОСЛЕ). Каскадный MARK-путь
    НЕ ставим — его вернёт _awgs_cascade_apply_iptables обычного режима.
    """
    state = awgs_state_load()
    lb = state.get("lb") or {}
    ok = True

    # хук (все варианты) + save + хвосты
    for v6 in (False, True):
        for h in _hook_variants(v6):
            _while_del(h)
        _while_del(lb_save_argv(v6))
        for spec in (lb.get("applied_v6" if v6 else "applied") or []):
            try:
                _while_del(spec)
            except Exception:
                pass

    # цепочки
    for v6 in (False, True):
        ipt = "ip6tables" if v6 else "iptables"
        chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
        _run([ipt, "-t", "mangle", "-F", chain])
        _run([ipt, "-t", "mangle", "-X", chain])

    # пер-exit правила (все слоты 1..16 — генерик-циклы, v4/v6)
    for slot in range(1, AWGS_LB_MAX_SLOTS + 1):
        iface = f"awg{slot}"
        mark = AWGS_CASCADE_FWMARK | slot
        table = AWGS_LB_TABLE_BASE + slot
        for spec in (
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface,
             "-j", "MASQUERADE"],
            ["iptables", "-D", "FORWARD", "-i", "awg0", "-o", iface,
             "-j", "ACCEPT"],
            ["iptables", "-D", "FORWARD", "-i", iface, "-o", "awg0",
             "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
             "-j", "ACCEPT"],
            ["iptables", "-t", "mangle", "-D", "FORWARD", "-i", "awg0",
             "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1240"],
            ["iptables", "-t", "mangle", "-D", "FORWARD", "-i", iface,
             "-o", "awg0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1240"],
            ["ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", iface,
             "-j", "MASQUERADE"],
            ["ip6tables", "-D", "FORWARD", "-i", "awg0", "-o", iface,
             "-j", "ACCEPT"],
            ["ip6tables", "-D", "FORWARD", "-i", iface, "-o", "awg0",
             "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
             "-j", "ACCEPT"],
            ["ip6tables", "-t", "mangle", "-D", "FORWARD", "-i", "awg0",
             "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1220"],
            ["ip6tables", "-t", "mangle", "-D", "FORWARD", "-i", iface,
             "-o", "awg0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", "1220"],
        ):
            _while_del(spec)
        _run(["bash", "-c",
              f"while ip rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
              f"ip route flush table {table} 2>/dev/null; "
              f"while ip -6 rule del fwmark {mark:#x} lookup {table} 2>/dev/null; do :; done; "
              f"ip -6 route flush table {table} 2>/dev/null; true"])

    # RU-FORWARD и легаси-каскадные MARK (каскад вернёт свои)
    _while_del(["iptables", "-D", "FORWARD", "-i", "awg0",
                "-m", "set", "--match-set", AWGS_IPSET_NAME, "dst",
                "-j", "ACCEPT"])
    _remove_cascade_mark_path()

    lb["applied"] = []
    lb["applied_v6"] = []
    awgs_state_save(state)
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  ТУННЕЛИ awg1..awgN
# ══════════════════════════════════════════════════════════════════════════════

def lb_tunnels_apply(state: Optional[dict] = None) -> bool:
    """Поднять ВСЕ туннели слотов (конфиги из боксов) + down лишних.

    Конфиг — тот же builder что и awg1 у каскада
    (_awgs_cascade_build_awg1_conf): отличий нет, разница только в пути
    awg{slot}.conf. Слоты > n (сдвиг списка при удалении exit'ов) —
    disable + удалить конфиг. awg-quick@awg0 (серверный) не трогаем.
    """
    from .awg_cascade import _awgs_cascade_build_awg1_conf
    from .awg_constants import AWGS_CONF_DIR
    if state is None:
        state = awgs_state_load()
    if not state.get("lb_mode"):
        return False
    slots = lb_slot_map(state)
    if not slots:
        return False
    v6_on = bool(state.get("allow_ipv6_tunnel"))
    ok = True
    for name, info in slots.items():
        box = info["box"]
        subnet = info["subnet"]
        cascade_v6 = ""
        if v6_on:
            from .awg_net_common import awg_v6_ula_from_subnet
            cascade_v6 = awg_v6_ula_from_subnet(subnet)
        conf = _awgs_cascade_build_awg1_conf(
            exit_host=box.get("endpoint", ""),
            exit_port=int(box.get("port", 51820)),
            exit_pubkey=box.get("server_pubkey", ""),
            client_privkey=box.get("peer_privkey", ""),
            psk=box.get("peer_psk", "") or "",
            exit_subnet=subnet,
            exit_peer_ip=box.get("peer_ip", ""),
            exit_params=box.get("params") or None,
            exit_protocol_version=box.get("protocol_version", "2.0"),
            allow_ipv6=bool(cascade_v6),
        )
        path = AWGS_CONF_DIR / f"awg{info['slot']}.conf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(conf)
        path.chmod(0o600)
        _run(["systemctl", "enable", f"awg-quick@awg{info['slot']}"])
        r = _run(["systemctl", "restart", f"awg-quick@awg{info['slot']}"],
                 capture=True)
        if r.returncode != 0:
            ok = False
            _warn(f"awg{info['slot']} ({name}) не перезапустился: {r.stderr}")
    lb_tunnels_down(keep=len(slots))
    return ok


def lb_tunnels_down(keep: int = 1) -> None:
    """Погасить туннели слотов > keep (default 1: остаётся только awg1)."""
    from .awg_constants import AWGS_CONF_DIR
    for slot in range(keep + 1, AWGS_LB_MAX_SLOTS + 1):
        _run(["systemctl", "disable", "--now", f"awg-quick@awg{slot}"])
        p = AWGS_CONF_DIR / f"awg{slot}.conf"
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ПРОБЫ / ДОЛИ (чистые — тестируются без сервера)
# ══════════════════════════════════════════════════════════════════════════════

def _parse_ping(text: str) -> tuple:
    """Вывод ping → (rtt_avg_ms|None, loss_pct|None)."""
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text or "")
    rtt = float(m.group(2)) if m else None
    lm = re.search(r"(\d+)% packet loss", text or "")
    loss = float(lm.group(1)) if lm else None
    return rtt, loss


def _probe_slot(info: dict, lb: dict) -> dict:
    """Проба слота: handshake age + ping шлюза + tx_bytes rate.

    alive = handshake свежий (≤300с, keepalive 25с + RejectAfterTime) ИЛИ
    ping ок — двухступенчатая защита от ложных (как failover_check).
    tx_rate: дельта tx_bytes интерфейса за окно тика (для leastload).
    """
    iface = info["iface"]
    gw = f"{_base_of(info['subnet'])}.1"
    age = None
    try:
        from .awg_cascade import _awgs_cascade_parse_handshake_age
        r = _run(["awg", "show", iface], capture=True)
        if r.returncode == 0:
            age = _awgs_cascade_parse_handshake_age(r.stdout or "")
    except Exception:
        pass
    r = _run(["ping", "-n", "-I", iface, "-c", "3", "-W", "2", gw],
             capture=True)
    rtt, loss = _parse_ping(r.stdout or "")
    ping_ok = r.returncode == 0
    alive = (age is not None and age <= 300) or ping_ok

    tx_now = None
    try:
        tx_now = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes")
                     .read_text().strip())
    except Exception:
        pass
    tx_prev = (lb.get("tx_prev") or {}).get(info.get("name") or iface)
    tx_rate = None
    if tx_now is not None and isinstance(tx_prev, int):
        tx_rate = max(0, tx_now - tx_prev)      # B/тик ≈ B/мин
    if tx_now is not None:
        lb.setdefault("tx_prev", {})[info.get("name") or iface] = tx_now
    return {"name": info.get("name"), "alive": alive, "age": age,
            "rtt_ms": rtt, "loss_pct": loss, "tx_rate_bps": tx_rate,
            "ping_ok": ping_ok}


def lb_balance_shares(lb: dict, strategy: str,
                       probes: dict) -> Optional[dict]:
    """Доли слотов для весовых (порт _balance_shares Mieru, чистая).

    leastping: w ∝ 1/RTT; leastload: w ∝ 1/(1+kbps) — kbps-масштаб
    (B/s даёт 1e-7 и все равны); smart: score = 0.5·норм(RTT) +
    0.3·норм(потери) + 0.2·норм(kbps/NORM) — TTFB-плечо заменено
    потерями (пробы HTTP через туннель невозможны, Table=off).
    EMA-сглаживание α=0.35; деградация всех метрик → равномерный
    фолбэк. Доли < 0.5% — вне ротации, остаток перенормируется.
    """
    strategy = (strategy or "").lower()
    if strategy not in AWGS_LB_METRIC_STRATEGIES:
        return None
    ema_all: dict = lb.setdefault("metrics_ema", {})
    metrics: dict = {}
    weights: dict = {}
    for name, p in probes.items():
        if not p.get("alive"):
            continue
        a = AWGS_LB_EMA_ALPHA
        prev = ema_all.get(name) or {}
        rtt = p.get("rtt_ms")
        rtt = float(rtt) if rtt is not None else None
        loss = p.get("loss_pct")
        loss = float(loss) if loss is not None else None
        tx = p.get("tx_rate_bps")
        tx = float(tx) if tx is not None else None
        kbps = (tx / 1000.0) if tx is not None else None
        # предыстория: None → «худшие» по умолчанию; 0 — ЧЕСТНЫЙ ноль
        # (or-идиома здесь запрещена: 0.0 falsy → превращала нулевые
        # потери в 100% и ломала smart-оценку — баг 05.10, тесты ловят)
        pr_rtt = prev.get("rtt_ms")
        pr_rtt = 2000.0 if pr_rtt is None else float(pr_rtt)
        pr_loss = prev.get("loss_pct")
        pr_loss = 100.0 if pr_loss is None else float(pr_loss)
        pr_tx = prev.get("tx_kbps")
        pr_tx = 0.0 if pr_tx is None else float(pr_tx)
        sm = {
            "rtt_ms": round((1 - a) * pr_rtt
                            + a * (rtt if rtt is not None else pr_rtt), 2),
            "loss_pct": round((1 - a) * pr_loss
                              + a * (loss if loss is not None else pr_loss), 2),
            "tx_kbps": round((1 - a) * pr_tx
                             + a * (kbps if kbps is not None else pr_tx), 1),
        }
        ema_all[name] = sm
        metrics[name] = sm
        if strategy == "leastping":
            w = (1.0 / max(sm["rtt_ms"], 1.0)) if sm["rtt_ms"] else 0.0
        elif strategy == "leastload":
            w = 1.0 / (1.0 + max(sm["tx_kbps"], 0.0))
        else:  # smart
            lat_n = min(1.0, max(sm["rtt_ms"], 0) / AWGS_LB_NORM_LAT_MS)
            loss_n = min(1.0, sm["loss_pct"] / AWGS_LB_NORM_LOSS_PCT)
            load_n = min(1.0, sm["tx_kbps"] * 1000 / AWGS_LB_NORM_LOAD)
            score = round(AWGS_LB_W_LATENCY * lat_n + AWGS_LB_W_TTFB * loss_n
                          + AWGS_LB_W_LOAD * load_n, 4)
            sm["score"] = score
            w = 1.0 / max(score, AWGS_LB_SCORE_FLOOR)
        weights[name] = w
    if not weights:
        return None
    total = sum(weights.values())
    q = {nm: (w / total if total > 0 else 1.0 / len(weights))
         for nm, w in weights.items()}
    kept = {nm: v for nm, v in q.items() if v >= AWGS_LB_SHARE_FLOOR}
    if kept and len(kept) < len(q):
        sk = sum(kept.values())
        q = {nm: v / sk for nm, v in kept.items()}
    return {"strategy": strategy, "ts": _now_iso(), "shares": q,
            "metrics": metrics}


def lb_shares_materially_changed(old: Optional[dict],
                                  new: Optional[dict]) -> bool:
    """Гистерезис ребаланса (порт Mieru, чистая). None/пусто → True."""
    o = (old or {}).get("shares") or {}
    n = (new or {}).get("shares") or {}
    if set(o) != set(n):
        return True
    return any(abs(n[i] - o.get(i, 0.0)) > AWGS_LB_WEIGHTS_HYSTERESIS
               for i in n)


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH-ТИК (расширяет awgs_cascade_failover_check при lb on)
# ══════════════════════════════════════════════════════════════════════════════

def _notify(detail: str) -> None:
    try:
        from .tg_bot import tg_notify_event
        tg_notify_event("awg_failover", detail)
    except Exception:
        pass


def _rules_in_sync(lb: dict, v6: bool) -> bool:
    """Живые правила хвоста == applied (сверка iptables -S, self-heal)?"""
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    key = "applied_v6" if v6 else "applied"
    applied = lb.get(key) or []
    if not applied:
        return True                     # пусто — нечего сверять
    r = _run([ipt, "-t", "mangle", "-S", chain], capture=True)
    live = (r.stdout or "")
    for spec in applied:
        want = " ".join(spec[4:])       # после 'iptables -t mangle': '-A awg_lb ...'
        want = want.replace("-A ", "-A ", 1)
        if want not in live:
            return False
    return True


def lb_health_tick() -> str:
    """Тик LB (та же минута, что failover-таймер; диспетчеризация в
    awgs_cascade_failover_check).

    Возвращает: ok | rebalance | heal | pinned-fallback | pinned-return
    | all-dead | off. Пробы всех слотов → EMA → доли; ребаланс при
    материальном дрейфе/смене состава; self-heal диспетчера; фазы
    закрепления (fallback при смерти, авто-возврат); TG-события.
    """
    state = awgs_state_load()
    if not lb_is_on(state):
        return "off"
    slots = lb_slot_map(state)
    lb = _lb_tree(state)
    strategy = lb_strategy(state)
    pinned = state.get("lb_pinned") or ""

    # 1. пробы
    probes: dict = {}
    for name, info in slots.items():
        info = dict(info)
        info["name"] = name
        probes[name] = _probe_slot(info, lb)
    alive = [nm for nm, p in probes.items() if p["alive"]]
    lb["alive"] = alive
    lb["probes"] = {k: {kk: vv for kk, vv in v.items() if kk != "name"}
                    for k, v in probes.items()}
    if not alive:
        _err("health: все слоты мертвы — диспетчер НЕ снимаю (трафик "
             "стоит; прямой выход = deanon). Ждём восстановления.")
        _notify("AWG-балансировка: все exit-ноды недоступны — туннели "
                "стоят, ждём восстановления")
        awgs_state_save(state)
        return "all-dead"

    # 2. закрепление: фазы A/B
    status = "ok"
    if pinned:
        if pinned in alive:
            if lb.get("pinned_fallback"):
                lb["pinned_fallback"] = False
                status = "pinned-return"
                _info(f"health: закреплённый '{pinned}' восстановлен")
                _notify(f"AWG-балансировка: закреплённый exit "
                        f"<b>{pinned}</b> восстановлен — возврат")
        else:
            if not lb.get("pinned_fallback"):
                lb["pinned_fallback"] = True
                status = "pinned-fallback"
                _warn(f"health: закреплённый '{pinned}' мёртв — временно "
                      f"первый живой ({alive[0]})")
                _notify(f"AWG-балансировка: закреплённый exit <b>{pinned}</b> "
                        f"недоступен — временно через <b>{alive[0]}</b>")

    # 3. доли (взвешенные) + ребаланс-решение
    need_rewrite = False
    if strategy in AWGS_LB_METRIC_STRATEGIES:
        new_bal = lb_balance_shares(lb, strategy, probes)
        old_bal = lb.get("balance") or None
        if new_bal and lb_shares_materially_changed(old_bal, new_bal):
            lb["balance"] = new_bal
            need_rewrite = True
            # pinned-события важнее — не перезаписываем их (а ребаланс
            # при этом всё равно происходит)
            if status == "ok":
                status = "rebalance"
    elif lb.get("balance"):
        lb["balance"] = None

    # состав живых изменился → rewrite (пробы могли опоздать в alive)
    if lb.get("alive_prev") and set(lb["alive_prev"]) != set(alive) \
            and status == "ok":
        need_rewrite = True
    lb["alive_prev"] = list(alive)

    # 4. self-heal: живые правила == applied?
    for v6 in (False, True):
        if not _rules_in_sync(lb, v6):
            need_rewrite = True
            status = "heal" if status == "ok" else status
            _warn("health: rules out of sync — self-heal диспетчера")

    if need_rewrite:
        if not lb_dispatcher_install(state):
            _warn("health: dispatcher_install вернул False (см. лог)")
    awgs_state_save(state)
    _info(f"health[{strategy}]: alive={len(alive)}/{len(slots)}"
          f"{' (pin)' if pinned else ''} → {status}")
    return status


# ══════════════════════════════════════════════════════════════════════════════
#  АКТИВАЦИЯ / ДЕАКТИВАЦИЯ / RESYNC
# ══════════════════════════════════════════════════════════════════════════════

def _hmark_available() -> bool:
    r = _run(["iptables", "-j", "HMARK", "-h"], capture=True)
    txt = ((r.stdout or "") + (r.stderr or "")).lower()
    return r.returncode == 0 or "hmark" in txt


def lb_activate(strategy: str, pinned: str = "") -> bool:
    """Вход в LB-режим. Порядок: туннели → state lb_mode → диспетчер
    → routing script. При сбое посередине — полный откат через
    lb_deactivate() + возврат прежнего активного exit'а."""
    strategy = (strategy or "").lower()
    if strategy not in AWGS_LB_STRATEGIES:
        strategy = AWGS_LB_DEFAULT_STRATEGY
    state = awgs_state_load()
    exits = state.get("cascade_exits") or []
    if len(exits) < 2:
        _warn("LB: нужно ≥2 exit-нод (сейчас "
              f"{len(exits)}) — включать нечего")
        return False
    if strategy == "clienthash" and not _hmark_available():
        _warn("LB: ядро без xt_HMARK — clienthash недоступен, "
              "включаю random")
        strategy = "random"
    if pinned and pinned not in {e.get("name") for e in exits}:
        _warn(f"LB: закрепление '{pinned}' не найдено в списке exit'ов")
        pinned = ""

    # 1. туннели (state ещё lb off — но tunnels_apply читает lb_mode!)
    state["lb_mode"] = True
    state["lb_strategy"] = strategy
    state["lb_pinned"] = pinned
    awgs_state_save(state)          # tunnels_apply увидит lb_mode
    if not lb_tunnels_apply(state):
        _warn("LB: не все туннели поднялись — откат")
        lb_deactivate()
        return False

    # 2. диспетчер
    lb = _lb_tree(state)
    lb["alive"] = list(lb_slot_map(state).keys())
    lb["balance"] = None
    lb["hmark_available"] = _hmark_available()
    if not lb_dispatcher_install(state):
        _warn("LB: диспетчер встал не полностью — откат")
        lb_deactivate()
        return False

    # 3. routing script lb-формы
    try:
        from .awg_cascade import awgs_cascade_routing_regen_lb
        awgs_cascade_routing_regen_lb()
    except Exception as e:
        _warn(f"LB: routing script: {e}")

    # 4. b4-сплит: blanket-форма подхватит awg2..awgN (lb_extra_ifaces)
    try:
        from . import awg_b4_split
        if awg_b4_split.is_active():
            awg_b4_split.nft_apply_split()
    except Exception:
        pass

    _info(f"LB включён: стратегия {strategy}, туннелей {len(exits)}"
          f"{f', закреплён {pinned}' if pinned else ''}")
    _notify(f"AWG-балансировка включена: <b>{strategy}</b>, "
            f"туннелей {len(exits)}")
    return True


def lb_deactivate() -> bool:
    """Выход из LB. Порядок (урок deactivate): state lb_mode=False
    ПЕРВЫМ → снять диспетчер → погасить лишние туннели → вернуть
    awg1 прежнему активному exit'у (activate_exit) → каскадный
    MARK-путь (apply_iptables) → b4-форма."""
    state = awgs_state_load()
    active = state.get("cascade_active_exit") or ""
    exits = state.get("cascade_exits") or []
    if not active and exits:
        active = exits[0].get("name", "")

    # 1. state первым (урок: до скриптов/regen — иначе boot-скрипт
    #    сгенерится по живому ещё-включённому состоянию)
    state["lb_mode"] = False
    state["lb_pinned"] = ""
    awgs_state_save(state)

    # 2. диспетчер + пер-exit
    lb_dispatcher_remove()

    # 3. туннели > 1 — down
    lb_tunnels_down(keep=1)

    # 4. awg1 → прежний активный (перезапишет конфиг + routing script
    #    обычной формы + рестарт awg1)
    ok = True
    if active:
        from .awg_cascade import (awgs_cascade_activate_exit,
                                   _awgs_cascade_apply_iptables,
                                   _awgs_cascade_create_routing_script)
        from .awg_state import awgs_state_load as _sl
        st2 = _sl()
        box = next((e for e in (st2.get("cascade_exits") or [])
                    if e.get("name") == active), None)
        subnet = (box or {}).get("subnet") or AWGS_DEFAULT_SUBNET
        v6_on = bool(st2.get("allow_ipv6_tunnel"))
        v6 = ""
        if v6_on:
            from .awg_net_common import awg_v6_ula_from_subnet
            v6 = awg_v6_ula_from_subnet(subnet)
        if not awgs_cascade_activate_exit(active):
            ok = False
            _warn(f"LB off: активация прежнего exit '{active}' не удалась")
        # каскадный MARK-путь (обычная форма) — вернуть вручную
        _awgs_cascade_apply_iptables(subnet, subnet_v6=v6)
        _awgs_cascade_create_routing_script(subnet, subnet_v6=v6)
    # 5. b4-форма вернётся тиком сплита (blanket awg0/awg1)
    _info(f"LB выключен, активный exit: {active or '—'}")
    _notify(f"AWG-балансировка выключена — активный exit: {active or '—'}")
    return ok


def lb_resync() -> bool:
    """Пересборка после register/remove exit'а при lb on (сдвиг слотов)."""
    state = awgs_state_load()
    if not state.get("lb_mode"):
        return True
    if not lb_is_on(state):
        # exit'ов стало <2 — LB больше не имеет смысла
        _warn("resync: exit'ов <2 — выключаю LB")
        return lb_deactivate()
    if not lb_tunnels_apply(state):
        _warn("resync: туннели не полностью")
    if not lb_dispatcher_install(state):
        _warn("resync: диспетчер не полностью")
    try:
        from .awg_cascade import awgs_cascade_routing_regen_lb
        awgs_cascade_routing_regen_lb()
    except Exception as e:
        _warn(f"resync: routing script: {e}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / ROUTING SCRIPT (lb-форма awg-routing.sh)
# ══════════════════════════════════════════════════════════════════════════════

def lb_status_info(state: Optional[dict] = None) -> dict:
    """Снимок для меню/тестов: стратегия, слоты, живость, доли."""
    if state is None:
        state = awgs_state_load()
    lb = state.get("lb") or {}
    bal = lb.get("balance") or {}
    probes = lb.get("probes") or {}
    out = {
        "on": lb_is_on(state),
        "strategy": lb_strategy(state) if state.get("lb_mode") else "",
        "pinned": state.get("lb_pinned") or "",
        "pinned_fallback": bool(lb.get("pinned_fallback")),
        "balance_ts": bal.get("ts"),
        "slots": [],
    }
    for name, info in lb_slot_map(state).items():
        pr = probes.get(name) or {}
        out["slots"].append({
            "name": name, "slot": info["slot"], "iface": info["iface"],
            "endpoint": (info["box"].get("endpoint") or "") + ":"
                         + str(info["box"].get("port") or ""),
            "mark": info["mark"], "table": info["table"],
            "alive": bool(pr.get("alive")),
            "rtt_ms": pr.get("rtt_ms"),
            "tx_kbps": pr.get("tx_rate_bps"),
            "share": round(((bal.get("shares") or {}).get(name) or 0.0), 4),
        })
    return out


def lb_routing_script_text(state: Optional[dict] = None) -> str:
    """LB-блок awg-routing.sh (замена разделов 2-4 обычной формы).

    Ставится ПОСЛЕ головы-скрипта (ipset ru.zone + сплит-снапшот —
    их генерит awg_cascade). Бут-заглушка хвоста: catch-all на СЛОТ 1
    (prio-форма) — до первого health-тика (≤60с) весь NEW идёт через
    awg1; это безопаснее, чем «без хвоста» (пакеты улетели бы в main
    → WAN напрямую = deanon). Первый тик перестроит по стратегии.
    """
    if state is None:
        state = awgs_state_load()
    slots = lb_slot_map(state)
    n = len(slots)
    if not n:
        return ""
    v6_on = bool(state.get("allow_ipv6_tunnel"))
    fwm = f"{AWGS_CASCADE_FWMARK:#x}"
    our = f"{_OUR_VALUE:#x}/{_OUR_MASK_CT:#x}"
    full = f"{_OUR_MASK_FULL:#x}"
    ipset = AWGS_IPSET_NAME
    b4x_s = " ".join(_split_excl())

    # ожидание линков (systemd поднимает awg-quick@awgN параллельно;
    # маршруты replace упадут на несуществующем интерфейсе)
    wait = "\n".join(
        f"for t in $(seq 1 15); do ip link show awg{s} >/dev/null 2>&1 && break; sleep 1; done"
        for s in range(1, n + 1))

    per_slot = []
    for name, info in slots.items():
        s = info["slot"]
        iface = info["iface"]
        mark = f"{info['mark']:#x}"
        table = info["table"]
        base = _base_of(info["subnet"])
        v6_block = ""
        if v6_on:
            v6_block = f"""
ip6tables -t nat -C POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o {iface} -j MASQUERADE
ip6tables -C FORWARD -i awg0 -o {iface} -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i awg0 -o {iface} -j ACCEPT
ip6tables -C FORWARD -i {iface} -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i {iface} -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -t mangle -C FORWARD -i awg0 -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || ip6tables -t mangle -A FORWARD -i awg0 -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip6tables -t mangle -C FORWARD -i {iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || ip6tables -t mangle -A FORWARD -i {iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip -6 route replace default dev {iface} table {table} 2>/dev/null || true
while ip -6 rule del fwmark {mark} lookup {table} 2>/dev/null; do :; done
ip -6 rule add fwmark {mark} lookup {table}
"""
        per_slot.append(f"""
# ── слот {s}: {name} ({info['box'].get('endpoint')}:{info['box'].get('port')}) ──
ip route replace {base}.0/24 dev {iface} table {table} 2>/dev/null || true
ip route replace default via {base}.1 dev {iface} table {table} 2>/dev/null || true
while ip rule del fwmark {mark} lookup {table} 2>/dev/null; do :; done
ip rule add fwmark {mark} lookup {table}
iptables -t nat -C POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE
iptables -C FORWARD -i awg0 -o {iface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o {iface} -j ACCEPT
iptables -C FORWARD -i {iface} -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {iface} -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -C FORWARD -i awg0 -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || iptables -t mangle -A FORWARD -i awg0 -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -C FORWARD -i {iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || iptables -t mangle -A FORWARD -i {iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240{v6_block}""")

    # зачистка лишних слотов (сдвиг списка)
    extra = "\n".join(
        f"while ip rule del fwmark {(AWGS_CASCADE_FWMARK | s):#x} lookup {AWGS_LB_TABLE_BASE + s} 2>/dev/null; do :; done; "
        f"ip route flush table {AWGS_LB_TABLE_BASE + s} 2>/dev/null; "
        f"while ip -6 rule del fwmark {(AWGS_CASCADE_FWMARK | s):#x} lookup {AWGS_LB_TABLE_BASE + s} 2>/dev/null; do :; done; "
        f"ip -6 route flush table {AWGS_LB_TABLE_BASE + s} 2>/dev/null; true"
        for s in range(n + 1, AWGS_LB_MAX_SLOTS + 1))

    v6_hook = ""
    v6_save = ""
    if v6_on:
        v6_hook = (f"\nip6tables -t mangle -C PREROUTING -i awg0 -j {AWGS_LB_CHAIN6} 2>/dev/null || "
                   f"ip6tables -t mangle -A PREROUTING -i awg0 -j {AWGS_LB_CHAIN6}")
        v6_save = (f"\nip6tables -t mangle -C PREROUTING -i awg0 -j CONNMARK --save-mark "
                   f"--nfmask {full} --ctmask {full} 2>/dev/null || "
                   f"ip6tables -t mangle -A PREROUTING -i awg0 -j CONNMARK --save-mark "
                   f"--nfmask {full} --ctmask {full}")

    return f"""
# ══ LB-ФОРМА (балансировка): диспетчер + пер-exit (idempotent) ══
# Слоты: {n}. Хвост-заглушка при буте: catch-all → awg1 (первый health-тик
# ≤60с перестроит по стратегии «{lb_strategy(state)}»).
# 1. ждём линки туннелей (systemd поднимает параллельно)
{wait}
# 2. цепочка awg_lb: голова (restore/RETURN) + заглушка
iptables -t mangle -N {AWGS_LB_CHAIN} 2>/dev/null
iptables -t mangle -F {AWGS_LB_CHAIN}
iptables -t mangle -A {AWGS_LB_CHAIN} -m connmark --mark {our} -j CONNMARK --restore-mark --nfmask {full} --ctmask {full}
iptables -t mangle -A {AWGS_LB_CHAIN} -m mark --mark {our} -j RETURN
iptables -t mangle -A {AWGS_LB_CHAIN} -j MARK --set-mark {AWGS_CASCADE_FWMARK | 1:#x}
iptables -t mangle -A {AWGS_LB_CHAIN} -m mark --mark {AWGS_CASCADE_FWMARK | 1:#x} -j RETURN
# 3. хук → save (порядок критичен: хук РАНЬШЕ save)
iptables -t mangle -C PREROUTING -i awg0 -m set ! --match-set {ipset} dst{(' ' + b4x_s) if b4x_s else ''} -j {AWGS_LB_CHAIN} 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -i awg0 -m set ! --match-set {ipset} dst{(' ' + b4x_s) if b4x_s else ''} -j {AWGS_LB_CHAIN}
iptables -t mangle -C PREROUTING -i awg0 -j CONNMARK --save-mark --nfmask {full} --ctmask {full} 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -i awg0 -j CONNMARK --save-mark --nfmask {full} --ctmask {full}{v6_hook}{v6_save}
# 4. RU-сети — forward напрямую
iptables -C FORWARD -i awg0 -m set --match-set {ipset} dst -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -i awg0 -m set --match-set {ipset} dst -j ACCEPT
# 5. пер-слот: таблицы/маршруты/MASQUERADE/FORWARD/TCPMSS
{''.join(per_slot)}
# 6. зачистка лишних слотов
{extra}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (п. multiexit [6])
# ══════════════════════════════════════════════════════════════════════════════

def lb_menu() -> None:
    """Подменю балансировки (из _awgs_cascade_menu_multiexit, пункт [6])."""
    core = _core_module()
    from .awg_constants import AWGS_LB_STRATEGIES as _STRATS
    while True:
        import os
        os.system("clear")
        state = awgs_state_load()
        info = lb_status_info(state)
        GREEN, NC, DIM, RED, YELLOW, CYAN = (core.GREEN, core.NC, core.DIM,
                                             core.RED, core.YELLOW, core.CYAN)
        box_top, box_row, box_sep, box_item, box_bottom = (
            core._box_top, core._box_row, core._box_sep, core._box_item,
            core._box_bottom)
        print()
        box_top("Балансировка каскада — все exit'ы одновременно")
        box_row()
        box_row(f"  Слоты = порядок списка exit'ов: awg1..awg{max(1, len(info['slots']))}."
                f" Новые соединения распределяются между ними;")
        box_row(f"  устоявшиеся прилипают к слоту (connmark). Exit-ноды не меняются.")
        box_row()
        on = info["on"]
        box_row(f"  Режим: {'ВКЛ' if on else 'выкл'}"
                f"{f', стратегия {CYAN}{info['strategy']}{NC}' if on else ''}"
                f"{f', закреплён {GREEN}{info['pinned']}{NC}' if on and info['pinned'] else ''}")
        if on and info["pinned_fallback"]:
            box_row(f"  {RED}закреплённый мёртв — временно первый живой{NC}")
        if info["balance_ts"]:
            box_row(f"  Доли пересчитаны: {info['balance_ts'][:19]}")
        if info["slots"]:
            box_row()
            for s in info["slots"]:
                alive = (GREEN + "✓" if s["alive"] else RED + "✗") + NC if on else DIM + "–" + NC
                share = f"{s['share']*100:.1f}%" if (on and s["share"]) else "  —"
                rtt_s = f"{s['rtt_ms']:.0f}ms" if s.get("rtt_ms") else ""
                box_row(f"  {alive} awg{s['slot']} {s['name']:<14} {s['endpoint']:<22}"
                        f" {share:>6}  {rtt_s}")
        box_row()
        box_item("1", "Включить (выбор стратегии)")
        box_item("2", "Сменить стратегию на лету")
        box_item("3", "Закрепить exit (весь трафик → выбранный)")
        box_item("4", "Снять закрепление")
        box_item("5", "Выключить (вернуть failover-режим)")
        box_item("0", "Назад")
        box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("0", "q", ""):
            return
        if ch == "1":
            print()
            for i, s in enumerate(_STRATS, 1):
                d = {"prio": "первый живой (аналог failover, дефолт)",
                     "rr": "по очереди на соединение",
                     "random": "равномерно случайно на соединение",
                     "clienthash": "клиент прилипает к exit'у (нужен xt_HMARK)",
                     "leastping": "доли ∝ 1/RTT (взвешенный random)",
                     "leastload": "доли ∝ 1/нагрузке интерфейса",
                     "smart": "RTT+потери+нагрузка ★ (как VLESS)"}
                print(f"  {i}. {s:<12} {d.get(s, '')}")
            try:
                v = input(f"{CYAN}Стратегия [1-{len(_STRATS)}]:{NC} ").strip()
                if v.isdigit() and 1 <= int(v) <= len(_STRATS):
                    strat = _STRATS[int(v) - 1]
                    pin = ""
                    if input(f"{CYAN}Закрепить exit? [y/N]:{NC} ").strip().lower() in ("y", "yes", "д", "да"):
                        exits = state.get("cascade_exits") or []
                        for i, e in enumerate(exits, 1):
                            print(f"    [{i}] {e.get('name')}")
                        p = input(f"{CYAN}Номер (Enter = без закрепления):{NC} ").strip()
                        if p.isdigit() and 1 <= int(p) <= len(exits):
                            pin = exits[int(p) - 1].get("name", "")
                    if lb_activate(strat, pin):
                        core.success(f"Балансировка включена: {strat}"
                                     + (f", закреплён {pin}" if pin else ""))
                    else:
                        core.warn("Не удалось (см. лог) — режим откачен")
            except ValueError:
                pass
            input(f"\n{core.BLUE}Enter…{NC}")
        elif ch == "2":
            if not on:
                core.warn("LB выключен")
                input(f"\n{core.BLUE}Enter…{NC}")
                continue
            print()
            for i, s in enumerate(_STRATS, 1):
                mark = " ←" if s == info["strategy"] else ""
                print(f"  {i}. {s}{mark}")
            try:
                v = input(f"{CYAN}Стратегия [1-{len(_STRATS)}]:{NC} ").strip()
                if v.isdigit() and 1 <= int(v) <= len(_STRATS):
                    st = awgs_state_load()
                    st["lb_strategy"] = _STRATS[int(v) - 1]
                    st["lb"] = st.get("lb") or {}
                    st["lb"]["balance"] = None      # форс-ребаланс
                    awgs_state_save(st)
                    lb_dispatcher_install(st)
                    core.success(f"Стратегия: {_STRATS[int(v) - 1]} (правила "
                                 "переписаны; туннели не трогались)")
            except ValueError:
                pass
            input(f"\n{core.BLUE}Enter…{NC}")
        elif ch == "3":
            if not on:
                core.warn("LB выключен")
                input(f"\n{core.BLUE}Enter…{NC}")
                continue
            exits = state.get("cascade_exits") or []
            if not exits:
                continue
            print()
            for i, e in enumerate(exits, 1):
                print(f"  [{i}] {e.get('name')} — {e.get('endpoint')}:{e.get('port')}")
            try:
                p = input(f"{CYAN}Номер exit для закрепления:{NC} ").strip()
                if p.isdigit() and 1 <= int(p) <= len(exits):
                    st = awgs_state_load()
                    st["lb_pinned"] = exits[int(p) - 1].get("name", "")
                    lb = _lb_tree(st)
                    lb["pinned_fallback"] = False
                    awgs_state_save(st)
                    lb_dispatcher_install(st)
                    core.success(f"Закреплено: {st['lb_pinned']}")
            except ValueError:
                pass
            input(f"\n{core.BLUE}Enter…{NC}")
        elif ch == "4":
            st = awgs_state_load()
            st["lb_pinned"] = ""
            lb = _lb_tree(st)
            lb["pinned_fallback"] = False
            awgs_state_save(st)
            if st.get("lb_mode"):
                lb_dispatcher_install(st)
            core.info("Закрепление снято")
            input(f"\n{core.BLUE}Enter…{NC}")
        elif ch == "5":
            if not on:
                core.warn("LB и так выключен")
                input(f"\n{core.BLUE}Enter…{NC}")
                continue
            try:
                ok = input("\n  Точно выключить? [y/N]: ").strip().lower()
            except EOFError:
                ok = ""
            if ok in ("y", "yes", "д", "да"):
                if lb_deactivate():
                    core.success("Балансировка выключена, активный exit восстановлен")
                else:
                    core.warn("Выключено с замечаниями (см. лог)")
            input(f"\n{core.BLUE}Enter…{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  ХУК-СИНК (вызов из awg_b4_split.cascade_mark_sync при lb on)
# ══════════════════════════════════════════════════════════════════════════════

def lb_hook_sync(excl: bool) -> bool:
    """Синк хука диспетчера при вкл/выкл B4-сплита (lb on).

    Add-first-then-delete (как cascade_mark_sync): пока обе формы хука
    существуют, пакет матчит ПЕРВЫЙ (jump awg_lb) — переходное окно
    без разрыва. Затем старая форма удаляется. v4+v6.
    """
    want_with = excl
    for v6 in (False, True):
        want = lb_hook_argv(v6) if want_with else _hook_no_split(v6)
        other = _hook_no_split(v6) if want_with else lb_hook_argv(v6)
        if want == other:
            # v6: единственная форма (set-матчи в ip6tables невозможны,
            # сплит-исключения в v6 нет) — только убедиться, что стоит;
            # удаление «другой» снесло бы только что добавленную
            _check_or_add(want)
            continue
        # 1) убедиться что нужная форма есть
        _check_or_add(want)
        # 2) удалить другую форму
        _while_del(other)
    return True


def _hook_no_split(v6: bool = False) -> list:
    """Хук БЕЗ сплит-исключения (вторая форма для синка).

    v6 — единственная голая форма (-i awg0 -j awg_lb6): set-матчи
    inet в ip6tables невозможны, сплит-исключения в v6 нет
    (== lb_hook_argv(True)).
    """
    ipt = "ip6tables" if v6 else "iptables"
    chain = AWGS_LB_CHAIN6 if v6 else AWGS_LB_CHAIN
    if v6:
        return [ipt, "-t", "mangle", "-A", "PREROUTING",
                "-i", "awg0", "-j", chain]
    return [ipt, "-t", "mangle", "-A", "PREROUTING",
            "-i", "awg0", "-m", "set", "!", "--match-set",
            AWGS_IPSET_NAME, "dst", "-j", chain]
