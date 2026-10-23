"""
chimera/modules/icmp_gate.py
───────────────────────────────────────────────────────────────────────────────
ICMP Gate — маскировка ноды от ICMP-зондов: echo-запросы (пинг) отвечают
только доверенным источникам, остальным — тишина («хоста нет»).

Кейс (окт.2026): ноды флота отвечали на пинг ЛЮБОМУ источнику — сток-строка
`-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT` (Ubuntu
UFW) и отсутствие icmp-фильтров в raw-стеке. Для Censys/Shodan/массовых
сканеров это бесплатный фингерпринт живого хоста; port_knocking уже прячет
VPN-порты от тех же сканеров, а пинг оставался открытым окном. ICMP Gate
закрывает окно по той же философии «deny by default, доверенным — ACCEPT».

Роли (семантика доверия, сами списки — в state, НЕ в коде):
  • role="exit"  — allow = admin_ips + peer_ips (peer — bridge/entry-ноды
                   каскада и ICMP-партнёры вроде GRE/pingtunnel-relay);
  • role="entry" — allow = admin_ips только (по умолчанию пиринги НЕ
                   пингуются никем, кроме админа).
admin_ips / peer_ips — IP/CIDR (v4+v6), хранятся в
/var/lib/xray-installer/icmp_gate.json на самой ноде: инфраструктурные
адреса не должны попадать в публичный репозиторий (SECURITY_LEAK_POLICY).

Два механизма применения (mode):
  • mode="ufw"  — managed-блок в /etc/ufw/before.rules и before6.rules
                  перед сток-строкой echo-request ACCEPT + `ufw reload`.
                  Сток-строка НЕ удаляется (после нашего DROP она мертва);
                  remove() просто вырезает блок. Нативно переживает
                  ufw reload/reboot, не плодит сущностей.
  • mode="raw"  — iptables/ip6tables-правила с comment-тегом в TOP INPUT
                  (над ban/knocking/ufw-цепочками) + пересохранение
                  /etc/iptables/rules.v4|v6 (их поднимает telemt-iptables
                  при буте — тот же путь персистентности, что у
                  port-knocking/clients-wl на raw-нодах).
  • mode="auto" — детект: в INPUT есть raw-правила chimera (knocking/
                  clients-wl/manual-ban/telemt) → raw, иначе ufw.

Порядок правил (raw, позиция в INPUT — верх):
  1. -s <admin/peer> -p icmp  -j ACCEPT   (доверенным — любые ICMP-типы:
                                         ответ на их пинг, traceroute изнутри)
  2. -p icmp --icmp-type echo-request       -j DROP  (остальным — «хоста нет»)
  3. -p icmp --icmp-type timestamp-request  -j DROP  (сканерские зонды:
                                         nmap -PP; ядро отвечает по умолчанию)
  4. -p icmp --icmp-type address-mask-request -j DROP (nmap -PM)
IPv6: аналогично, drop только icmpv6-type echo-request (другие v6-типы
не трогаем — NDP/PMTUD живут на них).

Что НЕ трогаем (принципиально):
  • destination-unreachable / time-exceeded / parameter-problem /
    packet-too-big — PMTUD и traceroute-сквозняк; валидатор ЗАПРЕЩАЕТ
    добавить их в drop_types (иначе чинится «маскировка», а ломается TCP);
  • FORWARD-цепочку и ufw-before-forward (GRE-транзит не касается INPUT);
  • echo-reply (type 0) входящий — это ответы на собственные зонды ноды
    (icmptunnel/pingtunnel-клиенты и мониторинг ждут их обратно);
  • TCP/UDP вообще — port_knocking/clients_wl/ban-стек работают как раньше.

Совместимость с мониторингом (chain_relay.icmp_rtt, node_health_monitor):
  ICMP-RTT — ИНФОРМАЦИОННАЯ колонка, вердикт ноды решает full-path зонд
  (кейс №3/№9). Источники зондов, не входящие в allow, увидят «—» в колонке
  RTT, вердикты не изменятся. Если мониторинговый хост должен видеть RTT —
  добавьте его в peer_ips.

Идемпотентность: raw — чистка своих правил по comment-тегу перед вставкой
(bottom-up delete, как port_knocking Bug 1 fix); ufw — вырезание старого
managed-блока перед вставкой нового. Повторный apply безопасен.

Публичный API:
    icmp_gate_apply(overrides)  — применить (роль/списки можно передать
                                  поверх state; headless-деплой)
    icmp_gate_remove()          — выключить (вырезать всё своё)
    icmp_gate_check()           — машинная проверка состояния (dict)
    icmp_gate_status()          — человеческий статус (str)
    do_manage_icmp_gate()       — интерактивное меню (точка входа _core)

Точка входа из _core.py:
    from chimera.modules.icmp_gate import do_manage_icmp_gate
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

__all__ = [
    "icmp_gate_apply",
    "icmp_gate_remove",
    "icmp_gate_check",
    "icmp_gate_status",
    "do_manage_icmp_gate",
]

# ── Пути и константы (патчатся в тестах) ─────────────────────────────────────
IG_STATE_FILE   = Path("/var/lib/xray-installer/icmp_gate.json")
IG_LOG_FILE     = Path("/var/log/chimera.log")
IG_BEFORE_RULES = Path("/etc/ufw/before.rules")
IG_BEFORE6_RULES = Path("/etc/ufw/before6.rules")
IG_RULES_V4     = Path("/etc/iptables/rules.v4")
IG_RULES_V6     = Path("/etc/iptables/rules.v6")

# Comment-тег всех своих iptables/ip6tables-правил: идемпотентная установка
# и безопасная очистка — ищем/удаляем только правила с этим маркером.
IG_COMMENT_TAG = "chimera-icmp-gate"

# Маркеры managed-блока в before.rules/before6.rules.
IG_BLOCK_BEGIN = "# BEGIN chimera-icmp-gate (managed by chimera)"
IG_BLOCK_END   = "# END chimera-icmp-gate"

IG_ROLES = ("exit", "entry")
IG_MODES = ("auto", "ufw", "raw")

# Зонды, которые прячем (v4). НЕ расширять наугад: PMTUD-критичные типы
# запрещены валидатором (см. _IG_FORBIDDEN_DROP_TYPES).
_IG_ALLOWED_DROP_TYPES = ("echo-request", "timestamp-request",
                          "address-mask-request")
# Типы, выпадение которых ломает PMTUD/traceroute — запрет с понятной ошибкой.
_IG_FORBIDDEN_DROP_TYPES = ("destination-unreachable", "time-exceeded",
                            "parameter-problem", "packet-too-big", "any",
                            "redirect", "source-quench", "router-solicitation",
                            "router-advertisement")

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
                    NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM',
                            'NC')}


_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'],
    _C['DIM'], _C['NC'],
)


# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, quiet: bool = False,
         timeout: int = 30) -> subprocess.CompletedProcess:
    """subprocess.run без исключений (таймаут/нет бинарника → rc!=0)."""
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw, check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return subprocess.CompletedProcess(cmd, 126, "", "")


def _log(level: str, msg: str) -> None:
    """Пишет в /var/log/chimera.log с тегом [ICMP-GATE]."""
    try:
        IG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\033\[[0-9;]*m', '', msg)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with IG_LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [{level}] [ICMP-GATE] {clean}\n")
    except Exception:
        pass


def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC} {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}•{NC} {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC} {msg}")


def _tg_notify_event(event: str, detail: str = "") -> None:
    """Лёгкая делегация в _core._tg_notify_event; no-op если недоступен."""
    try:
        import importlib
        _core = importlib.import_module("chimera._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass  # TG не настроен или _core недоступен


# ── STATE ──────────────────────────────────────────────────────────────────────
def _ig_default_state() -> dict:
    return {
        "enabled":      False,
        "role":         "exit",
        "mode":         "auto",
        "admin_ips":    [],   # доверенные «свои» (v4/v6, IP или CIDR)
        "peer_ips":     [],   # пиры: на exit-роли — bridge-ноды/ICMP-партнёры
        "drop_types":   list(_IG_ALLOWED_DROP_TYPES),
        "drop_v6":      True,
        "installed_at": "",
    }


def _ig_state_load() -> dict:
    """State из JSON с мержем дефолтов (обратная совместимость полей)."""
    try:
        if IG_STATE_FILE.exists():
            data = json.loads(IG_STATE_FILE.read_text())
            if isinstance(data, dict):
                merged = _ig_default_state()
                merged.update(data)
                return merged
    except Exception:
        pass
    return _ig_default_state()


def _ig_state_save(state: dict) -> None:
    try:
        IG_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        IG_STATE_FILE.write_text(json.dumps(state, indent=2,
                                            ensure_ascii=False))
        IG_STATE_FILE.chmod(0o600)
    except Exception as e:
        _warn(f"не удалось сохранить state: {e}")


# ── Валидация ─────────────────────────────────────────────────────────────────
def _ig_normalize_ip(token: str) -> "tuple[bool, str, str]":
    """IP/CIDR (v4+v6) → (ok, канонический CIDR, ошибка).

    '198.51.100.7'   → '198.51.100.7/32'
    '203.0.113.0/24' → '203.0.113.0/24'
    '2001:db8::1'    → '2001:db8::1/128'
    """
    v = (token or "").strip()
    if not v:
        return False, "", "пусто"
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return False, "", f"не IP/CIDR: {token}"
    if net.prefixlen == 0:
        return False, "", (
            f"{token} — это весь интернет; allowlist такого не tolerирует"
        )
    return True, str(net), ""


def _ig_validate(state: dict) -> list:
    """Список ошибок конфига (пустой = ок)."""
    errors: list = []
    if state.get("role") not in IG_ROLES:
        errors.append(f"role должен быть {' или '.join(IG_ROLES)}, "
                      f"не {state.get('role')!r}")
    if state.get("mode") not in IG_MODES:
        errors.append(f"mode должен быть {'/'.join(IG_MODES)}, "
                      f"не {state.get('mode')!r}")
    for field in ("admin_ips", "peer_ips"):
        for tok in state.get(field) or []:
            ok, _canon, err = _ig_normalize_ip(str(tok))
            if not ok:
                errors.append(f"{field}: {err}")
    drop = state.get("drop_types") or []
    if not isinstance(drop, list) or not drop:
        errors.append("drop_types не может быть пустым (иначе модуль бессмысленен)")
        drop = []
    for t in drop:
        if t in _IG_FORBIDDEN_DROP_TYPES:
            errors.append(
                f"drop_types: {t} запрещён — это PMTUD/traceroute-критичный "
                f"тип, его дроп ломает TCP (см. докстринг модуля)"
            )
        elif t not in _IG_ALLOWED_DROP_TYPES:
            errors.append(f"drop_types: неизвестный тип {t!r} "
                          f"(допустимо: {', '.join(_IG_ALLOWED_DROP_TYPES)})")
    return errors


def _ig_allowed_sources(state: dict) -> list:
    """Итоговый allowlist по роли: exit → admin+peer, entry → admin."""
    allowed = [str(x) for x in (state.get("admin_ips") or [])]
    if state.get("role") == "exit":
        allowed += [str(x) for x in (state.get("peer_ips") or [])]
    # нормализация + уникальность с сохранением порядка
    seen, out = set(), []
    for tok in allowed:
        ok, canon, _e = _ig_normalize_ip(tok)
        if ok and canon not in seen:
            seen.add(canon)
            out.append(canon)
    return out


def _ig_split_v4v6(tokens: list) -> "tuple[list, list]":
    """[(v4-CIDR...), (v6-CIDR...)] из списка канонических CIDR."""
    v4, v6 = [], []
    for tok in tokens:
        try:
            (v4 if ipaddress.ip_network(tok).version == 4 else v6).append(tok)
        except ValueError:
            continue
    return v4, v6


# ── Построители правил ─────────────────────────────────────────────────────────
def _ig_build_raw_rules_v4(state: dict) -> list:
    """Спеки правил IPv4 (без -I/-A): сначала allow, затем drop."""
    allowed = _ig_allowed_sources(state)
    v4, _v6 = _ig_split_v4v6(allowed)
    rules: list = []
    for src in v4:
        rules.append(["-s", src, "-p", "icmp", "-m", "comment",
                      "--comment", f"{IG_COMMENT_TAG}:allow", "-j", "ACCEPT"])
    for t in state.get("drop_types") or []:
        rules.append(["-p", "icmp", "--icmp-type", t, "-m", "comment",
                      "--comment", f"{IG_COMMENT_TAG}:drop", "-j", "DROP"])
    return rules


def _ig_build_raw_rules_v6(state: dict) -> list:
    """Спеки правил IPv6: allow (v6-источники) + drop echo-request."""
    allowed = _ig_allowed_sources(state)
    _v4, v6 = _ig_split_v4v6(allowed)
    rules: list = []
    for src in v6:
        rules.append(["-s", src, "-p", "icmpv6", "-m", "comment",
                      "--comment", f"{IG_COMMENT_TAG}:allow6", "-j", "ACCEPT"])
    if state.get("drop_v6", True):
        rules.append(["-p", "icmpv6", "--icmpv6-type", "echo-request",
                      "-m", "comment", "--comment",
                      f"{IG_COMMENT_TAG}:drop6", "-j", "DROP"])
    return rules


def _ig_ufw_block_lines_v4(state: dict) -> list:
    """Строки managed-блока для /etc/ufw/before.rules."""
    lines = []
    for spec in _ig_build_raw_rules_v4(state):
        lines.append("-A ufw-before-input " + " ".join(spec))
    return lines


def _ig_ufw_block_lines_v6(state: dict) -> list:
    """Строки managed-блока для /etc/ufw/before6.rules."""
    lines = []
    for spec in _ig_build_raw_rules_v6(state):
        lines.append("-A ufw6-before-input " + " ".join(spec))
    return lines


# ── RAW-механика (iptables/ip6tables + comment-тег) ──────────────────────────
def _ig_find_own_rule_lines(table: str) -> list:
    """Номера строк своих правил в `<table> -L INPUT` (по убыванию).

    Bottom-up delete — номера строк не сдвигаются при удалении
    (тот же фикс, что port_knocking Bug 1).
    """
    r = _run([table, "-L", "INPUT", "--line-numbers", "-n"], capture=True)
    if r.returncode != 0:
        return []
    nums: list = []
    for line in (r.stdout or "").splitlines():
        if IG_COMMENT_TAG in line:
            m = re.match(r"\s*(\d+)", line)
            if m:
                nums.append(int(m.group(1)))
    return sorted(nums, reverse=True)


def _ig_raw_clean(table: str) -> int:
    """Удалить все свои правила в INPUT у table. Возвращает счётчик."""
    removed = 0
    for n in _ig_find_own_rule_lines(table):
        if _run([table, "-D", "INPUT", str(n)], quiet=True).returncode == 0:
            removed += 1
    return removed


def _ig_raw_install(table: str, rules: list) -> bool:
    """Чистка своих + вставка fresh-набора в TOP INPUT (порядок сохраняем).

    Вставка в reverse-порядке через `-I INPUT 1`: последняя вставленная
    строка окажется первой → итоговый порядок совпадает со списком rules
    (allow выше drop).
    """
    _ig_raw_clean(table)
    for spec in reversed(rules):
        if _run([table, "-I", "INPUT", "1"] + spec, quiet=True).returncode != 0:
            _err(f"{table}: не удалось вставить правило "
                 f"({' '.join(spec)[:80]}…)")
            return False
    return True


def _ig_persist_raw() -> None:
    """Пересохранить /etc/iptables/rules.v4|v6 (путь telemt-iptables).

    Только если каталог /etc/iptables уже существует — на raw-нодах его
    поднимает telemt-iptables.service при буте. Намеренно НЕ зовём
    netfilter-persistent: на UFW-машинах его save ломает бут
    (живой кейс), raw-нодам он не нужен.
    """
    if not IG_RULES_V4.parent.is_dir():
        return
    r = _run(["iptables-save"], capture=True)
    if r.returncode == 0 and r.stdout:
        try:
            IG_RULES_V4.write_text(r.stdout)
        except OSError:
            pass
    r = _run(["ip6tables-save"], capture=True)
    if r.returncode == 0 and r.stdout:
        try:
            IG_RULES_V6.write_text(r.stdout)
        except OSError:
            pass


def _ig_install_raw(state: dict) -> bool:
    rules4 = _ig_build_raw_rules_v4(state)
    rules6 = _ig_build_raw_rules_v6(state)
    if not rules4:
        _err("пустой набор правил v4 (проверьте role/drop_types)")
        return False
    if not _ig_raw_install("iptables", rules4):
        return False
    _info(f"iptables: {len(rules4)} правил (allow {len(rules4) - len(state.get('drop_types') or [])}, "
          f"drop {len(state.get('drop_types') or [])})")
    if rules6:
        if _ig_raw_install("ip6tables", rules6):
            _info(f"ip6tables: {len(rules6)} правил (v6)")
        else:
            return False
    _ig_persist_raw()
    _ok("правила применены и пересохранены в rules.v4/v6")
    return True


def _ig_remove_raw() -> bool:
    n4 = _ig_raw_clean("iptables")
    n6 = _ig_raw_clean("ip6tables")
    _ig_persist_raw()
    _ok(f"убрано правил: v4={n4}, v6={n6}")
    return True


# ── UFW-механика (managed-блок в before.rules/before6.rules) ─────────────────
def _ig_ufw_write_block(path: Path, chain: str, lines: list) -> "tuple[bool, str]":
    """Вставить/заменить managed-блок в before-файле перед сток-строкой
    echo-request ACCEPT. Возвращает (ok, сообщение).

    Сток-строку не удаляем и не комментируем: наш DROP стоит раньше и
    делает её мёртвой; remove() вырезает только наш блок — файл всегда
    возвращается к сток-виду.
    """
    if not path.exists():
        return False, f"{path} не найден"
    try:
        text = path.read_text()
    except OSError as e:
        return False, f"{path}: {e}"

    # бэкап стока (однократный, до первой модификации)
    bak = path.with_name(path.name + ".bak-icmp-gate")
    if not bak.exists():
        try:
            bak.write_text(text)
        except OSError:
            pass

    # идемпотентность: вырезать старый блок, если был
    if IG_BLOCK_BEGIN in text:
        text = re.sub(
            re.escape(IG_BLOCK_BEGIN) + r".*?" + re.escape(IG_BLOCK_END)
            + r"\n?", "", text, flags=re.S)
    if not lines:
        try:
            path.write_text(text)
            return True, f"{path}: блок удалён"
        except OSError as e:
            return False, f"{path}: {e}"

    block = (IG_BLOCK_BEGIN + "\n"
             + "\n".join(lines) + "\n"
             + IG_BLOCK_END + "\n")

    # точка вставки: перед сток-строкой echo-request ACCEPT этой цепочки
    stock = re.search(
        r"^-A " + re.escape(chain)
        + r" -p icmpv?6? --icmpv?6?-type echo-request -j ACCEPT\s*$",
        text, flags=re.M)
    if stock:
        text = text[:stock.start()] + block + text[stock.start():]
    else:
        # fallback: перед первым правилом цепочки, иначе перед COMMIT
        first = re.search(r"^-A " + re.escape(chain) + r"\s", text,
                          flags=re.M)
        anchor = first.start() if first else text.rfind("COMMIT")
        if anchor < 0:
            return False, f"{path}: не найдена точка вставки ({chain})"
        text = text[:anchor] + block + text[anchor:]
    try:
        path.write_text(text)
        return True, f"{path}: блок обновлён ({len(lines)} строк)"
    except OSError as e:
        return False, f"{path}: {e}"


def _ig_install_ufw(state: dict) -> bool:
    v4 = _ig_ufw_block_lines_v4(state)
    v6 = _ig_ufw_block_lines_v6(state) if state.get("drop_v6", True) else []
    ok1, msg1 = _ig_ufw_write_block(IG_BEFORE_RULES, "ufw-before-input", v4)
    (_ok if ok1 else _err)(msg1)
    if not ok1:
        return False
    if IG_BEFORE6_RULES.exists():
        ok2, msg2 = _ig_ufw_write_block(IG_BEFORE6_RULES, "ufw6-before-input",
                                        v6)
        (_ok if ok2 else _err)(msg2)
        if not ok2:
            return False
    r = _run(["ufw", "reload"], capture=True)
    if r.returncode != 0:
        _warn("ufw reload вернул rc="
              f"{r.returncode}: {(r.stderr or r.stdout or '').strip()[:120]}")
        return False
    _ok("ufw reload прошёл, блоки активны")
    return True


def _ig_remove_ufw() -> bool:
    ok_all = True
    for path, chain in ((IG_BEFORE_RULES, "ufw-before-input"),
                        (IG_BEFORE6_RULES, "ufw6-before-input")):
        ok, msg = _ig_ufw_write_block(path, chain, [])
        if path.exists():
            (_ok if ok else _err)(msg)
            ok_all = ok_all and ok
    r = _run(["ufw", "reload"], capture=True)
    if r.returncode != 0:
        _warn(f"ufw reload rc={r.returncode}")
        ok_all = False
    return ok_all


# ── Детект режима ─────────────────────────────────────────────────────────────
_RAW_STACK_TAGS = ("chimera-port-knocking", "chimera-clients-wl",
                   "xray-manual-ban", "telemt-syn-limit")


def _ig_detect_mode() -> str:
    """raw, если INPUT уже содержит raw-правила chimera-стека; иначе ufw."""
    r = _run(["iptables", "-S", "INPUT"], capture=True)
    if r.returncode == 0 and r.stdout:
        for ln in r.stdout.splitlines():
            if ln.startswith("-A INPUT") and any(t in ln for t in _RAW_STACK_TAGS):
                return "raw"
    if IG_BEFORE_RULES.exists():
        return "ufw"
    return "raw"


# ── Публичный API ─────────────────────────────────────────────────────────────
def icmp_gate_apply(overrides: dict | None = None) -> bool:
    """Применить ICMP Gate. overrides мержатся поверх state (headless-деплой).

    Пример:
        icmp_gate_apply({"role": "exit", "mode": "ufw",
                         "admin_ips": ["198.51.100.10"],
                         "peer_ips": ["203.0.113.20"]})
    """
    state = _ig_state_load()
    if overrides:
        state.update(overrides)
    errors = _ig_validate(state)
    if errors:
        for e in errors:
            _err(e)
        _log("ERR", f"apply отклонён валидатором: {errors[0]}")
        return False
    if not _ig_allowed_sources(state):
        _warn("allowlist пуст — НИКТО не сможет пинговать ноду "
              "(полный stealth); уверены, что это нужно?")
    mode = state.get("mode", "auto")
    if mode == "auto":
        mode = _ig_detect_mode()
        _info(f"mode=auto → детект: {mode}")
    state["mode"] = mode
    if state.get("role") == "entry" and state.get("peer_ips"):
        _warn("role=entry игнорирует peer_ips (пинг — только admin_ips)")
    ok = _ig_install_raw(state) if mode == "raw" else _ig_install_ufw(state)
    if ok:
        state["enabled"] = True
        state["installed_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        _ig_state_save(state)
        role = state["role"]
        n_allow = len(_ig_allowed_sources(state))
        _log("SUCCESS", f"включён: role={role}, mode={mode}, "
                        f"allow={n_allow} ист.")
        _tg_notify_event("icmp_gate",
                         f"ICMP Gate включён: role={role}, mode={mode}")
    else:
        _log("ERR", f"apply не удался (mode={mode})")
    return ok


def icmp_gate_remove() -> bool:
    """Полностью выключить: вырезать свои правила/блоки, state enabled=False."""
    state = _ig_state_load()
    mode = state.get("mode", "auto")
    if mode == "auto":
        mode = _ig_detect_mode()
    ok = _ig_remove_raw() if mode == "raw" else _ig_remove_ufw()
    # чистим и второй механизм тоже (защита от смены режима руками)
    if mode == "raw":
        _ig_remove_ufw()
    else:
        _ig_raw_clean("iptables")
        _ig_raw_clean("ip6tables")
    if ok:
        state["enabled"] = False
        _ig_state_save(state)
        _log("SUCCESS", "выключен, свои правила вырезаны")
        _tg_notify_event("icmp_gate", "ICMP Gate выключен")
    return ok


def icmp_gate_check() -> dict:
    """Машинная проверка для деплой-скриптов/мониторинга."""
    state = _ig_state_load()
    mode = (state.get("mode") if state.get("mode") in ("ufw", "raw")
            else _ig_detect_mode())
    allowed = _ig_allowed_sources(state)
    v4a, v6a = _ig_split_v4v6(allowed)
    exp_v4 = len(v4a) + len(state.get("drop_types") or [])
    exp_v6 = len(v6a) + (1 if state.get("drop_v6", True) else 0)
    out = {
        "enabled": bool(state.get("enabled")),
        "role": state.get("role"),
        "mode": mode,
        "expected_allow": len(allowed),
        "expected_rules_v4": exp_v4,
        "expected_rules_v6": exp_v6,
    }
    if mode == "raw":
        n4 = len(_ig_find_own_rule_lines("iptables"))
        n6 = len(_ig_find_own_rule_lines("ip6tables"))
        out.update(raw_v4_rules=n4, raw_v6_rules=n6,
                   ufw_block_v4=False, ufw_block_v6=False)
        out["ok"] = bool(state.get("enabled")) and n4 == exp_v4 and n6 == exp_v6
    else:
        def _has_block(p: Path) -> bool:
            try:
                return p.exists() and IG_BLOCK_BEGIN in p.read_text()
            except OSError:
                return False
        b4 = _has_block(IG_BEFORE_RULES)
        b6 = _has_block(IG_BEFORE6_RULES)
        out.update(raw_v4_rules=0, raw_v6_rules=0,
                   ufw_block_v4=b4, ufw_block_v6=b6)
        want6 = bool(state.get("drop_v6", True)) and IG_BEFORE6_RULES.exists()
        out["ok"] = bool(state.get("enabled")) and b4 and (b6 or not want6)
    return out


def icmp_gate_status() -> str:
    """Человеческий статус одной строкой + детали по строкам."""
    state = _ig_state_load()
    chk = icmp_gate_check()
    head = (f"{GREEN}● активен{NC}" if chk["ok"]
            else f"{YELLOW}⚠ включён, правил нет{NC}" if state.get("enabled")
            else f"{DIM}○ выключен{NC}")
    lines = [f"ICMP Gate: {head}"]
    lines.append(f"  role={state.get('role')}  mode={chk['mode']}  "
                 f"drop_v4={','.join(state.get('drop_types') or [])}  "
                 f"drop_v6={'да' if state.get('drop_v6', True) else 'нет'}")
    allowed = _ig_allowed_sources(state)
    lines.append(f"  allow ({len(allowed)}): "
                 + (", ".join(allowed) if allowed else "— пусто (полный stealth)"))
    if chk["mode"] == "raw":
        lines.append(f"  правила: v4={chk['raw_v4_rules']}/{chk['expected_rules_v4']}, "
                     f"v6={chk['raw_v6_rules']}/{chk['expected_rules_v6']} "
                     f"(факт/ожидается)")
    else:
        lines.append(f"  блоки: before.rules={'да' if chk['ufw_block_v4'] else 'НЕТ'}, "
                     f"before6.rules={'да' if chk['ufw_block_v6'] else 'НЕТ/не нужен'}")
    return "\n".join(lines)


# ── Интерактивное меню ─────────────────────────────────────────────────────────
def _ig_input(prompt: str, default: str = "") -> str:
    try:
        val = input(f"{CYAN}{prompt}{NC}" +
                    (f" [{default}]" if default else "") + ": ").strip()
    except EOFError:
        return default
    return val or default


def do_manage_icmp_gate() -> None:
    """Меню модуля (точка входа из _core)."""
    while True:
        print()
        print(icmp_gate_status())
        print()
        print(f"  [{BOLD}1{NC}] {'Переконфигурировать и включить' if _ig_state_load().get('enabled') else 'Настроить и включить'}")
        print(f"  [{BOLD}2{NC}] Выключить (вырезать все свои правила)")
        print(f"  [{BOLD}3{NC}] Проверить сейчас (check)")
        print(f"  [{BOLD}0{NC}] Назад")
        ch = _ig_input("Выбор", "0")
        if ch == "0":
            return
        if ch == "1":
            state = _ig_state_load()
            role = _ig_input("Роль: exit (пинг: админ + пиры) / entry (только админ)",
                             state.get("role", "exit")).lower()
            if role not in IG_ROLES:
                _err(f"неизвестная роль {role!r}")
                continue
            mode = _ig_input("Механизм: auto / ufw / raw",
                             state.get("mode", "auto")).lower()
            if mode not in IG_MODES:
                _err(f"неизвестный mode {mode!r}")
                continue
            admins = _ig_input("admin_ips через запятую (IP/CIDR, v4+v6)",
                               ", ".join(state.get("admin_ips") or []))
            peers = _ig_input("peer_ips через запятую (для exit-роли)",
                              ", ".join(state.get("peer_ips") or []))
            overrides = {
                "role": role,
                "mode": mode,
                "admin_ips": [x.strip() for x in admins.split(",") if x.strip()],
                "peer_ips": [x.strip() for x in peers.split(",") if x.strip()],
            }
            if icmp_gate_apply(overrides):
                _ok("готово")
            else:
                _err("apply не удался — см. ошибки выше")
            input(f"{DIM}Enter…{NC}")
        elif ch == "2":
            if icmp_gate_remove():
                _ok("ICMP Gate выключен")
            input(f"{DIM}Enter…{NC}")
        elif ch == "3":
            chk = icmp_gate_check()
            for k, v in chk.items():
                print(f"  {k}: {v}")
            input(f"{DIM}Enter…{NC}")
