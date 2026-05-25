"""
vless_installer/modules/dpi_detector.py
───────────────────────────────────────────────────────────────────────────────
DPI-детектор — анализ error.log Xray на паттерны активного зондирования.

  • Анализирует /var/log/xray/error.log на паттерны TLS-зондирования
  • При превышении порога score — банит IP через AutoBan
  • Интеграция с CHAIN_PINNED_NODE_INDEX (fallback при падении ноды)
  • Cron каждые 5 минут

Точка входа из _core.py:
    from vless_installer.modules.dpi_detector import do_manage_dpi_detector
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",   msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Делегируем вызовы в _core через importlib (избегаем circular import) ──────
def _core_call(func_name: str, *args, **kwargs):
    import importlib
    _core = importlib.import_module("vless_installer._core")
    return getattr(_core, func_name)(*args, **kwargs)

def _autoban_load() -> dict:
    return _core_call("_autoban_load")

def _autoban_save(data: dict) -> None:
    _core_call("_autoban_save", data)

def _autoban_get_chain_ips() -> list:
    return _core_call("_autoban_get_chain_ips")

def _ban_report_append(ip: str, count: int, reason: str, asn_info: dict) -> None:
    _core_call("_ban_report_append", ip, count, reason, asn_info)

def _lookup_asn(ip: str) -> dict:
    return _core_call("_lookup_asn", ip)

def _rebuild_and_restart_xray(ok_msg: str = "Xray активен") -> None:
    _core_call("_rebuild_and_restart_xray", ok_msg)

def _tg_notify_event(event: str, detail: str = "") -> None:
    try:
        _core_call("_tg_notify_event", event, detail)
    except Exception:
        pass

def _get_chain_pinned_node_index() -> int:
    import importlib
    _core = importlib.import_module("vless_installer._core")
    return getattr(_core, "CHAIN_PINNED_NODE_INDEX", -1)

def _set_chain_pinned_node_index(val: int) -> None:
    import importlib
    _core = importlib.import_module("vless_installer._core")
    _core.CHAIN_PINNED_NODE_INDEX = val

# ── Импорты из других модулей ─────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back, _BOX_W,
)
from vless_installer.modules.tui import tui_confirm

# ── Константы ─────────────────────────────────────────────────────────────────
_DPI_STATE_FILE  = Path("/var/lib/xray-installer/dpi_detector.json")
_DPI_LOG         = Path("/var/log/xray-dpi-detector.log")
_DPI_CRON        = Path("/etc/cron.d/xray-dpi-detector")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")


_DPI_STATE_FILE  = Path("/var/lib/xray-installer/dpi_detector.json")
_DPI_LOG         = Path("/var/log/xray-dpi-detector.log")
_DPI_CRON        = Path("/etc/cron.d/xray-dpi-detector")

# ── Паттерны DPI-зондирования в error.log Xray ────────────────────────────
# Каждый паттерн — tuple(regex, описание, вес).
# Вес суммируется по IP: при превышении порога — бан.
_DPI_PATTERNS: list[tuple] = [
    # TLS без SNI — классический признак зондирования
    (re.compile(r'tls.*?no.*?sni|missing.*?sni|sni.*?empty|sni.*?not.*?found',
                re.IGNORECASE), "TLS без SNI", 3),

    # Неожиданное завершение хендшейка
    (re.compile(r'tls.*?handshake.*?(?:fail|error|timeout|reset|eof|unexpect)',
                re.IGNORECASE), "TLS handshake fail", 2),

    # HTTP-запрос на TLS-порт (активное зондирование)
    (re.compile(r'(?:failed to read|invalid.*?header|not.*?tls|plain.*?http.*?tls)',
                re.IGNORECASE), "HTTP на TLS-порту", 3),

    # Быстрое переподключение / connection reset после хендшейка
    (re.compile(r'connection.*?reset.*?peer|broken.*?pipe|read.*?tcp.*?reset',
                re.IGNORECASE), "Быстрый disconnect", 1),

    # Неизвестная версия TLS или cipher suite
    (re.compile(r'no.*?supported.*?version|unsupported.*?version|no.*?cipher.*?suite',
                re.IGNORECASE), "Неизвестный TLS", 3),

    # Зондирование ALPN (пробуют разные протоколы)
    (re.compile(r'alpn.*?negotiat|no.*?alpn|alpn.*?fail',
                re.IGNORECASE), "ALPN probe", 2),

    # REALITY-специфичные: неверный shortId или publicKey
    (re.compile(r'(?:short.*?id.*?mismatch|invalid.*?public.*?key|reality.*?auth.*?fail)',
                re.IGNORECASE), "REALITY auth fail", 4),
]

# Порог суммарного веса для бана (по умолчанию)
_DPI_THRESHOLD_DEFAULT = 6
# Окно анализа (минут)
_DPI_WINDOW_DEFAULT = 15


def _dpi_state_load() -> dict:
    try:
        if _DPI_STATE_FILE.exists():
            return json.loads(_DPI_STATE_FILE.read_text())
    except Exception:
        pass
    return {
        "enabled":   False,
        "threshold": _DPI_THRESHOLD_DEFAULT,
        "window_min": _DPI_WINDOW_DEFAULT,
        "whitelist": ["127.0.0.1", "::1"],
    }


def _dpi_state_save(data: dict) -> None:
    _DPI_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DPI_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _DPI_STATE_FILE.chmod(0o600)


def _pinned_node_check_and_fallback() -> bool:
    """
    Проверяет доступность pinned-ноды (_get_chain_pinned_node_index()).

    Логика двухфазная:
      Фаза A — восстановление: если сейчас активен fallback (_pinned_original_index
        задан) и оригинальная нода снова отвечает — возвращаемся к ней.
      Фаза B — деградация: если pinned-нода не отвечает — переключаемся на первую
        живую альтернативу и сохраняем _pinned_original_index для Фазы A.

    Возвращает True, если конфиг был изменён (fallback или restore).
    """

    if not _STATE_FILE.exists():
        return False

    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception:
        return False

    pinned = state.get("chain_pinned_node_index", -1)
    nodes  = state.get("chain_nodes", [])
    orig   = state.get("_pinned_original_index", -1)  # -1 = нет активного fallback

    if len(nodes) < 2:
        return False

    def _tcp_ok(host: str, port: int, timeout: float = 5.0) -> bool:
        import socket
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except Exception:
            return False

    def _fallback_log(msg: str) -> None:
        try:
            with open("/var/log/xray-auto-fallback.log", "a") as fh:
                fh.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
        except Exception:
            pass

    # ── Фаза A: мы уже в fallback — проверяем, поднялась ли оригинальная нода ──
    if 0 <= orig < len(nodes) and orig != pinned:
        orig_nd   = nodes[orig]
        orig_host = orig_nd.get("host", "")
        orig_port = int(orig_nd.get("port", 443))

        if _tcp_ok(orig_host, orig_port):
            # Оригинальная нода восстановлена — возвращаемся
            state["chain_pinned_node_index"] = orig
            state.pop("_pinned_original_index", None)
            try:
                _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            except Exception:
                return False

            _set_chain_pinned_node_index(orig)
            try:
                _rebuild_and_restart_xray("Xray активен — pinned нода восстановлена")
            except Exception as e:
                log_to_file("WARN", f"_pinned_node_check_and_fallback restore: rebuild failed: {e}")

            cur_nd   = nodes[pinned]
            cur_host = cur_nd.get("host", "")
            _fallback_log(
                f"PINNED-RESTORE: оригинальная нода #{orig+1} ({orig_host}) снова UP → "
                f"возврат с #{pinned+1} ({cur_host})"
            )
            log_to_file("INFO",
                f"pinned-restore: #{pinned+1} ({cur_host}) → #{orig+1} ({orig_host})")
            _tg_notify_event("xray_up",
                f"✅ Pinned-нода <b>#{orig+1} ({orig_host})</b> восстановлена.\n"
                f"Возврат с fallback-ноды #{pinned+1} ({cur_host}).")
            return True
        else:
            # Оригинальная нода ещё не поднялась — ничего не делаем
            return False

    # ── Фаза B: проверяем текущую pinned-ноду ────────────────────────────────
    if not (0 <= pinned < len(nodes)):
        return False

    pinned_nd   = nodes[pinned]
    pinned_host = pinned_nd.get("host", "")
    pinned_port = int(pinned_nd.get("port", 443))

    if _tcp_ok(pinned_host, pinned_port):
        return False  # нода живая — fallback не нужен

    # Pinned-нода недоступна — ищем первую живую альтернативу
    fallback_idx = None
    for i, nd in enumerate(nodes):
        if i == pinned:
            continue
        if _tcp_ok(nd.get("host", ""), int(nd.get("port", 443))):
            fallback_idx = i
            break

    if fallback_idx is None:
        _fallback_log(
            f"PINNED-FALLBACK: нода #{pinned+1} ({pinned_host}) DOWN, "
            f"нет живых альтернатив — конфиг не изменён"
        )
        return False

    fb_nd   = nodes[fallback_idx]
    fb_host = fb_nd.get("host", "")

    # Сохраняем оригинальный pinned для фазы восстановления
    state["_pinned_original_index"]  = pinned
    state["chain_pinned_node_index"] = fallback_idx
    try:
        _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception:
        return False

    _set_chain_pinned_node_index(fallback_idx)

    try:
        _rebuild_and_restart_xray("Xray активен — pinned fallback применён")
    except Exception as e:
        log_to_file("WARN", f"_pinned_node_check_and_fallback: rebuild failed: {e}")

    _fallback_log(
        f"PINNED-FALLBACK: нода #{pinned+1} ({pinned_host}) DOWN → "
        f"переключено на ноду #{fallback_idx+1} ({fb_host})"
    )
    log_to_file("INFO",
        f"pinned-fallback: #{pinned+1} ({pinned_host}) → #{fallback_idx+1} ({fb_host})")
    _tg_notify_event("xray_down",
        f"⚠️ Pinned-нода <b>#{pinned+1} ({pinned_host})</b> недоступна.\n"
        f"Автоматический fallback → нода <b>#{fallback_idx+1} ({fb_host})</b>.")

    return True


def _dpi_run_once() -> int:
    """
    Сканирует error.log за последние N минут.
    Считает сумму весов DPI-паттернов по каждому IP.
    При превышении порога:
      - Добавляет UFW deny
      - Пишет в autoban.json (shared banned list)
      - Логирует в _DPI_LOG
    Возвращает число новых банов.
    """
    cfg       = _dpi_state_load()
    threshold = cfg.get("threshold", _DPI_THRESHOLD_DEFAULT)
    window    = cfg.get("window_min", _DPI_WINDOW_DEFAULT)
    whitelist = set(cfg.get("whitelist", ["127.0.0.1", "::1"]))

    # Также берём whitelist из autoban (единая БД)
    try:
        ab = _autoban_load()
        for ip in ab.get("whitelist", []):
            whitelist.add(ip)
        for ip in _autoban_get_chain_ips():
            whitelist.add(ip)
    except Exception:
        pass

    error_log = Path("/var/log/xray/error.log")
    if not error_log.exists():
        return 0

    cutoff = time.time() - window * 60
    ip_score: dict[str, int]        = {}
    ip_reasons: dict[str, list]     = {}
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    try:
        lines = error_log.read_text(errors="replace").splitlines()[-8000:]
    except Exception:
        return 0

    for line in lines:
        # Фильтр по времени
        dt_m = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})', line)
        if dt_m:
            try:
                ts = datetime.strptime(
                    f"{dt_m.group(1)} {dt_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                ).timestamp()
                if ts < cutoff:
                    continue
            except Exception:
                pass

        ip_m = ip_pattern.search(line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        if ip in whitelist:
            continue

        for pattern, desc, weight in _DPI_PATTERNS:
            if pattern.search(line):
                ip_score[ip]   = ip_score.get(ip, 0) + weight
                ip_reasons.setdefault(ip, [])
                if desc not in ip_reasons[ip]:
                    ip_reasons[ip].append(desc)
                break  # один матч на строку, не суммируем дважды

    # ── Дополнительный источник: access.log ──────────────────────────────────
    # access.log пишется на entry-ноде и фиксирует соединения, которые Xray
    # принял, но которые демонстрируют поведение активного зондирования:
    #   • соединение приходит, но routing = "BLOCK" (неизвестный протокол/порт)
    #   • множественные повторные попытки с одного IP за короткое окно
    #   • соединение установлено, но 0 байт трафика (handshake probe)
    # Эти события не попадают в error.log, поэтому access.log — второй источник.
    access_log = Path("/var/log/xray/access.log")
    if access_log.exists():
        try:
            acc_lines = access_log.read_text(errors="replace").splitlines()[-15000:]
        except Exception:
            acc_lines = []

        # Паттерны зондирования в access.log
        _ACC_PATTERNS: list[tuple] = [
            # Соединение заблокировано роутингом — нестандартный протокол/порт
            (re.compile(r'accepted\s+\S+\s+\[.*?->\s*BLOCK\]', re.IGNORECASE),
             "access: routing→BLOCK", 3),
            # Нулевой трафик: upload=0 и download=0 байт после принятого соединения
            (re.compile(r'\b0\s+bytes?\s+upload.*?0\s+bytes?\s+download|\b0\s+0\b.*\|',
                        re.IGNORECASE),
             "access: 0-bytes probe", 2),
            # Множество accepted с одного IP в одной строке / повтор IP в короткий
            # промежуток — считается в ip_acc_hits ниже, а не через этот паттерн.
        ]

        # Счётчик попыток подключения из access.log per-IP (для порогового анализа)
        ip_acc_hits: dict[str, int] = {}

        pat_acc_ip = re.compile(r'accepted\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        for line in acc_lines:
            # Фильтр по времени (формат access.log: YYYY/MM/DD hh:mm:ss)
            dt_m = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})', line)
            if dt_m:
                try:
                    ts = datetime.strptime(
                        f"{dt_m.group(1)} {dt_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                    ).timestamp()
                    if ts < cutoff:
                        continue
                except Exception:
                    pass

            ip_m = pat_acc_ip.search(line)
            if not ip_m:
                # Попробуем общий IP-паттерн
                ip_m = ip_pattern.search(line)
            if not ip_m:
                continue
            ip = ip_m.group(1)
            if ip in whitelist:
                continue

            # Подсчёт accepted-хитов per-IP
            if "accepted" in line.lower():
                ip_acc_hits[ip] = ip_acc_hits.get(ip, 0) + 1

            # Проверка структурных паттернов зондирования
            for pat, desc, weight in _ACC_PATTERNS:
                if pat.search(line):
                    ip_score[ip] = ip_score.get(ip, 0) + weight
                    ip_reasons.setdefault(ip, [])
                    if desc not in ip_reasons[ip]:
                        ip_reasons[ip].append(desc)
                    break

        # Бонусный вес за флудовые попытки: >20 accepted с одного IP за окно
        for ip, hits in ip_acc_hits.items():
            if ip in whitelist:
                continue
            if hits > 20:
                bonus = min((hits - 20) // 5, 6)  # +1 за каждые 5 лишних, max +6
                ip_score[ip] = ip_score.get(ip, 0) + bonus
                ip_reasons.setdefault(ip, [])
                reason = f"access: flood {hits} conn"
                if reason not in ip_reasons[ip]:
                    ip_reasons[ip].append(reason)

    # ── Загружаем уже забаненных (не баним второй раз) ───────────────────────
    try:
        ab_cfg = _autoban_load()
        already_banned = set(ab_cfg.get("banned", {}).keys())
    except Exception:
        already_banned = set()

    new_bans = 0
    for ip, score in ip_score.items():
        if score < threshold:
            continue
        if ip in already_banned:
            continue

        reasons_str = ", ".join(ip_reasons.get(ip, ["DPI probe"]))
        ban_ts = datetime.now().isoformat()

        # UFW ban
        r = _run(["ufw", "deny", "from", ip, "to", "any",
                  "comment", "xray-dpi-detector"],
                 check=False, quiet=True)
        if r.returncode != 0:
            continue

        # Пишем в autoban.json (единый список)
        try:
            ab_cfg = _autoban_load()
            ab_cfg.setdefault("banned", {})[ip] = {
                "count":     score,
                "banned_at": ban_ts,
                "reason":    f"DPI probe [{reasons_str}] score={score}",
            }
            ab_cfg.setdefault("ban_history", []).append({
                "ip":          ip,
                "banned_at":   ban_ts,
                "unbanned_at": None,
                "count":       score,
                "reason":      f"DPI [{reasons_str}]",
            })
            if len(ab_cfg["ban_history"]) > 500:
                ab_cfg["ban_history"] = ab_cfg["ban_history"][-500:]
            _autoban_save(ab_cfg)
        except Exception:
            pass

        # Лог
        try:
            _DPI_LOG.parent.mkdir(parents=True, exist_ok=True)
            with _DPI_LOG.open("a") as f:
                f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] BAN {ip}"
                        f"  score={score}  reasons=[{reasons_str}]\n")
        except Exception:
            pass

        log_to_file("INFO", f"DPI-detector: {ip} banned (score={score}, {reasons_str})")
        _tg_notify_event("xray_down",
            f"🔍 DPI-зонд заблокирован: <b>{ip}</b> (score={score})\n"
            f"<i>{reasons_str}</i>")
        # Записываем в читаемый отчёт с ASN-данными
        try:
            _asn = _lookup_asn(ip)
            _ban_report_append(ip, score, f"DPI [{reasons_str}]", _asn)
        except Exception:
            pass
        new_bans += 1

    # Попутно проверяем pinned-ноду — если деградировала, делаем fallback
    try:
        _pinned_node_check_and_fallback()
    except Exception:
        pass

    return new_bans


def _dpi_install_cron() -> None:
    """Устанавливает cron каждые 5 минут."""
    installer = str(Path(sys.argv[0]).resolve())
    cron_line = f"*/5 * * * * root /usr/bin/python3 {installer} --dpi-check >> {_DPI_LOG} 2>&1\n"
    _DPI_CRON.write_text(
        f"# xray-dpi-detector — анализ DPI-зондирования\n"
        f"# Генерируется установщиком VLESS v3.99\n"
        f"SHELL=/bin/bash\n"
        f"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"{cron_line}"
    )
    _DPI_CRON.chmod(0o644)
    success(f"DPI-детектор cron установлен (каждые 5 мин)")


def _dpi_remove_cron() -> None:
    _DPI_CRON.unlink(missing_ok=True)


def do_manage_dpi_detector() -> None:
    """Интерактивное управление DPI-детектором."""
    while True:
        os.system("clear")
        print()
        cfg       = _dpi_state_load()
        threshold = cfg.get("threshold", _DPI_THRESHOLD_DEFAULT)
        window    = cfg.get("window_min", _DPI_WINDOW_DEFAULT)
        cron_on   = _DPI_CRON.exists()

        _box_top("🔍  DPI-ДЕТЕКТОР")
        _box_row(f"  {DIM}Анализирует error.log Xray на паттерны активного зондирования.{NC}")
        _box_row(f"  {DIM}Каждый паттерн имеет вес; при превышении порога IP автоматически банится.{NC}")
        _box_sep()
        _box_row(f"  Cron (5 мин):  {''+GREEN+'ВКЛЮЧЁН'+NC if cron_on else ''+DIM+'ОТКЛЮЧЁН'+NC}")
        _box_row(f"  Порог score:   {CYAN}{threshold}{NC}  (сумма весов паттернов)")
        _box_row(f"  Окно анализа:  {CYAN}{window}{NC} мин")
        _box_sep()
        _box_row(f"  {BOLD}Отслеживаемые паттерны:{NC}")
        for _pat, _desc, _w in _DPI_PATTERNS:
            _box_row(f"    {DIM}•{NC} {_desc:<35} {DIM}вес={_w}{NC}")
        _box_sep()
        _box_item("1", f"{'Отключить' if cron_on else 'Включить'} cron DPI-детектора")
        _box_item("2", f"Изменить порог / окно")
        _box_item("3", f"Запустить анализ прямо сейчас")
        _box_item("4", f"📋 Последние строки лога")
        _box_item("5", f"Управление whitelist")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if cron_on:
                _dpi_remove_cron()
                cfg["enabled"] = False
                _dpi_state_save(cfg)
                success("DPI-детектор отключён")
            else:
                _dpi_install_cron()
                cfg["enabled"] = True
                _dpi_state_save(cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw_t = input(f"  Порог score [{threshold}]: ").strip()
            raw_w = input(f"  Окно (мин) [{window}]: ").strip()
            if raw_t.isdigit() and int(raw_t) > 0:
                cfg["threshold"] = int(raw_t)
            if raw_w.isdigit() and int(raw_w) > 0:
                cfg["window_min"] = int(raw_w)
            _dpi_state_save(cfg)
            success("Сохранено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            info("Запуск DPI-анализа...")
            n = _dpi_run_once()
            if n:
                success(f"Заблокировано DPI-зондов: {n}")
            else:
                success("DPI-зондов не обнаружено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            print()
            if _DPI_LOG.exists():
                # Фильтруем технический мусор из stderr (ошибки python/cron)
                _skip_prefixes = (
                    "/usr/bin/python", "python3:", "python:", "/bin/python",
                    "Traceback", "  File ", "ImportError", "ModuleNotFoundError",
                )
                all_lines = _DPI_LOG.read_text(errors="replace").splitlines()
                lines = [l for l in all_lines
                         if not any(l.startswith(p) for p in _skip_prefixes)][-30:]
                _box_top("📋 DPI-лог (последние 30 строк)")
                _max_line = _BOX_W - 3  # 2 пробела отступа + 1 запас
                for line in lines:
                    col = RED if "BAN" in line else DIM
                    remaining = line
                    first = True
                    while remaining:
                        chunk = remaining[:_max_line]
                        remaining = remaining[_max_line:]
                        indent = "  " if first else "    "
                        _box_row(f"{indent}{col}{chunk}{NC}")
                        first = False
                _box_bottom()
            else:
                warn("Лог пуст или не создан")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            wl = cfg.get("whitelist", ["127.0.0.1", "::1"])
            print()
            _box_top("Whitelist DPI-детектора")
            for i, ip in enumerate(wl, 1):
                _box_item(str(i), ip)
            _box_sep()
            _box_item("+", "Добавить")
            _box_item("-", "Удалить")
            _box_bottom()
            act = input("  Действие [+/-/Enter]: ").strip()
            if act == "+":
                new_ip = input("  IP: ").strip()
                if new_ip and new_ip not in wl:
                    wl.append(new_ip)
                    cfg["whitelist"] = wl
                    _dpi_state_save(cfg)
                    success(f"Добавлен: {new_ip}")
            elif act == "-":
                raw_n = input("  Номер: ").strip()
                if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl):
                    removed = wl.pop(int(raw_n) - 1)
                    cfg["whitelist"] = wl
                    _dpi_state_save(cfg)
                    success(f"Удалён: {removed}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА
# =============================================================================

