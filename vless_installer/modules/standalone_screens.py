"""
vless_installer/modules/standalone_screens.py
───────────────────────────────────────────────────────────────────────────────
Четыре автономных интерактивных экрана, не имеющих install-state мутаций:

  • check_exit_geo()           — GeoIP-проверка выходного IP (через ip-api.com)
  • do_view_logs()             — просмотр логов с фильтром / follow
  • do_check_domain_external() — DNS+HTTP+HTTPS+TCP проверка домена снаружи
  • do_system_dashboard()      — live-дашборд CPU/RAM/Disk/сервисы

Все функции — read-only относительно state.json (do_check_domain_external
читает domain/port из state, но не пишет). Чистые UI-экраны, безопасны для
автономного существования.

Точки входа из _core.py:
    from vless_installer.modules.standalone_screens import (
        check_exit_geo, do_view_logs, do_check_domain_external, do_system_dashboard,
    )

Доступ к helpers ядра (_run, _box_*, цвета, log_to_file) — через importlib
(lazy binding), как и в других извлечённых модулях.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("vless_installer._core")


def _c(name: str, default=None):
    """getattr(_core, name, default) — короткая форма для частых вызовов."""
    return getattr(_core_module(), name, default)


# ============================================================================
#  ГЕОПРОВЕРКА ВЫХОДНОГО IP
# ============================================================================
def check_exit_geo(silent: bool = False) -> None:
    """
    Проверяет реальный GeoIP выходного IP через ip-api.com.
    Предупреждает если страна = RU (трафик не обходит блокировки).
    При silent=False открывает собственный бокс (вызов напрямую из меню).
    При silent=True — рисует только содержимое (вызов из do_full_diagnostic).
    """
    core = _core_module()
    _run         = core._run
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    log_to_file  = core.log_to_file
    country_flag_emoji = core.country_flag_emoji
    CYAN, NC, RED, YELLOW, GREEN, DIM = core.CYAN, core.NC, core.RED, core.YELLOW, core.GREEN, core.DIM

    if not silent:
        _box_top(f"Геопроверка выходного IP")

    _box_row()

    try:
        r = _run(
            ["curl", "-s", "--max-time", "10",
             "http://ip-api.com/json?fields=status,country,countryCode,city,isp,query"],
            capture=True, check=False
        )
        if r.returncode != 0 or not r.stdout.strip():
            _box_warn("Не удалось получить GeoIP — нет ответа от ip-api.com")
            return
        data = json.loads(r.stdout.strip())
    except Exception as e:
        _box_warn(f"Ошибка GeoIP запроса: {e}")
        return

    if data.get("status") != "success":
        _box_warn("ip-api.com вернул ошибку — попробуйте позже")
        return

    ip         = data.get("query", "?")
    country    = data.get("country", "?")
    country_cc = data.get("countryCode", "?")
    city       = data.get("city", "?")
    isp        = data.get("isp", "?")

    _flag_cc  = country_flag_emoji(country_cc)
    _cty_tr   = country[:24]
    _city_tr  = city[:24]
    _isp_tr   = isp[:34]
    # ── Блок IP/ISP внутри рамки, затем рамка закрывается ──
    _box_row(f"  IP:      {CYAN}{ip}{NC}")
    _box_row(f"  ISP:     {CYAN}{_isp_tr}{NC}")
    _box_bottom()
    # Флаг + страна + город — вне рамки
    print(f"  {_flag_cc}  {CYAN}{_cty_tr} ({country_cc}){NC}  {DIM}{_city_tr}{NC}")
    print()

    # ── Статус в отдельном боксе ──
    if country_cc == "RU":
        _box_top()
        _box_row(f"  {RED}⚠  ВНИМАНИЕ: выходной IP находится в России!{NC}")
        _box_row(f"  {YELLOW}   Трафик может НЕ обходить российские блокировки.{NC}")
        _box_row(f"  {YELLOW}   Проверьте настройки exit-ноды (Режим B) или WARP.{NC}")
        _box_bottom()
        log_to_file("WARN", f"GeoIP: выходной IP {ip} в России ({isp})")
    else:
        _box_top()
        _box_row(f"  {GREEN}✓  Выходной IP за пределами России — блокировки обходятся{NC}")
        _box_bottom()
        log_to_file("INFO", f"GeoIP: выходной IP {ip} ({country}, {isp})")

    # Дополнительно — проверка через Cloudflare trace если WARP активен
    try:
        rc = _run(["warp-cli", "--version"], capture=True, check=False)
        if rc.returncode == 0:
            rt = _run(["curl", "-s", "--max-time", "8",
                       "https://www.cloudflare.com/cdn-cgi/trace"],
                      capture=True, check=False)
            warp_on = "warp=on" in rt.stdout
            warp_str = f"{GREEN}ON{NC}" if warp_on else f"{YELLOW}OFF{NC}"
            print()
            _box_top()
            _box_row(f"  WARP:    {warp_str} (Cloudflare trace)")
            _box_bottom()
    except Exception:
        pass


# ============================================================================
#  ПРОСМОТР ЛОГОВ
# ============================================================================
def do_view_logs() -> None:
    """Интерактивный просмотр логов с выбором источника, фильтром и follow-режимом."""
    import re as _re_log

    core = _core_module()
    _box_top     = core._box_top
    _box_bottom  = core._box_bottom
    _box_sep     = core._box_sep
    _box_row     = core._box_row
    _box_item    = core._box_item
    _box_warn    = core._box_warn
    _box_info    = core._box_info
    _box_ok      = core._box_ok
    _wcslen      = core._wcslen
    _BOX_W       = core._BOX_W
    LOG_FILE     = core.LOG_FILE
    warn         = core.warn
    CYAN, NC, DIM, GREEN, RED, YELLOW, WHITE, BOLD = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.RED, core.YELLOW, core.WHITE, core.BOLD
    )

    LOG_SOURCES = {
        "1": ("Xray access",    Path("/var/log/xray/access.log")),
        "2": ("Xray error",     Path("/var/log/xray/error.log")),
        "3": ("Nginx access",   Path("/var/log/nginx/access.log")),
        "4": ("Nginx error",    Path("/var/log/nginx/error.log")),
        "5": ("Fail2ban",       Path("/var/log/fail2ban.log")),
        "6": ("Установщик",     LOG_FILE),
        "7": ("Autoupdate",     Path("/var/log/xray-autoupdate.log")),
        "8": ("Watchdog",       Path("/var/log/xray-watchdog.log")),
        "9": ("UUID rotate",    Path("/var/log/xray-uuid-rotate.log")),
    }

    # Ширина контента внутри рамки: _BOX_W минус 2 символа отступа слева ("  ")
    _LOG_INNER = _BOX_W - 2

    # ── Подсветка дат/времени ярко-белым ─────────────────────────────────────
    _DATETIME_RE = _re_log.compile(
        r'(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{4}|Z)?'
        r'|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        r'|\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?'
        r'|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'
    )

    def _highlight_datetime(line: str) -> str:
        return _DATETIME_RE.sub(lambda m: f"{WHITE}{BOLD}{m.group(0)}{NC}", line)

    def _log_box_row(line: str) -> None:
        INDENT_CONT = " "
        CONT_W = len(INDENT_CONT)

        highlighted = _highlight_datetime(line)

        if _wcslen(line) <= _LOG_INNER:
            _box_row(f"  {highlighted}")
            return

        words = line.split(" ")
        current_plain = ""
        current_parts: list[str] = []
        first_line = True
        max_w = _LOG_INNER
        cont_max_w = _LOG_INNER - CONT_W

        def _flush(parts: list[str], is_first: bool) -> None:
            chunk = " ".join(parts)
            chunk_hi = _highlight_datetime(chunk)
            if is_first:
                _box_row(f"  {chunk_hi}")
            else:
                _box_row(f"  {INDENT_CONT}{chunk_hi}")

        for word in words:
            word_w = _wcslen(word)
            sep_w = 1 if current_plain else 0
            avail = max_w if first_line else cont_max_w
            if _wcslen(current_plain) + sep_w + word_w <= avail:
                if current_plain:
                    current_plain += " " + word
                else:
                    current_plain = word
                current_parts.append(word)
            else:
                if current_parts:
                    _flush(current_parts, first_line)
                    first_line = False
                while _wcslen(word) > cont_max_w:
                    cut = ""
                    cut_w = 0
                    for ch in word:
                        cw = _wcslen(ch)
                        if cut_w + cw > cont_max_w:
                            break
                        cut += ch
                        cut_w += cw
                    cut_hi = _highlight_datetime(cut)
                    _box_row(f"  {INDENT_CONT}{cut_hi}")
                    word = word[len(cut):]
                    first_line = False
                current_plain = word
                current_parts = [word]

        if current_parts:
            _flush(current_parts, first_line)

    # ── Меню выбора лога ──────────────────────────────────────────────────────
    os.system("clear")
    print()
    _box_top("Просмотр логов")
    for k, (name, path) in LOG_SOURCES.items():
        exists = f"{GREEN}✓{NC}" if path.exists() else f"{RED}✗{NC}"
        label_plain = f"✓ {name}  {path}" if path.exists() else f"✗ {name}  {path}"
        KEY_OVERHEAD = 7
        if len(label_plain) + KEY_OVERHEAD <= _BOX_W:
            _box_item(f"{k}", f"{exists} {name}  {DIM}{path}{NC}")
        else:
            _box_item(f"{k}", f"{exists} {name}")
            _box_row(f"       {DIM}{path}{NC}")
    _box_bottom()

    ch = input(f"  Выбор лога [1]: ").strip() or "1"
    if ch not in LOG_SOURCES:
        warn("Неверный выбор")
        return

    name, log_path = LOG_SOURCES[ch]
    if not log_path.exists():
        warn(f"Файл не найден: {log_path}")
        return

    raw_lines = input(f"  Строк [50]: ").strip() or "50"
    n_lines = int(raw_lines) if raw_lines.isdigit() else 50

    flt = input(f"  Фильтр (grep-слово, Enter = без фильтра): ").strip()

    follow = input(f"  Режим follow (tail -f)? [y/N]: ").strip().lower() == "y"

    print()
    title_plain = f"{name}  {log_path}"
    if _wcslen(title_plain) <= _BOX_W - 4:
        _box_top(f"{name}  {DIM}{log_path}{NC}")
    else:
        _box_top(f"{name}")
        _box_row(f"  {DIM}{log_path}{NC}")
        _box_sep()
    _box_row()

    if follow:
        _box_row(f"  {DIM}(Ctrl+C для выхода){NC}")
        _box_row()
        cmd = ["tail", f"-{n_lines}", "-f", str(log_path)]
        if flt:
            try:
                p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                p2 = subprocess.Popen(
                    ["grep", "--line-buffered", flt],
                    stdin=p1.stdout, stdout=None
                )
                p1.stdout.close()
                p2.wait()
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    p1.terminate()
                except Exception:
                    pass
        else:
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                pass
    else:
        lines = log_path.read_text(errors="replace").splitlines()
        if flt:
            lines = [l for l in lines if flt.lower() in l.lower()]
        lines = lines[-n_lines:]
        for _l in lines:
            _log_box_row(_l)
        _box_row()
        _box_row(f"  {DIM}Показано {len(lines)} строк{NC}")
        _box_row()
        _box_bottom()


# ============================================================================
#  ПРОВЕРКА ДОСТУПНОСТИ ДОМЕНА СНАРУЖИ
# ============================================================================
def do_check_domain_external() -> None:
    """
    Проверяет DNS-резолвинг, HTTP, HTTPS и доступность VLESS-порта снаружи.
    """
    core = _core_module()
    _run         = core._run
    _box_row     = core._box_row
    _box_warn    = core._box_warn
    _box_info    = core._box_info
    _box_ok      = core._box_ok
    log_to_file  = core.log_to_file
    STATE_FILE   = core.STATE_FILE
    CYAN, NC, DIM, GREEN, YELLOW = core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW

    _box_row()

    domain = ""
    port   = 443
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text())
            domain = st.get("domain", "")
            port   = st.get("server_port", 443)
    except Exception:
        pass

    if not domain:
        domain = input("  Домен для проверки: ").strip()
    if not domain:
        _box_warn("Домен не указан")
        return

    _box_row(f"  Домен: {CYAN}{domain}{NC}  |  Порт: {CYAN}{port}{NC}")

    # 1. DNS через Google 8.8.8.8
    _box_info("  [1/4] DNS-резолвинг через 8.8.8.8 ...")
    r = _run(
        ["dig", "+short", f"@8.8.8.8", domain, "A"],
        capture=True, check=False
    )
    if r.returncode == 0 and r.stdout.strip():
        resolved_ip = r.stdout.strip().splitlines()[-1]
        _box_ok(f"  DNS → {resolved_ip}")
    else:
        _box_warn(f"  DNS: домен не резолвится через 8.8.8.8!")
        resolved_ip = ""

    # 2. HTTP /.well-known/
    _box_info("  [2/4] HTTP 200 на /.well-known/ ...")
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10",
         f"http://{domain}/.well-known/"],
        capture=True, check=False
    )
    code = r.stdout.strip()
    if code in ("200", "301", "302", "403", "404"):
        _box_ok(f"  HTTP доступен (код {code})")
    else:
        _box_warn(f"  HTTP недоступен или таймаут (код {code or 'нет ответа'})")

    # 3. HTTPS TLS-рукопожатие
    _box_info("  [3/4] HTTPS TLS-рукопожатие ...")
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{ssl_verify_result}",
         "--max-time", "10",
         f"https://{domain}/"],
        capture=True, check=False
    )
    parts = r.stdout.strip().split()
    if r.returncode == 0 and parts:
        tls_code   = parts[0]
        tls_verify = parts[1] if len(parts) > 1 else "?"
        tls_ok = tls_verify == "0"
        colour = GREEN if tls_ok else YELLOW
        _box_row(f"    {colour}HTTPS код: {tls_code}  TLS verify: {'OK' if tls_ok else 'ОШИБКА ('+tls_verify+')'}{NC}")
    else:
        _box_warn(f"  HTTPS недоступен (returncode={r.returncode})")

    # 4. TCP доступность VLESS-порта снаружи
    _box_info(f"  [4/4] TCP доступность порта {port} (через curl --connect-to) ...")
    target_ip = resolved_ip or domain
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{errormsg}",
         "--max-time", "8",
         f"--connect-to", f"{domain}:{port}:{target_ip}:{port}",
         f"https://{domain}:{port}/"],
        capture=True, check=False
    )
    if r.returncode in (0, 35, 60):  # 35=SSL, 60=cert verify — порт отвечает
        _box_ok(f"  Порт {port} доступен снаружи")
    else:
        errmsg = r.stdout.strip() or r.stderr.strip()
        _box_warn(f"  Порт {port} недоступен: {errmsg or 'нет ответа'}")

    _box_row()
    log_to_file("INFO", f"External domain check: {domain}:{port}, DNS={resolved_ip}")


# ============================================================================
#  СИСТЕМНЫЙ ДАШБОРД
# ============================================================================
def do_system_dashboard() -> None:
    """Дашборд CPU / RAM / Disk / Uptime / Сервисы — обновляется каждые 3 с."""
    core = _core_module()
    _run         = core._run
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    CYAN, NC, DIM, GREEN, YELLOW, RED = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED
    )

    print(f"  {DIM}(Ctrl+C для выхода){NC}")
    time.sleep(0.5)

    def _read_cpu() -> float:
        try:
            lines = Path("/proc/stat").read_text().splitlines()
            vals = list(map(int, lines[0].split()[1:]))
            idle = vals[3]
            total = sum(vals)
            return idle, total
        except Exception:
            return 0, 1

    prev_idle, prev_total = _read_cpu()
    time.sleep(0.5)

    try:
        while True:
            os.system("clear")
            now = datetime.now().strftime("%H:%M:%S")

            # CPU
            cur_idle, cur_total = _read_cpu()
            diff_idle  = cur_idle  - prev_idle
            diff_total = cur_total - prev_total
            cpu_pct = 100.0 * (1 - diff_idle / max(diff_total, 1))
            prev_idle, prev_total = cur_idle, cur_total

            # RAM
            ram_pct = 0.0
            ram_used_mb = 0
            ram_total_mb = 0
            try:
                meminfo = {}
                for line in Path("/proc/meminfo").read_text().splitlines():
                    k, v = line.split(":", 1)
                    meminfo[k.strip()] = int(v.strip().split()[0])
                ram_total_mb = meminfo.get("MemTotal", 0) // 1024
                ram_avail_mb = meminfo.get("MemAvailable", 0) // 1024
                ram_used_mb  = ram_total_mb - ram_avail_mb
                ram_pct = 100.0 * ram_used_mb / max(ram_total_mb, 1)
            except Exception:
                pass

            # Disk
            disk_pct = 0.0
            try:
                r = _run(["df", "-h", "/"], capture=True, check=False)
                parts = r.stdout.splitlines()[-1].split()
                disk_pct = float(parts[4].replace("%", "")) if len(parts) >= 5 else 0
                disk_used  = parts[2]
                disk_total = parts[1]
            except Exception:
                disk_used = disk_total = "?"

            # Uptime
            try:
                up_s = float(Path("/proc/uptime").read_text().split()[0])
                up_h = int(up_s // 3600)
                up_m = int((up_s % 3600) // 60)
                uptime_str = f"{up_h}ч {up_m}м"
            except Exception:
                uptime_str = "?"

            # Активные соединения Xray
            xray_conns = "?"
            try:
                r = _run(["ss", "-tnp"], capture=True, check=False)
                xray_conns = str(sum(1 for l in r.stdout.splitlines() if "xray" in l))
            except Exception:
                pass

            def _bar(pct: float, width: int = 30) -> str:
                filled = max(0, min(width, int(pct * width / 100)))
                empty  = width - filled
                colour = GREEN if pct < 60 else YELLOW if pct < 85 else RED
                return f"{colour}{'▓' * filled}{NC}{DIM}{'░' * empty}{NC} {pct:.1f}%"

            print()
            _box_top(f"Системный дашборд  {now}")
            _box_row(f"  CPU:      {_bar(cpu_pct)}")
            _box_row(f"  RAM:      {_bar(ram_pct)}  {DIM}({ram_used_mb}/{ram_total_mb} МБ){NC}")
            _box_row(f"  Disk /:   {_bar(disk_pct)}  {DIM}({disk_used}/{disk_total}){NC}")
            _box_row(f"  Uptime:   {CYAN}{uptime_str}{NC}")
            _box_row(f"  Xray соединений: {CYAN}{xray_conns}{NC}")

            for svc in ("xray", "nginx", "dnscrypt-proxy"):
                r = _run(["systemctl", "is-active", svc], capture=True, check=False)
                st = r.stdout.strip()
                colour = GREEN if st == "active" else YELLOW
                _box_row(f"  {svc:<20} {colour}{st}{NC}")

            _box_row(f"  {DIM}Обновление каждые 3с  |  Ctrl+C для выхода{NC}")
            _box_bottom()
            time.sleep(3)

    except KeyboardInterrupt:
        print()
