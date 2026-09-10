"""
chimera/modules/dnscrypt_update.py
───────────────────────────────────────────────────────────────────────────────
Единый центр обновления/синхронизации DNSCrypt-proxy:
  • версия: установленная / latest (GitHub API) / обновление бинарника
  • авто-обновление: systemd timer (ежедневно 04:10) + bash-агент
  • синк пула серверов/релеев с живым списком: cron каждые 6 ч
    (standalone-скрипт /usr/local/bin/chimera-dnscrypt-pool-sync.py
    + шаблон /etc/dnscrypt-proxy/pool-template.json)
  • проверка цепочки xray → AGH(:53) → dnscrypt(:5300) — реальными
    DNS-запросами на каждом звене
  • ЕДИНЫЙ state-файл /var/lib/chimera/dnscrypt-state.json — ВСЕ DNS-меню
    (RA-меню dnscrypt_advanced, сеть _core «DU», AGH-меню, планировщик)
    читают статус из него → информация всегда синхронизирована между
    меню: обновил в одном — во всех остальных актуальна сразу.

ЗАЩИТА «СЕРВЕР БЕЗ DNS»:
  • обновление бинарника: бэкап → замена → рестарт → резолв-тест →
    цепочка-тест; провал → откат бинарника → рестарт → повторный тест
  • синк пула: конфиг меняется ТОЛЬКО при фактическом дрейфе пула;
    запись → рестарт → резолв-тест; провал → откат бэкапа конфига;
    провал отката → экстренный конфиг quad9-dnscrypt (известно-живые
    имена официального источника)
  • поверх: AGH fallback_dns (9.9.9.9/149.112.112.112) и redirect
    53→5300 (dns_redirect) — системный DNS живёт даже при падении
    dnscrypt-proxy целиком.

Артефакты на сервере:
  /usr/local/bin/chimera-dnscrypt-pool-sync.py   — синк-скрипт (cron 6 ч)
  /etc/dnscrypt-proxy/pool-template.json         — шаблон пула (из модуля)
  /etc/cron.d/xray-dnscrypt-pool-sync            — cron-задача
  /usr/local/bin/dnscrypt-autoupdate.sh          — авто-обновление
  /etc/systemd/system/dnscrypt-autoupdate.{service,timer}
  /var/lib/chimera/dnscrypt-state.json           — общий state (шапки меню)
  /var/log/dnscrypt-pool-sync.log, /var/log/dnscrypt-autoupdate.log

Точки входа:
    from chimera.modules.dnscrypt_update import (
        do_dnscrypt_update_menu, update_dnscrypt, check_dns_chain,
        run_pool_sync_now, install_pool_sync, install_autoupdate,
        get_pool_status_line, get_version_status_line, update_state,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

# ── Цвета (как в dnscrypt_advanced) ─────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE',
                            'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED = _C['RED']; GREEN = _C['GREEN']; YELLOW = _C['YELLOW']; CYAN = _C['CYAN']
BLUE = _C['BLUE']; BOLD = _C['BOLD']; DIM = _C['DIM']; WHITE = _C['WHITE']; NC = _C['NC']

def _info(msg):  print(f"{CYAN}[INFO]{NC}  {msg}")
def _ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}")
def _warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}")
def _err(msg):   print(f"{RED}[ERR]{NC}   {msg}")

# ── Константы путей ──────────────────────────────────────────────────────────
DNSCRYPT_CONF  = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
DNSCRYPT_BIN   = Path("/usr/local/bin/dnscrypt-proxy")
STATE_DIR      = Path("/var/lib/chimera")
STATE_FILE     = STATE_DIR / "dnscrypt-state.json"
POOL_SYNC_BIN  = Path("/usr/local/bin/chimera-dnscrypt-pool-sync.py")
POOL_TEMPLATE  = Path("/etc/dnscrypt-proxy/pool-template.json")
POOL_CRON      = Path("/etc/cron.d/xray-dnscrypt-pool-sync")
POOL_LOG       = Path("/var/log/dnscrypt-pool-sync.log")
AUTOPD_BIN     = Path("/usr/local/bin/dnscrypt-autoupdate.sh")
AUTOPD_SERVICE = Path("/etc/systemd/system/dnscrypt-autoupdate.service")
AUTOPD_TIMER   = Path("/etc/systemd/system/dnscrypt-autoupdate.timer")
AUTOPD_LOG     = Path("/var/log/dnscrypt-autoupdate.log")
BACKUP_DIR     = Path("/var/backups/dnscrypt/binaries")
AGH_SERVICE    = "AdGuardHome"
XRAY_CONF      = Path("/etc/xray/config.json")

# Целевые имена экстренного конфига (известно-живые, официальный источник)
EMERGENCY_NAMES = ["quad9-dnscrypt-ip4-nofilter-pri",
                   "quad9-dnscrypt-ip6-nofilter-pri"]


def _run(cmd, **kw) -> subprocess.CompletedProcess:
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(cmd, **kw)


# =============================================================================
#  STATE — единый файл для всех DNS-меню (синхронизация меню)
# =============================================================================
def read_state() -> Dict[str, Any]:
    """Читает state-файл; при отсутствии/битости — пустая структура."""
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def update_state(pool: Optional[Dict] = None,
                 version: Optional[Dict] = None,
                 chain: Optional[Dict] = None) -> None:
    """Атомарно (tmp+rename) мержит секции в state-файл."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        st = read_state()
        if pool:
            st["pool"] = {**st.get("pool", {}), **pool}
        if version:
            st["version"] = {**st.get("version", {}), **version}
        if chain:
            st["chain"] = {**st.get("chain", {}), **chain}
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception:
        pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def get_pool_status_line(template_total: int = 245) -> str:
    """Строка для шапок меню: пул из последнего синка (state) + fallback."""
    st = read_state().get("pool", {})
    total = st.get("total") or template_total
    alive = st.get("alive") or total
    countries = st.get("countries")
    last = st.get("last_sync")
    src = st.get("source", "")
    parts = [f"{total} шт."]
    if countries:
        parts.append(f"{countries} стран")
    if last:
        parts.append(f"синк {last}" + (f" ({src})" if src else ""))
        if alive != total:
            parts.append(f"живых {alive}")
    if st.get("error"):
        parts.append(f"{RED}ошибка: {st['error']}{NC}")
    return f"{CYAN}{' · '.join(str(p) for p in parts)}{NC}"


def get_version_status_line() -> str:
    """Строка для шапок меню: версия из state (fallback — живой замер)."""
    st = read_state().get("version", {})
    installed = st.get("installed")
    if not installed:
        installed = get_installed_version() or "?"
        update_state(version={"installed": installed})
    latest = st.get("latest")
    line = f"{CYAN}{installed}{NC}"
    if latest and latest != installed:
        line += f" {YELLOW}→ доступна {latest}{NC}"
    elif latest:
        line += f" {GREEN}(актуальна){NC}"
    auto = "авто ✓" if _timer_enabled("dnscrypt-autoupdate.timer") else "авто ✗"
    line += f" {DIM}[{auto}]{NC}"
    return line


# =============================================================================
#  ВЕРСИИ
# =============================================================================
def get_installed_version() -> Optional[str]:
    """Версия установленного бинарника (dnscrypt-proxy -version → 2.1.x)."""
    if not DNSCRYPT_BIN.exists():
        return None
    r = _run([str(DNSCRYPT_BIN), "-version"])
    m = re.search(r'\d+\.\d+\.\d+', r.stdout or "")
    return m.group(0) if m else None


def fetch_latest_version() -> Optional[str]:
    """Latest tag с GitHub API (кэшируется в state 6 ч)."""
    st = read_state().get("version", {})
    latest, checked = st.get("latest"), st.get("last_check")
    if latest and checked:
        try:
            dt = datetime.strptime(checked, "%Y-%m-%d %H:%M")
            if (datetime.now() - dt).total_seconds() < 6 * 3600:
                return latest
        except Exception:
            pass
    r = _run(["curl", "-fsSL", "--connect-timeout", "15",
              "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"])
    m = None
    try:
        m = json.loads(r.stdout).get("tag_name", "")
    except Exception:
        pass
    if m:
        update_state(version={"latest": m, "last_check": _now()})
    return m or latest


def _norm(ver: str) -> List[int]:
    return [int(x) for x in re.findall(r'\d+', ver)[:3]]


# =============================================================================
#  ЦЕПОЧКА xray → AGH(:53) → dnscrypt(:5300)
# =============================================================================
def _listen_port() -> int:
    """Фактический порт dnscrypt из TOML (default 5300)."""
    try:
        txt = DNSCRYPT_CONF.read_text(errors="replace")
        m = re.search(r"^listen_addresses\s*=\s*\[(.+?)\]", txt, re.S | re.M)
        if m:
            pm = re.search(r':(\d+)["\']', m.group(1))
            if pm:
                return int(pm.group(1))
    except Exception:
        pass
    return 5300


def _dig(port: int, name: str = "example.com") -> bool:
    """Реальный DNS-запрос к 127.0.0.1:port — есть ли ответ."""
    r = _run(["dig", "+short", "+time=3", "+tries=1",
              "@127.0.0.1", "-p", str(port), name])
    return r.returncode == 0 and bool((r.stdout or "").strip())


def _svc_active(name: str) -> bool:
    r = _run(["systemctl", "is-active", name])
    return (r.stdout or "").strip() == "active"


def _timer_enabled(name: str) -> bool:
    r = _run(["systemctl", "is-enabled", name])
    return (r.stdout or "").strip() == "enabled"


def check_dns_chain(verbose: bool = False) -> Dict[str, Any]:
    """Проверка всей цепочки xray → AGH(:53) → dnscrypt(:5300).

    Реальными запросами:
      1. dnscrypt: сервис активен + dig @127.0.0.1:5300 отвечает
      2. системный вход :53 (AGH или redirect 53→5300): dig @127.0.0.1:53
      3. xray: сервис активен + config.json DNS ссылается на 127.0.0.1 (AGH)

    Пишет результат в state (секция chain) — все меню видят одно и то же.
    Возвращает dict: {dnscrypt, system_dns, agh_owned, xray, xray_dns_ok, ok}.
    """
    port = _listen_port()
    result: Dict[str, Any] = {}
    # 1. dnscrypt
    dn_active = _svc_active("dnscrypt-proxy")
    dn_resolves = _dig(port)
    result["dnscrypt"] = dn_active and dn_resolves
    result["dnscrypt_port"] = port
    # 2. :53 — AGH владеет или redirect
    agh_active = _svc_active(AGH_SERVICE)
    sys_dns_ok = _dig(53)
    result["system_dns"] = sys_dns_ok
    result["agh_owned"] = agh_active
    result["agh"] = sys_dns_ok if agh_active else None
    # 3. xray
    xray_active = _svc_active("xray")
    xray_dns_ok = None
    if xray_active:
        try:
            cfg = XRAY_CONF.read_text(errors="replace")
            m = re.search(r'"dns"\s*:\s*\{', cfg)
            xray_dns_ok = bool(m) and "127.0.0.1" in cfg[m.start():m.start() + 2000]
        except Exception:
            xray_dns_ok = False
    result["xray"] = xray_active
    result["xray_dns_ok"] = xray_dns_ok
    # Итог: dnscrypt обязателен; :53 обязателен (AGH/redirect);
    # xray — если активен (на Exit-нодах может не быть DNS-потребителя).
    result["ok"] = bool(result["dnscrypt"] and sys_dns_ok and
                        (xray_dns_ok is not False))
    result["last_check"] = _now()
    update_state(chain={k: v for k, v in result.items() if k != "last_check"} |
                 {"last_check": result["last_check"]})

    if verbose:
        print()
        _info(f"Проверка цепочки DNS (xray → AGH → dnscrypt:{port}):")
        mark = lambda b: f"{GREEN}✓{NC}" if b else f"{RED}✗{NC}"
        _info(f"  1. dnscrypt-proxy ({port}): сервис {mark(dn_active)}, "
              f"резолвит {mark(dn_resolves)}")
        who = "AdGuard Home" if agh_active else "redirect 53→5300"
        _info(f"  2. системный DNS :53 ({who}): отвечает {mark(sys_dns_ok)}")
        if xray_active:
            _info(f"  3. xray: активен {mark(xray_active)}, "
                  f"DNS → 127.0.0.1 {mark(bool(xray_dns_ok))}")
        else:
            _info(f"  3. xray: {DIM}неактивен (не проверяется){NC}")
        if result["ok"]:
            _ok("Цепочка цела: все звенья отвечают.")
        else:
            _warn("Цепочка разорвана — см. звенья с ✗ выше.")
    return result


# =============================================================================
#  ОБНОВЛЕНИЕ БИНАРНИКА (ручное)
# =============================================================================
def update_dnscrypt(interactive: bool = True) -> bool:
    """Проверка версии → обновление бинарника с откатом.

    Шаги:
      1. installed vs latest (GitHub API)
      2. бэкап бинарника → /var/backups/dnscrypt/binaries/ (хранить 5)
      3. fetch_package(DNSCRYPT_SPEC, tag=latest) — зеркала + /root/
         (ручное размещение tar.gz поддерживается автоматически)
      4. рестарт → резолв-тест → цепочка-тест
      5. провал → откат бинарника → рестарт → повторный тест

    Возвращает True если dnscrypt работает (обновлён или уже актуален).
    """
    if not DNSCRYPT_BIN.exists():
        _warn("dnscrypt-proxy не установлен — обновлять нечего")
        return False

    installed = get_installed_version()
    latest = fetch_latest_version()
    update_state(version={"installed": installed, "latest": latest,
                          "last_check": _now()})
    if not installed:
        _err("Не удалось определить версию установленного бинарника")
        return False
    if not latest:
        _warn("GitHub API недоступен — версия latest неизвестна, отмена")
        return False

    if _norm(installed) >= _norm(latest):
        _ok(f"dnscrypt-proxy {installed} актуален (latest {latest})")
        if interactive:
            _info("Обновление не требуется.")
        return True

    _info(f"Обновление: {installed} → {latest}")
    if interactive:
        try:
            confirm = input(f"{CYAN}Обновить? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "n"
        if confirm not in ("", "y", "yes", "д", "да"):
            _info("Отменено пользователем")
            return False

    # Архитектура (маппинг как в dnscrypt_setup.install_dnscrypt)
    arch_raw = _run(["uname", "-m"]).stdout.strip()
    arch_map = {"x86_64": "linux_x86_64", "aarch64": "linux_arm64",
                "armv7l": "linux_arm", "i386": "linux_386", "i686": "linux_386"}
    arch = arch_map.get(arch_raw)
    if not arch:
        _err(f"Неподдерживаемая архитектура: {arch_raw}")
        return False

    # Бэкап текущего бинарника
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    bak = BACKUP_DIR / f"dnscrypt_{installed}_{datetime.now():%Y%m%d%H%M%S}"
    try:
        shutil.copy2(str(DNSCRYPT_BIN), str(bak))
        _ok(f"Бэкап бинарника: {bak}")
        # хранить последние 5
        olds = sorted(BACKUP_DIR.glob("dnscrypt_*"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        for old in olds[5:]:
            old.unlink(missing_ok=True)
    except Exception as e:
        _warn(f"Бэкап не создан ({e}) — продолжаю с откатом через re-download")

    # Скачивание + замена (fetch_package: зеркала, /root/, post_install)
    try:
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
    except Exception as e:
        _err(f"download_manager недоступен: {e}")
        return False

    if not fetch_package(DNSCRYPT_SPEC, tag=latest, arch=arch):
        _err("Не удалось скачать/установить бинарник — попробуйте позже "
             "или положите tar.gz в /root/ (см. подсказку выше)")
        return False

    new_ver = get_installed_version()
    _info(f"Бинарник заменён: {new_ver}")

    # Рестарт + тесты
    _run(["systemctl", "reset-failed", "dnscrypt-proxy"])
    _run(["systemctl", "restart", "dnscrypt-proxy"])
    port = _listen_port()
    ok = False
    for i in range(5):
        time.sleep(3)
        if _svc_active("dnscrypt-proxy") and _dig(port):
            ok = True
            break
    if ok:
        chain = check_dns_chain(verbose=interactive)
        ok = chain.get("dnscrypt") and chain.get("system_dns")
    if ok:
        _ok(f"dnscrypt-proxy обновлён {installed} → {new_ver} — резолвит, цепочка цела")
        update_state(version={"installed": new_ver, "latest": latest,
                              "last_check": _now(),
                              "last_update": _now()})
        return True

    # Откат бинарника
    _warn("Обновлённый бинарник не прошёл проверку — откат...")
    if bak and bak.exists():
        try:
            shutil.copy2(str(bak), str(DNSCRYPT_BIN))
            DNSCRYPT_BIN.chmod(0o755)
        except Exception as e:
            _err(f"Откат бинарника не удался: {e}")
    _run(["systemctl", "reset-failed", "dnscrypt-proxy"])
    _run(["systemctl", "restart", "dnscrypt-proxy"])
    for i in range(4):
        time.sleep(3)
        if _svc_active("dnscrypt-proxy") and _dig(port):
            _ok(f"Откат к {installed}: dnscrypt-proxy резолвит")
            update_state(version={"installed": installed, "last_check": _now()})
            return False
    _err("КРИТИЧНО: dnscrypt не поднялся после отката. AGH fallback_dns "
         "(9.9.9.9/149.112.112.112) держит системный DNS. Проверьте: "
         "journalctl -u dnscrypt-proxy -n 30")
    return False


# =============================================================================
#  АВТО-ОБНОВЛЕНИЕ (systemd timer 04:10 + bash-агент)
# =============================================================================
AUTOPD_SH = r'''#!/usr/bin/env bash
# dnscrypt-autoupdate.sh — авто-обновление dnscrypt-proxy.
# Устанавливается chimera/modules/dnscrypt_update.py::install_autoupdate().
# Аналог xray-autoupdate.sh: бэкап → зеркала → замена → тест → откат.
set -euo pipefail
LOG="/var/log/dnscrypt-autoupdate.log"
BIN=/usr/local/bin/dnscrypt-proxy
BACKUP_DIR="/var/backups/dnscrypt/binaries"
touch "$LOG" 2>/dev/null || true
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null || true; }

log "=== Проверка обновлений dnscrypt-proxy ==="
[[ -x "$BIN" ]] || { log "ERROR: бинарник не найден"; exit 1; }

CURRENT=$("$BIN" -version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
LATEST=$(curl -fsSL --connect-timeout 15 \
    "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest" \
    2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || true)
[[ -z "$CURRENT" || -z "$LATEST" ]] && { log "WARN: версия не определена"; exit 0; }
log "Установлена: $CURRENT | Последняя: $LATEST"

_norm() { echo "$1" | awk -F. '{printf "%05d%05d%05d\n", $1, $2, $3}'; }
[[ "$(_norm "$CURRENT")" == "$(_norm "$LATEST")" ]] && { log "INFO: версия актуальна"; exit 0; }

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  DC_ARCH="linux_x86_64" ;;
    aarch64) DC_ARCH="linux_arm64" ;;
    armv7*)  DC_ARCH="linux_arm" ;;
    *) log "ERROR: архитектура $ARCH не поддерживается"; exit 1 ;;
esac
TARBALL="dnscrypt-proxy-${DC_ARCH}-${LATEST}.tar.gz"

# Зеркала (порядок как в github_mirrors: release GitHub, потом gh-прокси)
MIRRORS=(
    "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${LATEST}/${TARBALL}"
    "https://ghproxy.net/https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${LATEST}/${TARBALL}"
    "https://gh-proxy.com/https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${LATEST}/${TARBALL}"
    "https://gh.llkk.cc/https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${LATEST}/${TARBALL}"
)
TMP_TGZ=$(mktemp /tmp/dnscrypt_au.XXXXXX.tar.gz)
EXTRACT_DIR=$(mktemp -d /tmp/dnscrypt_au_ex.XXXXXX)
trap 'rm -f "$TMP_TGZ" 2>/dev/null; rm -rf "$EXTRACT_DIR" 2>/dev/null' EXIT

DOWNLOADED=""
for URL in "${MIRRORS[@]}"; do
    if curl -fsSL --connect-timeout 30 --retry 2 "$URL" -o "$TMP_TGZ" 2>/dev/null \
       && [[ $(stat -c%s "$TMP_TGZ" 2>/dev/null || echo 0) -gt 100000 ]]; then
        DOWNLOADED="$URL"; break
    fi
done
[[ -z "$DOWNLOADED" ]] && { log "ERROR: ни одно зеркало не ответило"; exit 1; }
log "INFO: скачано с $DOWNLOADED"

tar -xzf "$TMP_TGZ" -C "$EXTRACT_DIR" 2>/dev/null || { log "ERROR: tar распаковка"; exit 1; }
NEW_BIN=$(find "$EXTRACT_DIR" -name dnscrypt-proxy -type f | head -1)
[[ -z "$NEW_BIN" || ! -x "$NEW_BIN" ]] && { log "ERROR: бинарник в архиве не найден"; exit 1; }

# Смоук-тест новой версии ДО остановки сервиса
"$NEW_BIN" -version 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+' || \
    { log "ERROR: новый бинарник не стартует"; exit 1; }

mkdir -p "$BACKUP_DIR"
BACKUP="${BACKUP_DIR}/dnscrypt_${CURRENT}_$(date +%Y%m%d%H%M%S)"
cp "$BIN" "$BACKUP" && chmod 755 "$BACKUP" || true
ls -t "${BACKUP_DIR}"/dnscrypt_* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

systemctl stop dnscrypt-proxy 2>/dev/null || true
cp "$NEW_BIN" "$BIN" && chmod 755 "$BIN"
systemctl reset-failed dnscrypt-proxy 2>/dev/null || true
systemctl start dnscrypt-proxy 2>/dev/null || true

# Порт из TOML (default 5300)
PORT=$(grep -oE "listen_addresses[^]]*" /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null \
    | grep -oE ':[0-9]+' | head -1 | tr -d ':' || echo 5300)

wait_dns() {
    for _i in 1 2 3 4 5; do
        sleep 3
        systemctl is-active --quiet dnscrypt-proxy 2>/dev/null || continue
        if dig +short +time=3 +tries=1 @127.0.0.1 -p "${PORT:-5300}" example.com 2>/dev/null | grep -q .; then
            return 0
        fi
    done
    return 1
}

if wait_dns; then
    if dig +short +time=3 +tries=1 @127.0.0.1 -p 53 example.com 2>/dev/null | grep -q .; then
        NEW_VER=$("$BIN" -version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "?")
        log "OK: обновлён $CURRENT → $NEW_VER. Бэкап: $BACKUP"
        python3 - "$NEW_VER" << 'PYSTATE'
import json, sys
from pathlib import Path
try:
    p = Path("/var/lib/chimera/dnscrypt-state.json")
    st = json.loads(p.read_text()) if p.exists() else {}
    v = st.get("version", {})
    v.update({"installed": sys.argv[1], "last_update": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")})
    st["version"] = v
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(st, ensure_ascii=False, indent=1))
except Exception:
    pass
PYSTATE
        exit 0
    else
        log "WARN: dnscrypt резолвит, но :53 (AGH/redirect) не отвечает"
    fi
fi

log "ERROR: не прошёл проверку — откат к $CURRENT"
cp "$BACKUP" "$BIN" && chmod 755 "$BIN" || true
systemctl reset-failed dnscrypt-proxy 2>/dev/null || true
systemctl restart dnscrypt-proxy 2>/dev/null || true
sleep 5
exit 1
'''


def install_autoupdate() -> bool:
    """Устанавливает авто-обновление: скрипт + service + timer (04:10)."""
    _info("Установка авто-обновления dnscrypt-proxy (ежедневно 04:10)...")
    try:
        AUTOPD_BIN.parent.mkdir(parents=True, exist_ok=True)
        AUTOPD_BIN.write_text(AUTOPD_SH.lstrip(), encoding="utf-8")
        AUTOPD_BIN.chmod(0o700)
        AUTOPD_SERVICE.write_text(
            "[Unit]\n"
            "Description=DNSCrypt-proxy Auto-Update\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/usr/local/bin/dnscrypt-autoupdate.sh\n"
            "StandardOutput=journal\n"
            "StandardError=journal\n"
            "TimeoutStartSec=600\n"
            "SuccessExitStatus=0 1\n", encoding="utf-8")
        AUTOPD_TIMER.write_text(
            "[Unit]\n"
            "Description=DNSCrypt-proxy Auto-Update Timer\n\n"
            "[Timer]\n"
            "OnCalendar=*-*-* 04:10:00\n"
            "RandomizedDelaySec=1800\n"
            "Persistent=true\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n", encoding="utf-8")
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "dnscrypt-autoupdate.timer"])
        _run(["systemctl", "start", "dnscrypt-autoupdate.timer"])
        _ok("Авто-обновление установлено и включено")
        _info(f"  Лог: {AUTOPD_LOG}")
        update_state(version={"auto_update": True})
        return True
    except Exception as e:
        _err(f"Не удалось установить авто-обновление: {e}")
        return False


def remove_autoupdate() -> bool:
    _info("Отключаю авто-обновление dnscrypt-proxy...")
    _run(["systemctl", "stop", "dnscrypt-autoupdate.timer"])
    _run(["systemctl", "disable", "dnscrypt-autoupdate.timer"])
    for p in (AUTOPD_TIMER, AUTOPD_SERVICE, AUTOPD_BIN):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    _run(["systemctl", "daemon-reload"])
    _ok("Авто-обновление удалено")
    update_state(version={"auto_update": False})
    return True


def autoupdate_enabled() -> bool:
    return _timer_enabled("dnscrypt-autoupdate.timer")


# =============================================================================
#  СИНК ПУЛА (cron каждые 6 ч, standalone-скрипт)
# =============================================================================
POOL_SYNC_SH = r'''#!/usr/bin/env python3
# chimera-dnscrypt-pool-sync.py — синк пула dnscrypt с живым списком.
# Устанавливается chimera/modules/dnscrypt_update.py::install_pool_sync().
# Запуск: cron /etc/cron.d/xray-dnscrypt-pool-sync (каждые 6 ч) или вручную.
#
# Логика:
#   1. Живые списки берём из КАШЕЙ самого dnscrypt-proxy
#      (/etc/dnscrypt-proxy/public-resolvers.md + relays.md) — они уже
#      minisign-верифицированы прокси при скачивании (простой режим).
#   2. Пул = шаблон (pool-template.json) ∩ живой список
#      + воскрешения из кладбища (имена, снова появившиеся в списке).
#   3. Маршруты ребилдятся по живым релеям; DoH-серверы из маршрутов
#      исключаются (не анонимизируются); wildcard — только живые релеи.
#   4. Конфиг перезаписывается ТОЛЬКО при фактическом изменении пула/маршрутов
#      (идемпотентность: нет изменений — нет рестарта).
#   5. После рестарта — резолв-тест; провал → откат бэкапа конфига;
#      провал отката → экстренный конфиг quad9-dnscrypt. Сервер без DNS
#      не остаётся (плюс AGH fallback_dns 9.9.9.9/149.112.112.112 поверх).
#   6. Итог пишется в /var/lib/chimera/dnscrypt-state.json (шапки меню).
import base64
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
TEMPLATE = Path("/etc/dnscrypt-proxy/pool-template.json")
LIVE_SRV = Path("/etc/dnscrypt-proxy/public-resolvers.md")
LIVE_REL = Path("/etc/dnscrypt-proxy/relays.md")
STATE = Path("/var/lib/chimera/dnscrypt-state.json")
MIN_POOL = 40          # ниже — живой список считается битым, конфиг не трогаем
MIN_LIVE_SECTIONS = 200

PROTO = {0x01: "DNSCrypt", 0x02: "DoH", 0x03: "DoT", 0x04: "DoQ", 0x81: "ODoH"}
EMERGENCY_NAMES = ["quad9-dnscrypt-ip4-nofilter-pri",
                   "quad9-dnscrypt-ip6-nofilter-pri"]


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def sections(path):
    if not path.exists():
        return []
    txt = path.read_text(errors="replace")
    return re.split(r"^## ", txt, flags=re.M)[1:]


def parse_live():
    live_srv = {}
    for sec in sections(LIVE_SRV):
        name = sec.split("\n", 1)[0].strip()
        protos = set()
        for s in re.findall(r"^sdns://([A-Za-z0-9_\-]+)", sec, re.M):
            try:
                b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))[0]
                protos.add(PROTO.get(b, "?"))
            except Exception:
                pass
        live_srv[name] = protos
    live_rel = {sec.split("\n", 1)[0].strip() for sec in sections(LIVE_REL)}
    return live_srv, live_rel


def current_listen():
    try:
        txt = CONF.read_text(errors="replace")
        m = re.search(r"^listen_addresses\s*=\s*\[[^\n]*\]", txt, re.M)
        if m:
            return m.group(0)
    except Exception:
        pass
    return "listen_addresses = ['127.0.0.1:5300']"


def current_port():
    m = re.search(r':(\d+)["\']', current_listen())
    return int(m.group(1)) if m else 5300


def resolves(port, attempts=4):
    for i in range(attempts):
        r = run(["dig", "+short", "+time=3", "+tries=1",
                 "@127.0.0.1", "-p", str(port), "example.com"])
        if r.returncode == 0 and r.stdout.strip():
            return True
        time.sleep(3)
    return False


def restart(port):
    run(["systemctl", "reset-failed", "dnscrypt-proxy"])
    run(["systemctl", "restart", "dnscrypt-proxy"])
    return resolves(port)


def build_config(listen, server_names, route_lines, params, with_odoh=True):
    names_str = ", ".join(f"'{n}'" for n in server_names)
    routes_str = ",\n  ".join(route_lines)
    params_lines = "\n".join(f"{k} = {v}" for k, v in params.items())
    odoh = """
[sources.odoh-servers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-servers.md',
]
cache_file    = 'odoh-servers.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 25

[sources.odoh-relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-relays.md',
]
cache_file    = 'odoh-relays.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 25
""" if with_odoh else ""
    return f"""## dnscrypt-proxy.toml — Chimera Project (pool-sync)
## Синхронизирован: {datetime.now():%Y-%m-%d %H:%M:%S}
## {len(server_names)} серверов · {len(route_lines)} маршрутов · ODoH · DNSSEC
## Пул = шаблон ∩ живой public-resolvers.md + воскрешения из кладбища

{listen}

server_names = [{names_str}]

{params_lines}

[sources]
  [sources.public-resolvers]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
    'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
    'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md',
  ]
  cache_file    = 'public-resolvers.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 25

  [sources.relays]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
    'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
    'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/relays.md',
  ]
  cache_file    = 'relays.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 25
{odoh}

[anonymized_dns]
  routes = [
  {routes_str}
  ]

[broken_implementations]
  fragments_blocked = [
  'cisco','cisco-ipv6','cisco-familyshield','cisco-familyshield-ipv6',
  'cisco-sandbox','cleanbrowsing-adult','cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family','cleanbrowsing-family-ipv6',
  'cleanbrowsing-security','cleanbrowsing-security-ipv6',
  ]

[blocked_names]
[blocked_ips]
[allowed_names]
[allowed_ips]
[schedules]
[captive_portals]
[local_doh]
"""


def emergency_config(listen, params):
    return build_config(listen, EMERGENCY_NAMES, [], params, with_odoh=False)


def parse_current_names():
    try:
        txt = CONF.read_text(errors="replace")
        m = re.search(r"^server_names\s*=\s*\[([^\]]+)\]", txt, re.M)
        if m:
            return [s.strip().strip("'\"") for s in m.group(1).split(",") if s.strip()]
    except Exception:
        pass
    return []


def parse_current_route_count():
    try:
        txt = CONF.read_text(errors="replace")
        return len(re.findall(r"server_name=", txt))
    except Exception:
        return 0


def state_write(**pool):
    try:
        st = {}
        if STATE.exists():
            st = json.loads(STATE.read_text())
        p = st.get("pool", {})
        p.update(pool)
        st["pool"] = p
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(st, ensure_ascii=False, indent=1))
    except Exception:
        pass


def main():
    log("=== pool-sync: синхронизация пула с живым списком ===")
    if not TEMPLATE.exists():
        log("ERROR: шаблон pool-template.json не найден — пропускаю")
        sys.exit(1)
    tpl = json.loads(TEMPLATE.read_text())
    live_srv, live_rel = parse_live()
    if len(live_srv) < MIN_LIVE_SECTIONS:
        log(f"WARN: живой список подозрительно мал ({len(live_srv)}) — "
            "кеш не скачан? Конфиг не трогаю")
        state_write(total=len(tpl["servers"]), last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    changed=False, error="live-list too small")
        sys.exit(0)

    tmpl_servers = tpl["servers"]
    kept = [n for n in tmpl_servers if n in live_srv]
    dead = [n for n in tmpl_servers if n not in live_srv]
    resurrected = [n for n in tpl.get("graveyard", []) if n in live_srv]
    pool = kept + resurrected
    log(f"Шаблон {len(tmpl_servers)} → живых {len(kept)}, мёртвых {len(dead)}, "
        f"воскрешено {len(resurrected)} → пул {len(pool)}")

    if len(pool) < MIN_POOL:
        log(f"ERROR: пул {len(pool)} < {MIN_POOL} — дрейф аномален, конфиг не трогаю")
        state_write(total=len(pool), changed=False,
                    last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    error=f"pool too small: {len(pool)}")
        sys.exit(1)

    # маршруты: только DNSCrypt/ODoH-серверы, релеи только живые
    routes = {}
    for name in pool:
        rt = tpl.get("routes", {}).get(name)
        if not rt:
            continue
        if not (live_srv.get(name, set()) & {"DNSCrypt", "ODoH"}):
            continue  # DoH-сервер — напрямую, без маршрута
        alive_rt = [r for r in rt if r in live_rel]
        if len(alive_rt) >= 2:
            routes[name] = alive_rt
    wildcard = [r for r in tpl.get("wildcard", []) if r in live_rel]

    route_lines = []
    for name, rt in routes.items():
        rlist = ", ".join(f"'{r}'" for r in rt)
        route_lines.append(f"{{ server_name='{name}', via=[{rlist}] }}")
    if wildcard:
        wlist = ", ".join(f"'{r}'" for r in wildcard)
        route_lines.append(f"{{ server_name='*', via=[{wlist}] }}")

    # идемпотентность: ничего не изменилось → без рестарта
    cur_names = parse_current_names()
    cur_routes = parse_current_route_count()
    if sorted(cur_names) == sorted(pool) and cur_routes == len(route_lines):
        log(f"Без изменений: пул {len(pool)}, маршруты {len(route_lines)} — рестарта нет")
        state_write(total=len(pool), alive=len(pool), changed=False,
                    countries=tpl.get("countries", 0), routes=len(route_lines),
                    resurrected=len(resurrected),
                    last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    source="cron", error=None)
        sys.exit(0)

    port = current_port()
    listen = current_listen()
    conf_new = build_config(listen, pool, route_lines, tpl["params"])

    # бэкап → запись → рестарт → тест
    bak = CONF.with_name(CONF.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
    try:
        shutil.copy2(str(CONF), str(bak))
    except Exception:
        bak = None
    CONF.write_text(conf_new)
    if restart(port):
        log(f"OK: пул применён ({len(pool)} серверов, {len(route_lines)} маршрутов)")
        # :53 (AGH/redirect) + xray — цепочка
        sys53 = run(["dig", "+short", "+time=3", "+tries=1",
                     "@127.0.0.1", "-p", "53", "example.com"])
        if sys53.returncode == 0 and sys53.stdout.strip():
            log("Цепочка: :53 (AGH/redirect) отвечает")
        else:
            log("WARN: :53 не отвечает — AGH/redirect вне зоны синка, проверьте вручную")
        state_write(total=len(pool), alive=len(pool), changed=True,
                    countries=tpl.get("countries", 0), routes=len(route_lines),
                    resurrected=len(resurrected), dead_removed=len(dead),
                    last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    source="cron", error=None)
        sys.exit(0)

    # откат
    log("WARN: рестарт с новым пулом не прошёл — откат бэкапа")
    if bak and bak.exists():
        shutil.copy2(str(bak), str(CONF))
        if restart(port):
            log("OK: откат успешлен, работает прежний пул")
            state_write(changed=False,
                        last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                        source="cron", error="rollback: new pool failed")
            sys.exit(1)
    # экстренный конфиг
    log("ERROR: откат не поднял резолвинг — ЭКСТРЕННЫЙ конфиг quad9-dnscrypt")
    CONF.write_text(emergency_config(listen, tpl["params"]))
    if restart(port):
        log("OK: экстренный конфиг применён — сервер с DNS (quad9-dnscrypt)")
        state_write(total=len(EMERGENCY_NAMES), changed=True,
                    last_sync=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    source="cron", error="emergency config applied")
        sys.exit(2)
    log("CRITICAL: даже экстренный конфиг не резолвит — AGH fallback_dns "
        "(9.9.9.9/149.112.112.112) держит системный DNS. "
        "journalctl -u dnscrypt-proxy -n 30")
    sys.exit(3)


if __name__ == "__main__":
    main()
'''


def _routes_from_advanced() -> Dict[str, List[str]]:
    """Персональные маршруты из dnscrypt_advanced._ANON_ROUTES → dict."""
    from chimera.modules.dnscrypt_advanced import _ANON_ROUTES
    routes: Dict[str, List[str]] = {}
    for line in _ANON_ROUTES:
        m = re.search(r"server_name='([^']+)',\s*via=\[([^\]]+)\]", line)
        if m and m.group(1) != "*":
            routes[m.group(1)] = re.findall(r"'([^']+)'", m.group(2))
    return routes


def install_pool_sync() -> bool:
    """Деплой синка пула: шаблон JSON + standalone-скрипт + cron 6 ч.

    Шаблон фиксирует ТЕКУЩУЮ кураторскую политику модуля (пул/маршруты/
    wildcard/кладбище/параметры): cron-скрипт самодостаточен и не зависит
    от наличия chimera-репо на сервере. Обновление chimera переустанавливает
    шаблон (вызывается из RA-меню/apply).
    """
    _info("Установка синка пула (cron каждые 6 ч)...")
    try:
        from chimera.modules import dnscrypt_advanced as adv
        template = {
            "servers": adv._SERVER_NAMES,
            "routes": _routes_from_advanced(),
            "wildcard": adv._WILDCARD_RELAYS,
            "graveyard": adv._POOL_GRAVEYARD,
            "countries": 51,
            "params": adv._SECURITY_PARAMS,
        }
        POOL_TEMPLATE.parent.mkdir(parents=True, exist_ok=True)
        POOL_TEMPLATE.write_text(json.dumps(template, ensure_ascii=False, indent=1),
                                 encoding="utf-8")
        POOL_SYNC_BIN.parent.mkdir(parents=True, exist_ok=True)
        POOL_SYNC_BIN.write_text(POOL_SYNC_SH.lstrip(), encoding="utf-8")
        POOL_SYNC_BIN.chmod(0o755)
        POOL_CRON.write_text(
            "# синк пула dnscrypt с живым списком (Chimera Project)\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "0 */6 * * * root /usr/bin/python3 "
            "/usr/local/bin/chimera-dnscrypt-pool-sync.py "
            f">> {POOL_LOG} 2>&1\n", encoding="utf-8")
        POOL_CRON.chmod(0o644)
        _ok("Синк пула установлен: cron каждые 6 ч, лог "
            f"{POOL_LOG}, шаблон {POOL_TEMPLATE}")
        return True
    except Exception as e:
        _err(f"Не удалось установить синк пула: {e}")
        return False


def remove_pool_sync() -> bool:
    _info("Отключаю синк пула...")
    for p in (POOL_CRON, POOL_SYNC_BIN, POOL_TEMPLATE):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    _ok("Синк пула удалён (cron + скрипт + шаблон)")
    return True


def pool_sync_installed() -> bool:
    return POOL_CRON.exists() and POOL_SYNC_BIN.exists()


def run_pool_sync_now(interactive: bool = True) -> bool:
    """Ручной запуск синка (меню): устанавливает артефакты при отсутствии,
    затем выполняет standalone-скрипт и показывает его вывод."""
    if not pool_sync_installed():
        if not install_pool_sync():
            return False
    elif interactive:
        # переустанавливаем шаблон — политика могла обновиться с chimera
        install_pool_sync()
    if interactive:
        _info("Запускаю синк пула (живые каши dnscrypt-proxy)...")
    r = subprocess.run([sys.executable, str(POOL_SYNC_BIN)],
                       text=True, capture_output=True)
    out = (r.stdout or "") + (r.stderr or "")
    if out.strip():
        print(out.rstrip())
    if r.returncode == 0:
        if interactive:
            _ok("Синк завершён")
        return True
    _warn(f"pool-sync завершился с кодом {r.returncode}")
    return False


# =============================================================================
#  ЕДИНОЕ МЕНЮ (вызывается из всех DNS-меню — синхронизировано через state)
# =============================================================================
def do_dnscrypt_update_menu() -> None:
    """Обновление/синк DNSCrypt — одно меню для всех точек входа
    (RA-меню [6], Сеть → DU, AGH-меню [6]).

    Синхронизация: статус читается из state-файла, обновление в любом
    меню меняет state — остальные меню отображают актуальное сразу.
    """
    while True:
        os.system("clear")
        print()
        try:
            from chimera.modules.box_renderer import (
                _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back)
        except ImportError:
            _box_top = lambda t: print(t)
            _box_sep = _box_row = _box_bottom = lambda *a: print(a[0] if a else "")
            _box_item = lambda k, v: print(f"  [{k}] {v}")
            _box_back = lambda: print("  [Q] Назад")

        st = read_state()
        ver = st.get("version", {})
        pool = st.get("pool", {})
        chain = st.get("chain", {})

        installed = ver.get("installed") or get_installed_version() or "?"
        latest = ver.get("latest") or "?"
        ver_col = (GREEN if latest == installed and installed != "?"
                   else YELLOW if latest != "?" else DIM)
        auto_on = autoupdate_enabled()
        sync_on = pool_sync_installed()

        _box_top("⬆️  ОБНОВЛЕНИЕ И СИНК DNSCRYPT-PROXY")
        _box_row()
        _box_row(f"  {BOLD}Версия:{NC} {CYAN}{installed}{NC} "
                 f"{ver_col}(latest: {latest}){NC} "
                 f"{DIM}проверена {ver.get('last_check', '—')}{NC}")
        _box_row(f"  {BOLD}Авто-обновление:{NC} "
                 f"{GREEN}вкл{NC} {DIM}(ежедневно 04:10, systemd timer){NC}"
                 if auto_on else
                 f"  {BOLD}Авто-обновление:{NC} {RED}выкл{NC}")
        _box_row(f"  {BOLD}Синк пула:{NC} "
                 f"{GREEN}вкл{NC} {DIM}(каждые 6 ч, cron){NC}"
                 if sync_on else
                 f"  {BOLD}Синк пула:{NC} {RED}выкл{NC}")
        if pool.get("last_sync"):
            _box_row(f"  {BOLD}Пул:{NC} {get_pool_status_line()}")
        if pool.get("resurrected"):
            _box_row(f"  {DIM}последний синк: воскрешено {pool['resurrected']}, "
                     f"удалено мёртвых {pool.get('dead_removed', 0)}{NC}")
        if chain.get("last_check"):
            _mk = lambda b: (GREEN + "✓" + NC) if b else (RED + "✗" + NC)
            _box_row(f"  {BOLD}Цепочка:{NC} dnscrypt {_mk(chain.get('dnscrypt'))} · "
                     f":53 {_mk(chain.get('system_dns'))} · "
                     f"xray {_mk(chain.get('xray'))} "
                     f"{DIM}({chain['last_check']}){NC}")
        if pool.get("error"):
            _box_row(f"  {RED}Последняя ошибка синка: {pool['error']}{NC}")
        _box_sep()
        _box_item("1", f"{GREEN}Проверить и обновить сейчас{NC}  {DIM}(бэкап→зеркала→тест→откат){NC}")
        _box_item("2", f"Авто-обновление: {'выключить' if auto_on else 'включить'}"
                       f"  {DIM}(systemd timer 04:10){NC}")
        _box_item("3", f"{CYAN}Синхронизировать пул сейчас{NC}  {DIM}(пул ∩ живой список){NC}")
        _box_item("4", f"Авто-синк пула (крон 6 ч): {'выключить' if sync_on else 'включить'}{NC}")
        _box_item("5", f"Проверить цепочку xray → AGH → dnscrypt{NC}  {DIM}(реальные запросы){NC}")
        _box_back()
        _box_bottom()
        print()
        try:
            ch = input(f"{CYAN}Выбор:{NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if ch == "1":
            update_dnscrypt(interactive=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            if autoupdate_enabled():
                remove_autoupdate()
            else:
                install_autoupdate()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            run_pool_sync_now(interactive=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            if pool_sync_installed():
                remove_pool_sync()
            else:
                install_pool_sync()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            check_dns_chain(verbose=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "0", ""):
            return


__all__ = [
    "do_dnscrypt_update_menu",
    "update_dnscrypt",
    "check_dns_chain",
    "run_pool_sync_now",
    "install_pool_sync",
    "remove_pool_sync",
    "pool_sync_installed",
    "install_autoupdate",
    "remove_autoupdate",
    "autoupdate_enabled",
    "get_installed_version",
    "fetch_latest_version",
    "get_pool_status_line",
    "get_version_status_line",
    "read_state",
    "update_state",
    "STATE_FILE",
]
