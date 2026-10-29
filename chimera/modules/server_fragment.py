"""
chimera/modules/server_fragment.py
───────────────────────────────────────────────────────────────────────────────
Server-side TLS segmentation — закрываем асимметрию ClientHello/ServerHello.

АРХИТЕКТУРА (v4.28, после фикса схемного бага):
  Клиентский fragment (freedom-outbound + dialerProxy, см. fragment_config.py)
  дробит ClientHello на мелкие TCP-кусочки. Но ТСПУ с двунаправленной
  аналитикой видит асимметрию: ClientHello дроблёный, а ServerHello +
  Certificate (3–5 КБ у REALITY) уходят цельными 1448-байтовыми
  сегментами. Это маркер прокси.

  Историческая справка: до v4.28 модуль писал `sockopt.fragment` в inbound —
  ПЛАЦЕБО: поля fragment в streamSettings.sockopt не существует, Xray-core
  молча его игнорировал (см. CHANGELOG, коммит c485acc). Серверной
  фрагментации ответов в Xray-core нет вообще. Вторая находка той же
  серии: даже ВАЛИДНОЕ поле `sockopt.tcpMaxSeg` (Xray ≥ 26.7.11) — тихое
  no-op на современных ядрах: Go ≥ 1.24 создаёт LISTEN-сокеты как MPTCP
  (godebug multipathtcp по умолчанию "2" = listeners), а ядро на
  MPTCP-сокетах не поддерживает TCP_MAXSEG (setsockopt → ENOPROTOOPT,
  Xray логирует Info и работает дальше). Эмпирика: Ubuntu 24.04 / ядро
  6.8 — воспроизведено strace; ядро 5.10 без MPTCP — Go откатывается на
  обычный TCP, поле работает. Фикс: GODEBUG=multipathtcp=0 в окружении
  xray-сервиса (проверено живьём: setsockopt TCP_MAXSEG = 0).

  РАБОЧИЕ механизмы (TCP-уровень, сегменты server→client ≤ MSS):
    A. sockopt.tcpMaxSeg на REALITY-inbound (основной, ядро Xray ≥ 26.7.11)
       + systemd-drop-in Environment=GODEBUG=multipathtcp=0 на xray.service
       (без него листенер MPTCP и setsockopt молча проваливается).
       После рестарта верифицируем по журналу systemd: если Xray снова
       логирует «failed to set TCP_MAXSEG» — автофолбэк на механизм B.
       Ядро наследует user_mss в принятые соединения и КАПИТИТ SEND MSS
       (сервер→клиент): set 1300 → snd_mss 1288 (−12 TCP-timestamps).
       Живёт в config.json → переживает ребут, реаплаится хуком rebuild.
    B. iptables/ip6tables mangle PREROUTING TCPMSS (старые ядра Xray и
       форс-фолбэк): переписываем MSS в SYN клиентов на порты REALITY-
       inbound → стек ограничивает send-MSS ответов (тот же паттерн,
       что telemt-ios-mss-fix на нодах). Персистентность — drop-in
       ExecStartPost=/usr/local/bin/chimera-server-frag-restore
       (правила переустанавливаются при каждом старте/рестарте xray).

  Оба механизма ограничивают размер СЕГМЕНТОВ на всё время соединения
  (не только handshake): ServerHello+Cert режется на куски ≤ MSS.
  Это не micro-fragment по 10–20 байт — TCP-уровень не умеет задержки
  между кусками; клиентский fragment остаётся обязательным, этот модуль
  только выравнивает ответную картину.

ВНИМАНИЕ:
  • Применяется ТОЛЬКО к inbound VLESS+REALITY. На xHTTP inbound
    бесполезно (там TLS терминирует nginx, не Xray).
  • Механизм A отключает ДЕФОЛТНЫЙ MPTCP процесса xray (GODEBUG):
    клиенты на plain TCP ничего не теряют (MPTCP-фолбэк и так был нормой);
    явный sockopt.tcpMptcp=true в конфигах продолжает работать.
  • Механизм A требует рестарта xray; механизм B применяется мгновенно,
    но его правила живут только до ребута (переустанавливаются
    ExecStartPost-хуком при старте xray).
  • При пересоздании config.json (reconfigure, switch-mode) настройки
    механизма A слетают — модуль хранит параметры в state.json и
    пере-применяет через server_fragment_reapply_after_rebuild().

ТОЧКИ ВЫЗОВА:
  • do_server_fragment_menu()                 — TUI-меню
  • server_fragment_enable()                  — применить сегментацию
  • server_fragment_disable()                 — снять сегментацию
  • server_fragment_status()                  — dict состояния
  • server_fragment_reapply_after_rebuild()   — хук после пересоздания config
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета (как во всех модулях проекта) ───────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
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

# ── Логирование ──────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [SERVER-FRAGMENT] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}");     _log("ERROR",   msg)


from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back, _box_desc, _box_info, _box_warn, _box_ok,
)


# ── Константы ────────────────────────────────────────────────────────────────
_XRAY_CONFIG     = Path("/etc/xray/config.json")
_XRAY_CONFIG_ALT = Path("/usr/local/etc/xray/config.json")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")

# Границы MSS (валидатор): TCP_MIN_MSS..стандартный Ethernet-MSS
_MSS_MIN = 536
_MSS_MAX = 1460

# Пресеты server-side сегментации. MSS капает SEND-сегменты сервера на всё
# время соединения: ServerHello + Cert (3–5 КБ у REALITY) режется на
# ceil(размер / MSS) кусков. Меньше MSS — больше кусков, больше пакетный
# оверхед на всём исходящем трафике коннекта.
_PRESETS = {
    "aggressive": {
        "mss":      800,
        "desc":     "Агрессивная (MSS 800) — ответ в 5–8 сегментах, оверхед ~45%",
    },
    "balanced": {
        "mss":      1300,
        "desc":     "Сбалансированная (MSS 1300) — рекомендуется, оверхед ~11%",
    },
    "light": {
        "mss":      1400,
        "desc":     "Лёгкая (MSS 1400) — 3 сегмента, минимальный оверхед",
    },
    "custom": {
        "mss":      0,
        "desc":     "Пользовательская — ввести MSS вручную",
    },
}

# Первая версия Xray-core с полем sockopt.tcpMaxSeg (появилось в v26.7.11,
# применяется на inbound-listener через Control-callback ДО listen()).
_TCPMAXSEG_MIN_VERSION = (26, 7, 11)

# Комментарий iptables-правил (для идентификации и идемпотентного удаления)
_IPT_COMMENT = "chimera-server-frag"

# Механизмы
MECH_SOCKOPT = "tcpMaxSeg"     # поле в config.json + GODEBUG-drop-in, ядро ≥ 26.7.11
MECH_TCPMSS  = "tcpmss"        # iptables mangle PREROUTING TCPMSS clamp

# systemd-drop-in на xray.service: механизм A — GODEBUG (отключить дефолтный
# MPTCP листенеров Go ≥1.24, иначе TCP_MAXSEG = тихое no-op), механизм B —
# ExecStartPost-восстановление правил после старта/ребута
_SVC_DROPIN = Path("/etc/systemd/system/xray.service.d/chimera-server-frag.conf")
_GODEBUG_ENV_LINE = "Environment=GODEBUG=multipathtcp=0"
# Бут-восстановление правил (механизм B): standalone-скрипт без импортов chimera
_RESTORE_SCRIPT = Path("/usr/local/bin/chimera-server-frag-restore")


# ── subprocess helper (локальный) ────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int = 60):
    import subprocess
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=timeout)
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  timeout=timeout)
    return subprocess.run(cmd, **kw)


# ── Xray config helpers ──────────────────────────────────────────────────────

def _find_xray_config() -> Optional[Path]:
    """Возвращает канонический путь к config.json (он же используется в systemd)."""
    for p in (_XRAY_CONFIG, _XRAY_CONFIG_ALT):
        if p.exists():
            return p
    return None


def _load_xray_config() -> Optional[dict]:
    p = _find_xray_config()
    if not p:
        return None
    try:
        return json.loads(p.read_text())
    except Exception as e:
        error(f"Не удалось прочитать xray config: {e}")
        return None


def _save_xray_config(cfg: dict) -> bool:
    """Атомарная запись (с учётом symlink — пишем в target)."""
    p = _find_xray_config() or _XRAY_CONFIG
    target = p.resolve() if p.is_symlink() else p
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        tmp.replace(target)
        # Восстанавливаем владельца, если это /etc/xray/config.json
        try:
            import shutil
            shutil.chown(target, user="nobody", group="nogroup")
        except Exception:
            pass
        return True
    except Exception as e:
        error(f"Не удалось сохранить xray config: {e}")
        return False


def _xray_test_and_restart() -> bool:
    """Проверяет конфиг, перезапускает xray, возвращает True при успехе."""
    p = _find_xray_config()
    if not p:
        error("config.json не найден — нечего проверять")
        return False

    # Тест
    xray_bin = Path("/usr/local/bin/xray")
    if not xray_bin.exists():
        xray_bin = Path("/usr/bin/xray")
    r = _run([str(xray_bin), "run", "-test", "-config", str(p)],
             capture=True, quiet=True, check=False)
    if r.returncode != 0:
        error("Конфиг невалиден! Откат не выполняю, чтобы не сломать работающий.")
        error((r.stdout + r.stderr)[:400])
        return False

    # Рестарт
    for svc in ("xray", "xray-core"):
        rs = _run(["systemctl", "is-active", "--quiet", svc], quiet=True)
        if rs.returncode == 0:
            _run(["systemctl", "restart", svc], quiet=True)
            time.sleep(2)
            rs2 = _run(["systemctl", "is-active", "--quiet", svc], quiet=True)
            return rs2.returncode == 0
    warn("xray сервис не активен — конфиг сохранён, но не перезапущен")
    return True


# ── Версия ядра Xray / feature-detect ────────────────────────────────────────

def _xray_core_version() -> Optional[tuple]:
    """
    Парсит `xray version` → кортеж чисел. Примеры:
      "Xray 26.10.21 (Xray, Penetrates Everything.) ..."  → (26, 10, 21)
      "Xray 1.8.24 ..."                                   → (1, 8, 24)
    Возвращает None, если бинарник не найден/не разобран.
    """
    for bin_path in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if not Path(bin_path).exists():
            continue
        r = _run([bin_path, "version"], capture=True, quiet=True,
                 check=False, timeout=20)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r'Xray\s+v?(\d+(?:\.\d+)+)', out)
        if m:
            try:
                return tuple(int(x) for x in m.group(1).split('.'))
            except ValueError:
                continue
    return None


def _core_supports_tcp_max_seg() -> bool:
    """Ядро Xray понимает sockopt.tcpMaxSeg на inbound (>= 26.7.11)?"""
    v = _xray_core_version()
    return v is not None and v >= _TCPMAXSEG_MIN_VERSION


# ── State helpers ────────────────────────────────────────────────────────────

def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(st: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception as e:
        error(f"Ошибка записи state.json: {e}")


def _load_server_fragment_state() -> dict:
    st = _load_state()
    return st.get("server_fragment", {})


def _save_server_fragment_state(sf: dict) -> None:
    st = _load_state()
    st["server_fragment"] = sf
    _save_state(st)


def _migrate_legacy_state(sf: dict) -> dict:
    """
    Легаси-миграция (state v4.27 и старше): ключи packets/length/interval —
    параметры плацебо-схемы sockopt.fragment. Маппим пресет на MSS,
    старые ключи выбрасываем. enabled сохраняем: юзер хотел сегментацию —
    теперь она заработает по-настоящему (см. CHANGELOG v4.28).
    """
    if any(k in sf for k in ("packets", "length", "interval")):
        legacy_mss = {"aggressive": 800, "balanced": 1300, "light": 1400}
        if not sf.get("mss"):
            sf["mss"] = legacy_mss.get(sf.get("preset", "balanced"), 1300)
        for k in ("packets", "length", "interval"):
            sf.pop(k, None)
    return sf


def _ensure_state() -> dict:
    st = _load_state()
    sf = st.get("server_fragment")
    if sf is None:
        sf = {
            "enabled":       False,
            "preset":        "balanced",
            "mss":           1300,
            "mechanism":     "",
            "ports":         [],
            "last_applied":  "",
        }
        st["server_fragment"] = sf
        _save_state(st)
    else:
        migrated = _migrate_legacy_state(dict(sf))
        if migrated != sf:
            st["server_fragment"] = migrated
            _save_state(st)
            sf = migrated
    if "mss" not in sf:
        sf.setdefault("mss", 1300)
    return sf


# ── Поиск подходящих inbound'ов ──────────────────────────────────────────────

def _find_reality_inbound(cfg: dict) -> Optional[dict]:
    """
    Находит ПЕРВЫЙ inbound VLESS+REALITY (для обратной совместимости).
    """
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") != "vless":
            continue
        ss = inb.get("streamSettings", {})
        if ss.get("security") == "reality":
            return inb
    return None


def _reality_inbounds(cfg: dict) -> list:
    """Все inbound VLESS+REALITY — сегментацию вешаем на каждый."""
    out = []
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") != "vless":
            continue
        ss = inb.get("streamSettings", {})
        if ss.get("security") == "reality":
            out.append(inb)
    return out


def _reality_inbound_ports(cfg: dict) -> list:
    """Порты всех VLESS+REALITY inbound (int, отсортированные, уникальные)."""
    ports = []
    for inb in _reality_inbounds(cfg):
        try:
            ports.append(int(inb.get("port")))
        except (TypeError, ValueError):
            continue
    return sorted(set(ports))


def _find_xhttp_inbound(cfg: dict) -> Optional[dict]:
    """Находит inbound VLESS+xHTTP (для информативности — сегментация тут не нужна)."""
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") != "vless":
            continue
        ss = inb.get("streamSettings", {})
        if ss.get("network") == "xhttp":
            return inb
    return None


# ── iptables TCPMSS (механизм B — fallback для ядер < 26.7.11) ──────────────

def _run_soft(cmd: list, capture: bool = False, timeout: int = 15):
    """_run, не падающий на отсутствующем/недоступном бинарнике (iptables/ip).
    Возвращает CompletedProcess с rc=127 — вызов site'ы трактуют как «нет правила»."""
    import subprocess
    try:
        return _run(cmd, capture=capture, quiet=True, check=False, timeout=timeout)
    except (FileNotFoundError, PermissionError, OSError):
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="")


def _has_global_ipv6() -> bool:
    """Есть ли на ноде глобальный IPv6 (нужна ли ip6tables-ветка)?"""
    r = _run_soft(["ip", "-6", "addr", "show", "scope", "global"], capture=True)
    out = (r.stdout or "").strip()
    return bool(out) and "inet6" in out


def _build_tcpmss_rule(ports: list, mss: int, ipv6: bool = False) -> list:
    """
    Чистый билдер правила (для тестов): возвращает argv БЕЗ позиции вставки.
      ["iptables", "-t", "mangle", "-p", "tcp", "-m", "tcp", "--dport", "443",
       "--syn", "-m", "comment", "--comment", "chimera-server-frag",
       "-j", "TCPMSS", "--set-mss", "1300"]
    """
    binname = "ip6tables" if ipv6 else "iptables"
    ports_u = sorted({int(p) for p in ports})
    cmd = [binname, "-t", "mangle"]
    if len(ports_u) == 1:
        cmd += ["-p", "tcp", "-m", "tcp", "--dport", str(ports_u[0])]
    else:
        cmd += ["-p", "tcp", "-m", "multiport", "--dports",
                ",".join(str(p) for p in ports_u)]
    cmd += ["--syn", "-m", "comment", "--comment", _IPT_COMMENT,
            "-j", "TCPMSS", "--set-mss", str(int(mss))]
    return cmd


def _install_tcpmss_rules(ports: list, mss: int) -> int:
    """
    Ставит TCPMSS-правила в mangle/PREROUTING (v4 + v6 при глобальном IPv6).
    Идемпотентно: перед вставкой проверяет -C. Возвращает число применённых
    правил (0 = ничего не потребовалось или ошибка).
    """
    if not ports:
        return 0
    installed = 0
    families = [False]                       # IPv4 — всегда
    if _has_global_ipv6():
        families.append(True)                # IPv6 — если есть глобальный адрес
    for ipv6 in families:
        base = _build_tcpmss_rule(ports, mss, ipv6=ipv6)
        # уже стоит? (iptables -t mangle -C PREROUTING <rule>)
        check = _run_soft(base[:3] + ["-C", "PREROUTING"] + base[3:])
        if check.returncode == 0:
            continue
        ins = _run_soft(base[:3] + ["-I", "PREROUTING", "1"] + base[3:])
        if ins.returncode == 0:
            installed += 1
        else:
            error(f"Не удалось установить TCPMSS-правило ({'ip6tables' if ipv6 else 'iptables'})")
    return installed


def _remove_tcpmss_rules() -> int:
    """
    Снимает все наши TCPMSS-правила из mangle/PREROUTING (v4+v6).
    Возвращает число удалённых правил. Идемпотентно.
    """
    removed = 0
    for binname in ("iptables", "ip6tables"):
        r = _run_soft([binname, "-t", "mangle", "-S", "PREROUTING"], capture=True)
        for line in (r.stdout or "").splitlines():
            if _IPT_COMMENT not in line or not line.startswith("-A "):
                continue
            # "-A PREROUTING <body>" → "iptables -t mangle -D PREROUTING <body>"
            del_spec = line.replace("-A PREROUTING ", "", 1)
            dr = _run_soft([binname, "-t", "mangle", "-D", "PREROUTING"]
                           + shlex.split(del_spec))
            if dr.returncode == 0:
                removed += 1
    return removed


def _count_tcpmss_rules() -> int:
    """Сколько наших TCPMSS-правил сейчас стоит (v4+v6)."""
    count = 0
    for binname in ("iptables", "ip6tables"):
        r = _run_soft([binname, "-t", "mangle", "-S", "PREROUTING"], capture=True)
        for line in (r.stdout or "").splitlines():
            if _IPT_COMMENT in line and line.startswith("-A "):
                count += 1
    return count


# ── systemd drop-in + журнальная верификация (механизмы A/B) ──────────────────

def _daemon_reload() -> bool:
    r = _run_soft(["systemctl", "daemon-reload"])
    return r.returncode == 0


def _dropin_content(mechanism: str) -> str:
    """Содержимое drop-in'а под выбранный механизм."""
    lines = ["[Service]"]
    if mechanism == MECH_SOCKOPT:
        # Go >= 1.24: multipathtcp="2" (MPTCP на листенерах) -> TCP_MAXSEG
        # на MPTCP-сокете = ENOPROTOOPT -> tcpMaxSeg тихое no-op. Выключаем.
        lines.append(_GODEBUG_ENV_LINE)
    else:
        # Правила TCPMSS живут до ребута — восстанавливаем при старте xray.
        # '+' — выполнять с полными привилегиями независимо от User= сервиса.
        lines.append(f"ExecStartPost=+{_RESTORE_SCRIPT}")
    return "\n".join(lines) + "\n"


def _dropin_installed(mechanism: Optional[str] = None) -> bool:
    """Стоит ли наш drop-in (и именно под данный механизм, если задан)."""
    if not _SVC_DROPIN.exists():
        return False
    try:
        content = _SVC_DROPIN.read_text()
    except Exception:
        return False
    if mechanism is None:
        return True
    return content.strip() == _dropin_content(mechanism).strip()


def _install_dropin(mechanism: str) -> bool:
    try:
        _SVC_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        _SVC_DROPIN.write_text(_dropin_content(mechanism))
    except Exception as e:
        error(f"Не удалось написать systemd drop-in: {e}")
        return False
    _daemon_reload()
    return True


def _remove_dropin() -> bool:
    """Снимает наш drop-in (идемпотентно). True — если что-то сняли."""
    removed = False
    try:
        if _SVC_DROPIN.exists():
            _SVC_DROPIN.unlink()
            removed = True
    except Exception as e:
        error(f"Не удалось удалить systemd drop-in: {e}")
        return False
    if removed:
        _daemon_reload()
    return removed


def _journal_tcpmaxseg_failed(since: str) -> bool:
    """
    Логировал ли Xray «failed to set TCP_MAXSEG» ПОСЛЕ момента since?
    (сигнал: механизм A не применился — напр., MPTCP или регрессия ядра).
    """
    for svc in ("xray", "xray-core"):
        r = _run_soft(["journalctl", "-u", svc, "--since", since,
                       "--no-pager", "-n", "200"], capture=True)
        out = (r.stdout or "") + (r.stderr or "")
        if "failed to set TCP_MAXSEG" in out:
            return True
    return False


_RESTORE_SCRIPT_CONTENT = '''#!/usr/bin/env python3
"""chimera-server-frag-restore — re-apply TCPMSS rules (mechanism B).

Вызывается systemd (ExecStartPost xray.service, от root через '+'): читает
state.json, и если server_fragment включён с механизмом tcpmss —
переустанавливает правила mangle/PREROUTING TCPMSS. Идемпотентно.
Standalone: только stdlib, без импортов chimera.
"""
import json
import subprocess
from pathlib import Path

STATE = Path("/var/lib/xray-installer/state.json")
CONFIG = Path("/etc/xray/config.json")
CONFIG_ALT = Path("/usr/local/etc/xray/config.json")
COMMENT = "chimera-server-frag"


def _sh(cmd):
    try:
        subprocess.run(cmd, capture_output=True, timeout=15)
    except Exception:
        pass


def _sf_state():
    try:
        return json.loads(STATE.read_text()).get("server_fragment", {})
    except Exception:
        return {}


def _ports_from_config():
    for p in (CONFIG, CONFIG_ALT):
        if not p.exists():
            continue
        try:
            cfg = json.loads(p.read_text())
            return sorted({int(i["port"]) for i in cfg.get("inbounds", [])
                           if i.get("protocol") == "vless"
                           and i.get("streamSettings", {}).get("security") == "reality"
                           and "port" in i})
        except Exception:
            continue
    return []


def main():
    sf = _sf_state()
    if not sf.get("enabled") or sf.get("mechanism") != "tcpmss":
        return 0
    mss = sf.get("mss") or 1300
    ports = sf.get("ports") or _ports_from_config()
    if not ports:
        return 0
    ports_u = sorted(set(ports))
    if len(ports_u) == 1:
        port_args = ["-p", "tcp", "-m", "tcp", "--dport", str(ports_u[0])]
    else:
        port_args = ["-p", "tcp", "-m", "multiport", "--dports",
                     ",".join(str(p) for p in ports_u)]
    for binname in ("iptables", "ip6tables"):
        try:
            r = subprocess.run([binname, "-t", "mangle", "-S", "PREROUTING"],
                               capture_output=True, text=True, timeout=15)
        except Exception:
            continue
        if any(COMMENT in line for line in (r.stdout or "").splitlines()):
            continue
        _sh([binname, "-t", "mangle", "-I", "PREROUTING", "1"] + port_args
            + ["--syn", "-m", "comment", "--comment", COMMENT,
               "-j", "TCPMSS", "--set-mss", str(int(mss))])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _write_restore_script() -> bool:
    """Устанавливает standalone-скрипт бут-восстановления (механизм B)."""
    try:
        _RESTORE_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        _RESTORE_SCRIPT.write_text(_RESTORE_SCRIPT_CONTENT)
        _RESTORE_SCRIPT.chmod(0o755)
    except Exception as e:
        error(f"Не удалось написать restore-скрипт: {e}")
        return False
    return True


def _remove_restore_script() -> bool:
    try:
        if _RESTORE_SCRIPT.exists():
            _RESTORE_SCRIPT.unlink()
            return True
    except Exception:
        pass
    return False


# ── Публичный API ────────────────────────────────────────────────────────────

def _resolve_mss(preset: str, mss) -> int:
    """Пресет + опциональное переопределение → валидный MSS. Кидает ValueError."""
    if preset not in _PRESETS:
        raise ValueError(f"Неизвестный пресет: {preset}")
    value = mss if mss else _PRESETS[preset]["mss"]
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"MSS должен быть числом: {value!r}")
    if not (_MSS_MIN <= value <= _MSS_MAX):
        raise ValueError(f"MSS вне диапазона {_MSS_MIN}–{_MSS_MAX}: {value}")
    if preset == "custom" and not mss:
        raise ValueError("Custom пресет требует задания mss")
    return value


def server_fragment_enable(
    preset: str = "balanced",
    mss = None,
    restart: bool = True,
) -> bool:
    """
    Включает серверную сегментацию ответов (ServerHello + Cert).

    Механизм выбирается автоматически по версии ядра Xray:
      • ядро >= 26.7.11 → A: sockopt.tcpMaxSeg на каждом REALITY-inbound
        + GODEBUG=multipathtcp=0 (drop-in на xray.service — Go >= 1.24
        создаёт листенеры MPTCP, где TCP_MAXSEG молча проваливается);
        после рестарта верифицируется по журналу, при провале — фолбэк на B;
      • старее → B: iptables/ip6tables mangle PREROUTING TCPMSS --set-mss
        + ExecStartPost-восстановление правил при старте xray (переживает
        ребут).

    Попутно вычищает легаси-плацебо sockopt.fragment из inbound (v4.27-).

    Args:
      preset:  aggressive / balanced / light / custom
      mss:     переопределение MSS (для custom — обязателен)
      restart: перезапустить xray при изменениях

    Возвращает True при успехе.
    """
    try:
        mss_val = _resolve_mss(preset, mss)
    except ValueError as e:
        error(str(e))
        return False

    cfg = _load_xray_config()
    if cfg is None:
        error("config.json не найден — сначала установите VLESS-сервер")
        return False

    inbounds = _reality_inbounds(cfg)
    if not inbounds:
        xh = _find_xhttp_inbound(cfg)
        if xh is not None:
            error("Server-side сегментация неприменима в xHTTP-режиме: TLS терминирует nginx,")
            error("не Xray. Включите REALITY-режим (сегментацию ответа nginx — отдельная задача).")
        else:
            error("Не найден VLESS+REALITY inbound в config.json")
        return False

    ports = _reality_inbound_ports(cfg)
    mechanism = MECH_SOCKOPT if _core_supports_tcp_max_seg() else MECH_TCPMSS

    original_cfg = json.loads(json.dumps(cfg))   # для отката
    config_changed = False
    dropin_installed_here = False
    ts_before = time.strftime("%Y-%m-%d %H:%M:%S")

    def _full_rollback() -> bool:
        """Откат config + drop-in + restore-скрипта + правил, повторный рестарт.

        Drop-in снимаем безусловно (GODEBUG- или ExecStartPost-вариант —
        оба наши; остаток ExecStartPost на удалённый скрипт валит юнит).
        """
        _remove_tcpmss_rules()
        _remove_dropin()
        _remove_restore_script()
        if config_changed:
            _save_xray_config(original_cfg)
            if restart:
                _xray_test_and_restart()
        return False

    for inb in inbounds:
        ss = inb.setdefault("streamSettings", {})
        sockopt = ss.setdefault("sockopt", {})
        # Легаси-чистка: плацебо-поле fragment в sockopt не существует
        if "fragment" in sockopt:
            sockopt.pop("fragment", None)
            config_changed = True
        if mechanism == MECH_SOCKOPT:
            if sockopt.get("tcpMaxSeg") != mss_val:
                sockopt["tcpMaxSeg"] = mss_val
                config_changed = True
        else:
            # старому ядру поле незнакомо (lenient-игнор) — не мусорим
            if "tcpMaxSeg" in sockopt:
                sockopt.pop("tcpMaxSeg", None)
                config_changed = True

    # ── Механизм A: GODEBUG-drop-in + config.json + рестарт ────────────────
    dropin_changed = False
    if mechanism == MECH_SOCKOPT:
        if not _dropin_installed(MECH_SOCKOPT):
            if _install_dropin(MECH_SOCKOPT):
                dropin_installed_here = True
                dropin_changed = True
            else:
                # drop-in не пишется (нет systemd?) — tcpMaxSeg будет no-op;
                # верификация по журналу это поймает и переключит на механизм B
                warn("GODEBUG drop-in не установлен — tcpMaxSeg может не примениться")

    if config_changed:
        if not _save_xray_config(cfg):
            if dropin_installed_here:
                _remove_dropin()
            return False

    if restart and (config_changed or dropin_changed):
        if not _xray_test_and_restart():
            warn("Откатываю изменения из-за ошибки перезапуска xray")
            return _full_rollback()

    info(f"Server-side сегментация: механизм {BOLD}{mechanism}{NC}, "
         f"preset={preset} mss={mss_val}, inbound-порты {ports}")

    # ── Верификация механизма A по журналу systemd ──────────────────────────
    fallback_reason = ""
    if mechanism == MECH_SOCKOPT and restart and (config_changed or dropin_changed):
        time.sleep(1)   # журналирование асинхронно
        if _journal_tcpmaxseg_failed(since=ts_before):
            fallback_reason = "tcpMaxSeg не применился (журнал: failed to set TCP_MAXSEG)"
            warn(fallback_reason + " — переключаюсь на iptables TCPMSS")
            if dropin_installed_here:
                _remove_dropin()
                dropin_installed_here = False
            mechanism = MECH_TCPMSS

    # ── Механизм B: iptables TCPMSS + бут-восстановление ────────────────────
    if mechanism == MECH_TCPMSS:
        if not (_write_restore_script() and _install_dropin(MECH_TCPMSS)):
            warn("Не удалось поставить бут-восстановление — правила живут до ребута")
        _install_tcpmss_rules(ports, mss_val)
        if _count_tcpmss_rules() == 0:
            error("TCPMSS-правила не установлены (iptables недоступен?) — откат")
            return _full_rollback()
        info(f"TCPMSS clamp: mangle/PREROUTING --set-mss {mss_val} на порты {ports}")

    # ── State ────────────────────────────────────────────────────────────────
    sf = _ensure_state()
    sf.update({
        "enabled":       True,
        "preset":        preset,
        "mss":           mss_val,
        "mechanism":     mechanism,
        "ports":         ports,
        "last_applied":  time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    if fallback_reason:
        sf["fallback_reason"] = fallback_reason
    else:
        sf.pop("fallback_reason", None)
    _save_server_fragment_state(sf)

    extra = f" (фолбэк: {fallback_reason})" if fallback_reason else ""
    success("Server-side TLS сегментация активирована "
            f"({mechanism}, MSS {mss_val}){extra}")
    _log("INFO", f"Server segment enabled: mechanism={mechanism}, preset={preset}, "
                  f"mss={mss_val}, ports={ports}{extra}")

    return True


def server_fragment_disable(restart: bool = True) -> bool:
    """Снимает серверную сегментацию: tcpMaxSeg из config + TCPMSS-правила."""
    cfg = _load_xray_config()
    if cfg is None:
        return False

    config_changed = False
    inbounds = _reality_inbounds(cfg)
    if not inbounds:
        warn("VLESS+REALITY inbound не найден — снимаю только TCPMSS-правила")
    else:
        for inb in inbounds:
            sockopt = inb.get("streamSettings", {}).get("sockopt", {})
            if "tcpMaxSeg" in sockopt:
                sockopt.pop("tcpMaxSeg", None)
                config_changed = True
            if "fragment" in sockopt:      # легаси-плацебо
                sockopt.pop("fragment", None)
                config_changed = True
        if not config_changed:
            info("tcpMaxSeg в конфиге уже отсутствует — изменений не требуется")

    # drop-in снимаем ДО рестарта: рестартнутый процесс сразу без GODEBUG/
    # ExecStartPost; daemon-reload внутри _remove_dropin
    dropin_removed = _remove_dropin()
    if dropin_removed:
        info("Снят systemd drop-in (GODEBUG=multipathtcp=0 / ExecStartPost)")
    _remove_restore_script()

    if config_changed:
        if not _save_xray_config(cfg):
            return False
        if restart:
            if not _xray_test_and_restart():
                return False
    elif dropin_removed and restart:
        info("Перезапускаю xray для применения окружения без GODEBUG")
        _xray_test_and_restart()

    removed = _remove_tcpmss_rules()
    if removed:
        info(f"Снято TCPMSS-правил: {removed}")

    sf = _ensure_state()
    sf["enabled"] = False
    sf["mechanism"] = ""
    sf["ports"] = []
    sf["last_disabled"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _save_server_fragment_state(sf)

    success("Server-side TLS сегментация отключена")
    _log("INFO", "Server segment disabled")
    return True


def server_fragment_status() -> dict:
    """
    Возвращает dict:
      enabled (bool)            — по state.json
      preset, mss, mechanism    — параметры и выбранный механизм
      ports (list)              — inbound-порты REALITY
      in_config (bool)          — tcpMaxSeg реально в config.json на всех inbound
      config_mss (int|None)     — значение tcpMaxSeg из config.json
      legacy_fragment (bool)    — в config осталось плацебо sockopt.fragment
      iptables_rules (int)      — сколько наших TCPMSS-правил стоит
      godebug_installed (bool)  — GODEBUG-drop-in (механизм A) стоит
      restore_installed (bool)  — restore-скрипт+ExecStartPost (B) стоят
      fallback_reason (str)     — почему случился фолбэк A→B (если был)
      core_version (str)        — версия ядра Xray ("26.10.21" / "1.8.24" / "")
      core_supported (bool)     — ядро >= 26.7.11 (понимает tcpMaxSeg)
      inbound_protocol (str)    — "reality" / "xhttp" / "none"
      last_applied, last_disabled
    """
    sf = _ensure_state()
    core_v = _xray_core_version()
    result = {
        "enabled":          sf.get("enabled", False),
        "preset":           sf.get("preset", ""),
        "mss":              sf.get("mss", 0),
        "mechanism":        sf.get("mechanism", ""),
        "ports":            sf.get("ports", []),
        "in_config":        False,
        "config_mss":       None,
        "legacy_fragment":  False,
        "iptables_rules":   0,
        "godebug_installed": False,
        "restore_installed": False,
        "core_version":     ".".join(str(x) for x in core_v) if core_v else "",
        "core_supported":   core_v is not None and core_v >= _TCPMAXSEG_MIN_VERSION,
        "inbound_protocol": "none",
        "last_applied":     sf.get("last_applied", ""),
        "last_disabled":    sf.get("last_disabled", ""),
    }

    cfg = _load_xray_config()
    if cfg:
        inbounds = _reality_inbounds(cfg)
        if inbounds:
            result["inbound_protocol"] = "reality"
            result["ports"] = _reality_inbound_ports(cfg)
            have = [inb.get("streamSettings", {}).get("sockopt", {}).get("tcpMaxSeg")
                    for inb in inbounds]
            result["config_mss"] = have[0] if have and have[0] is not None else None
            result["in_config"] = bool(have) and all(v is not None for v in have)
            result["legacy_fragment"] = any(
                "fragment" in inb.get("streamSettings", {}).get("sockopt", {})
                for inb in inbounds)
        elif _find_xhttp_inbound(cfg):
            result["inbound_protocol"] = "xhttp"

    result["iptables_rules"] = _count_tcpmss_rules()
    result["godebug_installed"] = _dropin_installed(MECH_SOCKOPT)
    result["restore_installed"] = (_RESTORE_SCRIPT.exists()
                                   and _dropin_installed(MECH_TCPMSS))
    if sf.get("fallback_reason"):
        result["fallback_reason"] = sf["fallback_reason"]
    return result


def server_fragment_reapply_after_rebuild() -> None:
    """
    Хук для вызова после пересоздания config.json (reconfigure, switch_mode,
    migration import). Если в state включена сегментация — пере-применяем её
    к свежему config.json (+ TCPMSS-правила, если механизм B).
    """
    sf = _load_server_fragment_state()
    if not sf.get("enabled"):
        return
    info("Server-side сегментация была включена — пере-применяю после пересоздания config")
    server_fragment_enable(
        preset=sf.get("preset", "balanced"),
        mss=sf.get("mss") or None,
        restart=True,
    )


# ── TUI-меню ─────────────────────────────────────────────────────────────────

def _format_status_line(st: dict) -> str:
    if not st["enabled"]:
        return f"{YELLOW}отключён{NC}"
    cfg_col = GREEN if st["in_config"] or st["iptables_rules"] else RED
    parts = [
        f"{GREEN}включён{NC}",
        f"{CYAN}{st['mechanism'] or '?'}{NC}",
        f"{CYAN}MSS {st['mss']}{NC}",
        f"{cfg_col}применён {'✓' if (st['in_config'] or st['iptables_rules']) else '✗'}{NC}",
    ]
    return "  │  ".join(parts)


def do_server_fragment_menu() -> None:
    """
    TUI-меню управления server-side TLS сегментацией.
    Вызывается из _menu_diagnostics() (пункт "SF").
    """
    _ensure_state()

    while True:
        os.system("clear")
        print()
        st = server_fragment_status()

        _box_top("🖥️   SERVER-SIDE TLS СЕГМЕНТАЦИЯ")
        _box_row(f"  Статус: {_format_status_line(st)}")
        if st["inbound_protocol"] == "xhttp":
            _box_row(f"  Режим: {YELLOW}xHTTP{NC} {DIM}— неприменимо (TLS терминирует nginx){NC}")
        elif st["inbound_protocol"] == "reality":
            _box_row(f"  Режим: {GREEN}VLESS+REALITY{NC} {DIM}порты {st['ports']}{NC}")
        else:
            _box_row(f"  Режим: {RED}не установлен{NC} {DIM}— сначала установите VLESS-сервер{NC}")
        _box_row(f"  Ядро Xray: {CYAN}{st['core_version'] or '?'}{NC} "
                 f"{DIM}({'tcpMaxSeg поддерживается' if st['core_supported'] else 'старое — fallback iptables TCPMSS'}){NC}")
        if st["legacy_fragment"]:
            _box_warn("В config найдено легаси-плацебо sockopt.fragment — "
                      "будет вычищено при следующем применении")
        _box_sep()
        _box_desc(
            "Сегментация ответа сервера: ServerHello + Certificate "
            "(3–5 КБ у REALITY) режутся на TCP-сегменты ≤ MSS. "
            "Клиентский fragment бьёт по ClientHello, этот — по ответу. "
            "Механизм: sockopt.tcpMaxSeg на inbound (ядро ≥ 26.7.11) "
            "или iptables TCPMSS clamp на старых ядрах."
        )
        _box_sep()
        _box_row()

        if st["inbound_protocol"] == "reality":
            if st["enabled"]:
                _box_item("1", f"🔴 Выключить сегментацию  {DIM}(снять tcpMaxSeg + TCPMSS-правила){NC}")
                _box_item("2", f"🔁 Сменить пресет        {DIM}(пере-применить с другим MSS){NC}")
                _box_item("3", f"⚙️  Custom MSS            {DIM}(ввести вручную 536–1460){NC}")
            else:
                _box_item("1", f"⚡ Агрессивная   {DIM}(MSS 800 — ответ в 5–8 сегментах, оверхед ~45%){NC}")
                _box_item("2", f"✅ Сбалансированная  {DIM}(MSS 1300 — рекомендуется, оверхед ~11%){NC}")
                _box_item("3", f"🔆 Лёгкая   {DIM}(MSS 1400 — 3 сегмента, минимальный оверхед){NC}")
                _box_item("4", f"⚙️  Пользовательская  {DIM}(ввести MSS вручную){NC}")
        else:
            _box_row(f"  {DIM}Действия недоступны — требуется VLESS+REALITY inbound{NC}")

        _box_sep()
        _box_item("S", f"📊 Подробный статус")
        _box_item("I", f"📖 Информация / как это работает")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", "Q", ""):
            break

        if st["inbound_protocol"] != "reality":
            if ch in ("S", "I"):
                pass  # эти пункты доступны всегда
            else:
                warn("Требуется VLESS+REALITY inbound")
                time.sleep(1.5)
                continue

        if st["enabled"]:
            # Меню при включённой сегментации
            if ch == "1":
                print()
                warn("Отключение снимет сегментацию ServerHello.")
                warn("Ответ снова станет цельным — ТСПУ увидит асимметрию.")
                try:
                    confirm = input(f"\n{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
                except KeyboardInterrupt:
                    confirm = ""
                if confirm == "y":
                    server_fragment_disable()
                else:
                    info("Отменено")
                input(f"\n{BLUE}Нажмите Enter...{NC}")

            elif ch == "2":
                # Сменить пресет
                print()
                _box_top("🔁  ВЫБОР НОВОГО ПРЕСЕТА")
                _box_item("1", f"⚡ Агрессивная  {DIM}(MSS 800){NC}")
                _box_item("2", f"✅ Сбалансированная  {DIM}(MSS 1300){NC}")
                _box_item("3", f"🔆 Лёгкая  {DIM}(MSS 1400){NC}")
                _box_item("4", f"⚙️  Custom  {DIM}(ввести MSS вручную){NC}")
                _box_bottom()
                try:
                    sub = input(f"{CYAN}Пресет:{NC} ").strip()
                except KeyboardInterrupt:
                    continue
                preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
                if sub in preset_map:
                    server_fragment_enable(preset=preset_map[sub])
                elif sub == "4":
                    _prompt_custom_and_apply()
                else:
                    warn("Неверный выбор")
                    time.sleep(1)
                input(f"\n{BLUE}Нажмите Enter...{NC}")

            elif ch == "3":
                _prompt_custom_and_apply()
                input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            # Меню при выключенной сегментации
            preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
            if ch in preset_map:
                server_fragment_enable(preset=preset_map[ch])
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _prompt_custom_and_apply()
                input(f"\n{BLUE}Нажмите Enter...{NC}")

        if ch == "S":
            _show_detailed_status(st)
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "I":
            _show_info()
            input(f"\n{BLUE}Нажмите Enter...{NC}")


def _prompt_custom_and_apply() -> None:
    """Запрашивает MSS и применяет custom-пресет."""
    print()
    info(f"Введите MSS ({_MSS_MIN}–{_MSS_MAX}):")
    try:
        raw = input(f"  {CYAN}MSS {DIM}(напр. 1300){NC}: ").strip() or "1300"
    except KeyboardInterrupt:
        return

    try:
        mss_val = int(raw)
    except ValueError:
        warn(f"Некорректное число: {raw}")
        time.sleep(2)
        return
    if not (_MSS_MIN <= mss_val <= _MSS_MAX):
        warn(f"MSS вне диапазона {_MSS_MIN}–{_MSS_MAX}")
        time.sleep(2)
        return

    server_fragment_enable(preset="custom", mss=mss_val)


def _show_detailed_status(st: dict) -> None:
    print()
    _box_top("📊  ПОДРОБНЫЙ СТАТУС SERVER SEGMENT")
    _box_row(f"  Глобально:    "
             f"{GREEN}включён{NC}" if st["enabled"]
             else f"  Глобально:    {YELLOW}отключён{NC}")
    _box_row(f"  Механизм:      {CYAN}{st['mechanism'] or '—'}{NC}")
    _box_row(f"  MSS:           {CYAN}{st['mss'] or '—'}{NC} "
             f"{DIM}(эффективный на проводе ≈ MSS − 12 из-за timestamps){NC}")
    _box_row(f"  Inbound:       {CYAN}{st['inbound_protocol']}{NC} "
             f"{DIM}порты {st['ports'] or '—'}{NC}")
    _box_row(f"  Ядро Xray:     {CYAN}{st['core_version'] or '?'}{NC} "
             f"{DIM}({'≥ 26.7.11' if st['core_supported'] else '< 26.7.11'}){NC}")
    _box_row(f"  В config.json: "
             f"{GREEN}tcpMaxSeg={st['config_mss']}{NC}" if st["in_config"]
             else f"  В config.json: {RED}отсутствует{NC}")
    if st.get("godebug_installed"):
        _box_row(f"  GODEBUG-drop-in: {GREEN}установлен{NC} "
                 f"{DIM}(multipathtcp=0 — листенеры без MPTCP){NC}")
    else:
        _box_row(f"  GODEBUG-drop-in: {DIM}не установлен{NC}")
    if st.get("restore_installed"):
        _box_row(f"  Бут-восстановление: {GREEN}установлено{NC} "
                 f"{DIM}(ExecStartPost){NC}")
    if st.get("fallback_reason"):
        _box_warn(f"Фолбэк механизма: {st['fallback_reason']}")
    _box_row(f"  TCPMSS-правил: {CYAN}{st['iptables_rules']}{NC} "
             f"{DIM}(mangle/PREROUTING){NC}")
    if st["preset"]:
        _box_row(f"  Пресет:        {CYAN}{st['preset']}{NC}")
    if st["last_applied"]:
        _box_row(f"  Посл. apply:   {DIM}{st['last_applied']}{NC}")
    if st["last_disabled"]:
        _box_row(f"  Посл. disable: {DIM}{st['last_disabled']}{NC}")
    _box_sep()
    if (st["enabled"] and st["mechanism"] == "tcpMaxSeg"
            and not st.get("godebug_installed")):
        _box_warn("ВНИМАНИЕ: механизм tcpMaxSeg без GODEBUG-drop-in —")
        _box_warn("на ядрах Linux с MPTCP это тихое no-op! Пере-примените.")
    if st["enabled"] and not (st["in_config"] or st["iptables_rules"]):
        _box_warn("ВНИМАНИЕ: в state включён, но механизм не применён!")
        _box_warn("Возможно, config.json был пересоздан. Пере-примените через меню.")
    if st["legacy_fragment"]:
        _box_warn("В config осталось легаси-плацебо sockopt.fragment (v4.27-):")
        _box_warn("любое применение/отключение его вычистит.")
    if not st["enabled"] and st["in_config"]:
        _box_warn("ВНИМАНИЕ: в state выключен, но tcpMaxSeg ещё в config!")
        _box_warn("Это рассинхрон — нажмите Выключить для очистки.")
    _box_bottom()


def _show_info() -> None:
    print()
    _box_top("📖  КАК РАБОТАЕТ SERVER-SIDE СЕГМЕНТАЦИЯ")
    _box_row()
    _box_row(f"  {BOLD}Проблема:{NC}")
    _box_row(f"  Клиентский fragment (меню F1) бьёт только ClientHello —")
    _box_row(f"  исходящий от клиента TLS-handshake. Серверный ответ")
    _box_row(f"  (ServerHello + Certificate, 3–5 КБ у REALITY) уходит")
    _box_row(f"  цельными крупными сегментами. ТСПУ с двунаправленной")
    _box_row(f"  аналитикой видит асимметрию — сильный маркер прокси.")
    _box_row()
    _box_row(f"  {BOLD}Решение (TCP-уровень):{NC}")
    _box_row(f"  Ядро Linux ограничивает send-MSS соединений:")
    _box_row(f"  • A: sockopt.tcpMaxSeg на REALITY-inbound (ядро Xray ≥ 26.7.11)")
    _box_row(f"    + GODEBUG=multipathtcp=0 (drop-in на xray.service):")
    _box_row(f"    Go ≥ 1.24 делает листенеры MPTCP, а ядро на MPTCP-сокетах")
    _box_row(f"    НЕ принимает TCP_MAXSEG — без GODEBUG это тихое no-op!")
    _box_row(f"    Применяется после рестарта и верифицируется по журналу;")
    _box_row(f"  • B: iptables mangle PREROUTING TCPMSS — переписывает MSS")
    _box_row(f"    в SYN клиентов (тот же паттерн, что telemt-ios-mss-fix);")
    _box_row(f"    бут-восстановление через ExecStartPost при старте xray.")
    _box_row()
    _box_row(f"  ServerHello + Cert режется на куски ≤ MSS (при 1300 —")
    _box_row(f"  3–4 сегмента). DPI теряет цельную сигнатуру ответа.")
    _box_row()
    _box_row(f"  {BOLD}Честные ограничения:{NC}")
    _box_row(f"  • Это НЕ micro-fragment: куски ≤ MSS, а не 10–20 байт,")
    _box_row(f"    и БЕЗ задержек между ними — TCP-уровень так не умеет.")
    _box_row(f"    Клиентский fragment остаётся обязательным.")
    _box_row(f"  • MSS действует на всё соединение (весь исходящий")
    _box_row(f"    трафик): при 1300 ≈ +11% пакетов к ответному потоку.")
    _box_row(f"  • До v4.28 модуль писал sockopt.fragment в inbound —")
    _box_row(f"    плацебо (поля не существует, ядро его игнорировало).")
    _box_row()
    _box_row(f"  {BOLD}Совместимость:{NC}")
    _box_row(f"  • Механизм A: Xray-core ≥ 26.7.11, рестарт xray, отключает")
    _box_row(f"    дефолтный MPTCP процесса (клиентам прозрачно);")
    _box_row(f"  • Механизм B: любые ядра, мгновенно; правила переживают")
    _box_row(f"    ребут (ExecStartPost) и re-apply после rebuild конфига")
    _box_row(f"  • Только VLESS+REALITY; mode A и mode B (Entry-нода)")
    _box_row(f"  • REALITY и так шлёт подлинный handshake сайта-цели;")
    _box_row(f"    сегментация — второй слой маскировки")
    _box_row()
    _box_row(f"  {BOLD}Связка:{NC}")
    _box_row(f"  Client fragment (F1) + Server segment (SF) =")
    _box_row(f"  симметричная двунаправленная картина TLS-handshake.")
    _box_bottom()
