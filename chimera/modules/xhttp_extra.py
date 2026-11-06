"""
chimera/modules/xhttp_extra.py
───────────────────────────────────────────────────────────────────────────────
Дополнительный VLESS+xHTTP+TLS инбаунд на отдельном порту с ВЫДЕЛЕННЫМ
(не панельным) клиентом — CDN-friendly резервный вход рядом с основным
REALITY-инбаундом (хост/путь/SNI + настоящий TLS-сертификат).

ПРОБЛЕМА (инцидент 05.11.2026 14:42): generate_xray_config*() пишет
config.json с нуля и стирает любые дополнительные инбаунды. Инбаунд,
добавленный в конфиг вручную, пропадал при каждой пересборке —
добавление/удаление пользователей, смена exit-ноды, смена FP, смена
домена, switch-mode, emergency repair. Клиенты «резервного входа»
молча теряли подключение.

РЕШЕНИЕ — персистенс по образцу pq_vless.py / telemt tproxy:
  • Параметры инбаунда (порт, path, host/SNI, TLS-сертификаты,
    ВЫДЕЛЕННЫЙ клиент с постоянным UUID) хранятся в общем state.json
    (ключи xhttp_extra_*, read-modify-write под flock).
  • restore_xhttp_extra_if_enabled() вызывается из
    _core._rebuild_and_restart_xray() ПОСЛЕ полной перегенерации
    config.json (и из emergency_repair) — переинжектирует инбаунд
    СОХРАНЁННЫМИ параметрами ДО финального рестарта xray.
  • Синхронизация панельных пользователей (users_manager:
    _users_patch_config_no_restart / _users_apply_to_config /
    _unified_save_users) ПРОПУСКАЕТ managed-тег — выделенный клиент
    не затирается при добавлении/удалении юзеров (users.json остаётся
    источником истины ТОЛЬКО для основного инбаунда).
  • users_watchdog классифицирует инбаунд как 'other' (порт !=
    server_port) → снапшот-защита без синхронизации с users.json.

КЛЮЧИ/UUID ЗАДАЮТСЯ ОДНОКРАТНО И ПЕРСИСТЕНТНЫ. При восстановлении
НИКОГДА не генерируются новые (иначе уже выданные клиентам ссылки
сломаются). Пересоздание — только правкой state.json (ключи
xhttp_extra_*) или повторным seed из живого конфига.

АРХИТЕКТУРА — по образцу pq_vless.py: модуль полностью автономен
(свои _run/_info/_warn, никаких импортов из _core.py на уровне
модуля). _core.py и emergency_repair.py обращаются к нему ИСКЛЮЧИТЕЛЬНО
отложенным (внутри тела функции) импортом. Рестарт xray после
переинжекции делает ВЫЗЫВАЮЩИЙ код (контракт как у restore_pq_vless).

ТОЧКИ ВЫЗОВА:
  • restore_xhttp_extra_if_enabled()     — хук после пересоздания config
  • xhttp_extra_managed_tags()           — теги для users_manager (скип)
  • xhttp_extra_seed_from_live_config()  — разовый seed state из живого конфига
  • xhttp_extra_disable()                — выключение (удаление инбаунда + флаг)
  • xhttp_extra_status()                 — dict состояния (диагностика)

Реальные значения (домен/UUID/пути сертификатов) живут ТОЛЬКО в state.json
на ноде — в коде и тестах исключительно нейтральные example.com/плейсхолдеры.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom,
    RED, GREEN, CYAN, YELLOW, DIM, NC,
)

# =============================================================================
#  ЛОКАЛЬНЫЕ ХЕЛПЕРЫ — без зависимости от _core.py (см. шапку файла)
# =============================================================================
LOG_FILE = Path("/var/log/chimera.log")

_TAG = "XHTTP-EXTRA"


def _log(level: str, msg: str) -> None:
    try:
        with LOG_FILE.open("a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"[{level}] [{_TAG}] {msg}\n")
    except Exception:
        pass


def _info(msg: str) -> None:
    print(f"  {CYAN}→{NC}  {msg}")
    _log("INFO", msg)


def _warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{NC}  {msg}")
    _log("WARN", msg)


def _success(msg: str) -> None:
    print(f"  {GREEN}✓{NC}  {msg}")
    _log("OK", msg)


def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 127, stdout="",
                                           stderr=f"command not found: {cmd[0]}")


# =============================================================================
#  КОНСТАНТЫ — те же реальные пути, что по всему проекту (продублированы
#  локально ради автономии модуля, как в pq_vless.py / mtproto.py)
# =============================================================================
XHTTP_EXTRA_TAG          = "inbound-vless-xhttp"
XHTTP_EXTRA_DEFAULT_PORT = 4443

STATE_FILE        = Path("/var/lib/xray-installer/state.json")
CONFIG_DIR        = Path("/etc/xray")
XRAY_CONFIG_PATHS = [CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")]

# Структурные дефолты инбаунда (могут переопределяться state-ключами)
DEFAULT_LISTEN = "::"
DEFAULT_ALPN   = ["h2", "http/1.1"]

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                      r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_XHTTP_EXTRA_STATE_KEYS = (
    "xhttp_extra_enabled", "xhttp_extra_port", "xhttp_extra_path",
    "xhttp_extra_host", "xhttp_extra_server_name",
    "xhttp_extra_cert_file", "xhttp_extra_key_file",
    "xhttp_extra_clients", "xhttp_extra_listen", "xhttp_extra_alpn",
    "xhttp_extra_last_applied",
)


# =============================================================================
#  СОСТОЯНИЕ — общий state.json проекта, свои ключи, read-modify-write с flock
# =============================================================================
def xhttp_extra_state_load() -> dict:
    """Возвращает только xhttp_extra_*-ключи из общего state.json."""
    if not STATE_FILE.exists():
        return {}
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception:
        return {}
    return {k: state.get(k) for k in _XHTTP_EXTRA_STATE_KEYS if k in state}


def xhttp_extra_state_save(values: dict) -> None:
    """Атомарно обновляет ТОЛЬКО xhttp_extra_*-ключи в общем state.json.

    Перечитывает файл под эксклюзивной fcntl-блокировкой непосредственно
    перед записью — не затирает UUID пользователей и любые другие ключи,
    изменённые конкурентно (тот же приём, что pq_state_save). В отличие
    от pq_state_save СОЗДАЁТ файл при отсутствии: seed из живого конфига
    обязан работать и как disaster-recovery (state.json потерян —
    восстановить персистенс одной командой)."""
    try:
        if not STATE_FILE.exists():
            STATE_FILE.write_text("{}\n")
    except Exception as e:
        _warn(f"Не удалось создать {STATE_FILE}: {e}")
        return
    try:
        with STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                for k in _XHTTP_EXTRA_STATE_KEYS:
                    if k in values:
                        state[k] = values[k]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        _warn(f"Не удалось сохранить состояние: {e}")


# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ: бинарь xray, config.json, валидация
# =============================================================================
def _find_xray_bin() -> Optional[str]:
    for candidate in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(candidate).exists():
            return candidate
    return None


def _xray_config_path() -> Optional[Path]:
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def _clients_valid(clients) -> bool:
    """Список выделенных клиентов валиден: непустой, каждый — dict с
    корректным UUID (email опционален, но рекомендован для статистики)."""
    if not isinstance(clients, list) or not clients:
        return False
    for c in clients:
        if not isinstance(c, dict):
            return False
        if not _UUID_RE.match(str(c.get("id", ""))):
            return False
    return True


def _state_sane(st: dict) -> tuple:
    """Достаточность сохранённого состояния для постройки инбаунда."""
    port = st.get("xhttp_extra_port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False, "xhttp_extra_port отсутствует/некорректен"
    path = st.get("xhttp_extra_path", "")
    if not isinstance(path, str) or not path.startswith("/"):
        return False, "xhttp_extra_path отсутствует/не начинается с '/'"
    host = st.get("xhttp_extra_host", "")
    if not isinstance(host, str) or not host:
        return False, "xhttp_extra_host отсутствует"
    if not Path(str(st.get("xhttp_extra_cert_file", ""))).exists():
        return False, "xhttp_extra_cert_file не найден на диске"
    if not Path(str(st.get("xhttp_extra_key_file", ""))).exists():
        return False, "xhttp_extra_key_file не найден на диске"
    if not _clients_valid(st.get("xhttp_extra_clients")):
        return False, "xhttp_extra_clients пуст/невалиден (нужен UUID)"
    return True, ""


# =============================================================================
#  ПОСТРОЕНИЕ ИНБАУНДА — чистая функция над dict (без I/O)
# =============================================================================
def _build_inbound(st: dict) -> dict:
    """Инбаунд-словарь из state-ключей. Структура 1:1 с той, что жила в
    config.json до миграции на персистенс (порт/listen/sniffing/xhttp/
    tls) — чтобы diff конфига после restore был минимальным."""
    clients = []
    for c in st.get("xhttp_extra_clients", []):
        cl = {"id": c["id"]}
        if c.get("email"):
            cl["email"] = c["email"]
        clients.append(cl)
    host = st["xhttp_extra_host"]
    server_name = st.get("xhttp_extra_server_name") or host
    return {
        "tag": XHTTP_EXTRA_TAG,
        "port": st["xhttp_extra_port"],
        "listen": st.get("xhttp_extra_listen") or DEFAULT_LISTEN,
        "protocol": "vless",
        "settings": {
            "clients": clients,
            "decryption": "none",
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False,
            "routeOnly": False,
        },
        "streamSettings": {
            "network": "xhttp",
            "xhttpSettings": {"path": st["xhttp_extra_path"], "host": host},
            "security": "tls",
            "tlsSettings": {
                "serverName": server_name,
                "alpn": st.get("xhttp_extra_alpn") or list(DEFAULT_ALPN),
                "certificates": [{
                    "certificateFile": st["xhttp_extra_cert_file"],
                    "keyFile": st["xhttp_extra_key_file"],
                }],
            },
        },
    }


def has_xhttp_extra_inbound(cfg: dict) -> bool:
    return any(isinstance(ib, dict) and ib.get("tag") == XHTTP_EXTRA_TAG
               for ib in cfg.get("inbounds", []))


def inject_xhttp_extra_inbound(cfg: dict, st: dict) -> bool:
    """Добавляет/актуализирует xHTTP-extra инбаунд в cfg (in-place).

    True — конфиг изменён (инбаунда не было, либо параметры разошлись
    со state — state является источником истины). False — инбаунд уже
    идентичен state, изменений не требуется."""
    inbound = _build_inbound(st)
    for i, ib in enumerate(cfg.get("inbounds", [])):
        if isinstance(ib, dict) and ib.get("tag") == XHTTP_EXTRA_TAG:
            if ib == inbound:
                return False
            cfg["inbounds"][i] = inbound
            return True
    cfg.setdefault("inbounds", []).append(inbound)
    return True


def remove_xhttp_extra_inbound(cfg: dict) -> bool:
    """Удаляет инбаунд по тегу. True — был и удалён, False — не было."""
    inbounds = cfg.get("inbounds", [])
    before = len(inbounds)
    cfg["inbounds"] = [ib for ib in inbounds
                       if not (isinstance(ib, dict)
                               and ib.get("tag") == XHTTP_EXTRA_TAG)]
    return len(cfg["inbounds"]) < before


# =============================================================================
#  ЗАПИСЬ С ПРОВЕРКОЙ — xray -test ПЕРЕД тем, как конфиг попадёт в реально
#  запущенный сервис (тот же приём, что _write_and_test в pq_vless.py)
# =============================================================================
def _write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    """Пишет конфиг и проверяет синтаксис через `xray run -test`.
    При провале — откатывает файл к прежнему содержимому. None = успех."""
    backup = cfg_path.read_text() if cfg_path.exists() else None
    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    except Exception as e:
        return f"Не удалось записать {cfg_path}: {e}"

    xray_bin = _find_xray_bin()
    if xray_bin:
        r = _run([xray_bin, "run", "-test", "-config", str(cfg_path)],
                 capture=True, check=False)
        if r.returncode != 0:
            full_output = (r.stderr or r.stdout or "").strip()
            _log("ERROR", f"xray -test провалился, полный вывод:\n{full_output}")
            try:
                failed_path = cfg_path.with_suffix(cfg_path.suffix + ".xhe-failed")
                failed_path.write_text(json.dumps(cfg, indent=2,
                                                  ensure_ascii=False))
                _log("INFO", f"Провалившийся конфиг сохранён в {failed_path}")
            except Exception:
                pass
            if backup is not None:
                cfg_path.write_text(backup)
            return f"xray -test провалился: {full_output[:1000]}"
    return None


# =============================================================================
#  ПУБЛИЧНЫЙ API
# =============================================================================
def xhttp_extra_managed_tags() -> set:
    """Теги инбаундов с выделенными клиентами — users_manager пропускает
    их при синхронизации панельных пользователей. Пустое множество =
    фича выключена/состояние нечитаемо — обычное поведение синхронизации."""
    st = xhttp_extra_state_load()
    if not st.get("xhttp_extra_enabled"):
        return set()
    return {XHTTP_EXTRA_TAG}


def restore_xhttp_extra_if_enabled() -> Optional[tuple]:
    """Хук для вызова после пересоздания config.json (rebuild, switch-mode,
    emergency repair). Если в state включён xHTTP-extra — пере-применяем
    инбаунд к свежему config.json ДО рестарта xray (рестарт делает
    вызывающий код). Возвращает None, если фича не включена; иначе
    (ok, сообщение) — тот же контракт, что restore_pq_vless_if_enabled."""
    st = xhttp_extra_state_load()
    if not st.get("xhttp_extra_enabled"):
        return None

    cfg_path = _xray_config_path()
    if not cfg_path:
        return False, "config.json не найден"
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    # Валидация ДО inject: _build_inbound() обращается к ключам напрямую
    # (KeyError на пустом state), а при битом состоянии конфиг лучше не
    # трогать вовсе — работающий инбаунд переживёт до починки state.
    sane, why = _state_sane(st)
    if not sane:
        return False, (f"состояние повреждено ({why}) — проверьте ключи "
                       f"xhttp_extra_* (инбаунд в конфиге не тронут)")

    # Инбаунд мог сохраниться (rebuild без регенерации/двойной вызов):
    # сверяем со state — при расхождении state источник истины.
    if not inject_xhttp_extra_inbound(cfg, st):
        return True, "инбаунд уже на месте (параметры совпадают)"

    err = _write_and_test(cfg_path, cfg)
    if err:
        return False, err
    xhttp_extra_state_save({"xhttp_extra_last_applied":
                            time.strftime("%Y-%m-%d %H:%M:%S")})
    return True, (f"инбаунд восстановлен на порту {st['xhttp_extra_port']} "
                  f"(клиентов: {len(st['xhttp_extra_clients'])})")


def xhttp_extra_seed_from_live_config(cfg_path: Optional[Path] = None) -> tuple:
    """Разовый seed state.json из ЖИВОГО config.json (миграция вручную
    добавленного инбаунда на персистенс). Находит инбаунд по тегу,
    извлекает порт/path/host/SNI/сертификаты/клиентов и сохраняет в
    state.json c xhttp_extra_enabled=True. Конфиг НЕ пишет, xray НЕ
    рестартует — только фиксирует параметры как источник истины."""
    path = cfg_path or _xray_config_path()
    if not path:
        return False, "config.json не найден"
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {path}: {e}"

    inbound = None
    for ib in cfg.get("inbounds", []):
        if isinstance(ib, dict) and ib.get("tag") == XHTTP_EXTRA_TAG:
            inbound = ib
            break
    if inbound is None:
        return False, (f"инбаунд с тегом {XHTTP_EXTRA_TAG} в {path} не найден "
                       f"— seed невозможен")

    ss = inbound.get("streamSettings", {}) or {}
    xhttp = ss.get("xhttpSettings", {}) or {}
    tls = ss.get("tlsSettings", {}) or {}
    certs = tls.get("certificates") or [{}]
    clients = [{"id": c["id"], **({"email": c["email"]} if c.get("email") else {})}
               for c in (inbound.get("settings", {}).get("clients") or [])
               if isinstance(c, dict) and c.get("id")]

    values = {
        "xhttp_extra_enabled": True,
        "xhttp_extra_port": inbound.get("port"),
        "xhttp_extra_listen": inbound.get("listen") or DEFAULT_LISTEN,
        "xhttp_extra_path": xhttp.get("path", ""),
        "xhttp_extra_host": xhttp.get("host", ""),
        "xhttp_extra_server_name": tls.get("serverName", ""),
        "xhttp_extra_cert_file": certs[0].get("certificateFile", ""),
        "xhttp_extra_key_file": certs[0].get("keyFile", ""),
        "xhttp_extra_clients": clients,
        "xhttp_extra_last_applied": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if tls.get("alpn"):
        values["xhttp_extra_alpn"] = tls["alpn"]

    sane, why = _state_sane(values)
    if not sane:
        return False, f"живой инбаунд неконсистентен ({why}) — seed отменён"

    xhttp_extra_state_save(values)
    return True, (f"state засеян из живого конфига: порт {values['xhttp_extra_port']}, "
                  f"клиентов {len(clients)}")


def xhttp_extra_disable(remove_from_config: bool = True) -> tuple:
    """Выключение персистенса: удаляет инбаунд из config.json (с
    валидацией xray -test) и ставит xhttp_extra_enabled=False. Параметры
    в state СОХРАНЯЮТСЯ — повторное включение = правка одного флага.
    Рестарт xray делает вызывающий код (контракт как у restore)."""
    cfg_path = _xray_config_path()
    removed = False
    if remove_from_config and cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            if remove_xhttp_extra_inbound(cfg):
                err = _write_and_test(cfg_path, cfg)
                if err:
                    return False, err
                removed = True
        except Exception as e:
            return False, f"Не удалось прочитать {cfg_path}: {e}"
    xhttp_extra_state_save({"xhttp_extra_enabled": False})
    return True, ("инбаунд удалён из конфига, персистенс выключен" if removed
                  else "персистенс выключен (инбаунда в конфиге не было)")


def xhttp_extra_status() -> dict:
    """Сводка состояния для диагностики/верификации раскатки."""
    st = xhttp_extra_state_load()
    result = {
        "enabled":      bool(st.get("xhttp_extra_enabled")),
        "port":         st.get("xhttp_extra_port"),
        "path":         st.get("xhttp_extra_path", ""),
        "host":         st.get("xhttp_extra_host", ""),
        "server_name":  st.get("xhttp_extra_server_name", ""),
        "cert_file":    st.get("xhttp_extra_cert_file", ""),
        "key_file":     st.get("xhttp_extra_key_file", ""),
        "clients":      len(st.get("xhttp_extra_clients") or []),
        "last_applied": st.get("xhttp_extra_last_applied", ""),
        "in_config":    False,
        "config_matches_state": False,
        "state_sane":   False,
    }
    sane, why = _state_sane(st)
    result["state_sane"] = sane
    if not sane:
        result["state_problem"] = why
    cfg_path = _xray_config_path()
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            for ib in cfg.get("inbounds", []):
                if isinstance(ib, dict) and ib.get("tag") == XHTTP_EXTRA_TAG:
                    result["in_config"] = True
                    if sane:
                        result["config_matches_state"] = (ib == _build_inbound(st))
                    break
        except Exception:
            pass
    return result


def do_xhttp_extra_report() -> None:
    """Человекочитаемый отчёт (для разовых проверок с ноды через
    python3 -c / экстренную диагностику). Меню не создаёт — управление
    через state.json + этот API."""
    st = xhttp_extra_status()
    print()
    _box_top("🛰  xHTTP-extra инбаунд (персистенс)")
    _box_row(f"  Персистенс: {'включён' if st['enabled'] else 'выключен'}")
    if st["enabled"]:
        ok = GREEN + "✓" + NC
        bad = RED + "✗" + NC
        _box_row(f"  Порт/path:    {st['port']}  {st['path']}")
        _box_row(f"  Host/SNI:     {st['host']}" +
                 (f"  (sni: {st['server_name']})" if st["server_name"] else ""))
        _box_row(f"  Клиентов:     {st['clients']}")
        _box_row(f"  В конфиге:    {ok if st['in_config'] else bad}")
        if st["in_config"]:
            _box_row(f"  Совпадает со state: {ok if st['config_matches_state'] else bad}")
        _box_row(f"  State валиден:      {ok if st['state_sane'] else bad}"
                 + (f"  ({st.get('state_problem', '')})" if not st["state_sane"] else ""))
        if st["last_applied"]:
            _box_row(f"  Последнее применение: {st['last_applied']}")
    _box_row()
    _box_sep()
    _box_row(f"  {DIM}Хук: _rebuild_and_restart_xray → restore_xhttp_extra_if_enabled(){NC}")
    _box_row(f"  {DIM}Сид: python3 -c 'from chimera.modules.xhttp_extra import "
             f"xhttp_extra_seed_from_live_config as s; print(s())'{NC}")
    _box_bottom()
