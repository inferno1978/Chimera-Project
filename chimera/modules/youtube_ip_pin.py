"""
chimera/modules/youtube_ip_pin.py
───────────────────────────────────────────────────────────────────────────────
ЭКСПЕРИМЕНТАЛЬНАЯ опция: закрепление YouTube-CDN по IP поверх выбора exit-ноды.

⚠️ ДИСКЛЕЙМЕР (обязателен к показу в UI при включении):
  YouTube отдаёт видео с подписанных URL конкретного cache-узла, который
  сервер YouTube выбирает в момент запроса manifest'а исходя из того, откуда
  пришёл запрос. Пиннинг по IP из внешнего списка НЕ гарантирует, что видео
  будет доступно — это best-effort, может давать 403/таймауты. Не использовать
  как основной механизм выбора региона (для этого есть выбор exit-ноды).

Источник данных: https://github.com/touhidurrr/iplist-youtube
  lists/cidr4.txt — ~557 CIDR IPv4 (~8.9KB), обновляется автором каждые 5 мин
  lists/cidr6.txt — ~710 CIDR IPv6 (~16.8KB)
  Нам достаточно рефетча раз в сутки — апстрим уже копит историю.

Архитектура:
  1. PackageSpec x2 (cidr4, cidr6) — через download_manager.fetch_package()
  2. download_youtube_iplist() — скачивает оба списка
  3. setup_youtube_iplist_autoupdate() — cron ежедневно
  4. apply_youtube_ip_pin(target_tag) — добавляет IP-правило в Xray config
  5. remove_youtube_ip_pin() — убирает только IP-правило
  6. UI интеграция через youtube_route.do_manage_youtube_via_ru()

IP-правило живёт РЯДОМ с доменным правилом youtube_route.py, а не вместо него.
Оба включаются/выключаются независимо. IP-правило помечено отдельным comment.

State в state.json:
  "youtube_ip_pin_enabled": bool
  "youtube_iplist_updated_at": ISO-timestamp
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.download_manager import PackageSpec, fetch_package


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ───────────────────────────────────────────────────────────────
_IPLIST_DIR = Path("/opt/chimera/youtube_iplist")
_CIDR4_FILE = _IPLIST_DIR / "cidr4.txt"
_CIDR6_FILE = _IPLIST_DIR / "cidr6.txt"

_IP_PIN_RULE_COMMENT = "youtube_ip_pin"

# Минимальное количество валидных CIDR для принятия файла.
# Если меньше — файл отбраковывается (усечённая загрузка, 404-страница вместо списка).
_MIN_CIDR4 = 300
_MIN_CIDR6 = 400

# Источник: github.com/touhidurrr/iplist-youtube
_GH_OWNER = "touhidurrr"
_GH_REPO = "iplist-youtube"
_GH_BRANCH = "main"
_GH_LISTS_DIR = "lists"


# ── URL-билдеры ──────────────────────────────────────────────────────────────
def _raw_github_url(filename: str) -> str:
    """Прямой raw.githubusercontent.com URL — основной источник.

    Используется ПЕРВЫМ в _mirror_urls(), потому что raw.githubusercontent.com
    не кэширует так агрессивно как jsDelivr (TTL по branch-ref). Для этого
    источника (touhidurrr/iplist-youtube) нет публикуемых sha256-чек-сумм
    (checksum_urls=None), соответственно staleness от кэширующего CDN
    нечем ловить — post_install проверяет только валидность CIDR, а
    устаревший-но-валидный список пройдёт проверку. См. аналогичный баг
    с geosite.dat/geoip.dat (коммит e90f255) — там спасла sha256-сверка,
    здесь её нет.
    """
    return (f"https://raw.githubusercontent.com/"
            f"{_GH_OWNER}/{_GH_REPO}/{_GH_BRANCH}/{_GH_LISTS_DIR}/{filename}")


def _jsdelivr_url(filename: str) -> str:
    """jsDelivr CDN URL — fallback на случай недоступности GitHub из РФ.

    Используется ВТОРЫМ в _mirror_urls(). jsDelivr кэширует по branch-ref
    с TTL, может отдавать устаревший контент — без checksum-верификации
    это не детектируется. Только fallback, не основной источник.
    """
    return (f"https://cdn.jsdelivr.net/gh/"
            f"{_GH_OWNER}/{_GH_REPO}@{_GH_BRANCH}/{_GH_LISTS_DIR}/{filename}")


def _mirror_urls(filename: str) -> list[str]:
    """Список зеркал для скачивания (прямой GitHub первым — без
    checksum-верификации нельзя полагаться на кэширующий CDN как
    основной источник, см. e90f255; jsDelivr — fallback)."""
    return [
        _raw_github_url(filename),  # прямой GitHub первым — не кэширует
        _jsdelivr_url(filename),    # jsDelivr — fallback, может отдавать stale
    ]


# ── post_install: валидация + копирование ────────────────────────────────────
def _post_install_iplist(src: Path, install_dests: list[Path]) -> bool:
    """Валидирует и копирует IP-список в install_dests.

    Валидация: построчно парсит ipaddress.ip_network(line, strict=False),
    считает валидные CIDR. Если меньше порога — отбраковывает (return False).

    Копирование: shutil.copy2 в каждую директорию из install_dests.
    """
    import shutil as _shutil

    _run = None
    _warn = None
    _info = None
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        _run = getattr(core, "_run", None)
        _warn = getattr(core, "warn", None)
        _info = getattr(core, "info", None)
    except Exception:
        pass

    def _log(msg: str):
        if _info:
            _info(msg)
        else:
            print(msg)

    def _log_warn(msg: str):
        if _warn:
            _warn(msg)
        else:
            print(f"[WARN] {msg}")

    # ── Валидация содержимого ──────────────────────────────────────────────
    try:
        content = src.read_text(errors="replace")
    except Exception as e:
        _log_warn(f"Не удалось прочитать {src}: {e}")
        return False

    valid_count = 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            valid_count += 1
        except ValueError:
            continue  # не CIDR — пропускаем (мусор в файле)

    # Определяем порог по имени файла.
    fname = src.name
    min_expected = _MIN_CIDR4 if "cidr4" in fname else _MIN_CIDR6

    if valid_count < min_expected:
        _log_warn(f"{fname}: только {valid_count} валидных CIDR "
                  f"(минимум {min_expected}) — файл отбракован")
        return False

    _log(f"{fname}: {valid_count} валидных CIDR — принято")

    # ── Копирование ────────────────────────────────────────────────────────
    src_size = src.stat().st_size
    any_ok = False
    for dest_dir in install_dests:
        dest = dest_dir / src.name
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            _shutil.copy2(str(src), str(dest))
            dest.chmod(0o644)
            dest_size = dest.stat().st_size
            if dest_size != src_size:
                _log_warn(f"  {dest}: размер {dest_size} ≠ {src_size} — копия неполная!")
                dest.unlink(missing_ok=True)
                continue
            if _run is not None:
                try:
                    _run(["chown", "root:root", str(dest)], check=False, quiet=True)
                except Exception:
                    pass
            _log(f"  {dest}: OK ({dest_size} байт, {valid_count} CIDR)")
            any_ok = True
        except Exception as e:
            _log_warn(f"  {dest}: {e}")

    if not any_ok:
        _log_warn(f"  ВСЕ копирования {src.name} провалились!")
    return any_ok


# ── PackageSpec ──────────────────────────────────────────────────────────────
# manual_incoming_dir — отдельная поддиректория /root/youtube_iplist/
# (не /root напрямую, чтобы не конфликтовать с geo-файлами)
_MANUAL_DIR = Path("/root/youtube_iplist")

# install_dests — одна директория (файлы не нужны в /etc/xray, Xray их не читает)
_INSTALL_DESTS: list[Path] = [_IPLIST_DIR]


CIDR4_SPEC = PackageSpec(
    name="youtube-cidr4",
    filename_builder=lambda **kw: "cidr4.txt",
    mirror_urls_builder=lambda filename, **kw: _mirror_urls(filename),
    install_dests=_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=4000,
    post_install=_post_install_iplist,
    checksum_urls=None,  # у апстрима нет публикуемых чек-сумм
)

CIDR6_SPEC = PackageSpec(
    name="youtube-cidr6",
    filename_builder=lambda **kw: "cidr6.txt",
    mirror_urls_builder=lambda filename, **kw: _mirror_urls(filename),
    install_dests=_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=8000,
    post_install=_post_install_iplist,
    checksum_urls=None,
)


# =============================================================================
#  СКАЧИВАНИЕ
# =============================================================================

def download_youtube_iplist() -> bool:
    """Скачивает оба IP-списка (cidr4 + cidr6) через fetch_package.

    По образцу geo_files.download_geo_files().
    Возвращает True если оба скачаны успешно.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    success = core.success

    _IPLIST_DIR.mkdir(parents=True, exist_ok=True)
    _MANUAL_DIR.mkdir(parents=True, exist_ok=True)

    info("Скачивание YouTube IP-списков (touhidurrr/iplist-youtube)...")
    info("  (экспериментальная опция — может выдавать 403 на видео)")

    success_count = 0
    failed_files: list[str] = []

    for spec, fname in (
        (CIDR4_SPEC, "cidr4.txt"),
        (CIDR6_SPEC, "cidr6.txt"),
    ):
        info(f"  Загрузка {fname}...")
        try:
            ok = fetch_package(spec, print_hint_on_failure=False,
                               progress_label=fname)
            if ok:
                success_count += 1
            else:
                failed_files.append(fname)
        except Exception as ex:
            warn(f"  Ошибка загрузки {fname}: {ex}")
            failed_files.append(fname)

    if success_count == 2:
        # Записываем timestamp обновления в state.json
        _save_iplist_state(updated=True)
        success("YouTube IP-списки готовы")
        return True
    elif success_count == 1:
        warn("Загружен только один IP-список — IP-pin может работать некорректно")
        _save_iplist_state(updated=True)
        return True
    else:
        warn("Не удалось загрузить YouTube IP-списки")
        return False


# =============================================================================
#  CRON — ежедневное обновление
# =============================================================================

def setup_youtube_iplist_autoupdate() -> None:
    """Создаёт cron-задачу для ежедневного обновления IP-списков.

    По образцу geo_files.setup_geo_autoupdate(), но:
      - Ежедневно (не раз в неделю)
      - Отдельный cron-файл /etc/cron.d/youtube-iplist-update
      - НЕ трогает /etc/cron.d/xray-geo-update
    """
    core = _core_module()
    success = core.success
    warn = core.warn

    script = Path("/usr/local/bin/youtube-iplist-update.sh")
    script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Ежедневное обновление YouTube IP-списков (touhidurrr/iplist-youtube)
        # Экспериментальная опция — может выдавать 403 на видео.
        set -uo pipefail
        LOG="/var/log/youtube-iplist-update.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Обновление YouTube IP-списков..." >> "$LOG"

        mkdir -p {_IPLIST_DIR} {_MANUAL_DIR}

        # Скачиваем через Python (переиспользуем fetch_package)
        /usr/bin/python3 -c "
        from chimera.modules.youtube_ip_pin import download_youtube_iplist
        ok = download_youtube_iplist()
        exit(0 if ok else 1)
        " >> "$LOG" 2>&1

        if [ $? -eq 0 ]; then
            echo "[$DATE] ✓ YouTube IP-списки обновлены" >> "$LOG"
        else
            echo "[$DATE] ✗ Ошибка обновления YouTube IP-списков" >> "$LOG"
        fi
    """))
    script.chmod(0o750)

    # Cron: ежедневно в 04:00
    cron_file = Path("/etc/cron.d/youtube-iplist-update")
    try:
        cron_file.write_text(
            f"# YouTube IP-list daily update (experimental)\n"
            f"0 4 * * * root {script}\n"
        )
        cron_file.chmod(0o644)
        success("Автообновление YouTube IP-списков: ежедневно в 04:00")
    except Exception as e:
        warn(f"Не удалось создать cron для YouTube IP-списков: {e}")


def remove_youtube_iplist_autoupdate() -> None:
    """Удаляет cron-задачу обновления IP-списков."""
    cron_file = Path("/etc/cron.d/youtube-iplist-update")
    script = Path("/usr/local/bin/youtube-iplist-update.sh")
    cron_file.unlink(missing_ok=True)
    script.unlink(missing_ok=True)


# =============================================================================
#  ПРИМЕНЕНИЕ / УДАЛЕНИЕ IP-ПРАВИЛА В XRAY CONFIG
# =============================================================================

def _load_cidr_list() -> list[str]:
    """Загружает все CIDR из обоих файлов. Возвращает список строк."""
    cidrs: list[str] = []
    for fpath in (_CIDR4_FILE, _CIDR6_FILE):
        if not fpath.exists():
            continue
        try:
            for line in fpath.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    cidrs.append(line)
                except ValueError:
                    continue
        except Exception:
            continue
    return cidrs


def apply_youtube_ip_pin(target_tag: str) -> bool:
    """Добавляет IP-правило для YouTube-CDN в Xray config.

    Args:
      target_tag: outboundTag для IP-правила (тот же что выбран для домена).
                  Должен быть не "off" — IP-pin работает только когда
                  уже выбрана конкретная нода (RU или chain-exit-N).

    Возвращает True если хотя бы один config.json пропатчен.
    """
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run = core._run
    _set_config_owner = core._set_config_owner
    info = core.info
    success = core.success
    warn = core.warn

    if not target_tag or target_tag == "off":
        warn("IP-pin требует выбранной exit-ноды — текущий маршрут 'off'")
        return False

    # Загружаем CIDR-список.
    cidrs = _load_cidr_list()
    if not cidrs:
        warn("YouTube IP-списки не найдены — скачайте: меню YouTube → IP-pin → обновить")
        return False

    info(f"YouTube IP-pin: {len(cidrs)} CIDR → {target_tag}")

    written: set = set()
    ok = False
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.setdefault("routing", {})
            # Убираем старое IP-правило (идемпотентность).
            rules = [r for r in routing.setdefault("rules", [])
                     if r.get("comment") != _IP_PIN_RULE_COMMENT]
            # Проверяем что outbound существует.
            outbounds = cfg.setdefault("outbounds", [])
            if not any(ob.get("tag") == target_tag for ob in outbounds):
                warn(f"Outbound '{target_tag}' не найден в {cfg_path} — "
                     f"возможно нода удалена")
                continue
            # Новое IP-правило. Prepended ПЕРЕД существующими.
            new_rule = {
                "type": "field",
                "ip": cidrs,
                "outboundTag": target_tag,
                "comment": _IP_PIN_RULE_COMMENT,
            }
            routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info(f"Конфиг: {cfg_path} (YouTube IP-pin → {target_tag}, {len(cidrs)} CIDR)")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if not ok:
        warn("Не удалось применить YouTube IP-pin")
        return False

    # Restart xray.
    #  FIX: если _youtube_apply_to_xray только что перезапустил Xray,
    # второй restart подряд может упасть (systemd не успел обработать первый).
    # Добавляем sleep 2с перед restart и увеличиваем таймаут ожидания.
    # v56 (start-limit-fix): сам рестарт — через _xray_safe_restart
    # (reset-failed): в цепочке _rebuild_and_restart_xray это уже ВТОРОЙ
    # рестарт за несколько секунд, дальше будут tproxy и финальный —
    # голые restarts упираются в StartLimitBurst=3/60s юнита xray,
    # последний start отклоняется (start-limit-hit) при валидном конфиге.
    time.sleep(2)
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    if callable(_safe_restart):
        _restart_ok = _safe_restart(wait_active=45)
    else:  # fallback на старое поведение (старое ядро без хелпера)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        _restart_ok = False
        for _ in range(45):
            r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r.stdout.strip() == "active":
                _restart_ok = True
                break
            time.sleep(1)
    if not _restart_ok:
        warn("Xray не запустился — проверьте: journalctl -u xray -n 30")
        _nginx_restart_if_reality()
        return False
    success(f"YouTube IP-pin → {target_tag} ({len(cidrs)} CIDR)")
    _nginx_restart_if_reality()
    return True


def remove_youtube_ip_pin() -> bool:
    """Удаляет только IP-правило из Xray config. Доменное не трогает."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run = core._run
    _set_config_owner = core._set_config_owner
    success = core.success
    warn = core.warn

    written: set = set()
    ok = False
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.get("routing", {})
            old_count = len(routing.get("rules", []))
            routing["rules"] = [r for r in routing.get("rules", [])
                                if r.get("comment") != _IP_PIN_RULE_COMMENT]
            new_count = len(routing["rules"])
            if new_count == old_count:
                continue  # правила не было
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            try:
                core.info(f"Конфиг: {cfg_path} (удалено IP-pin правило)")
            except Exception:
                pass
            ok = True
        except Exception as e:
            warn(f"Ошибка {cfg_path}: {e}")

    if not ok:
        success("YouTube IP-pin правило не найдено — уже выключено.")
    else:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        r = None
        for _ in range(30):
            r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r.stdout.strip() == "active":
                break
            time.sleep(1)
        if not r or r.stdout.strip() != "active":
            warn("Xray не запустился — проверьте: journalctl -u xray -n 30")
            _nginx_restart_if_reality()
            return False
        success("YouTube IP-pin выключен (правило убрано)")
        _nginx_restart_if_reality()
    return True


def _ip_pin_rule_in_xray_config() -> bool:
    """Проверяет наличие IP-pin правила в config.json."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for rule in cfg.get("routing", {}).get("rules", []):
                if rule.get("comment") == _IP_PIN_RULE_COMMENT:
                    return True
        except Exception:
            continue
    return False


# =============================================================================
#  STATE
# =============================================================================

def _save_iplist_state(updated: bool = False) -> None:
    """Сохраняет youtube_iplist_updated_at в state.json."""
    core = _core_module()
    try:
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
        else:
            state = {}
        if updated:
            state["youtube_iplist_updated_at"] = datetime.now().isoformat()
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        try:
            core.warn(f"Не удалось обновить state.json: {e}")
        except Exception:
            print(f"Не удалось обновить state.json: {e}")


def save_ip_pin_state(enabled: bool) -> None:
    """Сохраняет youtube_ip_pin_enabled в state.json."""
    core = _core_module()
    try:
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
        else:
            state = {}
        state["youtube_ip_pin_enabled"] = bool(enabled)
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        try:
            core.warn(f"Не удалось обновить state.json: {e}")
        except Exception:
            print(f"Не удалось обновить state.json: {e}")


def get_ip_pin_status() -> dict:
    """Возвращает статус IP-pin: enabled, updated_at, cidr_count, rule_in_config."""
    core = _core_module()
    try:
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    except Exception:
        state = {}

    enabled = state.get("youtube_ip_pin_enabled", False)
    updated_at = state.get("youtube_iplist_updated_at", "")
    cidr_count = len(_load_cidr_list())
    rule_in_config = _ip_pin_rule_in_xray_config()

    return {
        "enabled": enabled,
        "updated_at": updated_at,
        "cidr_count": cidr_count,
        "rule_in_config": rule_in_config,
    }


# =============================================================================
#  RESTORE (вызывается из youtube_route.restore_youtube_rule_if_needed)
# =============================================================================

def restore_ip_pin_if_needed(silent: bool = False) -> bool:
    """Пере-применяет IP-pin правило если state говорит что оно включено,
    но в config.json его нет.

    НЕ применяется если youtube_route_target == "off" — IP-pin требует
    выбранной ноды. В этом случае логирует warn, не падает.

    Возвращает True если правило было пере-применено.
    """
    try:
        core = _core_module()
    except Exception:
        return False

    try:
        if not core.STATE_FILE.exists():
            return False
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return False

    if not state.get("youtube_ip_pin_enabled", False):
        return False

    # Проверяем что для YouTube выбрана конкретная нода (не "off").
    target = state.get("youtube_route_target")
    if target is None:
        target = "ru" if state.get("youtube_via_ru", False) else "off"

    if target == "off":
        if not silent:
            try:
                core.warn("YouTube IP-pin включён в state, но маршрут YouTube 'off' "
                          "— IP-pin не применяется. Выберите ноду в меню YouTube.")
            except Exception:
                pass
        return False

    if _ip_pin_rule_in_xray_config():
        return False  # Уже на месте

    # Определяем outboundTag.
    if target == "ru":
        tag = None  # direct/direct-local — но для IP-pin нужен конкретный тег
        # IP-pin с RU означает direct/direct-local — используем тот же тег
        # что и доменное правило.
        awg = getattr(core, "AWG_EXIT_ENABLED", False)
        tag = "direct-local" if awg else "direct"
    else:
        tag = target  # chain-exit-N

    if not silent:
        try:
            core.info(f"Пере-применяем YouTube IP-pin → {tag} "
                      f"после regenerate xray-config...")
        except Exception:
            pass
    return apply_youtube_ip_pin(tag)
