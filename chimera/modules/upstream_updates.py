"""
chimera/modules/upstream_updates.py
───────────────────────────────────────────────────────────────────────────────
Единый центр авто/ручного обновления из апстрим-репозиториев для
трёх модулей, пострадавших от «тихих» изменений upstream (инцидент):

  • Turnable  — TheAirBlow/Turnable (releases, готовый ELF-бинарник)
  • CSQTT     — amurcanov/csqtt (ветка main, сборка Rust из исходников)
  • qWDTT     — SpaceNeuroX/proxy-turn-vk-android (ветка master, сборка Go)

ПРОБЛЕМА (класс бага):
  upstream меняет layout архива и требования toolchain БЕЗ уведомления:
    csqtt-uring → rust-server   (переименование серверной папки)
    server.go → ./server        (модульный layout) + go.mod: go 1.25.0
    Turnable: _run_update обещал latest, качал pinned 0.4.1
  Химера с зашитыми путями падала на установке. Пользователь узнавал
  о поломке только по красному экрану.

МЕХАНИЗМ:
  1. РЕВИЗИИ. Для source-модулей «версия» = HEAD sha ветки (GitHub API);
     для Turnable = тег релиза. ЛЮБОЙ коммит апстрима = «есть обновление».
  2. LAYOUT-PROBE. Пути сборки ищутся в распакованном архиве, а не
     предполагаются: Cargo.toml/go.mod сканируются, имя бинарника и
     требуемые версии toolchain читаются из upstream-файлов (реализовано
     в csqtt_packages.py / wdtt_packages.py, см. LAST_BUILD_INFO).
  3. ЕДИНЫЙ STATE — /var/lib/chimera/upstream-updates.json: установленная
     ревизия/версия, хэш tarball, layout, last_check/last_update/last_error,
     per-target флаг auto.
  4. РУЧНОЕ ОБНОВЛЕНИЕ — единое меню do_upstream_update_menu() (вызывается
     из меню Turnable/CSQTT/qWDTT) + быстрые статусы в шапках меню.
  5. АВТООБНОВЛЕНИЕ — агент /usr/local/bin/chimera-upstream-update.py +
     systemd timer chimera-upstream-update.timer (ежедневно 04:40,
     RandomizedDelaySec 30 мин, TimeoutStartSec 60 мин — Rust-сборка
     небыстрая). Бэкап → замена → smoke-тест сервиса → откат при провале.
     Никогда не ставит модуль с нуля (только бинарник существует).
  6. МЕНЕДЖЕР ЗАГРУЗОК — ВСЁ скачивание идёт через download_manager.
     fetch_package(spec): зеркала-фолбэки, ручное размещение в /root/,
     min_size, post_install (сборка+атомарная замена).

Артефакты на сервере:
  /usr/local/bin/chimera-upstream-update.py       — агент (генерируется)
  /etc/systemd/system/chimera-upstream-update.{service,timer}
  /var/lib/chimera/upstream-updates.json          — state
  /var/backups/chimera/upstream/{key}_{ts}        — бэкапы бинарников (по 5)
  /var/log/chimera-upstream-update.log            — лог агента

Точки входа:
    from chimera.modules.upstream_updates import (
        do_upstream_update_menu, update_target, check_target,
        run_agent, install_autoupdate, remove_autoupdate,
        get_update_status_line,
    )
    # CLI:  python3 main.py --upstream-autoupdate   (агент, не-интерактивно)
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
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ── Цвета (как в dnscrypt_update — самодостаточно, без циклических импортов) ──
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
STATE_DIR      = Path("/var/lib/chimera")
STATE_FILE     = STATE_DIR / "upstream-updates.json"
BACKUP_DIR     = Path("/var/backups/chimera/upstream")
LOG_FILE       = Path("/var/log/chimera-upstream-update.log")
AGENT_BIN      = Path("/usr/local/bin/chimera-upstream-update.py")
AGENT_SERVICE  = Path("/etc/systemd/system/chimera-upstream-update.service")
AGENT_TIMER    = Path("/etc/systemd/system/chimera-upstream-update.timer")
AGENT_TIMER_NAME = "chimera-upstream-update.timer"

# Кэш проверки GitHub API (как в dnscrypt_update.fetch_latest_version)
CHECK_CACHE_SEC = 6 * 3600
# Хранить бэкапов бинарника на цель
KEEP_BACKUPS = 5


# =============================================================================
# РЕЕСТР ЦЕЛЕЙ — три модуля из инцидента 
# =============================================================================
UPSTREAM_TARGETS: Dict[str, Dict[str, Any]] = {
    "turnable": {
        "title": "Turnable (WireTurn)",
        "kind": "release",                 # GitHub Releases → tag
        "owner": "TheAirBlow",
        "repo": "Turnable",
        "branch": None,
        "binary": Path("/opt/turnable/turnable"),
        "service": "turnable",
        # post_install TURNABLE_SPEC копирует бинарник ПОВЕРХ старого —
        # работающий процесс = ETXTBSY. Сервис останавливаем ДО fetch
        # (csqtt/wdtt это делают сами внутри post_install).
        "stop_service_before_fetch": True,
        "version_arg": "--version",
    },
    "csqtt": {
        "title": "CSQTT (RTP/TURN tunnel)",
        "kind": "branch",                  # ветка → HEAD sha
        "owner": "amurcanov",
        "repo": "csqtt",
        "branch": "main",
        "binary": Path("/usr/local/bin/csqtt-server"),
        "service": "csqtt",
    },
    "wdtt": {
        "title": "qWDTT (WireGuard/TURN VK)",
        "kind": "branch",
        "owner": "SpaceNeuroX",
        "repo": "proxy-turn-vk-android",
        "branch": "master",
        "binary": Path("/usr/local/bin/wdtt-server"),
        "service": "wdtt",
    },
}


def _spec_for(key: str):
    """Ленивая фабрика PackageSpec — всё скачивание через download_manager."""
    if key == "turnable":
        from chimera.modules.turn_packages import TURNABLE_SPEC
        return TURNABLE_SPEC
    if key == "csqtt":
        from chimera.modules.csqtt_packages import CSQTT_SOURCE_SPEC
        return CSQTT_SOURCE_SPEC
    if key == "wdtt":
        from chimera.modules.wdtt_packages import WDTT_SOURCE_SPEC
        return WDTT_SOURCE_SPEC
    raise KeyError(f"unknown upstream target: {key}")


# =============================================================================
#  STATE — единый файл (идиома dnscrypt_update: атомарный tmp+rename мерж)
# =============================================================================
def read_state() -> Dict[str, Any]:
    """Читает state-файл; при отсутствии/битости — пустая структура."""
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def update_state(key: Optional[str], **kv) -> None:
    """Атомарно (tmp+rename) мержит поля в state[key] (или в корень при key=None)."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        st = read_state()
        if key is None:
            st.update(kv)
        else:
            cur = st.get(key, {})
            cur.update(kv)
            st[key] = cur
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception:
        pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _age_min(checked: Optional[str]) -> Optional[int]:
    """Возраст записи last_check в минутах; None если не парсится."""
    if not checked:
        return None
    try:
        dt = datetime.strptime(checked, "%Y-%m-%d %H:%M")
        return int((datetime.now() - dt).total_seconds() // 60)
    except Exception:
        return None


# =============================================================================
#  GITHUB API — последняя ревизия/тег (одна точка сети для всех проверок)
# =============================================================================
def _github_api_json(url: str) -> Optional[dict]:
    """GET JSON с GitHub API. None при любой ошибке (сеть/403/парсинг)."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Chimera-Project",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def fetch_latest(key: str, force: bool = False) -> Optional[str]:
    """Последняя версия цели: release → tag (без 'v'); branch → sha[:12].

    Кэшируется в state на 6 часов (идиома dnscrypt_update) — повторные
    вызовы из меню не долбят API. force=True — обновить кэш сейчас.
    Возвращает None если API недоступен (безопасный дефолт: «не знаем —
    не обновляем авто-обновлением»; вручную — force-переустановка доступна).
    """
    st = read_state().get(key, {})
    latest, checked = st.get("latest"), st.get("last_check")
    if (not force and latest and checked
            and _age_min(checked) is not None
            and _age_min(checked) * 60 < CHECK_CACHE_SEC):
        return latest

    t = UPSTREAM_TARGETS[key]
    if t["kind"] == "release":
        url = (f"https://api.github.com/repos/{t['owner']}/{t['repo']}"
               f"/releases/latest")
        data = _github_api_json(url)
        val = (data or {}).get("tag_name", "") or None
        if val and val.startswith("v"):
            val = val[1:]
    else:
        url = (f"https://api.github.com/repos/{t['owner']}/{t['repo']}"
               f"/commits/{t['branch']}")
        data = _github_api_json(url)
        sha = ((data or {}).get("sha") or "")
        val = sha[:12] or None

    if val:
        update_state(key, latest=val, last_check=_now())
    return val


# =============================================================================
#  УСТАНОВЛЕННОЕ — версия бинарника / записанная ревизия
# =============================================================================
def get_installed_version(key: str) -> Optional[str]:
    """Версия установленного бинарника (только release-цели).

    None — бинарника нет; 'unknown' — есть, но версию не отдал.
    """
    t = UPSTREAM_TARGETS[key]
    b: Path = t["binary"]
    if not b.exists():
        return None
    varg = t.get("version_arg")
    if not varg:
        return None
    try:
        r = subprocess.run([str(b), varg], capture_output=True, text=True,
                           timeout=20)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"v?(\d+\.\d+[\.\d]*)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def installed_revision(key: str) -> Optional[str]:
    """Ревизия установленной сборки (branch-цели) из state.

    Для legacy-установок (ранее) ревизии нет → None. Это осознанный
    режим: авто-обновление не начинает «пересборку вслепую», пользователь
    один раз обновляет вручную (пункт меню), после чего ревизия
    записывается и дальше всё отслеживается автоматически.
    """
    st = read_state().get(key, {})
    rev = st.get("installed_rev")
    return rev if isinstance(rev, str) and rev else None


def _build_info(key: str) -> Dict[str, Any]:
    """Информация последней сборки из packages-модуля (LAST_BUILD_INFO):
    tarball_sha256, layout, toolchain-требования. Заполняется post_install
    (layout-probe), читается здесь для state/диагностики."""
    try:
        if key == "csqtt":
            from chimera.modules import csqtt_packages
            return dict(getattr(csqtt_packages, "LAST_BUILD_INFO", {}) or {})
        if key == "wdtt":
            from chimera.modules import wdtt_packages
            return dict(getattr(wdtt_packages, "LAST_BUILD_INFO", {}) or {})
    except Exception:
        pass
    return {}


# =============================================================================
#  CHECK — есть ли обновление (единая логика для меню/агента/статус-строк)
# =============================================================================
def check_target(key: str, force: bool = False) -> Dict[str, Any]:
    """Проверяет наличие обновления для цели.

    Возвращает dict:
      key, kind, installed (версия или ревизия), latest,
      update_available (bool), reason (пояснение, почему «нет»)
    """
    t = UPSTREAM_TARGETS[key]
    latest = fetch_latest(key, force=force)
    res: Dict[str, Any] = {
        "key": key, "kind": t["kind"],
        "installed": None, "latest": latest,
        "update_available": False, "reason": "",
    }
    if not t["binary"].exists():
        res["reason"] = "не установлен"
        return res
    if not latest:
        res["reason"] = "GitHub API недоступен"
        res["installed"] = (get_installed_version(key)
                            if t["kind"] == "release" else installed_revision(key))
        return res

    if t["kind"] == "release":
        cur = get_installed_version(key)
        res["installed"] = cur
        if cur in (None, "unknown"):
            res["reason"] = "версия бинарника не определена"
        elif cur != latest:
            res["update_available"] = True
        else:
            res["reason"] = "актуален"
    else:
        cur_rev = installed_revision(key)
        res["installed"] = cur_rev
        if not cur_rev:
            res["reason"] = ("ревизия неизвестна (legacy-установка) — "
                             "обновите вручную один раз")
        elif cur_rev != latest:
            res["update_available"] = True
        else:
            res["reason"] = "актуален"
    return res

# =============================================================================
#  СЕРВИСЫ / БЭКАПЫ / ОТКАТ
# =============================================================================
def _svc_active(name: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", name],
                       capture_output=True, text=True)
    return (r.stdout or "").strip() == "active"


def _svc(name: str, action: str) -> None:
    subprocess.run(["systemctl", action, name],
                   capture_output=True, check=False)


def _backup_binary(key: str) -> Optional[Path]:
    """Бэкап текущего бинарника → /var/backups/chimera/upstream/{key}_{ts}.

    Держим последние KEEP_BACKUPS на цель. Бэкап — основа отката:
    постулат «post_install заменяет бинарник ТОЛЬКО после успешной
    сборки» уже защищает установку, но smoke-тест сервиса может провалиться
    ПОСЛЕ замены (бинарник собрался, но не заводится) — тогда откат.
    """
    t = UPSTREAM_TARGETS[key]
    b: Path = t["binary"]
    if not b.exists():
        return None
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        bak = BACKUP_DIR / f"{key}_{datetime.now():%Y%m%d%H%M%S}"
        shutil.copy2(str(b), str(bak))
        bak.chmod(0o755)
        olds = sorted(BACKUP_DIR.glob(f"{key}_*"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        for old in olds[KEEP_BACKUPS:]:
            old.unlink(missing_ok=True)
        return bak
    except Exception:
        return None


def _rollback_binary(key: str, bak: Optional[Path]) -> bool:
    """Откат бинарника из бэкапа + рестарт сервиса."""
    t = UPSTREAM_TARGETS[key]
    if not (bak and bak.exists()):
        return False
    try:
        shutil.copy2(str(bak), str(t["binary"]))
        t["binary"].chmod(0o755)
    except Exception:
        return False
    _svc(t["service"], "restart")
    time.sleep(2)
    return True


# =============================================================================
#  UPDATE — проверка → подтверждение → fetch_package → smoke → state
# =============================================================================
def update_target(key: str, force: bool = False,
                  interactive: bool = True) -> bool:
    """Обновляет цель до последней ревизии/тега через download_manager.

    Шаги:
      1. бинарник существует? (не установлено — не обновляем)
      2. check_target(force=True) — свежая проверка GitHub API
      3. нечего обновлять и не force → «актуален», True
      4. подтверждение (interactive)
      5. бэкап бинарника
      6. turnable: stop сервиса (post_install пишет поверх — ETXTBSY)
      7. fetch_package(spec) — зеркала + /root/ + post_install (сборка
         с layout-probe + атомарная замена)
      8. smoke-тест: сервис был активен → должен быть активен; иначе откат
      9. запись ревизии/версии + LAST_BUILD_INFO в state

    force=True — переустановить даже без обновления (починка после
    ручной порчи бинарника / смены layout на зеркалах).
    """
    t = UPSTREAM_TARGETS[key]
    if not t["binary"].exists():
        _warn(f"{t['title']}: не установлен — обновлять нечего")
        if interactive:
            _info("Сначала установите модуль в его собственном меню.")
        return False

    info = check_target(key, force=True)
    latest = info.get("latest")
    if not latest:
        _err(f"{t['title']}: GitHub API недоступен — ревизия latest "
             f"неизвестна, отмена")
        update_state(key, last_error=f"{_now()} api unavailable")
        return False

    if not info["update_available"] and not force:
        _ok(f"{t['title']}: актуален ({info['installed'] or '—'})")
        return True

    arrow = f"{info['installed'] or '—'} → {latest}"
    if force and not info["update_available"]:
        arrow += "  [принудительная переустановка]"
    _info(f"{t['title']}: {arrow}")

    if interactive:
        try:
            ans = input(f"{CYAN}Обновить? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("", "y", "yes", "д", "да"):
            _info("Отменено пользователем")
            return False

    bak = _backup_binary(key)
    was_active = _svc_active(t["service"])
    if t.get("stop_service_before_fetch") and was_active:
        _svc(t["service"], "stop")

    ok = False
    try:
        from chimera.modules.download_manager import fetch_package
        spec = _spec_for(key)
        kwargs: Dict[str, Any] = {}
        if key == "turnable":
            # ДИНАМИЧЕСКАЯ версия (фикс раньше _run_update обещал
            # latest, а качал pinned 0.4.1): передаём тег в
            # mirror_urls_builder → URL релиза latest.
            kwargs["version"] = latest
        ok = fetch_package(spec, progress_label=t["title"], **kwargs)
    except Exception as e:
        _err(f"download_manager недоступен: {type(e).__name__}: {e}")

    if t.get("stop_service_before_fetch") and was_active:
        _svc(t["service"], "start")
        time.sleep(2)

    if not ok:
        # post_install атомарен: при провале сборки старый бинарник не
        # трогается. Но если вдруг файл исчез (частичная замена) — откат.
        if not t["binary"].exists() and bak:
            _warn("бинарник повреждён — откат из бэкапа")
            _rollback_binary(key, bak)
        update_state(key, last_error=f"{_now()} update failed")
        _err(f"{t['title']}: обновление не удалось — прежняя версия на месте")
        if key == "csqtt":
            # сборка CSQTT — самая тяжёлая (Rust+Zig, OOM на слабых
            # VPS). Подсказываем путь без сборки: готовый бинарь с другой
            # машины → повторная УСТАНОВКА модуля подхватит его сама.
            _info("Альтернатива без сборки: соберите csqtt-server на другой "
                  "машине (та же архитектура), положите в /root/ (или "
                  "/tmp/, /opt/, /usr/local/src/) и запустите установку "
                  "модуля CSQTT заново — установщик найдёт бинарь и не "
                  "будет собирать. Подробная инструкция — в меню установки.")
        return False

    # smoke-тест: сервис был активен → должен подняться на новой версии
    if was_active and not _svc_active(t["service"]):
        _warn(f"{t['title']}: сервис не поднялся после обновления — откат")
        if _rollback_binary(key, bak) and _svc_active(t["service"]):
            _err("откат выполнен, работает прежняя версия")
        else:
            _err("ОТКАТ НЕ УДАЛСЯ — проверьте журнал сервиса:")
            _info(f"  journalctl -u {t['service']} -n 30")
        update_state(key, last_error=f"{_now()} smoke-test failed")
        return False

    _record_installed(key, latest, info)
    _ok(f"{t['title']}: обновлено → {latest}")
    return True


def _record_installed(key: str, latest: str, info: Dict[str, Any]) -> None:
    """Записывает в state установленную ревизию/версию + build-инфо.

    Тонкость для branch-целей: архив ветки GitHub раздаёт через CDN-кэш,
    который может отставать от HEAD на минутах. Если post_install
    скачал ТОТ ЖЕ tarball (совпал sha256) — ревизию НЕ поднимаем: завтра
    агент увидит «обновление доступно» снова и перекачает, когда кэш
    зеркала протухнет. Иначе зациклились бы на «обновлён, но старый».
    """
    t = UPSTREAM_TARGETS[key]
    build = _build_info(key)
    kv: Dict[str, Any] = {
        "latest": latest,
        "last_update": _now(),
        "last_error": None,
    }
    if t["kind"] == "release":
        kv["installed"] = get_installed_version(key) or latest
        kv["installed_rev"] = None
    else:
        prev = read_state().get(key, {})
        new_sha = build.get("tarball_sha256")
        prev_sha = prev.get("tarball_sha256")
        same_archive = bool(new_sha and prev_sha and new_sha == prev_sha)
        if same_archive and prev.get("installed_rev") != latest:
            # Зеркало отдало прежний архив — ревизию не поднимаем.
            kv["last_error"] = (f"{_now()} зеркало отдало прежний архив "
                                f"(sha256 совпал) — повтор позже")
        else:
            kv["installed_rev"] = latest
            kv["installed"] = latest
    if build:
        for bfield in ("tarball_sha256", "layout", "rust_required",
                       "go_required", "build_target"):
            if build.get(bfield):
                kv[bfield] = build[bfield]
    update_state(key, **kv)

# =============================================================================
# АГЕНТ АВТООБНОВЛЕНИЯ — standalone-скрипт + systemd timer (идиома)
# =============================================================================
# Агент генерируется при установке таймера: в шапку подставляется корень
# репозитория Chimera (найден по расположению этого модуля), чтобы
# /usr/local/bin/chimera-upstream-update.py мог импортировать chimera.*
# независимо от того, где стоит Химера (/opt/vless-installer, /opt/chimera...).
AGENT_PY_TEMPLATE = '''#!/usr/bin/env python3
# chimera-upstream-update.py — агент автообновления из апстримов.
# Устанавливается chimera/modules/upstream_updates.py::install_autoupdate().
# Запуск: systemd timer chimera-upstream-update.timer (04:40) или вручную.
#
# Логика: для каждой цели (turnable/csqtt/wdtt) с включённым auto и
# установленным бинарником — GitHub API: HEAD sha / тег релиза; при
# отличии от записанной ревизии — fetch_package (зеркала + /root/) →
# post_install (layout-probe сборка + атомарная замена) → smoke-тест
# сервиса → откат из бэкапа при провале. Никогда не ставит с нуля.
import sys

sys.path.insert(0, "__REPO_ROOT__")

from chimera.modules.upstream_updates import run_agent  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_agent())
'''


def install_autoupdate() -> bool:
    """Устанавливает автообновление: агент + service + timer (04:40)."""
    _info("Установка автообновления из апстримов (ежедневно 04:40)...")
    try:
        repo_root = str(Path(__file__).resolve().parents[2])
        AGENT_BIN.parent.mkdir(parents=True, exist_ok=True)
        AGENT_BIN.write_text(
            AGENT_PY_TEMPLATE.replace("__REPO_ROOT__", repo_root),
            encoding="utf-8")
        AGENT_BIN.chmod(0o700)

        AGENT_SERVICE.write_text(
            "[Unit]\n"
            "Description=Chimera Upstream Auto-Update (Turnable/CSQTT/qWDTT)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/usr/bin/python3 /usr/local/bin/chimera-upstream-update.py\n"
            "StandardOutput=append:/var/log/chimera-upstream-update.log\n"
            "StandardError=append:/var/log/chimera-upstream-update.log\n"
            # Rust-сборка CSQTT на слабом VPS занимает до 40 минут —
            # таймаут 60 минут (dnscrypt-агенту хватало 10, тут сборки).
            "TimeoutStartSec=3600\n"
            "SuccessExitStatus=0 1\n", encoding="utf-8")
        AGENT_TIMER.write_text(
            "[Unit]\n"
            "Description=Chimera Upstream Auto-Update Timer\n\n"
            "[Timer]\n"
            # 04:40 — разнесено с dnscrypt-autoupdate (04:10) и h2 (03:00),
            # чтобы ночные апдейты не накладывались друг на друга.
            "OnCalendar=*-*-* 04:40:00\n"
            "RandomizedDelaySec=1800\n"
            "Persistent=true\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n", encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "enable", AGENT_TIMER_NAME],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "start", AGENT_TIMER_NAME],
                       capture_output=True, check=False)
        _ok("Автообновление установлено и включено")
        _info(f"  Агент:  {AGENT_BIN}")
        _info(f"  Лог:    {LOG_FILE}")
        _info("  Цели включаются/выключаются в меню каждого модуля")
        return True
    except Exception as e:
        _err(f"Не удалось установить автообновление: {e}")
        return False


def remove_autoupdate() -> bool:
    """Отключает и удаляет агент + service + timer."""
    _info("Отключаю автообновление из апстримов...")
    subprocess.run(["systemctl", "stop", AGENT_TIMER_NAME],
                   capture_output=True, check=False)
    subprocess.run(["systemctl", "disable", AGENT_TIMER_NAME],
                   capture_output=True, check=False)
    for p in (AGENT_TIMER, AGENT_SERVICE, AGENT_BIN):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    subprocess.run(["systemctl", "daemon-reload"],
                   capture_output=True, check=False)
    _ok("Автообновление удалено")
    return True


def autoupdate_enabled() -> bool:
    r = subprocess.run(["systemctl", "is-enabled", AGENT_TIMER_NAME],
                       capture_output=True, text=True)
    return (r.stdout or "").strip() == "enabled"


def _agent_log(msg: str) -> None:
    """Пишет строку в лог агента (двойная запись: файл + stdout)."""
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def run_agent() -> int:
    """Точка входа агента (timer) и CLI --upstream-autoupdate.

    Не-интерактивно. Для каждой цели:
      • binary отсутствует → skip (никогда не ставим с нуля из cron);
      • auto выключен в state → skip;
      • check_target(force=True) → update_target(interactive=False).
    Возвращает exit-код: 0 — всё проверено (обновлений могло не быть),
    1 — были ошибки (для SuccessExitStatus в юните).
    """
    _agent_log("=== Проверка обновлений из апстримов (turnable/csqtt/wdtt) ===")
    had_errors = False
    for key in UPSTREAM_TARGETS:
        t = UPSTREAM_TARGETS[key]
        st = read_state().get(key, {})
        # per-target флаг auto: по умолчанию ВКЛ (пользователь явно ставит
        # таймер); выключается в меню модуля.
        if not st.get("auto", True):
            _agent_log(f"{t['title']}: авто отключено в настройках — skip")
            continue
        if not t["binary"].exists():
            _agent_log(f"{t['title']}: не установлен — skip")
            continue
        try:
            info = check_target(key, force=True)
            if info["update_available"]:
                _agent_log(f"{t['title']}: доступно обновление "
                           f"{info['installed']} → {info['latest']}, применяю...")
                ok = update_target(key, force=False, interactive=False)
                _agent_log(f"{t['title']}: "
                           + ("обновлено" if ok else "ОШИБКА обновления"))
                if not ok:
                    had_errors = True
            else:
                _agent_log(f"{t['title']}: {info['reason']}")
        except Exception as e:
            _agent_log(f"{t['title']}: ИСКЛЮЧЕНИЕ {type(e).__name__}: {e}")
            had_errors = True
    _agent_log("=== Готово ===")
    return 1 if had_errors else 0


# =============================================================================
#  СТАТУСНЫЕ СТРОКИ — для шапок меню модулей (сеть НЕ дёргается)
# =============================================================================
def get_update_status_line(key: str) -> str:
    """Компактный статус для шапки меню модуля: из state-кэша (6 ч).

    Формат: «0.4.1 → 0.4.2 доступно» / «rev a1b2c3d · актуален» /
    «ревизия неизвестна (legacy)» + [авто ✓/✗].
    """
    t = UPSTREAM_TARGETS[key]
    st = read_state().get(key, {})
    installed = st.get("installed")
    latest = st.get("latest")
    if t["kind"] == "release":
        if installed and installed.startswith("v"):
            installed = installed[1:]
    parts = []
    if not t["binary"].exists():
        parts.append(f"{DIM}не установлен{NC}")
    elif not installed:
        parts.append(f"{DIM}ревизия неизвестна (legacy){NC}")
    elif latest and installed != latest:
        parts.append(f"{installed} {YELLOW}→ {latest} доступно{NC}")
    else:
        parts.append(f"{CYAN}{installed}{NC} {GREEN}(актуален){NC}")
    err = st.get("last_error")
    if err:
        short = str(err).split(" ", 1)[-1][:40]
        parts.append(f"{DIM}[последняя ошибка: {short}]{NC}")
    auto = "авто ✓" if autoupdate_enabled() else "авто ✗"
    if not st.get("auto", True):
        auto = f"{DIM}авто off{NC}"
    parts.append(f"{DIM}[{auto}]{NC}")
    return "  ".join(str(p) for p in parts)


def _fmt_target_row(key: str) -> str:
    """Строка таблицы для единого меню (одна цель)."""
    t = UPSTREAM_TARGETS[key]
    info = check_target(key, force=False)   # кэш 6 ч — быстро
    if info["update_available"]:
        status = f"{GREEN}→ {info['latest']}{NC} {YELLOW}доступно{NC}"
    elif info["reason"] == "не установлен":
        status = f"{DIM}не установлен{NC}"
    elif info["reason"] == "GitHub API недоступен":
        status = f"{YELLOW}API недоступен{NC}"
    elif info["reason"].startswith("ревизия неизвестна"):
        status = f"{YELLOW}legacy-установка{NC}"
    else:
        status = f"{GREEN}актуален{NC}"
    st = read_state().get(key, {})
    auto = st.get("auto", True)
    auto_str = (f"{GREEN}вкл{NC}" if auto else f"{DIM}выкл{NC}")
    lu = st.get("last_update", "—")
    return (f"  {t['title']}  {DIM}(github: {t['owner']}/{t['repo']}"
            f"{'/' + t['branch'] if t['branch'] else '/releases'}){NC}\n"
            f"    Установлено: {CYAN}{info['installed'] or '—'}{NC}"
            f"  →  Последняя: {status}\n"
            f"    Авто: {auto_str}  │  Обновлён: {DIM}{lu}{NC}")

# =============================================================================
#  МЕНЮ — единое (все три цели) или сфокусированное (из меню одного модуля)
# =============================================================================
def _sep(char: str = "─", width: int = 66) -> str:
    return f"{DIM}{char * width}{NC}"


def do_upstream_update_menu(focus: Optional[str] = None) -> None:
    """Интерактивное меню обновлений из апстримов.

    focus=None      — все три цели (Turnable/CSQTT/qWDTT), пакетные действия.
    focus="csqtt"   — одна цель: проверка/обновление/force/авто.
                     Вызывается из меню соответствующего модуля.

    Идиома (dnscrypt DU): статусы читаются из state-кэша → открытие
    меню не дёргает сеть повторно (проверка = раз в 6 ч или по запросу).
    """
    if focus is not None and focus not in UPSTREAM_TARGETS:
        _err(f"Неизвестная цель: {focus}")
        return
    keys = [focus] if focus else list(UPSTREAM_TARGETS.keys())

    while True:
        os.system("clear")
        print()
        title = ("ОБНОВЛЕНИЕ  •  " + UPSTREAM_TARGETS[focus]["title"]) \
            if focus else "ОБНОВЛЕНИЕ ИЗ АПСТРИМА  •  Turnable / CSQTT / qWDTT"
        print(f"{BOLD}  ⬆️  {title}{NC}")
        print(f"  {_sep()}")

        for k in keys:
            print(_fmt_target_row(k))
            print(f"  {_sep('·')}")

        timer_str = (f"{GREEN}установлен (04:40){NC}" if autoupdate_enabled()
                     else f"{RED}не установлен{NC}")
        print(f"  Таймер автообновления: {timer_str}")
        print(f"  {_sep()}")

        if focus:
            _item("1", "Проверить обновление сейчас")
            _item("2", "Обновить сейчас")
            _item("3", "Принудительно переустановить (force)")
            _item("4", "Авто-обновление этой цели: вкл/выкл")
            _item("T", "Установить таймер автообновления (04:40)")
            _item("R", "Удалить таймер автообновления")
        else:
            for i, k in enumerate(keys, 1):
                _item(str(i), f"{UPSTREAM_TARGETS[k]['title']} — подменю")
            _item("A", "Обновить все сейчас")
            _item("C", "Проверить все сейчас (обновить кэш)")
            _item("T", "Установить таймер автообновления (04:40)")
            _item("R", "Удалить таймер автообновления")
        _item("Q", "← Назад")
        print()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if focus:
            if ch == "1":
                info = check_target(focus, force=True)
                if info["update_available"]:
                    _ok(f"Доступно: {info['installed']} → {info['latest']}")
                else:
                    _info(f"{info['reason'] or 'актуален'}")
                _pause()
            elif ch == "2":
                update_target(focus, force=False, interactive=True)
                _pause()
            elif ch == "3":
                update_target(focus, force=True, interactive=True)
                _pause()
            elif ch == "4":
                st = read_state().get(focus, {})
                cur = st.get("auto", True)
                update_state(focus, auto=not cur)
                _ok(f"Авто-обновление {UPSTREAM_TARGETS[focus]['title']}: "
                    f"{'выключено' if cur else 'включено'}")
                _pause()
            elif ch == "t":
                install_autoupdate()
                _pause()
            elif ch == "r":
                remove_autoupdate()
                _pause()
            elif ch == "q":
                break
        else:
            num_map = {str(i): k for i, k in enumerate(keys, 1)}
            if ch in num_map:
                do_upstream_update_menu(focus=num_map[ch])
            elif ch == "a":
                for k in keys:
                    update_target(k, force=False, interactive=True)
                _pause()
            elif ch == "c":
                for k in keys:
                    info = check_target(k, force=True)
                    mark = (f"{GREEN}→ {info['latest']}{NC}"
                            if info["update_available"]
                            else f"{DIM}{info['reason'] or 'актуален'}{NC}")
                    print(f"  {UPSTREAM_TARGETS[k]['title']}: {mark}")
                _pause()
            elif ch == "t":
                install_autoupdate()
                _pause()
            elif ch == "r":
                remove_autoupdate()
                _pause()
            elif ch == "q":
                break


def _item(key: str, label: str) -> None:
    print(f"  {DIM}[{NC}{CYAN}{key}{NC}{DIM}]{NC}  {label}")


def _pause() -> None:
    try:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        sys.exit(1)
    do_upstream_update_menu()
