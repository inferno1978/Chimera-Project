"""
chimera/modules/dpi_bypass.py
───────────────────────────────────────────────────────────────────────────────
Централизованный модуль DPI Bypass (b4) для ЛЮБЫХ заблокированных ресурсов.

Отличие от youtube_b4.py:
  • youtube_b4.py — специализированный для YouTube (3 пресета, 22 домена).
  • dpi_bypass.py — универсальный: пользователь импортирует свои сеты
    из b4 Web UI / Discovery / вручную.

АрХИТЕКТУРА:
  • Делит binary/config/systemd с youtube_b4.py (те же пути).
  • Если b4 уже установлен (через youtube_b4 или этот модуль) —
    показывает «Установлен, активен», не предлагает переустановку.
  • Управляет set'ами в /etc/b4/config.json.
  • Автообновление binary с GitHub releases.
  • Полная интеграция с port_registry.

TUI:
  Главное меню → D (DPI Bypass) → меню управления.

───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [dpi_bypass] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg: str)      -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}   {msg}");   _log("ERR", msg)

# ── box_renderer ────────────────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_back, _box_info, _box_warn, _box_ok, _box_link, _box_desc,
)

# ── Делегирование ──────────────────────────────────────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

# ══════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ (shared с youtube_b4.py)
# ══════════════════════════════════════════════════════════════════════════
B4_BINARY_PATH = Path("/usr/local/bin/b4")
B4_CONFIG_FILE = Path("/etc/b4/config.json")
B4_CONFIG_DIR  = Path("/etc/b4")
B4_LOG_DIR     = Path("/var/log/b4")
B4_UNIT_PATH   = Path("/etc/systemd/system/b4.service")
B4_QUEUE_NUM   = 537
B4_MARK         = 32768
B4_WEB_PORT     = 9700
B4_IPT_COMMENT  = "chimera-youtube-b4"

_STATE_FILE = Path("/var/lib/xray-installer/dpi_bypass_state.json")


# ══════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {"installed": False, "version": "", "enabled": False}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {"installed": False, "version": "", "enabled": False}

def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _STATE_FILE.chmod(0o600)


# ══════════════════════════════════════════════════════════════════════════
#  ДЕТЕКТ УСТАНОВКИ (shared с youtube_b4.py)
# ══════════════════════════════════════════════════════════════════════════
def _detect_installed() -> bool:
    """Проверяет установлен ли b4 (binary + systemd-unit)."""
    return B4_BINARY_PATH.exists() and B4_UNIT_PATH.exists()


def _detect_service_active() -> bool:
    """Проверяет запущен ли сервис b4."""
    r = subprocess.run(["systemctl", "is-active", "b4"],
                       capture_output=True, text=True, check=False)
    return (r.returncode == 0 and r.stdout.strip() == "active")


def _detect_version() -> str:
    """Получает версию установленного b4 binary."""
    if not B4_BINARY_PATH.exists():
        return ""
    try:
        r = subprocess.run([str(B4_BINARY_PATH), "--version"],
                           capture_output=True, text=True, check=False, timeout=5)
        m = re.search(r'B4 version:\s*(\S+)', r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _detect_latest_version() -> str:
    """Проверяет последнюю версию b4 на GitHub."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/DanielLavrushin/b4/releases/latest",
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name", "")
        if tag.startswith("v"):
            tag = tag[1:]
        return tag
    except Exception as e:
        _log("WARN", f"check_latest_version: {e}")
        return ""


def _detect_sets() -> list:
    """Читает текущие set'ы из config.json b4."""
    if not B4_CONFIG_FILE.exists():
        return []
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        sets = cfg.get("sets", [])
        result = []
        for s in sets:
            result.append({
                "id":       s.get("id", "?"),
                "name":     s.get("name", "?"),
                "enabled":  s.get("enabled", True),
                "domains":  s.get("targets", {}).get("sni_domains", []),
                "sni_type": s.get("faking", {}).get("sni_type", ""),
            })
        return result
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════
#  АВТООБНОВЛЕНИЕ B4 BINARY
# ══════════════════════════════════════════════════════════════════════════
def _detect_arch() -> str:
    r = subprocess.run(["uname", "-m"], capture_output=True, text=True)
    m = r.stdout.strip()
    arch_map = {"x86_64": "amd64", "amd64": "amd64",
                "aarch64": "arm64", "arm64": "arm64",
                "armv7l": "armv7", "armv6l": "armv6",
                "i386": "386", "i686": "386"}
    return arch_map.get(m, "")


def auto_update() -> dict:
    """Проверяет и обновляет b4 binary до последней версии.

    Последовательность:
      1. Проверить последнюю версию на GitHub.
      2. Сравнить с установленной.
      3. Если есть обновление:
         a. Скачать новый binary.
         b. Проверить SHA256 (если .sha256 файл доступен).
         c. Остановить сервис.
         d. Заменить binary.
         e. Запустить сервис.
         f. Проверить что сервис active.
      4. КОНФИГ И SET'Ы НЕ ТРОГАЮТСЯ.

    Returns: {"updated": bool, "old_version": str, "new_version": str,
              "message": str}
    """
    if not _detect_installed():
        return {"updated": False, "message": "b4 не установлен"}

    old_version = _detect_version()
    latest = _detect_latest_version()
    if not latest:
        return {"updated": False, "old_version": old_version,
                "message": "Не удалось проверить последнюю версию"}

    if old_version == latest:
        return {"updated": False, "old_version": old_version,
                "new_version": latest, "message": f"Уже актуальная версия {old_version}"}

    _info(f"Обновление: {old_version} → {latest}")

    # 1. Скачать.
    arch = _detect_arch()
    if not arch:
        return {"updated": False, "message": "Неподдерживаемая архитектура"}
    url = f"https://github.com/DanielLavrushin/b4/releases/download/v{latest}/b4-linux-{arch}.tar.gz"
    tmp_tar = Path("/tmp/b4-update.tar.gz")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            tmp_tar.write_bytes(resp.read())
    except Exception as e:
        return {"updated": False, "message": f"Скачивание не удалось: {e}"}

    # 2. SHA256 проверка (если есть).
    sha_url = url + ".sha256"
    try:
        req = urllib.request.Request(sha_url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            expected_sha = resp.read().decode().strip().split()[0]
        import hashlib
        actual_sha = hashlib.sha256(tmp_tar.read_bytes()).hexdigest()
        if expected_sha and actual_sha != expected_sha:
            tmp_tar.unlink(missing_ok=True)
            return {"updated": False, "message": f"SHA256 mismatch: {actual_sha[:16]} ≠ {expected_sha[:16]}"}
        _ok(f"SHA256 проверен: {actual_sha[:16]}...")
    except Exception:
        _warn("SHA256 файл недоступен — пропуск проверки")
        pass  # не критично

    # 3. Распаковать.
    extract_dir = Path("/tmp/b4-update-extract")
    shutil.rmtree(extract_dir, ignore_errors=True)
    try:
        with tarfile.open(tmp_tar, "r:gz") as tf:
            tf.extractall(path=extract_dir)
    except Exception as e:
        tmp_tar.unlink(missing_ok=True)
        return {"updated": False, "message": f"Распаковка не удалось: {e}"}

    new_binary = extract_dir / "b4"
    if not new_binary.exists():
        tmp_tar.unlink(missing_ok=True)
        return {"updated": False, "message": "В архиве нет b4 binary"}

    # 4. Остановить сервис.
    _info("Останавливаю b4...")
    subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)

    # 5. Backup старого binary.
    backup_path = B4_BINARY_PATH.with_suffix(".bak")
    try:
        shutil.copy2(B4_BINARY_PATH, backup_path)
    except Exception:
        pass

    # 6. Заменить binary.
    try:
        shutil.copy2(new_binary, B4_BINARY_PATH)
        B4_BINARY_PATH.chmod(0o755)
    except Exception as e:
        # Восстановить из backup.
        if backup_path.exists():
            shutil.copy2(backup_path, B4_BINARY_PATH)
            B4_BINARY_PATH.chmod(0o755)
        return {"updated": False, "message": f"Замена binary не удалась: {e}"}

    # 7. Запустить сервис.
    _info("Запускаю b4...")
    subprocess.run(["systemctl", "start", "b4"], capture_output=True, check=False)
    time.sleep(2)

    # 8. Проверить что сервис active.
    if not _detect_service_active():
        # Восстановить из backup.
        _err("Новая версия не запустилась — восстанавливаю предыдущую...")
        subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)
        if backup_path.exists():
            shutil.copy2(backup_path, B4_BINARY_PATH)
            B4_BINARY_PATH.chmod(0o755)
        subprocess.run(["systemctl", "start", "b4"], capture_output=True, check=False)
        time.sleep(2)
        return {"updated": False, "old_version": old_version,
                "message": "Новая версия не запустилась — восстановлена предыдущая"}

    # 9. Обновить state.
    new_version = _detect_version()
    state = _load_state()
    state["version"] = new_version
    _save_state(state)

    # 10. Cleanup.
    backup_path.unlink(missing_ok=True)
    shutil.rmtree(extract_dir, ignore_errors=True)
    tmp_tar.unlink(missing_ok=True)

    _ok(f"b4 обновлён: {old_version} → {new_version}")
    _info("Конфиг и set'ы сохранены без изменений.")
    return {"updated": True, "old_version": old_version,
            "new_version": new_version,
            "message": f"Обновлено: {old_version} → {new_version}"}


# ══════════════════════════════════════════════════════════════════════════
#  ИМПОРТ КАСТОМНЫХ СЕТОВ
# ══════════════════════════════════════════════════════════════════════════
def import_custom_set(json_str: str) -> bool:
    """Импортирует кастомный b4 set из JSON-строки.

    Принимает JSON в формате b4 (один объект сета ИЛИ {"sets": [...]}).
    ДОБАВЛЯЕТ set к существующим (не заменяет!).
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        _err(f"Невалидный JSON: {e}")
        return False

    # Если {"sets": [...]} — берём все set'ы.
    if isinstance(data, dict) and "sets" in data:
        new_sets = data["sets"]
    elif isinstance(data, dict):
        new_sets = [data]
    else:
        _err("Ожидается JSON-объект с set")
        return False

    if not new_sets:
        _err("Пустой массив sets")
        return False

    # Обрабатываем каждый set.
    for s in new_sets:
        if not s.get("id"):
            s["id"] = f"custom-{int(time.time())}"
        targets = s.get("targets", {})
        if "geosite_categories" in targets:
            _warn("Убран geosite_categories (нет geosite_path).")
            targets.pop("geosite_categories", None)
        if not targets.get("sni_domains"):
            _err(f"Set '{s.get('name','?')}' не имеет targets.sni_domains — пропуск")
            continue

    # Читаем текущий конфиг.
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
    except Exception:
        cfg = {"sets": []}

    existing_sets = cfg.get("sets", [])
    # Удаляем set'ы с тем же id (перезаписываем).
    new_ids = {s.get("id") for s in new_sets}
    existing_sets = [s for s in existing_sets if s.get("id") not in new_ids]
    existing_sets.extend(new_sets)
    cfg["sets"] = existing_sets

    # Сохраняем.
    B4_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    # Перезапускаем.
    subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
    _ok(f"Импортировано {len(new_sets)} set'ов, b4 перезапущен")
    _info(f"Всего set'ов в конфиге: {len(existing_sets)}")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ SET'АМИ (CRUD)
# ══════════════════════════════════════════════════════════════════════════
def list_sets() -> list:
    """Список всех set'ов в конфиге."""
    return _detect_sets()


def remove_set(set_id: str) -> bool:
    """Удаляет set по id."""
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        before = len(cfg.get("sets", []))
        cfg["sets"] = [s for s in cfg.get("sets", []) if s.get("id") != set_id]
        after = len(cfg["sets"])
        if before == after:
            _warn(f"Set '{set_id}' не найден")
            return False
        B4_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
        _ok(f"Set '{set_id}' удалён, b4 перезапущен")
        return True
    except Exception as e:
        _err(f"Ошибка удаления: {e}")
        return False


def toggle_set(set_id: str) -> bool:
    """Включает/выключает set по id."""
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        for s in cfg.get("sets", []):
            if s.get("id") == set_id:
                s["enabled"] = not s.get("enabled", True)
                B4_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
                state = "включён" if s["enabled"] else "выключен"
                _ok(f"Set '{set_id}' {state}")
                return True
        _warn(f"Set '{set_id}' не найден")
        return False
    except Exception as e:
        _err(f"Ошибка переключения: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════
def health_check() -> dict:
    """Проверяет доступность сайтов из всех set'ов."""
    sets = _detect_sets()
    results = {"sets": [], "all_ok": True}
    for s in sets:
        domains = s.get("domains", [])
        if not domains:
            continue
        # Проверяем первый домен из set'a.
        test_domain = domains[0]
        try:
            r = subprocess.run(
                ["curl", "-sI", "--max-time", "10", "-o", "/dev/null",
                 "-w", "%{http_code} %{time_total}",
                 f"https://{test_domain}/"],
                capture_output=True, text=True, check=False, timeout=15,
            )
            http_code = r.stdout.strip().split()[0] if r.stdout.strip() else ""
            ok = (r.returncode == 0 and http_code and http_code[0] in ("2", "3", "4"))
        except Exception:
            ok = False
            http_code = "TIMEOUT"
        results["sets"].append({
            "name": s.get("name", "?"),
            "id": s.get("id", "?"),
            "test_domain": test_domain,
            "ok": ok,
            "code": http_code,
        })
        if not ok:
            results["all_ok"] = False
    return results


# ══════════════════════════════════════════════════════════════════════════
#  STATUS / INFO
# ══════════════════════════════════════════════════════════════════════════
def status() -> dict:
    """Полный статус b4."""
    installed = _detect_installed()
    if not installed:
        return {"installed": False, "service_active": False, "version": "",
                "latest_version": "", "update_available": False, "sets": []}
    service_active = _detect_service_active()
    version = _detect_version()
    latest = _detect_latest_version()
    update_available = bool(latest and version and latest != version)
    sets = _detect_sets()
    return {
        "installed": True,
        "service_active": service_active,
        "version": version,
        "latest_version": latest,
        "update_available": update_available,
        "sets": sets,
        "sets_count": len(sets),
        "config_path": str(B4_CONFIG_FILE),
        "binary_path": str(B4_BINARY_PATH),
        "queue_num": B4_QUEUE_NUM,
    }


# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════
def do_dpi_bypass_menu() -> None:
    """TUI-меню централизованного DPI Bypass."""
    while True:
        os.system("clear")
        s = status()
        _box_top(f"🛡  DPI BYPASS (B4) — ЦЕНТРАЛИЗОВАННЫЙ")
        _box_row()

        if not s["installed"]:
            _box_warn("b4 не установлен.")
            _box_row(f"  {DIM}b4 — DPI bypass демон для ЛЮБЫХ заблокированных ресурсов.{NC}")
            _box_row(f"  {DIM}Перехватывает исходящий TCP/UDP трафик и применяет{NC}")
            _box_row(f"  {DIM}fake SNI + фрагментацию для обхода ТСПУ.{NC}")
            _box_row()
            _box_row(f"  {DIM}Установите b4 через меню YouTube (Y → B),{NC}")
            _box_row(f"  {DIM}или вручную: python3 -m chimera.modules.youtube_b4 install{NC}")
            _box_row()
            _box_back()
            _box_bottom()
        else:
            # Статус.
            svc_col = GREEN if s["service_active"] else RED
            svc_str = "active" if s["service_active"] else "stopped"
            ver_str = s.get("version", "?")
            latest_str = s.get("latest_version", "")
            update_str = ""
            if s.get("update_available"):
                update_str = f"  {YELLOW}⚠ Доступно обновление: {latest_str}{NC}"
            elif latest_str and ver_str == latest_str:
                update_str = f"  {GREEN}✓ Актуальная версия{NC}"
            _box_row(f"  Статус:       {svc_col}{svc_str}{NC}")
            _box_row(f"  Версия:       {CYAN}{ver_str}{NC}{update_str}")
            _box_row(f"  Set'ов:       {CYAN}{s.get('sets_count', 0)}{NC}")
            _box_row(f"  Queue:        {CYAN}NFQUEUE {s.get('queue_num')}{NC}")
            _box_row(f"  Config:       {DIM}{s.get('config_path')}{NC}")
            _box_row()
            # Список set'ов.
            sets = s.get("sets", [])
            if sets:
                _box_row(f"  {BOLD}Активные set'ы:{NC}")
                _box_row()
                for st in sets:
                    en = GREEN if st.get("enabled") else DIM
                    nm = st.get("name", st.get("id", "?"))
                    dc = len(st.get("domains", []))
                    _box_row(f"    {en}●{NC} {nm}  {DIM}({dc} доменов){NC}")
                _box_row()
            else:
                _box_row(f"  {DIM}Set'ов нет. Импортируйте через пункт 2.{NC}")
                _box_row()
            _box_sep()
            if s["service_active"]:
                _box_item("1", "🛑 Остановить b4")
            else:
                _box_item("1", "🚀 Запустить b4")
            _box_item("2", "📥 Импортировать кастомный сет (JSON)")
            _box_item("3", "📋 Список set'ов (включить/выключить/удалить)")
            _box_item("4", "🔄 Проверить обновление b4")
            _box_item("5", "🏥 Health check (работают ли сайты?)")
            _box_item("6", "📋 Логи b4 (последние 30 строк)")
            _box_row()
            _box_back()
            _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return

        if ch in ("q", "0", ""):
            return

        if s["installed"]:
            if ch == "1":
                # Запуск/остановка.
                if s["service_active"]:
                    subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)
                    _ok("b4 остановлен")
                else:
                    subprocess.run(["systemctl", "start", "b4"], capture_output=True, check=False)
                    _ok("b4 запущен")
                input(f"\n{BOLD}Enter…{NC}")

            elif ch == "2":
                # Импорт кастомного сета.
                print()
                _box_top("📥  ИМПОРТ КАСТОМНОГО СЕТА")
                _box_row()
                _box_row(f"  {DIM}Вставьте JSON сета (из b4 Web UI / Discovery).{NC}")
                _box_row(f"  {DIM}Формат: {{\"name\":\"...\",\"targets\":{{\"sni_domains\":[...]}},...}}{NC}")
                _box_row(f"  {DIM}Или: {{\"sets\":[...]}} — импортируются все.{NC}")
                _box_row(f"  {DIM}Set ДОБАВЛЯЕТСЯ к существующим (не заменяет).{NC}")
                _box_row()
                _box_row(f"  {DIM}Двойной Enter — конец ввода. Ctrl+C — отмена.{NC}")
                _box_bottom()
                lines = []
                try:
                    while True:
                        line = input()
                        if not line.strip():
                            break
                        lines.append(line)
                except (KeyboardInterrupt, EOFError):
                    print()
                    _warn("Отмена.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                json_str = "\n".join(lines)
                if json_str.strip():
                    import_custom_set(json_str)
                input(f"\n{BOLD}Enter…{NC}")

            elif ch == "3":
                # Управление set'ами.
                sets = list_sets()
                if not sets:
                    _warn("Set'ов нет.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                print()
                _box_top("📋  SET'Ы B4")
                _box_row()
                for i, st in enumerate(sets, 1):
                    en = GREEN if st.get("enabled") else DIM
                    nm = st.get("name", st.get("id", "?"))
                    dc = len(st.get("domains", []))
                    _box_row(f"  {DIM}{i}.{NC} {en}●{NC} {nm}  {DIM}({dc} доменов, id={st.get('id','?')}){NC}")
                _box_row()
                _box_item("N", "Переключить on/off (введите номер)")
                _box_item("D", "Удалить (введите номер)")
                _box_row()
                _box_back()
                _box_bottom()
                try:
                    sub_ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    continue
                if sub_ch == "n":
                    try:
                        idx = int(input("Номер: ")) - 1
                        toggle_set(sets[idx]["id"])
                    except (ValueError, IndexError):
                        _warn("Неверный номер.")
                elif sub_ch == "d":
                    try:
                        idx = int(input("Номер: ")) - 1
                        sid = sets[idx]["id"]
                        confirm = input(f"  {RED}Удалить '{sid}'? (y/N):{NC} ").strip().lower()
                        if confirm == "y":
                            remove_set(sid)
                    except (ValueError, IndexError):
                        _warn("Неверный номер.")
                input(f"\n{BOLD}Enter…{NC}")

            elif ch == "4":
                # Проверка обновления.
                _info("Проверяю обновления...")
                result = auto_update()
                if result.get("updated"):
                    _ok(result["message"])
                else:
                    _info(result["message"])
                input(f"\n{BOLD}Enter…{NC}")

            elif ch == "5":
                # Health check.
                print()
                _info("Проверяю доступность сайтов из set'ов...")
                result = health_check()
                for st in result.get("sets", []):
                    col = GREEN if st["ok"] else RED
                    status_str = f"{col}{'✓ OK' if st['ok'] else '✗ FAIL'}{NC}"
                    print(f"  {st['name']:<25} {status_str}  {DIM}{st.get('code','')}{NC}")
                if result["all_ok"]:
                    _ok("Все сайты доступны!")
                else:
                    _warn("Часть сайтов недоступна. Возможно, нужно переключить preset или обновить set.")
                input(f"\n{BOLD}Enter…{NC}")

            elif ch == "6":
                # Логи.
                os.system("clear")
                _box_top("📋  ЛОГИ B4 (ПОСЛЕДНИЕ 30 СТРОК)")
                _box_row()
                try:
                    r = subprocess.run(
                        ["journalctl", "-u", "b4", "-n", "30", "--no-pager", "-o", "cat"],
                        capture_output=True, text=True, check=False, timeout=5,
                    )
                    raw = r.stdout or "(пусто)"
                except Exception as e:
                    raw = f"Ошибка: {e}"
                # Усечение строк по ширине рамки.
                from chimera.modules.box_renderer import _get_box_width as _gw
                _w = _gw() - 2
                for line in raw.splitlines():
                    _line = line if len(line) <= _w else line[:_w-3] + "..."
                    print(f"  {DIM}{_line}{NC}")
                _box_row()
                _box_row(f"  {DIM}Полные логи:{NC}")
                _box_row(f"    {CYAN}journalctl -u b4 -f{NC}  {DIM}(live режим){NC}")
                _box_row(f"    {CYAN}journalctl -u b4 -n 100 --no-pager{NC}  {DIM}(последние 100){NC}")
                _box_row(f"  {DIM}Файл логов:{NC} /var/log/b4/")
                _box_bottom()
                input(f"\n{BOLD}Enter…{NC}")


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":  # pragma: no cover
    import sys
    if len(sys.argv) < 2:
        do_dpi_bypass_menu()
    else:
        import argparse
        p = argparse.ArgumentParser(description="DPI Bypass (b4) — централизованный")
        p.add_argument("cmd", choices=["status", "update", "health", "sets"])
        args = p.parse_args()
        if args.cmd == "status":
            print(json.dumps(status(), indent=2))
        elif args.cmd == "update":
            print(json.dumps(auto_update(), indent=2))
        elif args.cmd == "health":
            print(json.dumps(health_check(), indent=2))
        elif args.cmd == "sets":
            print(json.dumps(list_sets(), indent=2))
