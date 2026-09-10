"""
chimera/modules/xray_install.py
───────────────────────────────────────────────────────────────────────────────
Установка / обновление / geo-файлы / конфиг Xray-core (Tier-4 рефакторинг).

27 функций, вынесенных из _core.py:

Установка Xray-core:
  • _verify_sha256(file_path, checksums_url, file_name)
  • _xray_print_manual_download_hint(zip_name, tag, xray_arch)
  • _xray_try_local_zip(zip_name, xray_arch, chk_url, latest_tag)
  • install_xray()                                       — мутирует XRAY_BIN, STAGE_XRAY_DONE
  • _parse_x25519_keys(output) / _parse_x25519_field(pattern, output)
  • generate_reality_keys()                              — мутирует PARAM_PRIVATE_KEY/PUBLIC_KEY
  • _detect_xhttp_mode_support()                         — мутирует XHTTP_MODE_SUPPORTED
  • generate_xray_config()                               — мутирует DNSCRYPT_LISTEN_PORT
  • generate_xray_config_xhttp()                         — мутирует DNSCRYPT_LISTEN_PORT
  • create_xray_service()

Обновление / geo / rollback:
  • _xray_get_release_info(prerelease)
  • _xray_version_norm(ver) / _xray_current_version()
  • _xray_geo_is_runetfreedom()
  • _geo_print_manual_download_hint()
  • _xray_update_geo_runetfreedom()
  • _xray_do_upgrade(tag, is_prerelease)
  • _xray_restart_all_services()
  • _nginx_restart_if_reality()
  • _xray_find_config()
  • _xray_config_rollback(backup_cfg, cfg)
  • _xray_safe_apply_config(cfg, *, service_restart)
  • _xray_rollback(backup_path)
  • do_xray_update_interactive()
  • setup_xray_autoupdate() / _install_autoupdate_service()

Точки входа из _core.py:
    from chimera.modules.xray_install import (
        _verify_sha256, _xray_print_manual_download_hint, _xray_try_local_zip,
        install_xray, _parse_x25519_keys, _parse_x25519_field,
        generate_reality_keys, _detect_xhttp_mode_support,
        generate_xray_config, generate_xray_config_xhttp, create_xray_service,
        _xray_get_release_info, _xray_version_norm, _xray_current_version,
        _xray_geo_is_runetfreedom, _geo_print_manual_download_hint,
        _xray_update_geo_runetfreedom, _xray_do_upgrade, _xray_restart_all_services,
        _nginx_restart_if_reality, _xray_find_config, _xray_config_rollback,
        _xray_safe_apply_config, _xray_rollback, do_xray_update_interactive,
        setup_xray_autoupdate, _install_autoupdate_service,
    )

Глобалы ядра мутируются через ``setattr(core, "X", value)`` (или
``core.X = value``) — это preserves ту же семантику, что и ``global X;
X = value``, поскольку ``_core`` — это сам модуль ядра.

Доступ к helpers ядра (``_run``, ``info``/``warn``/``success``/``dim``/``die``,
ANSI-цвета, ``command_exists``, ``_set_config_owner``, ``_box_*``,
``log_to_file``, ``PROGRESS``, ``_xray_log_block``, ``_apply_stats_to_config``,
``_assert_reality_dest_sane``, ``_build_sockopt``, ``_build_xhttp_settings``,
``_build_tls_settings_xhttp``, ``build_split_tunnel_routing_rules``) —
через importlib (lazy binding), как и в других извлечённых модулях
(standalone_screens.py, system_deps.py, reconfigure.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from chimera.modules.geo_mirrors import (
    get_geosite_urls, get_geoip_urls, get_all_mirrors,
    MANUAL_UPLOAD_PATHS, XRAY_LOOKUP_DIRS, MIN_SIZES,
    GEO_MIRRORS_COUNT, recommended_manual_path,
)
from chimera.modules.xray_mirrors import (
    get_xray_zip_mirrors, get_xray_checksums_mirrors,
    XRAY_ZIP_MIRRORS_COUNT, XRAY_CHK_MIRRORS_COUNT,
)
from chimera.modules.geo_packages import GEOSITE_SPEC, GEOIP_SPEC
from chimera.modules.agh_probe import agh_dns_available


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ШАГ 4: УСТАНОВКА XRAY + SHA256
# =============================================================================
def _verify_sha256(file_path: Path, checksums_url: str, file_name: str) -> bool:
    core = _core_module()
    command_exists = core.command_exists
    warn     = core.warn
    _run     = core._run
    success  = core.success
    RED, NC  = core.RED, core.NC

    if not command_exists("sha256sum"):
        warn("sha256sum не найден — пропускаем верификацию")
        return True
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        r = _run(["curl", "-fsSL", "--connect-timeout", "10",
                  checksums_url, "-o", str(tmp_path)],
                 check=False, quiet=True)
        if r.returncode != 0 or tmp_path.stat().st_size == 0:
            warn("Не удалось загрузить checksums.txt — верификация пропущена")
            return True

        content = tmp_path.read_text()
        m = re.search(rf'^([0-9a-f]{{64}})\s+\*?{re.escape(file_name)}$',
                      content, re.MULTILINE)
        if not m:
            warn(f"Хэш для '{file_name}' не найден — верификация пропущена")
            return True

        expected = m.group(1)
        r2 = _run(["sha256sum", str(file_path)], capture=True, check=False)
        actual = r2.stdout.split()[0]

        if actual == expected:
            success(f"SHA256 OK: {actual[:16]}...")
            return True
        else:
            print(f"{RED}[ERROR]{NC} SHA256 не совпал! Ожидается: {expected}",
                  file=sys.stderr)
            print(f"{RED}[ERROR]{NC} Получено: {actual}", file=sys.stderr)
            return False
    finally:
        tmp_path.unlink(missing_ok=True)


def _xray_print_manual_download_hint(zip_name: str, tag: str, xray_arch: str) -> None:
    """
    Выводит подробную инструкцию для ручного скачивания Xray
    и ожидаемые пути размещения файлов на сервере.

    После Wave 4 миграции: зеркала берутся из единого реестра xray_mirrors.py
    (10 URL вместо 7 inline-копий ранее). Это гарантирует что пользователь
    видит АКТУАЛЬНЫЙ список зеркал, синхронизированный с fetch_package().
    """
    core = _core_module()
    YELLOW, NC = core.YELLOW, core.NC
    BOLD, WHITE = core.BOLD, core.WHITE
    CYAN, GREEN = core.CYAN, core.GREEN
    DIM = core.DIM

    # Зеркала из единого реестра (10 URL через build_mirror_urls)
    XRAY_MANUAL_MIRRORS = get_xray_zip_mirrors(tag=tag, arch=xray_arch)
    XRAY_CHECKSUMS_MIRRORS = get_xray_checksums_mirrors(tag=tag, arch=xray_arch)
    sep = f"{YELLOW}{'─'*64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}⚠  Автоматическая загрузка Xray не удалась.{NC}")
    print(f"{BOLD}{WHITE}   Скачайте файл вручную и разместите его на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}📦  Нужный файл:{NC} {BOLD}{zip_name}{NC}  (версия: {tag})")
    print()
    print(f"{GREEN}🔗  Зеркала для скачивания ({len(XRAY_MANUAL_MIRRORS)}):{NC}")
    for i, url in enumerate(XRAY_MANUAL_MIRRORS, 1):
        print(f"    {DIM}{i}){NC} {url}")
    print()
    print(f"{GREEN}🔗  Контрольные суммы (checksums.txt, {len(XRAY_CHECKSUMS_MIRRORS)} зеркал):{NC}")
    for i, url in enumerate(XRAY_CHECKSUMS_MIRRORS, 1):
        print(f"    {DIM}{i}){NC} {url}")
    print()
    print(f"{CYAN}📂  Разместите скачанный ZIP в ОДНО из следующих мест:{NC}")
    print(f"    {BOLD}{GREEN}/root/{zip_name}{NC}               ← рекомендуется")
    print(f"    {BOLD}/tmp/xray.zip{NC}")
    print()
    print(f"{WHITE}💡  Команда для скачивания (выполните в другом окне/на другом ПК):{NC}")
    # Берём второй URL (обычно jsDelivr CDN — быстро и доступен из РФ)
    _mirror_url = XRAY_MANUAL_MIRRORS[1] if len(XRAY_MANUAL_MIRRORS) > 1 else XRAY_MANUAL_MIRRORS[0]
    print(f"    {DIM}curl -L \"{_mirror_url}\" -o /root/{zip_name}{NC}")
    print(f"    {DIM}scp /path/to/{zip_name} root@<IP>:/root/{zip_name}{NC}")
    print()
    print(f"{WHITE}▶  После размещения файла нажмите Enter для продолжения...{NC}")
    print(sep)
    print()


def _xray_try_local_zip(zip_name: str, xray_arch: str, chk_url: str, latest_tag: str) -> bool:
    """
    Ищет ZIP-архив Xray в /root/ и /tmp/, распаковывает и устанавливает.
    Возвращает True при успехе.
    """
    core = _core_module()
    XRAY_BIN = core.XRAY_BIN
    info    = core.info
    _run    = core._run
    warn    = core.warn
    success = core.success

    search_paths = [
        Path(f"/root/{zip_name}"),
        Path(f"/root/xray.zip"),
        Path(f"/tmp/xray.zip"),
        Path(f"/tmp/{zip_name}"),
        Path(f"/root/Xray-linux-{xray_arch}.zip"),
    ]
    for candidate in search_paths:
        if candidate.exists() and candidate.stat().st_size > 100_000:
            info(f"  Найден локальный файл: {candidate}")
            r2 = _run(["file", str(candidate)], capture=True, check=False)
            if not any(w in r2.stdout.lower() for w in ("zip", "archive")):
                warn(f"  {candidate} не является ZIP-архивом — пропуск")
                continue
            zip_tmp = Path("/tmp/xray_local.zip")
            shutil.copy2(candidate, zip_tmp)
            if not _verify_sha256(zip_tmp, chk_url, zip_name):
                warn("  SHA256 не совпал — файл повреждён или не та версия")
                zip_tmp.unlink(missing_ok=True)
                continue
            with tempfile.TemporaryDirectory(prefix="xray_extracted.") as ext_dir:
                _run(["unzip", "-o", str(zip_tmp), "-d", ext_dir],
                     check=False, quiet=True)
                zip_tmp.unlink(missing_ok=True)
                xray_bin_src = Path(ext_dir) / "xray"
                if xray_bin_src.exists():
                    shutil.copy2(xray_bin_src, "/usr/local/bin/xray")
                    Path("/usr/local/bin/xray").chmod(0o755)
                    _geo_thresholds = {
                        "geosite.dat": 10 * 1024 * 1024,
                        "geoip.dat":   15 * 1024 * 1024,
                    }
                    for dat in Path(ext_dir).glob("*.dat"):
                        dest = Path("/usr/local/share/xray") / dat.name
                        thr = _geo_thresholds.get(dat.name, 0)
                        if thr and dest.exists() and dest.stat().st_size >= thr:
                            info(f"  Сохранён runetfreedom {dat.name} — стандартный пропущен")
                        else:
                            shutil.copy2(dat, dest)
                    XRAY_BIN = Path("/usr/local/bin/xray")
                    setattr(core, "XRAY_BIN", XRAY_BIN)
                    success(f"Xray {latest_tag} установлен из локального файла {candidate}")
                    return True
    return False


def _max_version_tag(tags: list) -> str:
    """
     (stale-mirror-guard): возвращает МАКСИМАЛЬНЫЙ тег из списка
    (semver-подобное сравнение: v26.10.3 > v26.7.28 > v26.3.27).
    Некорректные теги игнорируются; при пустом результате — ''.
    """
    def _key(tag: str):
        if not isinstance(tag, str):
            return None
        m = re.match(r"^[vV]?(\d+(?:\.\d+)*)", tag.strip())
        if not m:
            return None
        return tuple(int(p) for p in m.group(1).split("."))
    best_tag, best_key = "", None
    for t in tags:
        k = _key(t)
        if k is None:
            continue
        # добиваем нулями до общей длины для корректного сравнения кортежей
        if best_key is not None:
            width = max(len(k), len(best_key))
            k2 = k + (0,) * (width - len(k))
            b2 = best_key + (0,) * (width - len(best_key))
            if k2 > b2:
                best_tag, best_key = t, k
        else:
            best_tag, best_key = t, k
    return best_tag


def install_xray() -> None:
    core = _core_module()
    XRAY_BIN = core.XRAY_BIN
    STAGE_XRAY_DONE = core.STAGE_XRAY_DONE
    info    = core.info
    PROGRESS = core.PROGRESS
    _run    = core._run
    die     = core.die
    CONFIG_DIR    = core.CONFIG_DIR
    XRAY_BACKUP_DIR = core.XRAY_BACKUP_DIR
    command_exists = core.command_exists
    warn    = core.warn
    success = core.success
    YELLOW, CYAN = core.YELLOW, core.CYAN
    BOLD, NC = core.BOLD, core.NC
    DIM, GREEN = core.DIM, core.GREEN

    info("Установка Xray-core...")
    PROGRESS.update(2, "Xray установка")

    arch = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    arch_map = {
        "x86_64": "64", "aarch64": "arm64-v8a",
        "i386": "32", "i686": "32",
    }
    xray_arch = arch_map.get(arch)
    if arch.startswith("armv7"):
        xray_arch = "arm32-v7a"
    if not xray_arch:
        die(f"Неподдерживаемая архитектура: {arch}")

    for d in (Path("/usr/local/share/xray"), Path("/usr/local/etc/xray"),
              CONFIG_DIR, Path("/var/log/xray"), XRAY_BACKUP_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Пользователь xray
    r = _run(["id", "xray"], check=False, quiet=True)
    if r.returncode != 0:
        _run(["useradd", "-r", "-s", "/usr/sbin/nologin", "-d", "/var/lib/xray", "xray"],
             check=False, quiet=True)
    Path("/var/lib/xray").mkdir(exist_ok=True)
    for d in (Path("/var/lib/xray"), Path("/var/log/xray")):
        _run(["chown", "-R", "xray:xray", str(d)], check=False, quiet=True)
        d.chmod(0o750)

    xray_installed = False

    # Метод 1: официальный установщик XTLS
    # Скачивание install-release.sh через fetch_package(XRAY_INSTALLER_SPEC):
    # post_install сам запускает `bash src install`, удаляет drop-in файлы и
    # проверяет что xray появился. Зеркала — 10 URL через xray_mirrors.
    info("Метод 1: официальный установщик XTLS...")
    try:
        # Ленивый импорт — чтобы избежать circular imports на module load time.
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.xray_packages import XRAY_INSTALLER_SPEC
        installer_ok = fetch_package(
            XRAY_INSTALLER_SPEC, print_hint_on_failure=False,
        )
    except Exception as ex:
        # метод 2 (прямой zip + SHA256) — штатный разработанный
        # fallback, деградации нет — info вместо warn.
        info(f"Официальный установщик недоступен ({ex}) — перехожу к прямой загрузке")
        installer_ok = False

    if installer_ok:
        # post_install XRAY_INSTALLER_SPEC уже запустил `bash install` и
        # почистил drop-in файлы. Здесь только проверяем результат.
        xray_dropin_dir = Path("/etc/systemd/system/xray.service.d")
        if xray_dropin_dir.exists():
            shutil.rmtree(xray_dropin_dir, ignore_errors=True)
            info("Удалены drop-in файлы официального установщика Xray")
        if command_exists("xray") or Path("/usr/local/bin/xray").exists():
            found = shutil.which("xray") or "/usr/local/bin/xray"
            XRAY_BIN = Path(found)
            setattr(core, "XRAY_BIN", XRAY_BIN)
            xray_installed = True
            success("Xray установлен через официальный установщик")
    else:
        # штатный fallback на метод 2 — info вместо warn.
        info("Официальный установщик недоступен — перехожу к прямой загрузке")

    # Метод 2: прямой zip с GitHub + SHA256 (несколько зеркал)
    if not xray_installed:
        info("Метод 2: прямая загрузка с GitHub releases...")

        # ── Шаг A: пробуем stable latest ─────────────────────────────────────
        latest_tag = ""
        info("  Запрашиваю последний stable релиз...")

        # GitHub API — несколько зеркал/эндпоинтов
        _API_MIRRORS = [
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            "https://ghproxy.net/https://api.github.com/repos/XTLS/Xray-core/releases/latest",
        ]
        # (stale-mirror-guard): зеркала gh-proxy КЭШИРУЮТ ответы API на
        # недели/месяцы. Инцидент: установка 28.08 с РФ получила от ghproxy
        # закэшированный "latest" = v26.3.27 (на 4 месяца старее реального
        # v26.7.28) → всё скачалось самосогласованно по старому тегу (zip+
        # SHA256 совпали) → на сервере осел бинарник с uTLS-отпечатком
        # Firefox 120 (2023 год). Стёртый TLS-отпечаток — эталонная
        # сигнатура прокси-инструментов для DPI: ТСПУ на международном
        # плече RU→зарубеж рвал REALITY-хендшейк entry→exit (клиент видел
        # 30-секундный таймаут = tcpUserTimeout из sockopt), при живом
        # обычном TLS и живом ping. Поэтому: собираем tag_name СО ВСЕХ
        # зеркал и берём МАКСИМАЛЬНУЮ версию, а не первый ответ.
        _collected_tags: list = []
        for attempt in range(1, 4):
            for api_url in _API_MIRRORS:
                try:
                    r = _run([
                        "curl", "-fsSL", "--connect-timeout", "10",
                        "-H", "Accept: application/vnd.github+json",
                        api_url,
                    ], capture=True, check=False)
                    if r.returncode == 0 and r.stdout:
                        data = json.loads(r.stdout)
                        _tag = data.get("tag_name", "")
                        if _tag and _tag not in _collected_tags:
                            _collected_tags.append(_tag)
                except Exception:
                    pass
            if _collected_tags:
                break
            # транзиентный флап API, ретрай внутри цикла — info.
            info(f"  latest: попытка {attempt}/3 не удалась, повтор...")
            time.sleep(2)
        if _collected_tags:
            latest_tag = _max_version_tag(_collected_tags)
            if len(_collected_tags) > 1:
                info(f"  Ответы зеркал: {', '.join(_collected_tags)} → выбираю максимальный: {latest_tag}")
            else:
                info(f"  Stable latest: {latest_tag}")

        # ── Шаг B: stable недоступен — предлагаем выбор из prerelease ────────
        if not latest_tag:
            warn("  Stable latest недоступен — пробуем prerelease...")
            prerelease_tags: list[dict] = []
            _API_LIST_MIRRORS = [
                "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10",
                "https://ghproxy.net/https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10",
            ]
            for api_url in _API_LIST_MIRRORS:
                try:
                    r = _run([
                        "curl", "-fsSL", "--connect-timeout", "10",
                        "-H", "Accept: application/vnd.github+json",
                        api_url,
                    ], capture=True, check=False)
                    if r.returncode == 0 and r.stdout:
                        releases = json.loads(r.stdout)
                        for rel in releases:
                            tag  = rel.get("tag_name", "")
                            pre  = rel.get("prerelease", False)
                            name = rel.get("name", tag)
                            pub  = rel.get("published_at", "")[:10]
                            if tag:
                                prerelease_tags.append({
                                    "tag": tag, "pre": pre,
                                    "name": name, "date": pub,
                                })
                            if len(prerelease_tags) >= 3:
                                break
                    if prerelease_tags:
                        break
                except Exception:
                    pass

            if prerelease_tags:
                print()
                print(f"  {BOLD}{CYAN}╔══════════════════════════════════════════════════╗{NC}")
                print(f"  {BOLD}{CYAN}║   Выберите версию Xray для установки             ║{NC}")
                print(f"  {BOLD}{CYAN}╚══════════════════════════════════════════════════╝{NC}")
                print()
                for i, rel in enumerate(prerelease_tags, 1):
                    label = f"{YELLOW}[prerelease]{NC}" if rel["pre"] else f"{GREEN}[stable]{NC}  "
                    print(f"    {BOLD}{i}{NC}) {rel['tag']:<18} {label}  {DIM}{rel['date']}{NC}")
                print()
                print(f"    {BOLD}0{NC}) Ввести версию вручную (например: v24.9.30)")
                print()

                while True:
                    try:
                        choice = input(f"  {CYAN}Ваш выбор [1-{len(prerelease_tags)}/0]:{NC} ").strip()
                    except (EOFError, KeyboardInterrupt):
                        choice = "1"
                    if choice == "0":
                        try:
                            manual = input(f"  {CYAN}Введите тег версии (например v24.9.30):{NC} ").strip()
                        except (EOFError, KeyboardInterrupt):
                            manual = ""
                        if manual:
                            latest_tag = manual
                            info(f"  Выбрана версия вручную: {latest_tag}")
                            break
                    elif choice.isdigit() and 1 <= int(choice) <= len(prerelease_tags):
                        latest_tag = prerelease_tags[int(choice) - 1]["tag"]
                        info(f"  Выбрана версия: {latest_tag}")
                        break
                    else:
                        warn(f"  Введите число от 0 до {len(prerelease_tags)}")
            else:
                # ── Шаг C: GitHub API полностью недоступен — hardcoded fallback
                latest_tag = "v25.4.30"
                warn(f"  GitHub API недоступен — используем hardcoded версию {latest_tag}")

        info(f"  Устанавливаю Xray {latest_tag}...")

        zip_name = f"Xray-linux-{xray_arch}.zip"

        # ── Зеркала для скачивания ZIP — из единого реестра xray_mirrors ──────
        # Раньше здесь был inline список из 7 URL (прямой GitHub + 6 ghproxy),
        # теперь — 10 URL через get_xray_zip_mirrors() (jsDelivr CDN × 4 +
        # raw GitHub + release GitHub + 3 gh-proxy + Statically).
        _ZIP_MIRRORS = get_xray_zip_mirrors(tag=latest_tag, arch=xray_arch)
        # .dgst URL — для _xray_try_local_zip (manual retry).
        # post_install XRAY_ZIP_SPEC сам скачивает .dgst через
        # fetch_package(XRAY_CHECKSUMS_SPEC, tag=..., arch=...) — здесь URL нужен
        # только для _verify_sha256 в _xray_try_local_zip.
        _CHK_URLS = get_xray_checksums_mirrors(tag=latest_tag, arch=xray_arch)
        chk_url = _CHK_URLS[0] if _CHK_URLS else ""

        # Выводим все ссылки в терминал чтобы пользователь мог скачать вручную
        print()
        info(f"  Версия для установки: {BOLD}{latest_tag}{NC}")
        info(f"  Архив:                {BOLD}{zip_name}{NC}")
        print(f"  {DIM}Зеркала для скачивания ({XRAY_ZIP_MIRRORS_COUNT}):{NC}")
        for url in _ZIP_MIRRORS:
            print(f"    {DIM}{url}{NC}")
        print()

        # ── Скачивание через fetch_package(XRAY_ZIP_SPEC) ─────────────────────
        # fetch_package сам:
        #   1. Проверяет /root/Xray-linux-{arch}.zip (manual_incoming_dir) —
        #      если найден, использует без сети.
        #   2. Иначе — перебирает 10 зеркал через urllib.
        #   3. При успехе — post_install:
        #      a. ZIP magic проверка (PK\x03\x04).
        #      b. Скачивание checksums.txt через fetch_package(XRAY_CHECKSUMS_SPEC).
        #      c. SHA256 верификация. При провале — False (пробуем следующее зеркало zip'а).
        #      d. Распаковка + copy xray → /usr/local/bin/xray (chmod 0o755).
        #      e. Preservation of runetfreedom .dat файлов (skip если >= threshold).
        #   4. При провале всех зеркал — возвращает False (hint подавлен, т.к.
        #      ниже своя _xray_print_manual_download_hint).
        try:
            from chimera.modules.download_manager import fetch_package
            from chimera.modules.xray_packages import (
                XRAY_ZIP_SPEC, _xray_zip_context,
            )
            # Устанавливаем контекст для post_install (tag/arch нужны для
            # скачивания правильного checksums.txt и поиска хэша в нём).
            _xray_zip_context["tag"] = latest_tag
            _xray_zip_context["arch"] = xray_arch
            zip_ok = fetch_package(
                XRAY_ZIP_SPEC,
                tag=latest_tag, arch=xray_arch,
                print_hint_on_failure=False,
            )
        except Exception as ex:
            warn(f"  Ошибка загрузки Xray zip: {ex}")
            zip_ok = False

        if zip_ok:
            xray_installed = True
            XRAY_BIN = Path("/usr/local/bin/xray")
            setattr(core, "XRAY_BIN", XRAY_BIN)
            # Сообщаем реальный статус SHA256 (не печатаем ложное "верифицирован").
            # _XRAY_SHA256_STATUS устанавливается post_install'ом XRAY_ZIP_SPEC.
            from chimera.modules.xray_packages import _XRAY_SHA256_STATUS
            if _XRAY_SHA256_STATUS == "verified":
                success(f"Xray {latest_tag} установлен из zip (SHA256 верифицирован)")
            elif _XRAY_SHA256_STATUS == "skipped":
                warn(f"Xray {latest_tag} установлен из zip (SHA256 верификация пропущена — checksums.txt недоступен)")
                success(f"Xray {latest_tag} установлен из zip")
            elif _XRAY_SHA256_STATUS == "no_tag":
                warn(f"Xray {latest_tag} установлен из zip (SHA256 верификация пропущена — tag неизвестен)")
                success(f"Xray {latest_tag} установлен из zip")
            else:
                success(f"Xray {latest_tag} установлен из zip")
        else:
            warn("  Автоматическая загрузка Xray не удалась со всех зеркал")

        # ── Метод 3: ручное размещение файла пользователем ───────────────────
        if not xray_installed:
            _xray_print_manual_download_hint(zip_name, latest_tag, xray_arch)

            while True:
                try:
                    input(f"{CYAN}  Нажмите Enter после размещения файла (или Ctrl+C для выхода):{NC} ")
                except (EOFError, KeyboardInterrupt):
                    die("Установка прервана пользователем.")

                # Сначала проверяем локальные файлы (включая /root/ и /tmp/)
                if _xray_try_local_zip(zip_name, xray_arch, chk_url, latest_tag):
                    xray_installed = True
                    break

                # Пробуем скачать ещё раз через fetch_package (вдруг сеть появилась)
                info("  Повторная попытка загрузки с зеркал...")
                try:
                    zip_ok_retry = fetch_package(
                        XRAY_ZIP_SPEC,
                        tag=latest_tag, arch=xray_arch,
                        print_hint_on_failure=False,
                    )
                except Exception:
                    zip_ok_retry = False
                if zip_ok_retry:
                    xray_installed = True
                    XRAY_BIN = Path("/usr/local/bin/xray")
                    setattr(core, "XRAY_BIN", XRAY_BIN)
                    success(f"Xray {latest_tag} установлен (повторная попытка)")
                    break

                warn("  Файл не найден или повреждён. Попробуйте ещё раз.")
                print(f"  {DIM}Ожидаемый файл: {BOLD}/root/{zip_name}{NC}")

    found = shutil.which("xray") or "/usr/local/bin/xray"
    XRAY_BIN = Path(found)
    setattr(core, "XRAY_BIN", XRAY_BIN)
    if not (XRAY_BIN.exists() and os.access(XRAY_BIN, os.X_OK)):
        die("Xray не установлен. Проверьте доступность github.com.")

    r = _run([str(XRAY_BIN), "version"], capture=True, check=False)
    xray_ver = r.stdout.splitlines()[0] if r.stdout else "unknown"
    # (stale-mirror-guard): сверяем РЕАЛЬНУЮ версию бинарника с той,
    # что собирались поставить. Расхождение = зеркало подсунуло не тот zip
    # (кэш) или локальный файл оказался другой версии.
    try:
        _real_ver = (xray_ver.split()[1] if len(xray_ver.split()) > 1 else "").strip()
        _want_ver = latest_tag.lstrip("vV") if latest_tag else ""
        if _want_ver and _real_ver and _real_ver != _want_ver:
            warn(f"  ВНИМАНИЕ: установлен Xray {_real_ver}, ожидался {_want_ver}!")
            warn("  Зеркало могло отдать устаревший/чужой файл. Старый бинарник =")
            warn("  старый uTLS-отпечаток (fp=firefox) → DPI режет REALITY-ногу")
            warn("  entry→exit на международном плече. Перезапустите установку")
            warn("  или положите актуальный zip в /root/ вручную.")
    except Exception:
        pass
    STAGE_XRAY_DONE = True
    setattr(core, "STAGE_XRAY_DONE", STAGE_XRAY_DONE)
    PROGRESS.update(3, "Xray")
    success(f"Xray готов: {xray_ver}")
    _detect_xhttp_mode_support()

# =============================================================================
#  ШАГ 5: ГЕНЕРАЦИЯ КЛЮЧЕЙ REALITY
# =============================================================================
def _parse_x25519_keys(output: str) -> tuple[str, str]:
    """Надёжный парсер xray x25519 — работает со всеми версиями (включая v26+ где Password = PublicKey)"""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    data = {}
    for line in lines:
        if ':' in line:
            k, v = line.split(':', 1)
            key = k.strip().lower().replace(' ', '').replace('key', '')
            data[key] = v.strip()

    private = (data.get("private") or
               next((v for k, v in data.items() if "private" in k), ""))

    public = (data.get("password") or          # новый формат Xray
              data.get("public") or
              next((v for k, v in data.items() if "public" in k), ""))

    return private, public


def _parse_x25519_field(pattern: str, output: str) -> str:
    for line in output.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            return line.split()[-1]
    return ""


def generate_reality_keys() -> None:
    core = _core_module()
    PARAM_PRIVATE_KEY = core.PARAM_PRIVATE_KEY
    PARAM_PUBLIC_KEY  = core.PARAM_PUBLIC_KEY
    PROTOCOL_MODE = core.PROTOCOL_MODE
    PRIVATE_KEY_MODE = core.PRIVATE_KEY_MODE
    XRAY_BIN = core.XRAY_BIN
    info    = core.info
    _run    = core._run
    warn    = core.warn
    success = core.success
    die     = core.die
    YELLOW, NC = core.YELLOW, core.NC

    if PROTOCOL_MODE == "xhttp":
        info("xHTTP TLS: генерация ключей REALITY пропущена (используется TLS-сертификат)")
        PARAM_PRIVATE_KEY = PARAM_PRIVATE_KEY or "n/a"
        PARAM_PUBLIC_KEY  = PARAM_PUBLIC_KEY  or "n/a"
        setattr(core, "PARAM_PRIVATE_KEY", PARAM_PRIVATE_KEY)
        setattr(core, "PARAM_PUBLIC_KEY",  PARAM_PUBLIC_KEY)
        return

    if PRIVATE_KEY_MODE == "manual":
        info("Ключи введены вручную — проверка пары...")
        r = _run([str(XRAY_BIN), "x25519", "--input", PARAM_PRIVATE_KEY],
                 capture=True, check=False)
        if r.stdout:
            derived_priv, derived_pub = _parse_x25519_keys(r.stdout)
            if derived_pub and derived_pub != PARAM_PUBLIC_KEY:
                warn("Введённый Public Key не соответствует Private Key!")
                warn(f"  Ожидается: {derived_pub}")
                ans = input(f"{YELLOW}Использовать корректный Public Key? [Y/n]:{NC} ").strip().lower()
                if ans != 'n':
                    PARAM_PUBLIC_KEY = derived_pub
                    setattr(core, "PARAM_PUBLIC_KEY", PARAM_PUBLIC_KEY)
                    success("Public Key исправлен")
            else:
                success("Ключевая пара валидна")
        return

    info("Генерация ключей REALITY (x25519)...")
    r = _run([str(XRAY_BIN), "x25519"], capture=True, check=False)
    keys_output = r.stdout
    info("Вывод xray x25519:")
    print(keys_output)

    PARAM_PRIVATE_KEY, PARAM_PUBLIC_KEY = _parse_x25519_keys(keys_output)
    setattr(core, "PARAM_PRIVATE_KEY", PARAM_PRIVATE_KEY)
    setattr(core, "PARAM_PUBLIC_KEY",  PARAM_PUBLIC_KEY)

    if not PARAM_PRIVATE_KEY or not PARAM_PUBLIC_KEY:
        die("Не удалось извлечь ключи REALITY. Обновите Xray или проверьте вывод xray x25519.")

    success(f"Ключи сгенерированы (Public: {PARAM_PUBLIC_KEY[:20]}...)")
def _detect_xhttp_mode_support() -> None:
    """
    Определяет поддерживает ли установленный Xray поле "mode" в xhttpSettings.
    Xray с нумерацией YY.M.DD (например 26.3.27) — это date-based версии,
    они НЕ поддерживают поле "mode". Семантические версии (1.x, 2.x) — поддерживают.

    ВАЖНО: Шаг 2 (xray -test) намеренно убран — date-based Xray не падает на тесте
    с "mode", но падает при реальном запуске сервиса. Поэтому date-based версии
    (major >= 25) всегда возвращают False без дополнительных проверок.
    """
    core = _core_module()
    XHTTP_MODE_SUPPORTED = core.XHTTP_MODE_SUPPORTED
    _run    = core._run
    XRAY_BIN = core.XRAY_BIN
    warn    = core.warn
    info    = core.info

    # Шаг 1: определить версию по строке
    try:
        r = _run([str(XRAY_BIN), "version"], capture=True, check=False)
        ver_line = r.stdout.splitlines()[0] if r.stdout else ""
        m = re.search(r'Xray\s+(\d+)\.(\d+)\.(\d+)', ver_line)
        if m:
            major = int(m.group(1))
            # Date-based нумерация: major >= 25 означает год (2025, 2026...)
            # Такие версии не поддерживают "mode" в xhttpSettings
            if major >= 25:
                XHTTP_MODE_SUPPORTED = False
                setattr(core, "XHTTP_MODE_SUPPORTED", XHTTP_MODE_SUPPORTED)
                # date-based нумерация — НОРМА для актуальных релизов
                # Xray (25.x.x+); поле корректно опускается — info вместо warn.
                info(f"Xray {ver_line.split()[1]} — date-based версия, "
                     "поле \"mode\" в xhttpSettings не поддерживается, будет опущено")
                return
            # Семантическая версия (1.x / 2.x) — поддерживает mode
            XHTTP_MODE_SUPPORTED = True
            setattr(core, "XHTTP_MODE_SUPPORTED", XHTTP_MODE_SUPPORTED)
            info(f"Xray {ver_line.split()[1]} — семантическая версия, "
                 "поле \"mode\" в xhttpSettings поддерживается")
            return
    except Exception:
        pass

    # Шаг 2 (fallback): версию распознать не удалось — безопасный default
    XHTTP_MODE_SUPPORTED = False
    setattr(core, "XHTTP_MODE_SUPPORTED", XHTTP_MODE_SUPPORTED)
    warn("Не удалось определить версию Xray — поле \"mode\" в xhttpSettings будет опущено")


def generate_xray_config() -> None:
    core = _core_module()
    # Anti-Empty Identity Guard — UUID/ShortID/REALITY-ключи не должны
    # быть пустыми при регенерации (state.json битый/утерян → восстановление
    # из живого config.json/users.json; иначе ссылки юзеров ломаются).
    try:
        core._identity_params_recover()
    except Exception:
        pass  # guard не должен блокировать генерацию
    DNSCRYPT_LISTEN_PORT = core.DNSCRYPT_LISTEN_PORT
    _assert_reality_dest_sane = core._assert_reality_dest_sane
    info    = core.info
    CONFIG_DIR = core.CONFIG_DIR
    _run    = core._run
    PARAM_USE_DNSCRYPT = core.PARAM_USE_DNSCRYPT
    DNSCRYPT_CONF = core.DNSCRYPT_CONF
    warn    = core.warn
    PARAM_DOMAIN_STRATEGY = core.PARAM_DOMAIN_STRATEGY
    IS_IPV6_AVAILABLE = core.IS_IPV6_AVAILABLE
    DNSCRYPT_INSTALLED = core.DNSCRYPT_INSTALLED
    DNSCRYPT_LISTEN_ADDR = core.DNSCRYPT_LISTEN_ADDR
    _xray_log_block = core._xray_log_block
    SERVER_PORT = core.SERVER_PORT
    PARAM_UUID = core.PARAM_UUID
    PARAM_DOMAIN = core.PARAM_DOMAIN
    XTLS_FLOW = core.XTLS_FLOW
    AWG_EXIT_ENABLED = core.AWG_EXIT_ENABLED
    _build_sockopt = core._build_sockopt
    PARAM_REALITY_DEST = core.PARAM_REALITY_DEST
    PARAM_SOCKET_PATH = core.PARAM_SOCKET_PATH
    PARAM_SPIDERX = core.PARAM_SPIDERX
    PARAM_PRIVATE_KEY = core.PARAM_PRIVATE_KEY
    PARAM_PUBLIC_KEY = core.PARAM_PUBLIC_KEY
    PARAM_SHORTID = core.PARAM_SHORTID
    AWG_FWMARK = core.AWG_FWMARK
    SPLIT_TUNNEL_ENABLED = core.SPLIT_TUNNEL_ENABLED
    build_split_tunnel_routing_rules = core.build_split_tunnel_routing_rules
    _apply_stats_to_config = core._apply_stats_to_config
    _set_config_owner = core._set_config_owner
    XRAY_BIN = core.XRAY_BIN
    success = core.success
    log_to_file = core.log_to_file

    _assert_reality_dest_sane()
    info("Создание конфигурации Xray...")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # ПАТЧ: гарантируем создание группы/пользователя xray ДО chown.
    # Если установка Xray прервалась раньше — chown root:xray упадёт с "invalid group".
    _run(["groupadd", "-f", "xray"], check=False, quiet=True)
    _run(["useradd", "-r", "-g", "xray", "-s", "/sbin/nologin", "xray"],
         check=False, quiet=True)
    # ПАТЧ: директория должна быть доступна для записи root.
    # Если она принадлежит xray:xray с правами 750 — скрипт не может записать config.json.
    try:
        os.chmod(str(CONFIG_DIR), 0o755)
        _run(["chown", "root:xray", str(CONFIG_DIR)], check=False, quiet=True)
    except Exception:
        pass

    # Динамически определяем реальный порт DNSCrypt
    if PARAM_USE_DNSCRYPT:
        r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                        capture=True, check=False)
        if r_active.stdout.strip() == "active":
            real_port: str = ""
            try:
                r = _run(["ss", "-ulnp"], capture=True, check=False)
                for line in r.stdout.splitlines():
                    if "dnscrypt" in line.lower():
                        m = re.search(r':(\d+)\s', line)
                        if m:
                            real_port = m.group(1)
                            break
            except Exception:
                pass
            if not real_port and DNSCRYPT_CONF.exists():
                content = DNSCRYPT_CONF.read_text()
                m = re.search(r'^listen_addresses\s*=.*?:(\d+)', content, re.MULTILINE)
                if m:
                    real_port = m.group(1)
            if real_port and real_port.isdigit():
                if real_port != str(DNSCRYPT_LISTEN_PORT):
                    warn(f"DNSCrypt реально слушает на порту {real_port}, "
                         f"а не {DNSCRYPT_LISTEN_PORT} — обновляем")
                DNSCRYPT_LISTEN_PORT = int(real_port)
                setattr(core, "DNSCRYPT_LISTEN_PORT", DNSCRYPT_LISTEN_PORT)
                info(f"DNSCrypt порт для Xray config: {DNSCRYPT_LISTEN_PORT}")
            else:
                warn(f"Не удалось определить реальный порт DNSCrypt — "
                     f"используем {DNSCRYPT_LISTEN_PORT}")

    # queryStrategy
    query_strategy = "UseIPv4"
    if PARAM_DOMAIN_STRATEGY == "UseIPv6v4":
        query_strategy = "UseIPv6v4"
    if not IS_IPV6_AVAILABLE:
        query_strategy = "UseIPv4"

    # BUGFIX: clients — из единого источника юзеров
    # (_users_collect_for_config), а не только PARAM_UUID. Регенерация
    # конфига (AGH-финализация, «Пересоздать конфиг Xray», emergency
    # repair) не должна выкидывать существующих юзеров из inbound —
    # иначе xray рвёт соединения «invalid request user id» → EOF у
    # клиентов со ссылками, выданными до регенерации. Fresh install
    # не меняется (юзеров нет → clients=[PARAM_UUID]).
    try:
        from chimera.modules.users_manager import (
            _users_collect_for_config, _clients_from_users)
        _cfg_users = _users_collect_for_config(
            PARAM_UUID, f"user@{PARAM_DOMAIN}")
    except Exception:
        _cfg_users = [{"uuid": PARAM_UUID,
                       "email": f"user@{PARAM_DOMAIN}"}]
    _cfg_clients = _clients_from_users(_cfg_users, XTLS_FLOW)

    # DNS servers JSON
    # AGH-AWARE (v37): если AdGuard Home владеет 127.0.0.1:53 — DNS Xray
    # идёт через AGH (кеш + фильтры + DoT-upstream dnscrypt), иначе —
    # напрямую в dnscrypt:5300 (как раньше).
    # (agh_probe): health-check углублён — обязательная живая проба
    # резолва (end-to-end AGH → DNSCrypt → интернет) + нейтрализация
    # iptables redirect 53→5300 (он молча уводил локальный DNS в обход
    # AGH). Сбой любого шага → прежний путь DNSCrypt:5300.
    # (agh-autostart): AGH установлен, но остановлен → ПОДНИМАЕМ его
    # перед пробой («AGH должен запускаться и слушать порты, если он
    # установлен»). Не установлен — autostart безвреден (no-op).
    agh_ok, agh_note = agh_dns_available(run=_run, log_info=info,
                                         log_warn=warn, autostart=True)

    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    dnscrypt_running = (DNSCRYPT_INSTALLED or r_active.stdout.strip() == "active")

    if agh_ok:
        dns_servers = [
            {"address": "127.0.0.1", "port": 53,
             "network": "udp", "skipFallback": False},
        ]
        if dnscrypt_running:
            # Живой fallback: AGH лёг ПОСЛЕ генерации — Xray перейдёт на
            # DNSCrypt:5300, DNS для VPN-клиентов не умирает (skipFallback=False).
            dns_servers.append(
                {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
                 "network": "udp", "skipFallback": False})
        # последний живой fallback — Quad9 напрямую (UDP:53 anycast).
        # Достижим и с зарубежных, и с РФ-хостингов (1.1.1.1/8.8.8.8 в РФ
        # душатся/заблокированы РКН). Срабатывает ТОЛЬКО при падении AGH+DNSCrypt —
        # лучше открытый DNS, чем DNS black-hole для IPIfNonMatch-резолва
        # (иначе доменные соединения зависают на таймаутах DNS).
        dns_servers.append(
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False})
        dns_servers += [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
        info(f"DNS: AdGuardHome здоров ({agh_note}) — Xray → AGH:53 → DNSCrypt")
    elif dnscrypt_running:
        info(f"DNS: используем DNSCrypt-proxy "
             f"({DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT})")
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            # живой Quad9-fallback — достижим из РФ (в отличие от 1.1.1.1/8.8.8.8)
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    elif IS_IPV6_AVAILABLE:
        info("DNS: настройка IPv6-приоритетных серверов (dual-stack)")
        dns_servers = [
            {"address": "2a10:50c0::1:ff",       "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2a10:50c0::2:ff",        "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2606:4700:4700::1111",   "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2606:4700:4700::1001",   "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2001:4860:4860::8888",   "port": 53, "network": "udp", "skipFallback": True},
            {"address": "1.1.1.1",                "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8",                "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        info("DNS: настройка IPv4-серверов (IPv6 недоступен)")
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": True},
        ]

    config: dict[str, Any] = {
        "log": _xray_log_block(),
        "dns": {
            "servers": dns_servers,
            "hosts": {
                "dns.google":         "8.8.8.8",
                "dns.cloudflare.com": "1.1.1.1",
                "localhost":          "127.0.0.1",
            },
            "disableCache":           False,
            "queryStrategy":          query_strategy,
            "disableFallback":        False,
            "disableFallbackIfMatch": True,
        },
        "inbounds": [{
            "tag":      "inbound-vless",
            "port":     SERVER_PORT,
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                # BUGFIX: clients — из единого источника юзеров
                # (_users_collect_for_config), а не только PARAM_UUID:
                # регенерация конфига не должна выкидывать существующих
                # юзеров из inbound (иначе — «invalid request user id»
                # и EOF у клиентов со ссылками, выданными до регенерации).
                "clients": _cfg_clients,
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                # AWG использует маршрутизацию ядра — sniffing доменов не нужен (metadataOnly=True).
                # Базовый VLESS/REALITY: metadataOnly=False обязателен — xray должен читать SNI/Host
                # чтобы freedom мог резолвить домены и применять UseIPv6v4 domainStrategy.
                "metadataOnly": True if AWG_EXIT_ENABLED else False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": _build_sockopt(),
                "security": "reality",
                "realitySettings": {
                    "show":        False,
                    "dest":        (PARAM_REALITY_DEST + ":443") if AWG_EXIT_ENABLED else PARAM_SOCKET_PATH,
                    # xver=1 (Proxy Protocol) только в классическом режиме:
                    # Xray передаёт реальный IP клиента в Nginx через unix socket.
                    # xver=0 при AWG: Xray слушает напрямую, PP-заголовок некому читать.
                    "xver":        0 if AWG_EXIT_ENABLED else 1,
                    "spiderX":     PARAM_SPIDERX,
                    "serverNames": [PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN],
                    "privateKey":  PARAM_PRIVATE_KEY,
                    "publicKey":   PARAM_PUBLIC_KEY,
                    "shortIds":    [PARAM_SHORTID],
                    # Гейт версий клиента (minClientVer) — механика по факту
                    # стенда 2026-09-10 (docs/faq/VLESS_FAQ.md §18): ClientVer
                    # в хендшейке отчитывают ВСЕ — sing-box → [1,8,1], mihomo
                    # → [1,8,2] (mihomo проходит непустые пороги ≤ "1.8.2";
                    # прежний комментарий «не отчитывают вовсе и не проходят
                    # НИКАКОЙ порог» был неверен — те тесты валил MLKEM-чек
                    # ClientHello ядра 26.9.8+, не гейт), Xray-клиент →
                    # версию ядра. Xray 26.7.11–26.7.28: unset/"" =
                    # ДЕФОЛТ-гейт 26.3.27, валит mihomo/sing-box, лечится
                    # явным minClientVer="1.8.0" (рецепт podkop). Xray
                    # 26.9.8+ (наш флот): дефолт-гейт УБРАН — unset/"" =
                    # гейт выключен, непустые пороги живут ("2.0.0" валит
                    # mihomo [1,8,2], "1.8.0"/"1.0.0" пропускает; sing-box
                    # против 26.9.8+ не пройдёт ни при каком гейте — барьер
                    # MLKEM, не версия). "" остаётся правильным значением;
                    # поля пишем ЯВНО, чтобы поведение не зависело от
                    # дефолтов ядра при смене версии. Источники: XTLS/
                    # Xray-core #6477 (RPRX) + PR #6507, MetaCubeX/
                    # mihomo#3042, MHSanaei/3x-ui#5922, стенд 2 ядра ×
                    # 4 гейта × 3 клиента.
                    "minClientVer": "",
                    "maxClientVer": "",
                },
            },
        }],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct",
             # UseIPv6v4: Xray предпочитает IPv6 при исходящих соединениях.
             # Без этого клиент не увидит IPv6 сайтов даже при наличии AAAA.
             "settings": {"domainStrategy": "UseIPv6v4"},
             # ПАТЧ: mark=AWG_FWMARK направляет исходящий трафик xray через AWG таблицу.
             # Используем AWG_EXIT_ENABLED (из state.json), а не AWG_INSTALLED
             # (AWG_INSTALLED=True только в момент первичной установки, но сбрасывается
             # в False при reconfigure/emergency_repair, что вызывало EOF у клиентов).
             **({"streamSettings": {"sockopt": {"mark": AWG_FWMARK}}}
                if AWG_EXIT_ENABLED else {})},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # Примечание: правило {"protocol": ["dns"], "outboundTag": "direct"} намеренно
                # отсутствует — оно перехватывало DNS до DNSCrypt-proxy, обходя шифрование.
                {"type": "field", "ip": ["127.0.0.1/32", "::1/128"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"],  "outboundTag": "BLOCK"},
                # ВАЖНО: catch-all — весь прочий трафик уходит напрямую.
                # Должен быть последним. При вставке RIPE-правил в начало списка
                # это правило остаётся в конце, обеспечивая маршрут для не-РФ трафика.
                # Без него клиенты получают массовые EOF после применения RIPE/split-tunnel.
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }

    # ── AWG: всегда добавляем direct-local (БЕЗ fwmark) + IP-проверка ─────────
    # В AWG-режиме outbound "direct" имеет sockopt.mark = AWG_FWMARK → весь трафик
    # уходит через awg0 (exit-VPS). Для IP-проверочных доменов (2ip.ru, myip.ru,
    # whoer.net) нужна семантика "напрямую, без туннеля" — чтобы пользователь мог
    # проверить работу туннеля (2ip.ru → entry-IP, speedtest.net → exit-IP).
    # Решение: второй outbound "direct-local" (freedom БЕЗ fwmark) — пакеты идут
    # напрямую через default route ОС (физический интерфейс), не AWG-таблицу.
    # IPv6: domainStrategy=UseIPv4 принудительно, если на entry нет IPv6
    # (IS_IPV6_AVAILABLE проверяется через _check_ipv6_preflight — пинг до
    # 2001:4860:4860::8888 + curl ipv6.icanhazip.com). Иначе freedom попытается
    # AAAA-резолв и получит IPv6 blackhole → EOF для клиентов на РФ-доменах.
    # Это правило применяется ВСЕГДА при AWG_EXIT_ENABLED=True, независимо от
    # SPLIT_TUNNEL_ENABLED — это базовая диагностика туннеля. Полный split tunnel
    # (geosite:category-ru, geoip:ru, RIPE) — см. ниже, только если включён.
    if AWG_EXIT_ENABLED:
        _dl_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"
        if not any(ob.get("tag") == "direct-local" for ob in config["outbounds"]):
            config["outbounds"].insert(0, {
                "protocol": "freedom",
                "tag":      "direct-local",
                "settings": {"domainStrategy": _dl_strategy},
                # НЕТ sockopt.mark → ОС использует default route ОС, не awg0.
            })
            info(f"AWG: добавлен outbound direct-local "
                 f"(domainStrategy={_dl_strategy}, без fwmark → напрямую через default route ОС)")
        # IP-проверочные домены → direct-local (всегда, даже без split tunnel)
        from chimera.modules.split_tunnel import build_awg_ip_check_rule
        _ip_check_rules = build_awg_ip_check_rule("direct-local")
        # Вставляем в НАЧАЛО списка (высший приоритет) — до loopback/bittorrent/catch-all.
        # build_awg_ip_check_rule возвращает list (domain + ip правило), вставляем весь список.
        config["routing"]["rules"][:0] = _ip_check_rules
        info("AWG: IP-проверочные домены (2ip.ru, 2ip.io, myip.ru, whoer.net) → direct-local")

    # ── Split tunneling (Режим A, REALITY) ───────────────────────────────────
    # Полный split tunnel: geosite:category-ru + geoip:ru + пользовательские
    # домены/IP. В AWG-режиме РФ-домены идут через direct-local (без fwmark).
    if SPLIT_TUNNEL_ENABLED:
        _st_direct_tag = "direct-local" if AWG_EXIT_ENABLED else "direct"
        st_rules = build_split_tunnel_routing_rules(
            proxy_tag="direct", direct_tag=_st_direct_tag)
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил "
                 f"(Режим A, REALITY, AWG direct_tag={_st_direct_tag})")

    cfg_file = CONFIG_DIR / "config.json"
    _apply_stats_to_config(config)
    cfg_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    _set_config_owner(cfg_file)

    # Симлинк
    alt_dir = Path("/usr/local/etc/xray")
    if alt_dir.exists():
        alt_cfg = alt_dir / "config.json"
        alt_cfg.unlink(missing_ok=True)
        try:
            alt_cfg.symlink_to(cfg_file)
            info(f"Симлинк /usr/local/etc/xray/config.json → {cfg_file}")
        except Exception:
            pass

    r = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
             capture=True, check=False)
    if r.returncode == 0:
        success("Конфигурация Xray валидирована")
        if IS_IPV6_AVAILABLE:
            success("DNS: IPv6-приоритет (AdGuard IPv6 → CF IPv6 → Google IPv6 → fallback IPv4)")
        else:
            success("DNS: IPv4-режим (1.1.1.1 → 8.8.8.8 → 9.9.9.9)")
    else:
        # (geo-self-heal): негрузимые geo-правила = МЁРТВЫЙ Xray (exit 23
        # + RestartPreventExitStatus=23) = i/o timeout для ВСЕХ клиентов.
        _healed = False
        try:
            _cfg_h = json.loads(cfg_file.read_text())
            from chimera.modules.split_tunnel import strip_geo_rules
            if strip_geo_rules(_cfg_h):
                cfg_file.write_text(json.dumps(_cfg_h, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_file)
                r2 = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
                          capture=True, check=False)
                if r2.returncode == 0:
                    _healed = True
                    warn("GEO-SELF-HEAL: geo-файлы не загрузились — geosite/geoip-"
                         "правила УДАЛЕНЫ, Xray жив. Обновите geo-файлы "
                         "(Сеть → 3 → GeoIP/GeoSite).")
        except Exception:
            pass
        if not _healed:
            warn("Конфигурация создана (валидация вернула предупреждение)")
            log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")


def generate_xray_config_xhttp() -> None:
    """
    Генерация конфига Xray для VLESS + xHTTP + TLS (Режим A).

    в начале — Anti-Empty Identity Guard (UUID и параметры доступа
    не должны остаться пустыми при регенерации — см. _core.
    _identity_params_recover).

    Схема Nginx → Xray (см. https://github.com/XTLS/Xray-core/discussions/4113 —
    fallbacks для xHTTP НЕ поддерживаются в Xray-core):
      • Nginx терминирует TLS на SERVER_PORT (по умолч. 443), отдаёт сайт-заглушку
        для "/" и проксирует xhttp path на 127.0.0.1:XHTTP_BACKEND_PORT.
      • Xray принимает xHTTP на 127.0.0.1:XHTTP_BACKEND_PORT с security: none
        (TLS-трафик уже расшифрован Nginx).

    Это позволяет одновременно держать рабочий сайт-заглушку и прокси на одном :443.
    """
    core = _core_module()
    # Anti-Empty Identity Guard — UUID и параметры доступа не должны
    # остаться пустыми при регенерации (см. _core._identity_params_recover).
    try:
        core._identity_params_recover()
    except Exception:
        pass  # guard не должен блокировать генерацию
    DNSCRYPT_LISTEN_PORT = core.DNSCRYPT_LISTEN_PORT
    info    = core.info
    CONFIG_DIR = core.CONFIG_DIR
    PARAM_DOMAIN_STRATEGY = core.PARAM_DOMAIN_STRATEGY
    IS_IPV6_AVAILABLE = core.IS_IPV6_AVAILABLE
    _run    = core._run
    DNSCRYPT_INSTALLED = core.DNSCRYPT_INSTALLED
    DNSCRYPT_LISTEN_ADDR = core.DNSCRYPT_LISTEN_ADDR
    PARAM_DOMAIN = core.PARAM_DOMAIN
    _build_xhttp_settings = core._build_xhttp_settings
    XHTTP_MODE = core.XHTTP_MODE
    XHTTP_PATH = core.XHTTP_PATH
    XHTTP_BACKEND_PORT = core.XHTTP_BACKEND_PORT
    _xray_log_block = core._xray_log_block
    SERVER_PORT = core.SERVER_PORT
    PARAM_UUID = core.PARAM_UUID
    _build_tls_settings_xhttp = core._build_tls_settings_xhttp
    AWG_FWMARK = core.AWG_FWMARK
    AWG_EXIT_ENABLED = core.AWG_EXIT_ENABLED
    SPLIT_TUNNEL_ENABLED = core.SPLIT_TUNNEL_ENABLED
    build_split_tunnel_routing_rules = core.build_split_tunnel_routing_rules
    _apply_stats_to_config = core._apply_stats_to_config
    _set_config_owner = core._set_config_owner
    XRAY_BIN = core.XRAY_BIN
    success = core.success
    warn    = core.warn
    log_to_file = core.log_to_file

    info("Создание конфигурации Xray (xHTTP TLS)...")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # queryStrategy
    query_strategy = "UseIPv4"
    if PARAM_DOMAIN_STRATEGY == "UseIPv6v4":
        query_strategy = "UseIPv6v4"
    if not IS_IPV6_AVAILABLE:
        query_strategy = "UseIPv4"

    # BUGFIX: clients — из единого источника юзеров
    # (_users_collect_for_config), а не только PARAM_UUID — регенерация
    # конфига не должна выкидывать существующих юзеров из inbound
    # («invalid request user id» → EOF у клиентов со старыми ссылками).
    # xHTTP не использует flow — передаём пустой.
    try:
        from chimera.modules.users_manager import (
            _users_collect_for_config, _clients_from_users)
        _cfg_users = _users_collect_for_config(
            PARAM_UUID, f"user@{PARAM_DOMAIN}")
    except Exception:
        _cfg_users = [{"uuid": PARAM_UUID,
                       "email": f"user@{PARAM_DOMAIN}"}]
    _cfg_clients_no_flow = _clients_from_users(_cfg_users)

    # DNS серверы
    # AGH-AWARE (v37): аналогично generate_xray_config() — при живом AGH
    # DNS Xray идёт через 127.0.0.1:53 (AGH), а не напрямую в dnscrypt.
    # (agh_probe): health-check углублён — живая проба резолва
    # (end-to-end AGH → DNSCrypt → интернет) + нейтрализация iptables
    # redirect 53→5300. Сбой любого шага → прежний путь DNSCrypt:5300.
    # (agh-autostart): AGH установлен, но остановлен → поднимаем перед пробой.
    agh_ok, agh_note = agh_dns_available(run=_run, log_info=info,
                                         log_warn=warn, autostart=True)

    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    dnscrypt_running = (DNSCRYPT_INSTALLED or r_active.stdout.strip() == "active")

    if agh_ok:
        dns_servers = [
            {"address": "127.0.0.1", "port": 53,
             "network": "udp", "skipFallback": False},
        ]
        if dnscrypt_running:
            # Живой fallback на случай падения AGH после генерации
            dns_servers.append(
                {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
                 "network": "udp", "skipFallback": False})
        # (синхрон с generate_xray_config): последний живой fallback
        # Quad9 напрямую (UDP:53 anycast, достижим и из РФ, и из-за рубежа).
        # Срабатывает ТОЛЬКО при падении AGH+DNSCrypt — лучше открытый DNS,
        # чем black-hole для IPIfNonMatch-резолва. 1.1.1.1/8.8.8.8 ниже —
        # skipFallback (мёртвый груз в РФ, живые за рубежом).
        dns_servers.append(
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False})
        dns_servers += [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
        info(f"DNS: AdGuardHome здоров ({agh_note}) — Xray → AGH:53 → DNSCrypt")
    elif dnscrypt_running:
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            # (синхрон с generate_xray_config): живой Quad9-fallback
            # достижим из РФ (1.1.1.1/8.8.8.8 ниже — skipFallback, отрава в РФ).
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    elif IS_IPV6_AVAILABLE:
        dns_servers = [
            {"address": "2a10:50c0::1:ff",       "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2606:4700:4700::1111",   "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2001:4860:4860::8888",   "port": 53, "network": "udp", "skipFallback": True},
            {"address": "1.1.1.1",                "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8",                "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": True},
        ]

    cert_path = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem"
    key_path  = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem"
    # ── CDN masking: если профиль активен, используем экспертный inbound ───
    # вместо базового _build_xhttp_settings(). Профиль даёт расширенные
    # extra-поля (xPadding/session/seq/xmux.maxConcurrency=1), специализированные
    # для маскировки под реальный HTTPS через CDN Beeline.
    #
    # Не затрагивает простой XHTTP-режим — только ветка XHTTP_CDN_MASKING=True.
    if getattr(core, "XHTTP_CDN_MASKING", False):
        try:
            from chimera.modules.xhttp_cdn_masking import (
                build_xhttp_cdn_masking_inbound,
                CDN_MASKING_INBOUND_PORT,
            )
            # Используем отдельный backend-порт (7443), чтобы CDN-masking
            # профиль не конфликтовал с простым XHTTP (8443).
            # ВАЖНО: переменная называется _xhttp_s3 (как в простой ветке ниже),
            # чтобы строка "xhttpSettings": _xhttp_s3 работала в обоих случаях.
            _xhttp_s3 = build_xhttp_cdn_masking_inbound(
                PARAM_DOMAIN, XHTTP_PATH, port=CDN_MASKING_INBOUND_PORT)
            _xhttp_backend_port = _xhttp_s3.pop("__backend_port",
                                                      CDN_MASKING_INBOUND_PORT)
            # Обновляем глобал, чтобы setup_nginx_final() проксировал на
            # правильный порт. В simple-XHTTP этого не делаем — там работает
            # дефолтный XHTTP_BACKEND_PORT (8443).
            XHTTP_BACKEND_PORT = _xhttp_backend_port
            setattr(core, "XHTTP_BACKEND_PORT", _xhttp_backend_port)
            # Серверный sockopt для CDN masking — без marks/firewall,
            # tcpNoDelay=True для низкой латентности на loopback.
            _sockopt_s3 = {"tcpNoDelay": True}
            info("CDN masking: используется экспертный профиль XHTTP "
                 f"(backend=127.0.0.1:{_xhttp_backend_port}, extra=24+ полей)")
        except ImportError as _e:
            # Если модуль недоступен (edge-case) — fallback на простой профиль.
            warn = core.warn
            warn(f"CDN masking: модуль недоступен ({_e}), fallback на простой XHTTP")
            _xhttp_s3, _sockopt_s3 = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)
    else:
        _xhttp_s3, _sockopt_s3 = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)

    # Сертификат здесь НЕ используется самим Xray — TLS терминирует Nginx на :SERVER_PORT.
    # cert_path / key_path оставлены для обратной совместимости с возможными хуками,
    # но в streamSettings.security стоит "none" → tlsSettings не добавляется.
    info(f"xHTTP backend: Xray слушает 127.0.0.1:{XHTTP_BACKEND_PORT} (security: none, "
         f"TLS терминирует Nginx на :{SERVER_PORT})")

    config: dict[str, Any] = {
        "log": _xray_log_block(),
        "dns": {
            "servers": dns_servers,
            "hosts": {
                "dns.google":         "8.8.8.8",
                "dns.cloudflare.com": "1.1.1.1",
                "localhost":          "127.0.0.1",
            },
            "disableCache":           False,
            "queryStrategy":          query_strategy,
            "disableFallback":        False,
            "disableFallbackIfMatch": True,
        },
        "inbounds": [{
            "tag":      "inbound-xhttp",
            "port":     XHTTP_BACKEND_PORT,   # loopback-only, Nginx проксирует сюда
            "listen":   "127.0.0.1",         # только loopback — извне не доступно
            "protocol": "vless",
            "settings": {
                # BUGFIX: clients — из единого источника юзеров
                # (_users_collect_for_config), а не только PARAM_UUID
                # (регенерация не выкидывает существующих юзеров).
                "clients": _cfg_clients_no_flow,
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network":       "xhttp",
                "security":      "none",      # TLS терминирован Nginx, тут уже голый HTTP
                "sockopt":       _sockopt_s3,
                "xhttpSettings": _xhttp_s3,
            },
        }],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct",
                # UseIPv6v4: Xray предпочитает IPv6 при исходящих соединениях.
                "settings": {"domainStrategy": "UseIPv6v4"},
                # ПАТЧ: при AWG_EXIT_ENABLED добавляем sockopt.mark, чтобы исходящий
                # трафик Xray маршрутизировался через AWG-туннель (policy routing fwmark).
                **({"streamSettings": {"sockopt": {"mark": AWG_FWMARK}}}
                   if AWG_EXIT_ENABLED else {}),
            },
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # Примечание: правило {"protocol": ["dns"], "outboundTag": "direct"} намеренно
                # отсутствует — оно перехватывало DNS до DNSCrypt-proxy, обходя шифрование.
                {"type": "field", "ip": ["127.0.0.1/32", "::1/128"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"],  "outboundTag": "BLOCK"},
                # ВАЖНО: catch-all — весь прочий трафик уходит напрямую.
                # Должен быть последним. При вставке RIPE-правил в начало списка
                # это правило остаётся в конце, обеспечивая маршрут для не-РФ трафика.
                # Без него клиенты получают массовые EOF после применения RIPE/split-tunnel.
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }

    # ── AWG: всегда добавляем direct-local (БЕЗ fwmark) + IP-проверка ─────────
    # См. подробный комментарий в generate_xray_config() — тут та же логика.
    # В AWG-режиме "direct" имеет fwmark → весь трафик через awg0 (exit-VPS).
    # Для IP-проверочных доменов (2ip.ru, myip.ru, whoer.net) нужен второй
    # outbound без fwmark → напрямую через default route ОС.
    # IPv6: UseIPv4 принудительно при отсутствии IPv6 на entry (см. _check_ipv6_preflight).
    # Применяется ВСЕГДА при AWG_EXIT_ENABLED=True, независимо от split tunnel.
    if AWG_EXIT_ENABLED:
        _dl_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"
        if not any(ob.get("tag") == "direct-local" for ob in config["outbounds"]):
            config["outbounds"].insert(0, {
                "protocol": "freedom",
                "tag":      "direct-local",
                "settings": {"domainStrategy": _dl_strategy},
            })
            info(f"AWG: добавлен outbound direct-local "
                 f"(domainStrategy={_dl_strategy}, без fwmark → напрямую через default route ОС)")
        from chimera.modules.split_tunnel import build_awg_ip_check_rule
        _ip_check_rules = build_awg_ip_check_rule("direct-local")
        # build_awg_ip_check_rule возвращает list (domain + ip правило).
        config["routing"]["rules"][:0] = _ip_check_rules
        info("AWG: IP-проверочные домены (2ip.ru, 2ip.io, myip.ru, whoer.net) → direct-local")

    # ── Split tunneling (Режим A, xHTTP TLS) ─────────────────────────────────
    # Полный split tunnel: geosite:category-ru + geoip:ru + пользовательские.
    if SPLIT_TUNNEL_ENABLED:
        _st_direct_tag = "direct-local" if AWG_EXIT_ENABLED else "direct"
        st_rules = build_split_tunnel_routing_rules(
            proxy_tag="direct", direct_tag=_st_direct_tag)
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил "
                 f"(Режим A, xHTTP TLS, AWG direct_tag={_st_direct_tag})")

    cfg_file = CONFIG_DIR / "config.json"
    _apply_stats_to_config(config)
    cfg_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    _set_config_owner(cfg_file)

    alt_dir = Path("/usr/local/etc/xray")
    if alt_dir.exists():
        alt_cfg = alt_dir / "config.json"
        alt_cfg.unlink(missing_ok=True)
        try:
            alt_cfg.symlink_to(cfg_file)
        except Exception:
            pass

    # Валидация (может упасть если сертификат ещё не получен — нормально)
    r = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
             capture=True, check=False)
    if r.returncode == 0:
        success(f"Конфигурация xHTTP TLS валидирована "
                f"(mode={XHTTP_MODE}, path={XHTTP_PATH}, "
                f"backend=127.0.0.1:{XHTTP_BACKEND_PORT}, TLS=Nginx:{SERVER_PORT})")
    else:
        # (geo-self-heal): см. generate_xray_config
        _healed = False
        try:
            _cfg_h = json.loads(cfg_file.read_text())
            from chimera.modules.split_tunnel import strip_geo_rules
            if strip_geo_rules(_cfg_h):
                cfg_file.write_text(json.dumps(_cfg_h, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_file)
                r2 = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
                          capture=True, check=False)
                if r2.returncode == 0:
                    _healed = True
                    warn("GEO-SELF-HEAL: geo-файлы не загрузились — geosite/geoip-"
                         "правила УДАЛЕНЫ, Xray жив. Обновите geo-файлы "
                         "(Сеть → 3 → GeoIP/GeoSite).")
        except Exception:
            pass
        if not _healed:
            warn("Конфигурация создана (валидация вернула предупреждение — возможно, сертификат ещё не получен)")
            log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")

# =============================================================================
# =============================================================================
def create_xray_service() -> None:
    core = _core_module()
    info    = core.info
    PARAM_SOCKET_PATH = core.PARAM_SOCKET_PATH
    PARAM_USE_DNSCRYPT = core.PARAM_USE_DNSCRYPT
    PROTOCOL_MODE = core.PROTOCOL_MODE
    AWG_EXIT_ENABLED = core.AWG_EXIT_ENABLED
    _run    = core._run
    XRAY_SERVICE = core.XRAY_SERVICE
    XRAY_BIN = core.XRAY_BIN
    CONFIG_DIR = core.CONFIG_DIR
    success = core.success

    info("Настройка systemd-сервиса Xray...")

    sock_dir = str(Path(PARAM_SOCKET_PATH).parent)

    after_line = ("After=network.target network-online.target nss-lookup.target "
                  "systemd-resolved.service")
    wants_line = "Wants=network-online.target"
    if PARAM_USE_DNSCRYPT:
        after_line += " dnscrypt-proxy.service"
        wants_line  = "Wants=network-online.target dnscrypt-proxy.service"

    # Для xHTTP TLS Xray слушает только loopback-порт (Nginx терминирует TLS на 443
    # и проксирует xhttp path сюда). Сокет не нужен, rm -f не нужен.
    # Применимо ко всем xHTTP-режимам: A, B+AWG, B+H2, B+exit-ноды — везде Xray
    # слушает 127.0.0.1:XHTTP_BACKEND_PORT с security:none.
    if PROTOCOL_MODE == "xhttp":
        pre_cmds = ""
        svc_desc = "Xray Service (VLESS xHTTP — backend for Nginx TLS)"
    elif AWG_EXIT_ENABLED:
        # === FIX 1c/AWG: В AWG-режиме unix socket не используется.
        # Xray слушает напрямую на 0.0.0.0:SERVER_PORT (TCP).
        # Socket-директория и rm -f не нужны — Xray не создаёт сокет. ===
        pre_cmds = ""
        svc_desc = "Xray Service (VLESS TCP REALITY + AWG)"
        # === END FIX 1c/AWG ===
    else:
        # Классический REALITY: Xray получает fallback-трафик и перенаправляет в unix socket,
        # который слушает Nginx. Socket должен быть очищен перед стартом.
        sock_parent = Path(PARAM_SOCKET_PATH).parent
        sock_parent.mkdir(parents=True, exist_ok=True)
        try:
            _run(["chown", "xray:xray", str(sock_parent)], check=False, quiet=True)
            sock_parent.chmod(0o755)  # nginx (www-data) должен входить
        except Exception:
            pass
        # BUGFIX: rm -f PARAM_SOCKET_PATH удалял unix-сокет которым владеет nginx
        # (nginx bind-ится на него при старте). После удаления nginx переставал
        # слушать и все клиенты получали EOF до перезапуска nginx.
        # Xray НЕ является сервером на этом сокете — он только делает connect
        # к нему при fallback (dest в realitySettings). rm -f не нужен.
        pre_cmds = (
            f"ExecStartPre=/bin/mkdir -p {sock_dir}"
        )
        svc_desc = "Xray Service (VLESS TCP REALITY)"

    pre_block = f"\n        {pre_cmds}\n" if pre_cmds else ""

    # ── пин пути geo-файлов ─────────────────────────────────────────────
    # Xray-core ищет geoip/geosite ТОЛЬКО в: env xray.location.asset →
    # каталог бинарника → /usr/local/share/xray → /usr/share/xray →
    # /opt/share/xray. Поле routing.geoDataBasePath Xray НЕ поддерживает,
    # /etc/xray сам по себе НЕ ищется. Канонические файлы Chimera живут в
    # /etc/xray — пиним env на него, когда оба файла на месте (иначе не
    # пиним вовсе: Xray возьмёт /usr/local/share/xray, куда их зеркалит
    # split_tunnel._geo_files_available).
    _geo_env_line = ""
    try:
        _gs = Path("/etc/xray/geosite.dat")
        _gi = Path("/etc/xray/geoip.dat")
        if _gs.exists() and _gi.exists() \
                and _gs.stat().st_size > 1024 * 1024 \
                and _gi.stat().st_size > 1024 * 1024:
            # имя env-переменной с ТОЧКАМИ systemd ОТКАЗЫВАЕТСЯ
            # парсить ("Invalid environment assignment, ignoring") — юнит
            # молча терял строку. Xray принимает обе формы (EnvFlag AltName:
            # xray.location.asset ↔ XRAY_LOCATION_ASSET) — используем
            # подчёркивания, которые systemd принимает всегда.
            _geo_env_line = "Environment=XRAY_LOCATION_ASSET=/etc/xray"
    except Exception:
        _geo_env_line = ""

    XRAY_SERVICE.write_text(textwrap.dedent(f"""\
        [Unit]
        Description={svc_desc}
        Documentation=https://github.com/xtls
        {after_line}
        {wants_line}
        StartLimitIntervalSec=60s
        # (start-limit-fix): было StartLimitBurst=3 — пересборка конфига
        # (YouTube restore → IP-pin → tproxy → финальный рестарт) делает
        # 3-5 start'ов за несколько секунд, и 4-й отклонялся: start-limit-hit,
        # xray мёртв при валидном конфиге. Код теперь зовёт reset-failed
        # перед каждым рестартом (_xray_safe_restart), а burst поднят до 10
        # как страховка для остальных вызывающих (watchdog, ExecReload).
        # Crash-loop-защита сохранена: Restart=on-failure + RestartSec=5s
        # → 10 попыток за ~50с, затем systemd сдаётся.
        StartLimitBurst=10

        [Service]
        User=xray
        Group=xray
        {_geo_env_line}
        CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
        AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
        NoNewPrivileges=true

        LimitNOFILE=1048576
        LimitNPROC=infinity
        Nice=-10
        IOSchedulingClass=best-effort
        IOSchedulingPriority=0
        MemoryAccounting=true
        {pre_block}
        ExecStart={XRAY_BIN} run -config {CONFIG_DIR}/config.json
        # FIX: Xray 26.x не обрабатывает SIGHUP для перечитывания конфига —
        # при получении HUP процесс завершается (code=killed, signal=HUP),
        # а systemd помечает юнит как inactive(dead) без автозапуска.
        # ExecReload через явный restart гарантирует подъём сервиса
        # после любого вызова systemctl reload xray.
        ExecReload=/bin/systemctl restart xray

        Restart=on-failure
        RestartSec=5s
        RestartPreventExitStatus=23
        TimeoutStartSec=30s
        TimeoutStopSec=10s

        [Install]
        WantedBy=multi-user.target
    """))

    _run(["systemctl", "daemon-reload"], check=True, quiet=True)
    _run(["systemctl", "enable", "xray"], check=True, quiet=True)
    success("Systemd-сервис настроен")


def _xray_get_release_info(prerelease: bool = False) -> "dict | None":
    """
    Возвращает dict с полями tag_name, prerelease из GitHub API.
    prerelease=False → /releases/latest
    prerelease=True  → /releases (первый, включая prerelease)
    """
    core = _core_module()
    _run = core._run
    warn = core.warn

    url = (
        "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5"
        if prerelease else
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    )
    for attempt in range(1, 4):
        try:
            r = _run(["curl", "-fsSL", "--connect-timeout", "10", url],
                     capture=True, check=False)
            data = json.loads(r.stdout)
            if prerelease:
                if isinstance(data, list) and data:
                    return data[0]
            else:
                if data.get("tag_name"):
                    return data
        except Exception:
            pass
        if attempt < 3:
            warn(f"Попытка {attempt}: не удалось получить данные GitHub, повтор...")
            time.sleep(2)
    return None


def _xray_version_norm(ver: str) -> str:
    ver = ver.lstrip("v")
    parts = (ver.split(".")[:3] + ["0", "0", "0"])[:3]
    try:
        return "".join(f"{int(p):05d}" for p in parts)
    except ValueError:
        return "000000000000000"


def _xray_current_version() -> str:
    core = _core_module()
    _run = core._run

    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    try:
        r = _run([xray_bin, "version"], capture=True, check=False)
        match = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', r.stdout)
        if match:
            return "v" + match.group(0)
    except Exception:
        pass
    return "v0.0.0"


def _xray_geo_is_runetfreedom() -> bool:
    """
    Проверяет что geosite.dat содержит категорию ru-available-only-inside.
    Делает это через быстрый grep по бинарному содержимому файла.
    Это единственный надёжный способ — размер файла ненадёжен.

     FIX: добавлен флаг -i (case-insensitive). Теги в geosite.dat
    хранятся в ВЕРХНЕМ регистре (RU-AVAILABLE-ONLY-INSIDE), а мы ищем
    строчное 'ru-available-only-inside'. Без -i grep не находил тег →
    функция возвращала False даже для валидного runetfreedom geosite.dat →
    при каждом запуске установщика гео-файлы перескачивались (~73 МБ).
    """
    # Xray ищет geo-файлы в нескольких местах в таком порядке:
    # 1. $XRAY_LOCATION_ASSET  2. /etc/xray/  3. /usr/local/share/xray/
    # Проверяем все возможные пути.
    candidates = [
        Path("/etc/xray/geosite.dat"),
        Path("/usr/local/share/xray/geosite.dat"),
        Path("/usr/local/etc/xray/geosite.dat"),
    ]
    # Путь рядом с бинарником
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    candidates.append(Path(xray_bin).parent / "geosite.dat")

    for p in candidates:
        if not p.exists():
            continue
        try:
            import subprocess as _sp
            # -i = case-insensitive (теги в geosite.dat в ВЕРХНЕМ регистре).
            # -a = treat binary as text (geosite.dat — protobuf binary).
            # -F = fixed string (не regex).
            # -q = quiet (только exit code).
            r = _sp.run(
                ["grep", "-qaFi", "ru-available-only-inside", str(p)],
                capture_output=True,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _geo_print_manual_download_hint() -> None:
    """
    Выводит инструкцию для ручного скачивания geosite.dat и geoip.dat
    со всеми известными зеркалами и путями размещения.

    Источники зеркал и путей — chimera.modules.geo_mirrors
    (единый реестр для всех точек скачивания geo-файлов).
    """
    core = _core_module()
    YELLOW, NC = core.YELLOW, core.NC
    BOLD, WHITE = core.BOLD, core.WHITE
    CYAN, GREEN = core.CYAN, core.GREEN
    DIM = core.DIM

    _GEO_MANUAL = get_all_mirrors()  # {"geosite.dat": [urls], "geoip.dat": [urls]}

    sep = f"{YELLOW}{'─'*64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}⚠  Не удалось скачать geo-файлы автоматически.{NC}")
    print(f"{WHITE}   Скачайте файлы вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    for fname, urls in _GEO_MANUAL.items():
        print(f"{CYAN}📦  {fname}  {DIM}({len(urls)} зеркал){NC}")
        for i, url in enumerate(urls, 1):
            print(f"    {DIM}{i:>2}){NC} {url}")
        print()

    # Пути ручного размещения — первый (рекомендуемый) подсвечен зелёным
    print(f"{CYAN}📂  Разместите файлы в ОДНО из следующих мест:{NC}")
    recommended = recommended_manual_path()
    for i, p in enumerate(MANUAL_UPLOAD_PATHS):
        if p == recommended:
            print(f"    {BOLD}{GREEN}{p}/{NC}  {BOLD}{GREEN}← рекомендуется (WinSCP-friendly){NC}")
        else:
            print(f"    {BOLD}{p}/{NC}")
    print()
    print(f"{WHITE}💡  Команда для скачивания на сервере (через любое живое зеркало):{NC}")
    # Берём первое зеркало (jsDelivr CDN — обычно самое доступное)
    _geo_site_url = _GEO_MANUAL['geosite.dat'][0]
    _geo_ip_url = _GEO_MANUAL['geoip.dat'][0]
    print(f"    {DIM}curl -fL \"{_geo_site_url}\" -o /root/geosite.dat{NC}")
    print(f"    {DIM}curl -fL \"{_geo_ip_url}\"   -o /root/geoip.dat{NC}")
    print(f"    {DIM}# Или SCP с вашего ПК (после ручного скачивания в браузере):{NC}")
    print(f"    {DIM}scp geosite.dat geoip.dat root@<IP>:{recommended}/{NC}")
    print()
    print(f"{WHITE}💡  После размещения файлов в {recommended}/ повторите установку{NC}")
    print(f"{WHITE}   или выберите в меню Geo → «Обновить прямо сейчас».{NC}")
    print()
    print(sep)
    print()


def _xray_update_geo_runetfreedom() -> bool:
    """
    Скачивает runetfreedom geosite.dat + geoip.dat и раскладывает
    во ВСЕ директории где Xray ищет geo-файлы.
    При неудаче — предлагает ручное размещение файлов.
    Возвращает True если geosite.dat скачан и установлен успешно.

    После Wave 4 миграции: использует fetch_package(GEOSITE_SPEC) и
    fetch_package(GEOIP_SPEC) из geo_packages.py (как и download_geo_files
    в geo_files.py). Зеркала — единый реестр geo_mirrors.py (19 URL на файл).
    post_install в GEOSITE_SPEC/GEOIP_SPEC копирует файл в 3 dest_dirs
    (/etc/xray, /usr/local/share/xray, /usr/local/etc/xray) + chmod 644 +
    chown root:xray.
    """
    core = _core_module()
    info    = core.info
    DIM, NC = core.DIM, core.NC
    _run    = core._run
    warn    = core.warn
    CYAN    = core.CYAN
    success = core.success

    # Зеркала импортируются из единого реестра (geo_mirrors.py) — для печати
    GEOSITE_URLS = get_geosite_urls()
    GEOIP_URLS   = get_geoip_urls()

    # Выводим ссылки в терминал (первые 4 зеркала для краткости)
    print()
    info(f"  Ссылки для скачивания geo-файлов (всего зеркал: {GEO_MIRRORS_COUNT}):")
    print(f"  {DIM}geosite.dat:{NC}")
    for url in GEOSITE_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    print(f"  {DIM}geoip.dat:{NC}")
    for url in GEOIP_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    print()

    # Все директории где Xray ищет geo-файлы (для retry-branch проверки
    # ручного размещения). fetch_package через GEOSITE_SPEC/GEOIP_SPEC
    # копирует в [_CONFIG_DIR, _XRAY_SHARE_DIR, _XRAY_ETC_DIR] — это
    # соответствует XRAY_LOOKUP_DIRS.
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    dest_dirs_raw = list(XRAY_LOOKUP_DIRS) + [Path(xray_bin).parent]
    seen: set = set()
    geo_dirs = []
    for d in dest_dirs_raw:
        if d not in seen:
            seen.add(d)
            try:
                d.mkdir(parents=True, exist_ok=True)
                geo_dirs.append(d)
            except Exception:
                if d.exists():
                    geo_dirs.append(d)

    # Пути ручного размещения — из единого реестра
    # (/root/ — первое, рекомендуется; плюс все Xray lookup dirs)
    _MANUAL_ROOTS = list(MANUAL_UPLOAD_PATHS)

    geosite_ok = False
    failed_files: list[str] = []

    # ── Скачивание через fetch_package (download_manager.py) ────────────────
    # fetch_package сам:
    #   1. Проверяет /root/{filename} (manual_incoming_dir из PackageSpec) —
    #      если найден, использует без сети.
    #   2. Иначе — перебирает 19 зеркал через urllib.
    #   3. При успехе — post_install копирует в 3 dest_dirs + chmod 644 +
    #      chown root:xray.
    #   4. При провале — возвращает False (hint подавлен, т.к. ниже свой).
    #
    # ВАЖНО: fetch_package НЕ проверяет install_dests при поиске ручного
    # файла — только /root/. Это гарантируется PackageSpec.__post_init__
    # assert (manual_incoming_dir != install_dests). Баг 21d7baf невозможен.
    from chimera.modules.download_manager import fetch_package

    for spec, fname in (
        (GEOSITE_SPEC, "geosite.dat"),
        (GEOIP_SPEC,   "geoip.dat"),
    ):
        info(f"  Загрузка {fname}...")
        try:
            ok = fetch_package(spec, print_hint_on_failure=False)
        except Exception as ex:
            warn(f"  Ошибка загрузки {fname}: {ex}")
            ok = False
        if ok:
            if fname == "geosite.dat":
                geosite_ok = True
                info(f"  geosite.dat → {', '.join(str(d) for d in geo_dirs)}")
        else:
            warn(f"  Не удалось скачать {fname} из всех источников — split tunneling будет частично отключён")
            failed_files.append(fname)

    # ── EMERGENCY FALLBACK: прямой curl на GitHub (волна 2026-07) ──────────
    # Если fetch_package провален на всех зеркалах — пробуем прямой curl
    # на GitHub release URL. См. подробное обоснование в
    # geo_files.emergency_curl_fallback().
    #
    # ВАЖНО: НЕ импортируем XRAY_LOOKUP_DIRS здесь повторно — он уже
    # импортирован вверху модуля. Повторный `from ... import` внутри
    # функции сделал бы переменную локальной для всей функции и сломал
    # строку `dest_dirs_raw = list(XRAY_LOOKUP_DIRS) + ...` выше
    # (UnboundLocalError).
    if failed_files:
        info(f"  fetch_package провален для {len(failed_files)} файл(а/ов) — "
             f"пробую emergency curl fallback...")
        try:
            from chimera.modules.geo_files import emergency_curl_fallback
            # geo_dirs здесь может содержать /usr/local/bin/xray (родная
            # директория бинарника) — для fallback не нужно, копируем только
            # в стандартные XRAY_LOOKUP_DIRS (уже импортированы вверху модуля).
            # only_files=failed_files — качаем только недостающие, не трогая
            # уже успешно скачанные ( ).
            em_ok = emergency_curl_fallback(
                dest_dirs=list(XRAY_LOOKUP_DIRS),
                only_files=list(failed_files),
            )
        except Exception as ex:
            warn(f"  emergency curl fallback упал с исключением: {ex}")
            em_ok = False
        if em_ok:
            # Пересчитываем успех — какие файлы реально на месте.
            new_failed: list[str] = []
            for fname in failed_files:
                min_size = MIN_SIZES[fname]
                placed = any(
                    (d / fname).exists() and (d / fname).stat().st_size >= min_size
                    for d in XRAY_LOOKUP_DIRS
                )
                if placed:
                    if fname == "geosite.dat":
                        geosite_ok = True
                        info(f"  geosite.dat → {', '.join(str(d) for d in geo_dirs)} "
                             f"(через emergency curl)")
                else:
                    new_failed.append(fname)
            failed_files = new_failed
            if not failed_files:
                success("  emergency curl fallback спас обновление гео-файлов")
        else:
            warn("  emergency curl fallback тоже провален")

    # Если что-то не скачалось даже после emergency fallback — предлагаем ручное размещение
    if failed_files:
        warn(f"  Не удалось загрузить гео-файлы — проверьте интернет-соединение")
        _geo_print_manual_download_hint()
        try:
            ans = input(f"{CYAN}  Разместили файлы вручную? Повторить проверку? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            # Повторная проверка наличия файлов вручную
            # (Аналогично download_geo_files в geo_files.py — здесь проверяем
            # И _root/, И dest_dirs, потому что пользователь явно подтвердил
            # что положил файл куда-то. Это не баг 21d7baf, а intentional retry.)
            for fname, min_size in (
                ("geosite.dat", MIN_SIZES["geosite.dat"]),
                ("geoip.dat",   MIN_SIZES["geoip.dat"]),
            ):
                if fname not in failed_files:
                    continue
                for manual_dir in _MANUAL_ROOTS + geo_dirs:
                    candidate = manual_dir / fname
                    if candidate.exists() and candidate.stat().st_size >= min_size:
                        info(f"  Найден: {candidate} ({candidate.stat().st_size // 1024} КБ)")
                        for dest_dir in geo_dirs:
                            dest = dest_dir / fname
                            try:
                                shutil.copy2(candidate, dest)
                                dest.chmod(0o644)
                            except Exception:
                                pass
                        if fname == "geosite.dat":
                            geosite_ok = True
                        failed_files.remove(fname)
                        info(f"  {fname} → {', '.join(str(d) for d in geo_dirs)}")
                        break

    return geosite_ok


def _xray_do_upgrade(tag: str, is_prerelease: bool = False) -> bool:
    """
    Скачивает, верифицирует и устанавливает Xray версии tag.

    Порядок действий (после Wave 4 миграции на fetch_package):
      1. Обновить geo-файлы (если ещё не runetfreedom) — нужны для теста конфига.
      2. Бэкап старого бинарника (ДО замены — для rollback при ошибке теста).
      3. fetch_package(XRAY_ZIP_SPEC, tag, arch) — скачать zip + SHA256 verify +
         распаковка + copy xray → /usr/local/bin/xray + .dat preservation.
         10 зеркал (вместо одного прямого URL в старом коде).
      4. Тест конфига новым бинарником.
      5. При ошибке теста — восстановление старого бинарника из бэкапа.
      6. Cleanup старых бэкапов (оставляем 5 последних).

    Раньше (до миграции):
      • Один прямой URL https://github.com/XTLS/Xray-core/releases/download/{tag}/...
        БЕЗ зеркал, БЕЗ fallback. Если github.com заблокирован — обновление
        тихо падает.
      • Тест конфига делался ДО замены бинарника (new_bin во временной папке).
        При ошибке — abort без замены.

    Теперь:
      • 10 зеркал через fetch_package(XRAY_ZIP_SPEC) — jsDelivr/raw/release/gh-proxy/Statically.
      • Тест конфига делается ПОСЛЕ замены бинарника. При ошибке — rollback
        из бэкапа. Это эквивалентно по safety: если тест провален, бинарник
        возвращается к старой версии.
    """
    core = _core_module()
    _run    = core._run
    warn    = core.warn
    YELLOW, NC = core.YELLOW, core.NC
    GREEN   = core.GREEN
    info    = core.info
    success = core.success
    RED     = core.RED
    DIM     = core.DIM

    xray_bin_path = shutil.which("xray") or "/usr/local/bin/xray"
    xray_bin = Path(xray_bin_path)
    current_ver = _xray_current_version()

    arch_map = {"x86_64": "64", "aarch64": "arm64-v8a", "armv7l": "arm32-v7a"}
    machine = subprocess.check_output(["uname", "-m"]).decode().strip()
    xray_arch = arch_map.get(machine)
    if not xray_arch:
        warn(f"Архитектура {machine} не поддерживается")
        return False

    label = f"{YELLOW}[PRERELEASE]{NC}" if is_prerelease else f"{GREEN}[LATEST]{NC}"
    info(f"Скачиваю Xray {label} {tag} ...")

    # ── Шаг 1: убеждаемся что geo-файлы — runetfreedom-версия ──────────────
    # Проверяем наличие категории ru-available-only-inside в geosite.dat.
    # Если уже есть — не скачиваем повторно (файл ~65 MB, долго).
    print()
    if _xray_geo_is_runetfreedom():
        info("Geo-файлы runetfreedom уже установлены — пропускаем загрузку")
        geo_ok = True
    else:
        info("Обновляю geosite.dat / geoip.dat (runetfreedom)...")
        geo_ok = _xray_update_geo_runetfreedom()
        if not geo_ok:
            warn("Не удалось скачать geo-файлы runetfreedom.")
            warn("Обновите вручную и повторите:")
            warn("  curl -fsSL https://github.com/runetfreedom/russia-v2ray-rules-dat"
                 "/releases/latest/download/geosite.dat -o /usr/local/share/xray/geosite.dat")
            warn("  cp /usr/local/share/xray/geosite.dat /etc/xray/geosite.dat")
            return False
        success("Geo-файлы runetfreedom установлены")
    print()

    # ── Шаг 2: бэкап старого бинарника (ДО замены) ─────────────────────────
    # Нужен для rollback если тест конфига новым бинарником провалится.
    backup_dir = Path("/var/backups/xray/binaries")
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"xray_{current_ver}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    try:
        shutil.copy2(xray_bin, backup_path)
        backup_path.chmod(0o755)
        info(f"Бэкап бинарника: {backup_path}")
    except Exception as e:
        warn(f"Не удалось создать бэкап: {e}")
        backup_path = None

    # ── Шаг 3: скачивание + замена бинарника через fetch_package ───────────
    # fetch_package(XRAY_ZIP_SPEC) делает:
    #   1. Скачивание zip (10 зеркал через urllib — jsDelivr/raw/release/gh-proxy/Statically).
    #   2. ZIP magic проверка (PK\x03\x04).
    #   3. Скачивание checksums.txt через fetch_package(XRAY_CHECKSUMS_SPEC, tag=...).
    #   4. SHA256 верификация. При провале — False (пробуем следующее зеркало zip'а).
    #   5. Распаковка + copy xray → /usr/local/bin/xray (chmod 0o755).
    #   6. .dat preservation (skip если runetfreedom уже установлен >= threshold).
    # При провале всех зеркал / SHA256 — возвращает False.
    try:
        # Ленивый импорт — чтобы избежать circular imports на module load time.
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.xray_packages import (
            XRAY_ZIP_SPEC, _xray_zip_context,
        )
        # Устанавливаем контекст для post_install (tag/arch нужны для
        # скачивания правильного checksums.txt).
        _xray_zip_context["tag"] = tag
        _xray_zip_context["arch"] = xray_arch
        zip_ok = fetch_package(
            XRAY_ZIP_SPEC,
            tag=tag, arch=xray_arch,
            print_hint_on_failure=False,
        )
    except Exception as ex:
        warn(f"Ошибка загрузки Xray zip: {ex}")
        zip_ok = False

    if not zip_ok:
        warn(f"Ошибка загрузки Xray {tag} (все зеркала провалены)")
        return False

    # Сообщаем реальный статус SHA256 верификации (не печатаем ложное "ОК").
    # _XRAY_SHA256_STATUS устанавливается post_install'ом XRAY_ZIP_SPEC.
    from chimera.modules.xray_packages import _XRAY_SHA256_STATUS
    if _XRAY_SHA256_STATUS == "verified":
        success("SHA256 верификация: ОК")
    elif _XRAY_SHA256_STATUS == "skipped":
        warn("SHA256 верификация пропущена (checksums.txt недоступен по сети)")
    elif _XRAY_SHA256_STATUS == "no_tag":
        warn("SHA256 верификация пропущена (tag неизвестен)")
    elif _XRAY_SHA256_STATUS == "failed":
        # Этого не должно происходить — post_install возвращает False при failed.
        warn("SHA256 верификация провалилась (MITM?)")
    else:
        warn("SHA256 верификация: статус неизвестен")

    # ── Шаг 4: тест конфига новым бинарником ───────────────────────────────
    # Xray ищет geosite.dat/geoip.dat сначала рядом с бинарником
    # (os.Executable()), потом в системных путях (/usr/local/share/xray/).
    # Geo-файлы уже в /usr/local/share/xray/ (с шага 1) — новый бинарник
    # найдёт их автоматически.
    cfg_path = None
    for cp in (Path("/etc/xray/config.json"),
               Path("/usr/local/etc/xray/config.json")):
        if cp.exists():
            cfg_path = cp
            break

    if cfg_path:
        info("Тест конфига новым бинарником...")
        rt = _run(
            [str(xray_bin), "run", "-test", "-config", str(cfg_path)],
            capture=True, check=False,
        )
        if rt.returncode != 0:
            err_out = (rt.stderr.strip() or rt.stdout.strip())
            print()
            print(f"{RED}{'═'*64}{NC}")
            print(f"{RED}  ✗ ТЕСТ КОНФИГА НЕ ПРОШЁЛ{NC}")
            print(f"{RED}{'═'*64}{NC}")
            print(f"{DIM}{err_out}{NC}")
            print(f"{RED}{'═'*64}{NC}")
            # ── Rollback: восстанавливаем старый бинарник из бэкапа ──────
            if backup_path and backup_path.exists():
                warn(f"Откат к старому бинарнику ({current_ver})...")
                try:
                    xray_bin.unlink(missing_ok=True)
                    shutil.copy2(backup_path, xray_bin)
                    xray_bin.chmod(0o755)
                    info("Откат выполнен — бинарник восстановлен")
                except Exception as e:
                    warn(f"Не удалось откатить: {e}")
            else:
                warn("Бэкап недоступен — откат невозможен!")
            return False
        info("Тест конфига: ОК")

    # ── Шаг 5: cleanup старых бэкапов (оставляем 5 последних) ──────────────
    try:
        for old_b in sorted(backup_dir.glob("xray_*"))[:-5]:
            old_b.unlink(missing_ok=True)
    except Exception:
        pass

    return True


def _xray_restart_all_services() -> bool:
    """Перезапускает xray и nginx. Ждёт до 15 сек. Возвращает True если xray активен."""
    core = _core_module()
    info    = core.info
    _run    = core._run
    success = core.success

    info("Перезапуск Xray...")
    # (start-limit-fix): reset-failed перед рестартом (см.
    # вызовы после обновления бинарника идут в цепочке с другими рестартами)
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    _xray_active = False
    if callable(_safe_restart):
        _xray_active = _safe_restart(wait_active=15, attempts=2)
    else:
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        for i in range(1, 6):
            time.sleep(3)
            rs = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if rs.stdout.strip() == "active":
                _xray_active = True
                break
    if _xray_active:
        success("Xray запущен успешно")
        rn = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
        if rn.stdout.strip() == "active":
            _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
            info("Nginx перезапущен")
        return True
    return False


def _nginx_restart_if_reality() -> None:
    """
    Перезапускает nginx после restart xray при режиме REALITY+Unix-сокет.

    АРХИТЕКТУРА: при REALITY-режиме nginx слушает на unix:PARAM_SOCKET_PATH
    (listen unix:/dev/shm/XXXX.socket ssl proxy_protocol). Xray при старте
    выполняет ExecStartPre: rm -f PARAM_SOCKET_PATH — удаляет файл сокета.
    Сокет создаётся NGINX-ом при его (пере)запуске, не Xray-ом.

    BUGFIX: предыдущая логика ждала появления сокета ДО перезапуска nginx —
    deadlock, потому что сокет появляется только ПОСЛЕ запуска nginx.
    Исправление: сначала перезапускаем nginx (он создаёт сокет), затем ждём
    подтверждения что сокет появился.
    """
    core = _core_module()
    PROTOCOL_MODE = core.PROTOCOL_MODE
    PARAM_SOCKET_PATH = core.PARAM_SOCKET_PATH
    AWG_EXIT_ENABLED = core.AWG_EXIT_ENABLED
    _run    = core._run
    warn    = core.warn
    info    = core.info

    if PROTOCOL_MODE != "reality" or not PARAM_SOCKET_PATH:
        return
    # AWG-режим: Xray слушает напрямую на TCP-порту, unix-сокет не используется
    if AWG_EXIT_ENABLED:
        return
    rn = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
    if rn.stdout.strip() != "active":
        return
    # Перезапускаем nginx ПЕРВЫМ — он создаст bind на unix-сокет
    _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
    # Ждём подтверждения что сокет появился (nginx создаёт его при старте)
    for _i in range(20):
        if Path(PARAM_SOCKET_PATH).is_socket():
            break
        time.sleep(1)
    else:
        warn(f"Сокет {PARAM_SOCKET_PATH} не появился за 20 сек после restart nginx — проверьте: journalctl -u nginx -n 20")
        return
    time.sleep(1)
    info("nginx перезапущен, Unix-сокет готов")


def _xray_find_config() -> Path | None:
    """Возвращает актуальный путь к config.json (проверяет обе стандартные локации)."""
    for p in (Path("/etc/xray/config.json"),
              Path("/usr/local/etc/xray/config.json")):
        if p.exists():
            return p
    return None


def _xray_config_rollback(backup_cfg: Path, cfg: Path) -> None:
    """
    Откатывает config.json из резервной копии и перезапускает Xray.
    Вызывается когда xray не запустился после применения нового конфига.
    """
    core = _core_module()
    warn    = core.warn
    _set_config_owner = core._set_config_owner
    log_to_file = core.log_to_file
    _run    = core._run
    success = core.success

    warn("Откат конфигурации из резервной копии...")
    try:
        shutil.copy2(backup_cfg, cfg)
        _set_config_owner(cfg)
        log_to_file("WARN", f"Конфиг откатан из {backup_cfg} → {cfg}")
    except Exception as e:
        warn(f"Не удалось откатить конфиг: {e}")
        log_to_file("ERROR", f"Откат конфига провалился: {e}")
        return
    # (start-limit-fix): это ВТОРОЙ рестарт подряд после провала apply
    # без reset-failed именно здесь чаще всего ловится start-limit-hit
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    if callable(_safe_restart):
        _ok = _safe_restart(wait_active=15, attempts=2)
    else:
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(2)
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        _ok = r.stdout.strip() == "active"
    if _ok:
        success("Xray запущен на откатанном конфиге")
    else:
        warn("Xray не запустился даже после отката! Проверьте: journalctl -u xray -n 50")


def _ensure_sniffing_on_vless_inbounds(cfg_path: Path) -> None:
    """Автоматически включает sniffing на всех VLESS-инbound'ах.

    Если sniffing выключен — Xray не видит SNI внутри VLESS-туннеля,
    и routing по доменам (domain:...) не работает. Трафик уходит на
    exit-ноду вместо direct (где стоит b4).

    Эта функция вызывается из _xray_safe_apply_config ПЕРЕД валидацией.
    Она читает config.json, проверяет все inbounds с protocol=vless,
    и если sniffing выключен — включает его с destOverride=['http','tls'].

    Также обрабатывает tproxy-инbound'ы (protocol=vmess + tag=tproxy-*).
    """
    try:
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
    except Exception:
        return

    changed = False
    for ib in cfg.get("inbounds", []):
        proto = ib.get("protocol", "")
        tag = ib.get("tag", "")
        # VLESS-инbound'ы (основной + iOS shadow + любые другие).
        # TProxy-инbound'ы (для Telemt и др.).
        if proto in ("vless", "vmess") or tag.startswith("tproxy-"):
            sniffing = ib.get("sniffing", {})
            if not sniffing.get("enabled", False):
                ib["sniffing"] = {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                }
                changed = True
            elif "destOverride" not in sniffing:
                sniffing["destOverride"] = ["http", "tls"]
                ib["sniffing"] = sniffing
                changed = True

    if changed:
        try:
            with open(cfg_path, "w") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
        except Exception:
            pass


def _xray_safe_apply_config(cfg: Path | None = None,
                             *,
                             service_restart: bool = True) -> bool:
    """
    Безопасное применение конфига Xray:
      1. Находит cfg (если не передан явно).
      2. Создаёт временный бэкап текущего конфига.
      3. Запускает ``xray run -test`` — при ошибке останавливается (xray НЕ перезапускается).
      4. Синхронизирует вторую копию конфига (если есть).
      5. Делает ``systemctl restart xray`` и ждёт до 15 сек.
      6. Если xray не поднялся — автоматически откатывает конфиг из бэкапа.

    Возвращает True при успехе, False при любой ошибке.

    Используется вместо прямого ``systemctl restart xray`` везде, где конфиг мог измениться.
    """
    core = _core_module()
    warn    = core.warn
    _run    = core._run
    dim     = core.dim
    log_to_file = core.log_to_file
    _set_config_owner = core._set_config_owner
    success = core.success
    info    = core.info

    # ── 1. Найти конфиг ───────────────────────────────────────────────────────
    if cfg is None:
        cfg = _xray_find_config()
    if cfg is None:
        warn("_xray_safe_apply_config: конфиг Xray не найден")
        return False

    # ── 2. Бэкап текущего конфига ─────────────────────────────────────────────
    backup_cfg = cfg.with_suffix(".json.pre-apply")
    try:
        shutil.copy2(cfg, backup_cfg)
    except Exception as e:
        warn(f"Не удалось создать бэкап конфига: {e}. Применение отменено.")
        return False

    # ── 2.5. Авто-фикс sniffing на всех VLESS-инbound'ах ──────────────────────
    # Если на VLESS-инbound'е выключен sniffing — Xray не видит SNI внутри
    # туннеля, и routing по доменам (domain:...) не работает. Трафик уходит
    # на exit-ноду вместо direct (где стоит b4).
    # Автоматически включаем sniffing на всех inbound'ах с protocol=vless.
    _ensure_sniffing_on_vless_inbounds(cfg)

    # ── 3. Валидация ──────────────────────────────────────────────────────────
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    r = _run([xray_bin, "run", "-test", "-config", str(cfg)],
             capture=True, check=False)
    if r.returncode != 0:
        err_out = (r.stdout + r.stderr).strip()
        warn(f"xray -test: конфиг содержит ошибки — перезапуск отменён")
        if err_out:
            dim(f"  {err_out[:600]}")
        log_to_file("ERROR", f"xray -test провалился для {cfg}: {err_out[:400]}")
        try:
            backup_cfg.unlink(missing_ok=True)
        except Exception:
            pass
        return False

    # ── 4. Синхронизация второй копии конфига ─────────────────────────────────
    all_cfgs = [Path("/etc/xray/config.json"),
                Path("/usr/local/etc/xray/config.json")]
    for other in all_cfgs:
        if other != cfg and other.exists() and not other.is_symlink():
            try:
                shutil.copy2(cfg, other)
                _set_config_owner(other)
            except Exception as e:
                warn(f"Не удалось синхронизировать {other}: {e}")

    # ── 5. Перезапуск ─────────────────────────────────────────────────────────
    if not service_restart:
        backup_cfg.unlink(missing_ok=True)
        return True

    # (start-limit-fix): голый restart здесь — самый частый источник
    # start-limit-hit: _xray_safe_apply_config вызывается цепочками
    # (юзер добавлен → b4-сет импорт → routing-правило), каждый вызов =
    # restart. reset-failed через _core._xray_safe_restart снимает
    # счётчик StartLimitBurst юнита перед каждым рестартом.
    _safe_restart = getattr(core, "_xray_safe_restart", None)
    if callable(_safe_restart):
        restarted = _safe_restart(wait_active=15, attempts=2)
    else: # fallback для старого ядра без хелпера
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        restarted = False
        for i in range(1, 6):
            time.sleep(3)
            r2 = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r2.stdout.strip() == "active":
                restarted = True
                break
            info(f"Ожидание запуска Xray... ({i*3}/15 сек)")
    _nginx_restart_if_reality()

    if restarted:
        success("Xray перезапущен успешно (конфиг прошёл проверку)")
        log_to_file("SUCCESS", f"xray перезапущен после применения {cfg}")
        backup_cfg.unlink(missing_ok=True)
        return True

    # ── 6. Xray не поднялся — откат ───────────────────────────────────────────
    warn("Xray не запустился после применения конфига — запускаю откат")
    log_to_file("ERROR", "xray не запустился — откат конфига")
    _xray_config_rollback(backup_cfg, cfg)
    try:
        backup_cfg.unlink(missing_ok=True)
    except Exception:
        pass
    return False


def _xray_rollback(backup_path: Path) -> bool:
    """Откатывает бинарник из backup_path и перезапускает сервисы."""
    core = _core_module()
    warn    = core.warn
    info    = core.info

    xray_bin = Path(shutil.which("xray") or "/usr/local/bin/xray")
    try:
        shutil.copy2(backup_path, xray_bin)
        xray_bin.chmod(0o755)
        info(f"Бинарник откатан из: {backup_path}")
    except Exception as e:
        warn(f"Ошибка отката бинарника: {e}")
        return False
    return _xray_restart_all_services()


def do_xray_update_interactive() -> None:
    """
    Интерактивное обновление Xray из меню.
    Проверяет ветку latest И prerelease.
    Cron-задача использует только latest (xray-autoupdate.sh).
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    CYAN, NC = core.CYAN, core.NC
    DIM     = core.DIM
    BOLD    = core.BOLD
    GREEN   = core.GREEN
    RED     = core.RED
    YELLOW  = core.YELLOW
    info    = core.info
    success = core.success
    warn    = core.warn
    dim     = core.dim

    os.system("clear")
    print()
    _box_top("🔧  ОБНОВЛЕНИЕ XRAY-CORE")
    _box_row()
    current_ver = _xray_current_version()
    _box_row(f"  Текущая версия: {CYAN}{current_ver}{NC}")
    _box_sep()
    _box_row(f"  {DIM}Получение информации о релизах...{NC}")
    _box_bottom()
    print()

    info("Получение latest release...")
    latest_info = _xray_get_release_info(prerelease=False)
    latest_tag  = latest_info.get("tag_name", "") if latest_info else ""

    info("Получение prerelease info...")
    pre_info = _xray_get_release_info(prerelease=True)
    pre_tag  = pre_info.get("tag_name", "") if pre_info else ""
    is_pre   = pre_info.get("prerelease", False) if pre_info else False

    cur_norm    = _xray_version_norm(current_ver)
    latest_norm = _xray_version_norm(latest_tag) if latest_tag else cur_norm
    pre_norm    = _xray_version_norm(pre_tag) if pre_tag else cur_norm

    has_latest_update = bool(latest_tag and latest_norm > cur_norm)
    has_pre_update    = bool(pre_tag and is_pre and pre_norm > cur_norm and pre_tag != latest_tag)

    print()
    print(f"{CYAN}{'═'*64}{NC}")
    print(f"{CYAN}  ИНФОРМАЦИЯ О ВЕРСИЯХ{NC}")
    print(f"{CYAN}{'═'*64}{NC}")
    print(f"  Установлена:       {BOLD}{current_ver}{NC}")
    if latest_tag:
        marker = f"  {GREEN}← доступно{NC}" if has_latest_update else f"  {DIM}(актуально){NC}"
        print(f"  Stable (latest):   {GREEN}{latest_tag}{NC}{marker}")
    else:
        print(f"  Stable (latest):   {RED}не удалось получить{NC}")
    if pre_tag and is_pre:
        marker = f"  {YELLOW}← доступна prerelease{NC}" if has_pre_update else f"  {DIM}(не новее){NC}"
        print(f"  Prerelease:        {YELLOW}{pre_tag}{NC}{marker}")
    elif pre_tag:
        print(f"  Prerelease:        {DIM}отдельного prerelease нет{NC}")
    print(f"{CYAN}{'═'*64}{NC}")
    print()

    if not has_latest_update and not has_pre_update:
        success("Xray актуален. Обновлений нет.")
        return

    choices = []
    if has_latest_update:
        choices.append(("1", f"Обновить до {GREEN}stable{NC} {latest_tag}", latest_tag, False))
    if has_pre_update:
        choices.append(("2" if has_latest_update else "1",
                        f"Обновить до {YELLOW}prerelease{NC} {pre_tag}", pre_tag, True))

    for key, label, _t, _p in choices:
        print(f"  [{key}] {label}")
    print(f"  [Q] Отмена")
    print()

    target_tag    = None
    target_is_pre = False
    while True:
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            ch = "Q"
        if ch in ("Q", ""):
            info("Обновление отменено.")
            return
        for key, label, _t, _p in choices:
            if ch == key:
                target_tag, target_is_pre = _t, _p
                break
        if target_tag:
            break
        warn("Неверный выбор.")

    if target_is_pre:
        print()
        print(f"{YELLOW}{'═'*64}{NC}")
        print(f"{YELLOW}  ⚠  ВНИМАНИЕ: PRERELEASE ВЕРСИЯ{NC}")
        print(f"{YELLOW}{'═'*64}{NC}")
        print(f"  Версия {BOLD}{target_tag}{NC} является НЕСТАБИЛЬНОЙ (prerelease).")
        print(f"  Возможны: ошибки, изменение поведения, несовместимость.")
        print(f"  Автообновление по cron будет использовать только stable.")
        print(f"{YELLOW}{'═'*64}{NC}")
        print()
        try:
            confirm = input(
                f"{YELLOW}  Вы уверены? [y/N]:{NC} "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            confirm = "n"
        if confirm not in ("y", "yes"):
            info("Установка prerelease отменена.")
            return

    backup_dir = Path("/var/backups/xray/binaries")
    existing_backups_before = set(backup_dir.glob("xray_*")) if backup_dir.exists() else set()

    print()
    info(f"Начинаю обновление: {current_ver} → {target_tag} ...")
    ok = _xray_do_upgrade(target_tag, is_prerelease=target_is_pre)
    if not ok:
        warn("Обновление завершилось с ошибкой. Бинарник не заменён.")
        return

    xray_started = _xray_restart_all_services()
    new_ver = _xray_current_version()

    if xray_started:
        print()
        success(f"Xray успешно обновлён: {current_ver} → {new_ver}")
        if target_is_pre:
            warn("Установлена PRERELEASE версия. Следите за стабильностью.")
        dim("  Лог: /var/log/xray-autoupdate.log")
        return

    # Xray не запустился после установки
    print()
    print(f"{RED}{'═'*64}{NC}")
    print(f"{RED}  ✗ XRAY НЕ ЗАПУСТИЛСЯ ПОСЛЕ ОБНОВЛЕНИЯ{NC}")
    print(f"{RED}{'═'*64}{NC}")
    print()
    print(f"  Команда для просмотра причины:")
    print(f"  {BOLD}{CYAN}journalctl -u xray -n 50 --no-pager{NC}")
    print(f"{RED}{'═'*64}{NC}")
    print()

    all_backups  = sorted(backup_dir.glob("xray_*")) if backup_dir.exists() else []
    new_backups  = [b for b in all_backups if b not in existing_backups_before]
    rollback_src = new_backups[-1] if new_backups else (all_backups[-1] if all_backups else None)

    if rollback_src:
        rollback_ver = rollback_src.name.split("_")[1] if "_" in rollback_src.name else "предыдущая"
        print(f"  Доступен откат на: {GREEN}{rollback_ver}{NC}  ({DIM}{rollback_src}{NC})")
        print()
        try:
            ans = input(f"{CYAN}  Откатиться? [Y/n]:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "n"
        if ans in ("y", "yes", ""):
            info(f"Откат на {rollback_ver}...")
            if _xray_rollback(rollback_src):
                print()
                success(f"Откат выполнен. Xray работает на версии: {_xray_current_version()}")
                success("Все сервисы запущены. Система готова к использованию.")
            else:
                print()
                print(f"{RED}✗ Xray не запустился и после отката!{NC}")
                print(f"  {BOLD}{CYAN}journalctl -u xray -n 50 --no-pager{NC}")
                print(f"  {BOLD}{CYAN}xray run -test -config /etc/xray/config.json{NC}")
        else:
            warn("Откат отменён. Xray остаётся в нерабочем состоянии.")
    else:
        warn("Бэкап не найден — автоматический откат невозможен.")
        warn("Переустановите Xray через пункт меню [1].")


def setup_xray_autoupdate() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    CYAN, NC = core.CYAN, core.NC
    warn    = core.warn

    print()  # перевод строки после прогресс-бара (он оставляет курсор без \n)
    _box_top(f"Автообновление Xray-core")
    _box_row()
    _box_row()
    _box_item("Y", f"Включить автообновление (systemd timer, ежедневно 03:30)")
    _box_item("N", f"Отключить — обновлять вручную")
    _box_sep()
    _box_bottom()

    while True:
        choice = input(
            f"{CYAN}Включить автообновление Xray? [Y/n]:{NC} "
        ).strip().lower()
        if choice in ('y', 'yes', ''):
            _install_autoupdate_service()
            break
        elif choice in ('n', 'no'):
            break
        warn("Введите Y или N")


def _install_autoupdate_service() -> None:
    core = _core_module()
    info    = core.info
    _run    = core._run
    success = core.success
    dim     = core.dim

    info("Установка сервиса автообновления Xray...")
    agent = Path("/usr/local/bin/xray-autoupdate.sh")

    agent.write_text(textwrap.dedent(r"""
        #!/usr/bin/env bash
        set -euo pipefail
        LOG="/var/log/xray-autoupdate.log"
        BACKUP_DIR="/var/backups/xray/binaries"

        # Ротация лога выполняется logrotate (/etc/logrotate.d/xray-aux).
        touch "$LOG" 2>/dev/null || true
        chmod 600 "$LOG" 2>/dev/null || true
        log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null || true; }

        log "=== Проверка обновлений Xray-core ==="
        XRAY_BIN=$(command -v xray 2>/dev/null || echo /usr/local/bin/xray)
        [[ ! -x "$XRAY_BIN" ]] && log "ERROR: Xray не найден" && exit 1

        CURRENT_RAW=$("$XRAY_BIN" version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        CURRENT="v${CURRENT_RAW:-0.0.0}"
        log "Установлена: $CURRENT"

        LATEST=$(curl -fsSL --connect-timeout 15 \
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest" \
            2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tag_name',''))" 2>/dev/null || true)
        [[ -z "$LATEST" ]] && log "WARN: Не удалось получить latest" && exit 0
        log "Последняя: $LATEST"

        _norm() { echo "$1" | sed 's/^v//' | tr '.' ' ' | awk '{printf "%05d%05d%05d\n", $1, $2, $3}'; }
        [[ "$(_norm "$CURRENT")" == "$(_norm "$LATEST")" ]] && log "INFO: Версия актуальна" && exit 0

        log "INFO: Обновление $CURRENT → $LATEST"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  XRAY_ARCH="64" ;;
            aarch64) XRAY_ARCH="arm64-v8a" ;;
            armv7*)  XRAY_ARCH="arm32-v7a" ;;
            *) log "ERROR: Архитектура $ARCH не поддерживается" && exit 1 ;;
        esac

        mkdir -p "$BACKUP_DIR"
        BACKUP="${BACKUP_DIR}/xray_${CURRENT}_$(date +%Y%m%d%H%M%S)"
        cp "$XRAY_BIN" "$BACKUP" && chmod 755 "$BACKUP" || true
        ls -t "${BACKUP_DIR}"/xray_* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

        ZIP_NAME="Xray-linux-${XRAY_ARCH}.zip"
        ZIP_URL="https://github.com/XTLS/Xray-core/releases/download/${LATEST}/${ZIP_NAME}"
        ZIP_TMP=$(mktemp /tmp/xray_au.XXXXXX.zip)
        EXTRACT_DIR=$(mktemp -d /tmp/xray_au_ex.XXXXXX)
        trap 'rm -f "$ZIP_TMP" 2>/dev/null; rm -rf "$EXTRACT_DIR" 2>/dev/null' EXIT

        curl -fsSL --connect-timeout 30 --retry 3 "$ZIP_URL" -o "$ZIP_TMP" 2>/dev/null || \
            { log "ERROR: Ошибка загрузки"; exit 1; }

        CHKS_TMP=$(mktemp /tmp/xray_chk.XXXXXX.txt)
        CHKS_URL="https://github.com/XTLS/Xray-core/releases/download/${LATEST}/checksums.txt"
        if curl -fsSL --connect-timeout 10 "$CHKS_URL" -o "$CHKS_TMP" 2>/dev/null && [[ -s "$CHKS_TMP" ]]; then
            EXPECTED=$(grep -E "^[0-9a-f]{64}[[:space:]]+\*?${ZIP_NAME}$" "$CHKS_TMP" | awk '{print $1}' || true)
            rm -f "$CHKS_TMP"
            if [[ -n "$EXPECTED" ]]; then
                ACTUAL=$(sha256sum "$ZIP_TMP" | awk '{print $1}')
                if [[ "$ACTUAL" != "$EXPECTED" ]]; then
                    log "ERROR: SHA256 не совпал!"
                    exit 1
                fi
                log "INFO: SHA256 OK"
            fi
        else
            rm -f "$CHKS_TMP" 2>/dev/null || true
            log "WARN: checksums.txt недоступен — без верификации"
        fi

        unzip -o "$ZIP_TMP" -d "$EXTRACT_DIR" &>/dev/null || true
        NEW_BIN="${EXTRACT_DIR}/xray"
        [[ ! -x "$NEW_BIN" ]] && log "ERROR: Бинарник не найден в архиве" && exit 1

        CFG_PATH=""
        [[ -f /etc/xray/config.json ]] && CFG_PATH="/etc/xray/config.json"
        [[ -z "$CFG_PATH" && -f /usr/local/etc/xray/config.json ]] && CFG_PATH="/usr/local/etc/xray/config.json"
        if [[ -n "$CFG_PATH" ]]; then
            "$NEW_BIN" run -test -config "$CFG_PATH" &>/dev/null || \
                { log "ERROR: Тест конфига провален — откат"; exit 1; }
        fi

        cp "$NEW_BIN" "$XRAY_BIN" && chmod 755 "$XRAY_BIN"

        # Не перезатираем runetfreedom geo-файлы стандартными из zip XTLS.
        for DAT_FILE in "${EXTRACT_DIR}"/*.dat; do
            [[ -f "$DAT_FILE" ]] || continue
            DAT_NAME=$(basename "$DAT_FILE")
            DEST="/usr/local/share/xray/${DAT_NAME}"
            THRESHOLD=0
            [[ "$DAT_NAME" == "geosite.dat" ]] && THRESHOLD=$((10 * 1024 * 1024))
            [[ "$DAT_NAME" == "geoip.dat"   ]] && THRESHOLD=$((15 * 1024 * 1024))
            if [[ "$THRESHOLD" -gt 0 && -f "$DEST" ]]; then
                DEST_SIZE=$(stat -c%s "$DEST" 2>/dev/null || echo 0)
                if [[ "$DEST_SIZE" -ge "$THRESHOLD" ]]; then
                    log "INFO: Сохранён runetfreedom ${DAT_NAME} — zip пропущен"
                    continue
                fi
            fi
            cp "$DAT_FILE" "$DEST" 2>/dev/null || true
        done

        # (start-limit-fix): reset-failed — автообновление может совпасть
        # с другими рестартами xray в том же окне StartLimitBurst
        systemctl reset-failed xray 2>/dev/null || true
        systemctl restart xray 2>/dev/null || true
        # Ждём запуска до 15 секунд (по 3 сек × 5 попыток)
        XRAY_OK=0
        for _i in 1 2 3 4 5; do
            sleep 3
            if systemctl is-active --quiet xray 2>/dev/null; then
                XRAY_OK=1
                break
            fi
        done

        if [[ "$XRAY_OK" -eq 0 ]]; then
            log "ERROR: Xray не запустился за 15 сек — откат к $CURRENT"
            cp "$BACKUP" "$XRAY_BIN" && chmod 755 "$XRAY_BIN" || true
            systemctl reset-failed xray 2>/dev/null || true
            systemctl restart xray 2>/dev/null || true
            python3 "$(readlink -f "$0" 2>/dev/null || echo "$0")" --tg-event xray_down "🔴 Autoupdate ОШИБКА: Xray не запустился после $LATEST — откат к $CURRENT" 2>/dev/null || true
            exit 1
        fi

        NEW_VER=$("$XRAY_BIN" version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        log "OK: Обновлён $CURRENT → v${NEW_VER:-?}. Бэкап: $BACKUP"
        INSTALLER=$(cat /var/lib/xray-installer/installer_path 2>/dev/null || echo "")
        [[ -n "$INSTALLER" ]] && python3 "$INSTALLER" --tg-event xray_up "✅ Autoupdate: Xray обновлён $CURRENT → v${NEW_VER:-?}" 2>/dev/null || true
    """).lstrip())
    agent.chmod(0o700)

    Path("/etc/systemd/system/xray-autoupdate.service").write_text(textwrap.dedent("""\
        [Unit]
        Description=Xray-core Auto-Update
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart=/usr/local/bin/xray-autoupdate.sh
        StandardOutput=journal
        StandardError=journal
        TimeoutStartSec=300
        SuccessExitStatus=0 1
    """))

    Path("/etc/systemd/system/xray-autoupdate.timer").write_text(textwrap.dedent("""\
        [Unit]
        Description=Xray-core Auto-Update Timer

        [Timer]
        OnCalendar=*-*-* 03:30:00
        RandomizedDelaySec=1800
        Persistent=true

        [Install]
        WantedBy=timers.target
    """))

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "xray-autoupdate.timer"], check=False, quiet=True)
    _run(["systemctl", "start",  "xray-autoupdate.timer"], check=False, quiet=True)

    # Сохраняем путь к инсталлятору для вызова --tg-event из bash-скриптов
    try:
        _installer_path = Path(sys.argv[0]).resolve()
        Path("/var/lib/xray-installer").mkdir(parents=True, exist_ok=True)
        Path("/var/lib/xray-installer/installer_path").write_text(str(_installer_path))
    except Exception:
        pass

    success("Автообновление Xray настроено (ежедневно 03:30)")
    dim("  Лог: /var/log/xray-autoupdate.log")
    dim("  Бэкапы: /var/backups/xray/binaries/ (5 последних)")
