"""
vless_installer/modules/geo_files.py
───────────────────────────────────────────────────────────────────────────────
Загрузка и обновление geosite.dat / geoip.dat для split tunneling.

  • download_geo_files()      — скачивает с runetfreedom (с 8 зеркал-фолбэков),
                                 проверяет min size, копирует в /etc/xray,
                                 /usr/local/share/xray, /usr/local/etc/xray.
                                 Поддерживает ручное размещение в /root/.
  • setup_geo_autoupdate()    — cron every Sunday 03:00 + bash-скрипт с
                                 restart xray+nginx (для REALITY+Unix-сокет).
  • do_manage_geo_update()    — меню: обновить сейчас / вкл-выкл cron /
                                 показать лог. Мутирует SPLIT_TUNNEL_ENABLED
                                 в _core (через setattr, для форсирования
                                 загрузки).

Точки входа из _core.py:
    from vless_installer.modules.geo_files import (
        download_geo_files, setup_geo_autoupdate, do_manage_geo_update,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import shutil
import textwrap
import time
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  ЗАГРУЗКА GEO-ФАЙЛОВ
# ============================================================================
def download_geo_files() -> bool:
    """Скачивает актуальные geosite.dat и geoip.dat с runetfreedom.

    FIX: Xray ищет dat-файлы в нескольких местах (/etc/xray/ и /usr/local/share/xray/).
    Официальный установщик XTLS кладёт их только в /usr/local/share/xray/, поэтому
    копируем в ОБЕ директории и корректно выставляем права и владельца.
    При неудаче — выводим все известные ссылки и предлагаем ручное размещение.
    """
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _run    = core._run
    _geo_print_manual_download_hint = core._geo_print_manual_download_hint
    CONFIG_DIR  = core.CONFIG_DIR
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    GEOSITE_URL = core.GEOSITE_URL
    GEOIP_URL   = core.GEOIP_URL
    CYAN, NC, DIM = core.CYAN, core.NC, core.DIM

    info("Загрузка geosite.dat и geoip.dat (runetfreedom)...")
    info("  (первый запуск может занять 1–3 мин — скачивается ~30 МБ)")

    # Гарантируем наличие обеих директорий
    XRAY_SHARE_DIR = Path("/usr/local/share/xray")
    XRAY_ETC_DIR   = Path("/usr/local/etc/xray")
    for d in (CONFIG_DIR, XRAY_SHARE_DIR, XRAY_ETC_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Все известные зеркала
    GEOSITE_URLS = [
        "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/geosite.dat",
        GEOSITE_URL,
        "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://ghproxy.net/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://ghproxy.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://mirror.ghproxy.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://gh.con.sh/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://hub.gitmirror.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://github.moeyy.xyz/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
    ]
    GEOIP_URLS = [
        "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/geoip.dat",
        GEOIP_URL,
        "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://ghproxy.net/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://ghproxy.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://mirror.ghproxy.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://gh.con.sh/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://hub.gitmirror.com/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://github.moeyy.xyz/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
    ]

    print()
    info("  Зеркала geosite.dat:")
    for url in GEOSITE_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    info("  Зеркала geoip.dat:")
    for url in GEOIP_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    print()

    dest_dirs = [CONFIG_DIR, XRAY_SHARE_DIR, XRAY_ETC_DIR]
    _MANUAL_ROOTS = [Path("/root")]

    success_count = 0
    failed_files: list[str] = []

    for urls, fname, min_size in (
        (GEOSITE_URLS, "geosite.dat", 3_000_000),
        (GEOIP_URLS,   "geoip.dat",   10_000),
    ):
        info(f"  Загрузка {fname}...")
        tmp_path = Path(f"/tmp/{fname}")
        downloaded = False

        try:
            # Сначала проверяем ручно размещённые файлы
            for manual_dir in _MANUAL_ROOTS:
                candidate = manual_dir / fname
                if candidate.exists() and candidate.stat().st_size >= min_size:
                    info(f"  Найден файл пользователя: {candidate} ({candidate.stat().st_size // 1024} КБ)")
                    shutil.copy2(candidate, tmp_path)
                    downloaded = True
                    break

            if not downloaded:
                for url in urls:
                    tmp_path.unlink(missing_ok=True)
                    r = _run([
                        "curl", "-fL", "--connect-timeout", "15",
                        "-m", "180", "--retry", "0",
                        "-o", str(tmp_path), url,
                    ], capture=True, check=False, quiet=True)
                    if r.returncode == 0 and tmp_path.exists() and tmp_path.stat().st_size > min_size:
                        downloaded = True
                        info(f"  Загружено с: {url.split('/')[2]}")
                        break
                    actual = tmp_path.stat().st_size if tmp_path.exists() else 0
                    warn(f"  curl {url.split('/')[2]}: код {r.returncode}, размер {actual} Б — пробую следующий...")

            if not downloaded:
                # Последняя попытка: wget
                tmp_path.unlink(missing_ok=True)
                r2 = _run([
                    "wget", "-q", "--timeout=60", "--tries=2",
                    "-O", str(tmp_path), urls[0],
                ], capture=True, check=False, quiet=True)
                if r2.returncode == 0 and tmp_path.exists() and tmp_path.stat().st_size > min_size:
                    downloaded = True
                else:
                    warn(f"  ✗ Не удалось скачать {fname} из всех источников — split tunneling будет частично отключён")
                    tmp_path.unlink(missing_ok=True)
                    failed_files.append(fname)
                    continue

            if downloaded:
                size_kb = tmp_path.stat().st_size // 1024
                for dest_dir in dest_dirs:
                    dest = dest_dir / fname
                    try:
                        shutil.copy2(str(tmp_path), str(dest))
                        dest.chmod(0o644)
                        try:
                            _run(["chown", "root:xray", str(dest)], check=False, quiet=True)
                        except Exception:
                            pass
                    except Exception:
                        pass
                tmp_path.unlink(missing_ok=True)
                success(f"  ✓ {fname} ({size_kb} КБ) → {', '.join(str(d) for d in dest_dirs)}")
                success_count += 1

        except Exception as ex:
            warn(f"  Ошибка загрузки {fname}: {ex}")
            tmp_path.unlink(missing_ok=True)
            failed_files.append(fname)

    if failed_files:
        warn("Не удалось загрузить гео-файлы — проверьте интернет-соединение")
        _geo_print_manual_download_hint()
        try:
            ans = input(f"{CYAN}  Разместили файлы вручную? Повторить проверку? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            for fname, min_size in (("geosite.dat", 3_000_000), ("geoip.dat", 10_000)):
                if fname not in failed_files:
                    continue
                for manual_dir in _MANUAL_ROOTS + dest_dirs:
                    candidate = manual_dir / fname
                    if candidate.exists() and candidate.stat().st_size >= min_size:
                        info(f"  Найден: {candidate}")
                        for dest_dir in dest_dirs:
                            dest = dest_dir / fname
                            try:
                                shutil.copy2(candidate, dest)
                                dest.chmod(0o644)
                            except Exception:
                                pass
                        success_count += 1
                        failed_files.remove(fname)
                        break

    if success_count == 2:
        success("Geo-файлы готовы")
        return True
    elif success_count == 1:
        warn("Загружен только один geo-файл — split tunneling может работать некорректно")
        return True
    else:
        warn("Не удалось загрузить geo-файлы — проверьте интернет-соединение")
        warn("Split tunneling будет отключён для этой установки")
        warn("Geo-файлы можно загрузить позже: разместите geosite.dat и geoip.dat в /usr/local/share/xray/")
        return False


# ============================================================================
#  АВТООБНОВЛЕНИЕ GEO-ФАЙЛОВ (cron)
# ============================================================================
def setup_geo_autoupdate() -> None:
    """Создаёт cron-задачу для еженедельного обновления geo-файлов."""
    core = _core_module()
    success = core.success
    warn    = core.warn
    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    GEOSITE_URL = core.GEOSITE_URL
    GEOIP_URL   = core.GEOIP_URL

    if not SPLIT_TUNNEL_ENABLED:
        return

    script = Path("/usr/local/bin/xray-geo-update.sh")
    script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Автообновление geosite/geoip для split tunneling (runetfreedom)
        set -euo pipefail
        LOG="/var/log/xray-geo-update.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Обновление geo-файлов..." >> "$LOG"

        # FIX: гарантируем наличие обеих директорий
        mkdir -p /etc/xray /usr/local/share/xray

        download_file() {{
            local url="$1" dest_etc="$2" dest_share="$3" name="$4"
            local tmp="/tmp/${{name}}.tmp"
            if curl -fsSL --connect-timeout 30 -m 120 --retry 3 -o "$tmp" "$url"; then
                SIZE=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
                if [ "$SIZE" -gt 10000 ]; then
                    # FIX: копируем в обе директории, где Xray ищет dat-файлы
                    cp "$tmp" "$dest_etc"
                    cp "$tmp" "$dest_share"
                    chmod 644 "$dest_etc" "$dest_share"
                    chown root:xray "$dest_etc" "$dest_share" 2>/dev/null || true
                    rm -f "$tmp"
                    echo "[$DATE] ✓ $name обновлён ($(($SIZE / 1024)) КБ)" >> "$LOG"
                    return 0
                fi
            fi
            rm -f "$tmp"
            echo "[$DATE] ✗ Не удалось обновить $name" >> "$LOG"
            return 1
        }}

        CHANGED=0
        download_file "{GEOSITE_URL}" "{GEOSITE_DAT}" "/usr/local/share/xray/geosite.dat" "geosite.dat" && CHANGED=1
        download_file "{GEOIP_URL}"   "{GEOIP_DAT}"   "/usr/local/share/xray/geoip.dat"   "geoip.dat"   && CHANGED=1

        if [ "$CHANGED" = "1" ]; then
            # Xray 26.x не поддерживает горячий reload через SIGHUP —
            # используем restart напрямую (ExecReload в юните тоже делает restart).
            if systemctl is-active --quiet xray 2>/dev/null; then
                systemctl restart xray 2>/dev/null \\
                    && echo "[$DATE] Xray перезапущен (geo обновлён)" >> "$LOG" \\
                    || echo "[$DATE] Ошибка перезапуска Xray" >> "$LOG"
            else
                systemctl start xray 2>/dev/null \\
                    && echo "[$DATE] Xray запущен" >> "$LOG" \\
                    || echo "[$DATE] Ошибка запуска Xray" >> "$LOG"
            fi
            # BUGFIX: при REALITY+Unix-сокет Xray создаёт новый /dev/shm/*.socket
            # при каждом перезапуске. nginx держит upstream на старый (удалённый)
            # сокет и все клиенты получают EOF до перезапуска nginx.
            # Ждём до 20с появления нового сокета, затем перезапускаем nginx.
            if systemctl is-active --quiet nginx 2>/dev/null; then
                for i in $(seq 1 20); do
                    if ls /dev/shm/*.socket 2>/dev/null | head -1 | grep -q .; then
                        systemctl restart nginx 2>/dev/null \\
                            && echo "[$DATE] nginx перезапущен (новый Unix-сокет xray)" >> "$LOG" \\
                            || echo "[$DATE] Ошибка перезапуска nginx" >> "$LOG"
                        break
                    fi
                    sleep 1
                done
            fi
        fi
        # Ротация лога выполняется logrotate (/etc/logrotate.d/xray-aux).
    """))
    script.chmod(0o750)

    # Добавляем в cron (каждое воскресенье в 03:00)
    cron_line = f"0 3 * * 0 root {script}\n"
    cron_file = Path("/etc/cron.d/xray-geo-update")
    try:
        cron_file.write_text(f"# Автообновление geo-файлов для Xray split tunneling\n{cron_line}")
        cron_file.chmod(0o644)
        success("Автообновление geo-файлов: каждое воскресенье в 03:00")
    except Exception as e:
        warn(f"Не удалось создать cron для geo-файлов: {e}")


# ============================================================================
#  МЕНЮ УПРАВЛЕНИЯ GEO-ФАЙЛАМИ
# ============================================================================
def do_manage_geo_update() -> None:
    """Меню управления geo-файлами и их автообновлением."""
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    _apply_split_tunnel_config_from_state = core._apply_split_tunnel_config_from_state
    BLUE = core.BLUE
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, DIM, GREEN, YELLOW, RED, BLUE = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED, core.BLUE
    )

    cron_path = Path("/etc/cron.d/xray-geo-update")

    while True:
        os.system("clear")
        print()
        _box_top(f"Управление GeoIP/GeoSite файлами")

        # Статус файлов
        for path, label in (
            (GEOSITE_DAT,                              "geosite.dat (/etc/xray)"),
            (GEOIP_DAT,                                "geoip.dat   (/etc/xray)"),
            (Path("/usr/local/share/xray/geosite.dat"), "geosite.dat (/share/xray)"),
            (Path("/usr/local/share/xray/geoip.dat"),   "geoip.dat   (/share/xray)"),
        ):
            if path.exists():
                sz   = path.stat().st_size // 1024
                age  = (time.time() - path.stat().st_mtime) / 86400
                col  = GREEN if age < 14 else YELLOW
                _box_row(f"  {col}✓{NC} {label:<38} {sz:>6} КБ  возраст {age:.0f} дн.")
            else:
                _box_row(f"  {RED}✗{NC} {label:<38} {RED}НЕ НАЙДЕН{NC}")

        cron_active = cron_path.exists()
        _box_row(f"  Авто-обновление:  {''+GREEN+'ВКЛЮЧЕНО'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЕНО'+NC}")
        _box_item("1", f"Обновить geo-файлы прямо сейчас")
        _box_item("2", f"{'Отключить' if cron_active else 'Включить'} еженедельное авто-обновление (cron)")
        _box_item("3", f"Показать лог обновлений")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            # Используем существующую функцию download_geo_files,
            # но форсируем загрузку независимо от SPLIT_TUNNEL_ENABLED
            _saved = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
            setattr(core, "SPLIT_TUNNEL_ENABLED", True)
            ok = download_geo_files()
            setattr(core, "SPLIT_TUNNEL_ENABLED", _saved)
            if ok:
                success("Geo-файлы успешно обновлены")
                # BUGFIX: после перезапуска Xray с REALITY+Unix-сокет создаётся
                # НОВЫЙ сокет в /dev/shm/. nginx держит upstream на старый (уже
                # несуществующий) сокет — все клиенты получают EOF до тех пор,
                # пока nginx не будет перезапущен. Голый `systemctl restart xray`
                # не решает проблему — нужна пересборка конфига через
                # _apply_split_tunnel_config_from_state(), которая вызывает
                # _rebuild_and_restart_xray() с ожиданием нового сокета и
                # перезапуском nginx.
                ans = input(f"{CYAN}Применить конфиг и перезапустить Xray (рекомендуется)? [Y/n]:{NC} ").strip().lower()
                if ans in ("", "y"):
                    info("Пересобираю конфиг и перезапускаю Xray+nginx...")
                    _apply_split_tunnel_config_from_state()
            else:
                warn("Не удалось обновить geo-файлы — проверьте интернет")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if cron_active:
                cron_path.unlink(missing_ok=True)
                geo_script = Path("/usr/local/bin/xray-geo-update.sh")
                geo_script.unlink(missing_ok=True)
                success("Авто-обновление geo-файлов отключено")
            else:
                # Используем setup_geo_autoupdate если split tunnel включён,
                # иначе устанавливаем standalone cron
                _saved2 = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
                setattr(core, "SPLIT_TUNNEL_ENABLED", True)
                setup_geo_autoupdate()
                setattr(core, "SPLIT_TUNNEL_ENABLED", _saved2)
                success("Авто-обновление geo-файлов включено (каждое воскресенье 03:00)")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            log_path = Path("/var/log/xray-geo-update.log")
            if log_path.exists():
                lines = log_path.read_text().splitlines()
                print()
                print()
                _box_top(f"Последние 30 строк лога")
                _box_row()
                for _l in lines[-30:]:
                    _box_row(f"  {DIM}{_l}{NC}")
                _box_row()
                _box_bottom()
            else:
                warn("Лог /var/log/xray-geo-update.log не найден (обновлений ещё не было)")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
