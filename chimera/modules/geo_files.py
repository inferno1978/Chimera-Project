"""
chimera/modules/geo_files.py
───────────────────────────────────────────────────────────────────────────────
Загрузка и обновление geosite.dat / geoip.dat для split tunneling.

  • download_geo_files()      — скачивает через download_manager.fetch_package()
                                 с PackageSpec из geo_packages.py.
                                 14 зеркал-фолбэков (через github_mirrors.py),
                                 копирование в /etc/xray, /usr/local/share/xray,
                                 /usr/local/etc/xray. Ручное размещение в /root/.
  • setup_geo_autoupdate()    — cron every Sunday 03:00 + bash-скрипт с
                                 multi-mirror fallback и restart xray+nginx
                                 (для REALITY+Unix-сокет).
  • do_manage_geo_update()    — меню: обновить сейчас / вкл-выкл cron /
                                 показать лог / показать ссылки для ручного
                                 скачивания.

АРХИТЕКТУРНАЯ ЗАЩИТА ОТ БАГА 21d7baf:
  download_geo_files() вызывает fetch_package(GEOSITE_SPEC) / fetch_package(GEOIP_SPEC).
  PackageSpec.__post_init__ assert гарантирует что manual_incoming_dir (/root/)
  НЕ совпадает ни с одним install_dest. Поэтому безусловная проверка ручного
  размещения ищет ТОЛЬКО в /root/ — файл в install_dests (от предыдущего
  запуска) НЕ блокирует повторное сетевое скачивание. Баг 21d7baf физически
  невозможен по конструкции.

Точки входа из _core.py:
    from chimera.modules.geo_files import (
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

from chimera.modules.geo_mirrors import (
    get_geosite_urls, get_geoip_urls,
    MANUAL_UPLOAD_PATHS, XRAY_LOOKUP_DIRS, MIN_SIZES,
    GEO_MIRRORS_COUNT, recommended_manual_path,
)
from chimera.modules.download_manager import fetch_package
from chimera.modules.geo_packages import GEOSITE_SPEC, GEOIP_SPEC


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  ЗАГРУЗКА GEO-ФАЙЛОВ
# ============================================================================
def download_geo_files() -> bool:
    """Скачивает актуальные geosite.dat и geoip.dat через download_manager.

    Использует fetch_package() с PackageSpec из geo_packages.py.
    PackageSpec.__post_init__ assert гарантирует что manual_incoming_dir
    (/root/) не совпадает ни с одним install_dest — баг 21d7baf (повторный
    вызов находит свой же файл в install_dests и не идёт в сеть) физически
    невозможен.

    FIX: Xray ищет dat-файлы в нескольких местах (/etc/xray/ и /usr/local/share/xray/).
    Официальный установщик XTLS кладёт их только в /usr/local/share/xray/, поэтому
    копируем в ОБЕ директории и корректно выставляем права и владельца.
    При неудаче — выводим все известные ссылки и предлагаем ручное размещение.
    """
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _geo_print_manual_download_hint = core._geo_print_manual_download_hint
    CONFIG_DIR  = core.CONFIG_DIR
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    CYAN, NC, DIM = core.CYAN, core.NC, core.DIM

    info(f"Загрузка geosite.dat и geoip.dat (через {GEO_MIRRORS_COUNT} зеркал)...")
    info("  (первый запуск может занять 1–3 мин — скачивается ~30 МБ)")

    # Гарантируем наличие обеих директорий
    XRAY_SHARE_DIR = Path("/usr/local/share/xray")
    XRAY_ETC_DIR   = Path("/usr/local/etc/xray")
    for d in (CONFIG_DIR, XRAY_SHARE_DIR, XRAY_ETC_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Показываем зеркала (первые 4) — для информативности
    GEOSITE_URLS = get_geosite_urls()
    GEOIP_URLS   = get_geoip_urls()
    print()
    info("  Зеркала geosite.dat (первые 4 из списка):")
    for url in GEOSITE_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    info("  Зеркала geoip.dat (первые 4 из списка):")
    for url in GEOIP_URLS[:4]:
        print(f"    {DIM}{url}{NC}")
    print()

    dest_dirs = [CONFIG_DIR, XRAY_SHARE_DIR, XRAY_ETC_DIR]

    success_count = 0
    failed_files: list[str] = []

    # ── Скачивание через fetch_package (download_manager.py) ────────────────
    # fetch_package сам:
    #   1. Проверяет /root/{filename} (manual_incoming_dir из PackageSpec) —
    #      если найден, использует без сети.
    #   2. Иначе — перебирает 14 зеркал через urllib.
    #   3. При успехе — post_install копирует в 3 dest_dirs + chmod + chown.
    #   4. При провале — возвращает False (hint подавлен, т.к. ниже свой).
    #
    # ВАЖНО: fetch_package НЕ проверяет install_dests при поиске ручного
    # файла — только /root/. Это гарантируется PackageSpec.__post_init__
    # assert (manual_incoming_dir != install_dests). Баг 21d7baf невозможен.
    for spec, fname in (
        (GEOSITE_SPEC, "geosite.dat"),
        (GEOIP_SPEC,   "geoip.dat"),
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

    # ── Retry-branch: "Разместили файлы вручную? Повторить проверку?" ──────
    # Это ОСОЗНАННО более широкий поиск чем безусловная проверка в
    # fetch_package: здесь проверяем И /root/, И dest_dirs — потому что
    # пользователь явно подтвердил что положил файл куда-то. Это не баг
    # 21d7baf (который был про БЕЗУСЛОВНУЮ проверку на каждый вызов), а
    # intentional retry после подтверждения.
    if failed_files:
        warn("Не удалось загрузить гео-файлы — проверьте интернет-соединение")
        _geo_print_manual_download_hint()
        try:
            ans = input(f"{CYAN}  Разместили файлы вручную? Повторить проверку? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            _MANUAL_ROOTS = [recommended_manual_path()]  # /root/
            for fname, min_size in (
                ("geosite.dat", MIN_SIZES["geosite.dat"]),
                ("geoip.dat",   MIN_SIZES["geoip.dat"]),
            ):
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
    """Создаёт cron-задачу для еженедельного обновления geo-файлов.

    FIX (multi-mirror): ранее cron-скрипт использовал ОДИН URL
    (raw.githubusercontent.com), что приводит к тихому провалу
    еженедельного обновления на серверах, где GitHub заблокирован.
    Теперь в скрипт встраивается весь список зеркал из geo_mirrors.py
    и bash-функция download_file() перебирает их по очереди.
    """
    core = _core_module()
    success = core.success
    warn    = core.warn
    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT

    if not SPLIT_TUNNEL_ENABLED:
        return

    # Получаем списки зеркал из единого реестра
    geosite_urls = get_geosite_urls()
    geoip_urls   = get_geoip_urls()

    # Формируем bash-массивы зеркал (с экранированием кавычек)
    geosite_urls_bash = "\n".join(f'        "{u}"' for u in geosite_urls)
    geoip_urls_bash   = "\n".join(f'        "{u}"' for u in geoip_urls)

    script = Path("/usr/local/bin/xray-geo-update.sh")
    script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Автообновление geosite/geoip для split tunneling (runetfreedom)
        # Multi-mirror fallback: перебирает {GEO_MIRRORS_COUNT} зеркал по очереди.
        set -uo pipefail
        LOG="/var/log/xray-geo-update.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Обновление geo-файлов (попытка {GEO_MIRRORS_COUNT} зеркал)..." >> "$LOG"

        # FIX: гарантируем наличие обеих директорий
        mkdir -p /etc/xray /usr/local/share/xray /usr/local/etc/xray

        # Минимальные размеры (защита от усечённых загрузок).
        # v4.25.1 FIX: берётся из MIN_SIZES (geo_mirrors.py), а не хардкод.
        # Ранее здесь стояли 3 МБ / 10 КБ — устаревшие значения из-за которых
        # cron "обновлял" geosite.dat на 10-МБ усечённую кэшированную копию
        # с jsDelivr (которая проходила старый порог), а реальное обновление
        # с GitHub Release (~73 МБ) не происходило. См. комментарий в
        # geo_mirrors.py:191-217 с описанием инцидента на проде.
        GEOSITE_MIN={MIN_SIZES["geosite.dat"]}
        GEOIP_MIN={MIN_SIZES["geoip.dat"]}

        # Bash-массивы зеркал (генерируются из chimera.modules.geo_mirrors)
        GEOSITE_URLS=(
{geosite_urls_bash}
        )
        GEOIP_URLS=(
{geoip_urls_bash}
        )

        download_file() {{
            local name="$1" dest_etc="$2" dest_share="$3" dest_etc3="$4" min_size="$5"
            shift 5
            local urls=("$@")
            local tmp="/tmp/${{name}}.tmp"

            # 1) Сначала проверяем ручное размещение в /root/ (WinSCP-friendly)
            if [ -f "/root/$name" ]; then
                local rsize=$(stat -c%s "/root/$name" 2>/dev/null || echo 0)
                if [ "$rsize" -ge "$min_size" ]; then
                    cp "/root/$name" "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || \\
                        cp "/root/$name" "$dest_etc" && cp "/root/$name" "$dest_share" && cp "/root/$name" "$dest_etc3"
                    chmod 644 "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                    chown root:xray "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                    echo "[$DATE] ✓ $name взят из /root/ ($((rsize / 1024)) КБ)" >> "$LOG"
                    return 0
                fi
            fi

            # 2) Перебираем зеркала по очереди
            for url in "${{urls[@]}}"; do
                rm -f "$tmp"
                if curl -fsSL --connect-timeout 20 -m 120 --retry 1 -o "$tmp" "$url" 2>/dev/null; then
                    local sz=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
                    if [ "$sz" -ge "$min_size" ]; then
                        cp "$tmp" "$dest_etc"
                        cp "$tmp" "$dest_share"
                        cp "$tmp" "$dest_etc3" 2>/dev/null || true
                        chmod 644 "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                        chown root:xray "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                        rm -f "$tmp"
                        local host=$(echo "$url" | sed -E 's|https?://([^/]+)/.*|\\1|')
                        echo "[$DATE] ✓ $name обновлён с $host ($((sz / 1024)) КБ)" >> "$LOG"
                        return 0
                    fi
                fi
            done
            rm -f "$tmp"
            echo "[$DATE] ✗ Не удалось обновить $name (все зеркала недоступны)" >> "$LOG"
            return 1
        }}

        CHANGED=0
        download_file "geosite.dat" "{GEOSITE_DAT}" "/usr/local/share/xray/geosite.dat" "/usr/local/etc/xray/geosite.dat" "$GEOSITE_MIN" "${{GEOSITE_URLS[@]}}" && CHANGED=1
        download_file "geoip.dat"   "{GEOIP_DAT}"   "/usr/local/share/xray/geoip.dat"   "/usr/local/etc/xray/geoip.dat"   "$GEOIP_MIN"   "${{GEOIP_URLS[@]}}"   && CHANGED=1

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
        cron_file.write_text(f"# Автообновление geo-файлов для Xray split tunneling (multi-mirror)\n{cron_line}")
        cron_file.chmod(0o644)
        success(f"Автообновление geo-файлов: каждое воскресенье в 03:00 ({GEO_MIRRORS_COUNT} зеркал в fallback)")
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
        _box_row(f"  Зеркал в fallback: {GREEN}{GEO_MIRRORS_COUNT}{NC}")
        _box_item("1", f"Обновить geo-файлы прямо сейчас")
        _box_item("2", f"{'Отключить' if cron_active else 'Включить'} еженедельное авто-обновление (cron)")
        _box_item("3", f"Показать лог обновлений")
        _box_item("4", f"Показать ссылки для ручного скачивания (WinSCP/scp)")
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

        elif ch == "4":
            # Показываем все зеркала и пути ручного размещения.
            # Дублирует _geo_print_manual_download_hint, но доступно
            # ПРОАКТИВНО (без ожидания ошибки загрузки).
            try:
                _geo_print_manual_download_hint = core._geo_print_manual_download_hint
                _geo_print_manual_download_hint()
            except Exception as _e:
                warn(f"Не удалось показать подсказку: {_e}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
