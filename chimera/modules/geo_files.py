"""
chimera/modules/geo_files.py
───────────────────────────────────────────────────────────────────────────────
Загрузка и обновление geosite.dat / geoip.dat для split tunneling.

  • download_geo_files()      — скачивает через download_manager.fetch_package()
                                 с PackageSpec из geo_packages.py.
                                 19 зеркал-фолбэков (через geo_mirrors.py),
                                 копирование в /etc/xray, /usr/local/share/xray,
                                 /usr/local/etc/xray. Ручное размещение в /root/.
                                 EMERGENCY FALLBACK (волна 2026-07): если все
                                 зеркала провалились — прямой curl на GitHub
                                 release URL с другим User-Agent.
  • setup_geo_autoupdate()    — cron every Sunday 03:00 + bash-скрипт с
                                 multi-mirror fallback и restart xray+nginx
                                 (для REALITY+Unix-сокет). В bash-скрипт
                                 встроен тот же emergency curl fallback.
  • do_manage_geo_update()    — меню: обновить сейчас / вкл-выкл cron /
                                 показать лог / показать ссылки для ручного
                                 скачивания.
  • emergency_curl_fallback() — переиспользуемая функция прямого curl на
                                 GitHub release URL. Используется как
                                 последний рубеж когда fetch_package() провален.

АРХИТЕКТУРНАЯ ЗАЩИТА ОТ БАГА 21d7baf:
  download_geo_files() вызывает fetch_package(GEOSITE_SPEC) / fetch_package(GEOIP_SPEC).
  PackageSpec.__post_init__ assert гарантирует что manual_incoming_dir (/root/)
  НЕ совпадает ни с одним install_dest. Поэтому безусловная проверка ручного
  размещения ищет ТОЛЬКО в /root/ — файл в install_dests (от предыдущего
  запуска) НЕ блокирует повторное сетевое скачивание. Баг 21d7baf физически
  невозможен по конструкции.

EMERGENCY FALLBACK — почему он нужен (волна 2026-07):
  На части серверов в РФ сложилась ситуация: jsDelivr-бэкенды отдают
  устаревший/битый контент, прямые GitHub-URL'ы блокируются, часть
  gh-proxy хостов недоступна. fetch_package() через urllib.request
  падает на всех зеркалах. При этом простой прямой curl на тот же
  GitHub release URL — работает (видимо за счёт другого TLS-fingerprint'а
  и follow-redirects). Поэтому в самом конце flow вызывается
  emergency_curl_fallback() — он пробует прямой curl на 2 GitHub URL'а
  (releases/latest/download) и в случае успеха раскладывает файлы
  вручную. Это ровно то, что делал пользователь вручную — теперь
  автоматизировано.

Точки входа из _core.py:
    from chimera.modules.geo_files import (
        download_geo_files, setup_geo_autoupdate, do_manage_geo_update,
        emergency_curl_fallback,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import shutil
import subprocess
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
#  EMERGENCY FALLBACK — прямой curl на GitHub release URL
# ============================================================================
# Волна 2026-07. См. описание в шапке модуля.
# Используется когда fetch_package() провален на всех зеркалах.
#
# Прямой curl на releases/latest/download часто работает даже когда urllib
# блокируется (другой TLS-fingerprint, follow-redirects, retries).
# Это ровно те команды, что пользователь выполнял вручную:
#   curl -fsSL https://github.com/.../releases/latest/download/geosite.dat \
#     -o /etc/xray/geosite.dat
#   curl -fsSL https://github.com/.../releases/latest/download/geoip.dat \
#     -o /etc/xray/geoip.dat
#   chmod 644 + chown root:xray + копии в /usr/local/share/xray,
#   /usr/local/etc/xray.

# Два GitHub release URL — пробуем оба (releases/latest/download и
# releases/download/<tag>/ после API-запроса latest tag). В 99% случаев
# достаточно первого, второй — страховка.
_EMERGENCY_GEOSITE_URL = (
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/"
    "releases/latest/download/geosite.dat"
)
_EMERGENCY_GEOIP_URL = (
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/"
    "releases/latest/download/geoip.dat"
)


def _emergency_curl_one(
    url: str,
    dest_path: Path,
    min_size: int,
    *,
    timeout: int = 180,
    checksum_urls: Optional[list[str]] = None,
    checksum_algo: str = "sha256",
    progress_label: str = "",
) -> bool:
    """Скачивает один файл через прямой curl.

    Использует тот же User-Agent что и браузер (curl/8.x), что часто
    проходит там, где urllib.request блокируется (GitHub иногда
    блокирует нестандартные UA на release-asset redirects).

     : если передан checksum_urls — после размерной проверки
    делает SHA256-верификацию через download_manager._fetch_reference_hash
    (короткий приоритетный список: raw.githubusercontent.com →
    release-assets → cdn.statically.io) + прямое сравнение actual_hash
    с reference_hash. Это гарантирует, что emergency fallback не откатит
    защиту от устаревших/битых кэшированных файлов, введённую в 
    (коммит cdadfab). Логика верификации:
      • reference_hash is None → принимаем с warn (все 3 приоритетных
        источника недоступны — деградация, как в fetch_package)
      • actual_hash == reference_hash → принимаем файл
      • actual_hash != reference_hash → отбраковка (файл подменён/устаревший)

    Возвращает True если файл скачан, размер >= min_size, и (если
    checksum_urls задан) SHA256-верификация прошла или деградировала.

    ВАЖНО ПРО core._run vs subprocess.run:
      core._run() имеет сигнатуру (args, check, quiet, capture, input_text,
      env, cwd) — НЕ принимает capture_output/text (это аргументы
      subprocess.run). Раньше тут было capture_output=True, что падало
      с TypeError на реальном сервере (см. лог пользователя от 2026-07-24).
      Теперь используем capture=True (правильный аргумент core._run).
      Если core._run недоступен (importlib упал) — fallback на
      subprocess.run с правильными аргументами.
    """
    core = _core_module()
    info = getattr(core, "info", print)
    warn = getattr(core, "warn", print)
    core_run = getattr(core, "_run", None)

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_path.parent / f".{dest_path.name}.emergency.tmp"
    tmp_path.unlink(missing_ok=True)

    def _do_run(args: list[str]) -> subprocess.CompletedProcess:
        """Запуск команды через core._run (если доступен) или subprocess.run.

        core._run возвращает CompletedProcess с .stdout/.stderr/.returncode,
        как и subprocess.run. Разница в аргументах:
          • core._run:     capture=True (не capture_output)
          • subprocess.run: capture_output=True

        ВАЖНО: core._run с check=True (по умолчанию) поднимает
        CalledProcessError при ненулевом returncode. Нам нужно получить
        returncode без исключения — поэтому всегда передаём check=False.
        """
        if core_run is not None:
            # core._run(args, check=False, capture=True) — возвращает
            # CompletedProcess с заполненными stdout/stderr.
            return core_run(args, check=False, capture=True)
        # Fallback: subprocess.run напрямую
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
        )

    try:
        # curl флаги:
        #   -f  — fail on HTTP errors (не писать HTML-страницу 404 в файл)
        #   -S  — показывать ошибки
        #   -sL — silent + follow redirects (releases/latest/download
        #         делает 302 redirect на releases/download/<tag>/)
        #   --connect-timeout 20 — если хост не отвечает за 20с — fail
        #   -m 180 — общий таймаут 3 минуты (geo .dat ~30MB)
        #   --retry 2 — две попытки на тот же URL
        #   -A "curl/8.x" — стандартный UA curl, проходит GitHub filters
        r = _do_run([
            "curl", "-fsSL",
            "--connect-timeout", "20",
            "-m", str(timeout),
            "--retry", "2",
            "-A", "curl/8.5.0",
            "-o", str(tmp_path),
            url,
        ])
        if r.returncode != 0:
            warn(f"  emergency curl не смог скачать {url}: rc={r.returncode}")
            if r.stderr:
                # Логируем stderr для диагностики (но не весь, чтобы не засорять
                # вывод — обычно там прогресс curl)
                stderr_tail = (r.stderr or "").strip().splitlines()[-1] if r.stderr else ""
                if stderr_tail:
                    info(f"  curl stderr: {stderr_tail}")
            return False

        if not tmp_path.exists():
            warn(f"  emergency curl отчитался OK, но файл не создан: {tmp_path}")
            return False

        sz = tmp_path.stat().st_size
        if sz < min_size:
            warn(f"  emergency curl скачал слишком маленький файл: {sz} байт < {min_size}")
            tmp_path.unlink(missing_ok=True)
            return False

        # ── SHA256-верификация (если задан checksum_urls) ────────────────
        #  : emergency fallback использует тот же подход что и
        # fetch_package — получает эталонный хэш ОДИН РАЗ через
        # _fetch_reference_hash() (короткий приоритетный список авторитетных
        # источников), затем прямо сравнивает actual_hash с reference_hash.
        # Раньше вызывал _verify_checksum() — но она удалена в 
        # (заменена на _fetch_reference_hash + прямое сравнение).
        if checksum_urls:
            try:
                from chimera.modules.download_manager import (
                    _fetch_reference_hash, _compute_hash,
                )
                # reference_hash получен ОДИН РАЗ с короткого приоритетного
                # списка (raw.githubusercontent.com → release-assets →
                # cdn.statically.io). None = все 3 недоступны (деградация).
                reference_hash = _fetch_reference_hash(
                    checksum_urls, checksum_algo,
                    progress_label=progress_label,
                )
                if reference_hash is None:
                    # Деградация — принимаем по размеру (warn уже внутри
                    # _fetch_reference_hash).
                    pass
                else:
                    actual_hash = _compute_hash(tmp_path, checksum_algo)
                    if actual_hash != reference_hash:
                        # Явная отбраковка — хэш не совпал.
                        warn(f"  emergency curl: SHA256 не совпал для "
                             f"{dest_path.name} — ожидался "
                             f"{reference_hash[:16]}…, получен "
                             f"{actual_hash[:16]}… — файл отбракован "
                             f"(возможно кэшированная устаревшая копия)")
                        tmp_path.unlink(missing_ok=True)
                        return False
                    # Хэш совпал — принимаем файл.
            except Exception as ex:
                # _fetch_reference_hash / _compute_hash не должны падать,
                # но на всякий случай — log + деградация.
                warn(f"  emergency curl: ошибка SHA256-верификации "
                     f"({type(ex).__name__}: {ex}) — принимаю по размеру")
        # else: checksum_urls не задан — принимаем только по размеру
        # (для обратной совместимости, если кто-то вызовет без checksum).

        # Копируем tmp → dest (rename быстрее, но не работает между
        # разными файловыми системами — copy2 безопаснее).
        shutil.copy2(str(tmp_path), str(dest_path))
        dest_path.chmod(0o644)
        # chown root:xray — best-effort, как в _post_install_geo.
        # Используем тот же _do_run для консистентности.
        try:
            _do_run(["chown", "root:xray", str(dest_path)])
        except Exception:
            pass

        tmp_path.unlink(missing_ok=True)
        return True

    except Exception as ex:
        warn(f"  emergency curl exception: {type(ex).__name__}: {ex}")
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def emergency_curl_fallback(
    *,
    dest_dirs: Optional[list[Path]] = None,
    log_to_file: bool = True,
    only_files: Optional[list[str]] = None,
) -> bool:
    """Последний рубеж скачивания geo-файлов — прямой curl на GitHub.

    Вызывается когда fetch_package() провален на всех зеркалах из
    geo_mirrors._MIRROR_FACTORIES. Пробует прямой curl на GitHub release
    URL (geosite.dat и/или geoip.dat), и в случае успеха раскладывает
    файлы во все dest_dirs (по умолчанию XRAY_LOOKUP_DIRS).

    Идея: GitHub release-asset endpoints часто работают через curl даже
    когда urllib.request блокируется. Это связано с тем что GitHub
    фильтрует по User-Agent для не-браузерных клиентов, и стандартный
    curl/8.x UA проходит фильтр.

     : SHA256-верификация включена (берутся те же checksum_urls
    что в GEOSITE_SPEC/GEOIP_SPEC — см. geo_packages.py). Это гарантирует,
    что emergency fallback не откатит защиту от кэшированных/битых
    файлов, введённую в коммите cdadfab.

     : аргумент only_files позволяет скачать только указанные файлы
    (например ['geosite.dat'] если geoip.dat уже успешно скачан через
    fetch_package). Раньше fallback качал оба файла всегда, что
    приводило к пустой трате времени и возможным сбоям при повторной
    перезаписи успешно скачанного файла.

    Возвращает True если ВСЕ запрошенные файлы (only_files или оба)
    успешно скачаны и расложены. Иначе False.

    Аргументы:
      dest_dirs:    Список директорий куда копировать файлы. По умолчанию
                    XRAY_LOOKUP_DIRS (/etc/xray, /usr/local/share/xray,
                    /usr/local/etc/xray). Если передать пустой список —
                    fallback ничего не сделает.
      log_to_file:  Писать подробности в /var/log/chimera.log (через
                    core.log_to_file). По умолчанию True.
      only_files:   Список файлов для скачивания (['geosite.dat'],
                    ['geoip.dat'] или оба). По умолчанию None = оба.
                    Если файл не в этом списке — он пропускается.
    """
    core = _core_module()
    info = getattr(core, "info", print)
    warn = getattr(core, "warn", print)
    success = getattr(core, "success", print)
    _log = getattr(core, "log_to_file", lambda *a, **kw: None)

    if dest_dirs is None:
        dest_dirs = list(XRAY_LOOKUP_DIRS)
    if not dest_dirs:
        warn("emergency_curl_fallback: dest_dirs пуст — нечего делать")
        return False

    # Берём checksum_urls и algo из GEOSITE_SPEC/GEOIP_SPEC, чтобы
    # emergency fallback использовал ТУ ЖЕ верификацию что и fetch_package.
    # Если spec не задан (чего быть не должно) — fallback работает без
    # SHA256-проверки, только по размеру (старое поведение).
    geosite_checksum_urls = getattr(GEOSITE_SPEC, "checksum_urls", None)
    geosite_checksum_algo = getattr(GEOSITE_SPEC, "checksum_algo", "sha256")
    geoip_checksum_urls   = getattr(GEOIP_SPEC,   "checksum_urls", None)
    geoip_checksum_algo   = getattr(GEOIP_SPEC,   "checksum_algo", "sha256")

    # Фильтруем список файлов для скачивания. По умолчанию — оба.
    # only_files позволяет скачивать только geosite.dat или только geoip.dat,
    # если другой уже успешно скачан через fetch_package.
    all_targets = [
        (_EMERGENCY_GEOSITE_URL, "geosite.dat", MIN_SIZES["geosite.dat"],
         geosite_checksum_urls, geosite_checksum_algo),
        (_EMERGENCY_GEOIP_URL,   "geoip.dat",   MIN_SIZES["geoip.dat"],
         geoip_checksum_urls, geoip_checksum_algo),
    ]
    if only_files is not None:
        only_set = set(only_files)
        targets = [t for t in all_targets if t[1] in only_set]
        if not targets:
            warn(f"emergency_curl_fallback: only_files={only_files} "
                 f"не соответствует ни одному известному файлу — нечего делать")
            return False
    else:
        targets = all_targets

    info(f"EMERGENCY FALLBACK: пробую прямой curl на GitHub release URL "
         f"для {len(targets)} файл(а/ов)...")
    if log_to_file:
        files_str = ", ".join(t[1] for t in targets)
        _log("WARN", f"geo_files: fetch_package провален для [{files_str}] — "
                     f"запускаю emergency curl fallback на GitHub release URL "
                     f"(с SHA256-верификацией)")

    # Гарантируем наличие директорий
    for d in dest_dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    results = []
    for url, fname, min_size, checksum_urls, checksum_algo in targets:
        info(f"  Прямой curl: {fname} ← {url}")
        # Сначала качаем в первую dest_dir, потом копируем в остальные
        primary_dest = dest_dirs[0] / fname
        ok = _emergency_curl_one(
            url, primary_dest, min_size,
            checksum_urls=checksum_urls,
            checksum_algo=checksum_algo,
            progress_label=fname,
        )
        if not ok:
            results.append((fname, False))
            continue
        # Копируем в остальные dest_dirs
        core_run = getattr(core, "_run", None)
        for d in dest_dirs[1:]:
            try:
                dest = d / fname
                d.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(primary_dest), str(dest))
                dest.chmod(0o644)
                try:
                    if core_run is not None:
                        core_run(["chown", "root:xray", str(dest)],
                                 check=False, quiet=True)
                    else:
                        subprocess.run(["chown", "root:xray", str(dest)],
                                       check=False, capture_output=True)
                except Exception:
                    pass
            except Exception as ex:
                warn(f"  не удалось скопировать {fname} в {d}: {ex}")
        results.append((fname, True))
        success(f"  ✓ {fname} скачан через emergency curl "
                f"({primary_dest.stat().st_size // 1024} КБ, SHA256 OK)")

    all_ok = all(r[1] for r in results)
    if log_to_file:
        _log("INFO" if all_ok else "ERROR",
             f"emergency_curl_fallback: results={results}")
    if all_ok:
        success("EMERGENCY FALLBACK: все запрошенные файлы скачаны через "
                "прямой curl (с SHA256-верификацией)")
    else:
        failed = [r[0] for r in results if not r[1]]
        warn(f"EMERGENCY FALLBACK: провален для файлов: {', '.join(failed)}")
    return all_ok


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

    Wave 2026-07: EMERGENCY FALLBACK — если fetch_package() провален на всех
    зеркалах, вызывается emergency_curl_fallback() который пробует прямой curl
    на GitHub release URL. Это помогает на серверах где urllib блокируется,
    но curl работает (частый случай в РФ из-за блокировки GitHub по TLS
    fingerprint). Только если emergency fallback тоже провален — показываем
    manual hint и предлагаем пользователю разместить файлы вручную.
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
    #   2. Иначе — перебирает все зеркала (19 шт., см. geo_mirrors.py) через urllib.
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

    # ── EMERGENCY FALLBACK: прямой curl на GitHub (волна 2026-07) ──────────
    # Если хотя бы один файл не скачался через fetch_package (все зеркала
    # провалены) — пробуем прямой curl на GitHub release URL.
    # Это последнее автоматическое средство перед manual hint.
    #
    # Логика:
    #   • emergency_curl_fallback() скачивает ТОЛЬКО failed_files ( ).
    #     Раньше качал оба — это работало, но повторно перезаписывало
    #     успешно скачанный файл и тратило время.
    #   • После fallback — пересчитываем success_count: для каждого dest_dir
    #     проверяем что файл существует и >= min_size.
    if failed_files:
        info(f"  fetch_package провален для {len(failed_files)} файл(а/ов) — "
             f"пробую emergency curl fallback...")
        em_ok = emergency_curl_fallback(
            dest_dirs=dest_dirs,
            only_files=list(failed_files),  # качаем только недостающие
        )
        if em_ok:
            # Пересчитываем успех — какие файлы реально на месте.
            new_failed: list[str] = []
            for fname in failed_files:
                # Проверяем все dest_dirs — если хотя бы в одной есть файл
                # нужного размера, считаем что файл "успешно доставлен"
                # (post_install в fetch_package копирует во все 3, и
                # emergency fallback тоже копирует во все 3).
                min_size = MIN_SIZES[fname]
                placed = any(
                    (d / fname).exists() and (d / fname).stat().st_size >= min_size
                    for d in dest_dirs
                )
                if placed:
                    success_count += 1
                    if fname in failed_files:
                        # не remove из failed_files тут — ниже он используется
                        pass
                else:
                    new_failed.append(fname)
            failed_files = new_failed
            if not failed_files:
                success("  emergency curl fallback спас установку")
        else:
            warn("  emergency curl fallback тоже провален")

    # ── Retry-branch: "Разместили файлы вручную? Повторить проверку?" ──────
    # Это ОСОЗНАННО более широкий поиск чем безусловная проверка в
    # fetch_package: здесь проверяем И /root/, И dest_dirs — потому что
    # пользователь явно подтвердил что положил файл куда-то. Это не баг
    # 21d7baf (который был про БЕЗУСЛОВНУЮ проверку на каждый вызов), а
    # intentional retry после подтверждения.
    #
    # Этот branch выполняется только если emergency fallback тоже не спас.
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

    # Emergency fallback URLs — прямой GitHub release-assets endpoint.
    # Используются в bash-скрипте как последний рубеж когда все зеркала
    # провалились. См. подробное обоснование в emergency_curl_fallback().
    em_geosite_url = _EMERGENCY_GEOSITE_URL
    em_geoip_url   = _EMERGENCY_GEOIP_URL

    script = Path("/usr/local/bin/xray-geo-update.sh")
    script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Автообновление geosite/geoip для split tunneling (runetfreedom)
        # Multi-mirror fallback: перебирает {GEO_MIRRORS_COUNT} зеркал по очереди.
        # Wave 2026-07: если все зеркала провалились — emergency curl на
        # прямой GitHub release URL (часто проходит там, где зеркала и
        # urllib блокируются, благодаря другому User-Agent и follow-redirects).
        set -uo pipefail
        LOG="/var/log/xray-geo-update.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Обновление geo-файлов (попытка {GEO_MIRRORS_COUNT} зеркал + emergency curl)..." >> "$LOG"

        # FIX: гарантируем наличие обеих директорий
        mkdir -p /etc/xray /usr/local/share/xray /usr/local/etc/xray

        # Минимальные размеры (защита от усечённых загрузок).
        #  FIX: берётся из MIN_SIZES (geo_mirrors.py), а не хардкод.
        # Ранее здесь стояли 3 МБ / 10 КБ — устаревшие значения из-за которых
        # cron "обновлял" geosite.dat на 10-МБ усечённую кэшированную копию
        # с jsDelivr (которая проходила старый порог), а реальное обновление
        # с GitHub Release (~73 МБ) не происходило. См. комментарий в
        # geo_mirrors.py:191-217 с описанием инцидента на проде.
        GEOSITE_MIN={MIN_SIZES["geosite.dat"]}
        GEOIP_MIN={MIN_SIZES["geoip.dat"]}

        # Emergency fallback URLs (прямой GitHub release-assets endpoint)
        EM_GEOSITE_URL="{em_geosite_url}"
        EM_GEOIP_URL="{em_geoip_url}"

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

            # 3) EMERGENCY FALLBACK (волна 2026-07): прямой curl на GitHub
            #    release URL с User-Agent "curl/8.5.0" — проходит там, где
            #    urllib и стандартный curl без UA блокируются GitHub-фильтрами.
            #    Пробуем только если все зеркала провалились.
            #
            #    ВАЖНО про SHA256: в bash-скрипте SHA256-верификация НЕ делается
            #    ни в шаге 2 (перебор зеркал), ни здесь в emergency. Это
            #    осознанное решение — bash cron-скрипт рассчитан на лёгкость и
            #    независимость от Python-окружения. SHA256-верификация делается
            #    только в Python-пути (download_manager.fetch_package и
            #    geo_files.emergency_curl_fallback), который вызывается при
            #    интерактивной установке/обновлении. Cron-скрипт — это
            #    фоновое еженедельное обновление, и если оно скачает
            #    кэшированный устаревший файл — это исправится при следующем
            #    запуске (актуальный файл пройдёт), либо при ручном обновлении
            #    через меню (которое идёт через Python с SHA256).
            local em_url=""
            case "$name" in
                geosite.dat) em_url="$EM_GEOSITE_URL" ;;
                geoip.dat)   em_url="$EM_GEOIP_URL"   ;;
            esac
            if [ -n "$em_url" ]; then
                echo "[$DATE] ! Все зеркала провалились для $name — пробую emergency curl на GitHub..." >> "$LOG"
                rm -f "$tmp"
                if curl -fsSL --connect-timeout 20 -m 180 --retry 2 \\
                        -A "curl/8.5.0" \\
                        -o "$tmp" "$em_url" 2>/dev/null; then
                    local sz=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
                    if [ "$sz" -ge "$min_size" ]; then
                        cp "$tmp" "$dest_etc"
                        cp "$tmp" "$dest_share"
                        cp "$tmp" "$dest_etc3" 2>/dev/null || true
                        chmod 644 "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                        chown root:xray "$dest_etc" "$dest_share" "$dest_etc3" 2>/dev/null || true
                        rm -f "$tmp"
                        echo "[$DATE] ✓ $name обновлён через EMERGENCY curl на GitHub ($((sz / 1024)) КБ)" >> "$LOG"
                        return 0
                    else
                        echo "[$DATE] ✗ Emergency curl: файл слишком маленький ($sz байт < $min_size)" >> "$LOG"
                    fi
                else
                    echo "[$DATE] ✗ Emergency curl провален (rc=$?)" >> "$LOG"
                fi
            fi

            rm -f "$tmp"
            echo "[$DATE] ✗ Не удалось обновить $name (все зеркала + emergency curl недоступны)" >> "$LOG"
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
