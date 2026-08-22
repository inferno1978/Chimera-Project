"""
chimera/modules/download_manager.py
───────────────────────────────────────────────────────────────────────────────
Декларативный download manager для скачивания пакетов/бинарников/файлов
данных проекта.

Архитектурно решает класс бага из geo_files.py (регрессия 21d7baf):
  После первого успешного запуска файлы уже лежат в install_dests
  (рабочих директориях). Безусловная проверка "ручного размещения"
  по тем же директориям находила свой же файл → копировала сам на себя
  → репортила успех БЕЗ сети → geo-правила замораживались навсегда.

Решение: PackageSpec.__post_init__ АРХИТЕКТУРНО ЗАПРЕЩАЕТ
manual_incoming_dir совпадать с любым install_dest. Это делает класс
бага физически невозможным по конструкции — assert падает на создании
spec, ДО любого сетевого вызова.

Использование:
    from chimera.modules.download_manager import PackageSpec, fetch_package
    from chimera.modules.github_mirrors import build_mirror_urls

    spec = PackageSpec(
        name="geosite",
        filename_builder=lambda: "geosite.dat",
        mirror_urls_builder=lambda filename: build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename=filename,
            tag="latest",
            ref="release",
        ),
        install_dests=[Path("/usr/local/share/xray"), Path("/etc/xray")],
        manual_incoming_dir=Path("/root"),
        min_size=20_000_000,  #  example only — use MIN_SIZES from geo_mirrors.py
        post_install=lambda tmp, dests: _copy_to_dests(tmp, dests),
    )
    ok = fetch_package(spec)

Точки входа:
    from chimera.modules.download_manager import (
        PackageSpec, fetch_package, print_manual_hint,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ============================================================================
#  PackageSpec — декларативное описание пакета для скачивания
# ============================================================================

@dataclass
class PackageSpec:
    """Декларативное описание пакета/файла для скачивания.

    Инвариант (КРИТИЧНО): manual_incoming_dir НЕ должен совпадать ни с одним
    install_dest. Это предотвращает класс бага из geo_files.py (регрессия
    21d7baf): после первой успешной установки файл лежит в install_dests,
    и если manual_incoming_dir == install_dest, то повторный вызов найдёт
    свой же файл и никогда не пойдёт в сеть.

    Поля:
      name:                  Человеко-читаемое имя пакета (для логов/подсказок).
      filename_builder:      Callable[..., str] — возвращает имя файла.
                             Принимает **filename_kwargs из fetch_package().
      mirror_urls_builder:   Callable[..., list[str]] — возвращает список URL.
                             Принимает filename= и **filename_kwargs.
      install_dests:         Куда копировать файл при успехе (все директории).
      manual_incoming_dir:   Где искать файл от пользователя (WinSCP).
                             ПО УМОЛЧАНИЮ /root/. НЕ должен совпадать с
                             install_dests — assert в __post_init__.
      min_size:              Минимальный размер файла в байтах (защита от
                             усечённых загрузок). 0 = не проверять.
      post_install:          Optional[Callable[[Path, list[Path]], bool]].
                             Вызывается после скачивания/копирования с
                             (tmp_path, install_dests). Возвращает True при
                             успехе. Если None — просто copy2+chmod во все
                             install_dests.
      checksum_urls:         Optional[list[str]] — список URL .sha256sum
                             файлов для верификации контента после размерной
                             проверки. Если задан — после успешной загрузки
                             (размер >= min_size) fetch_package скачивает
                             .sha256sum, парсит hex-хэш, считает sha256
                             скачанного файла и сравнивает. Несовпадение →
                             отбраковка и переход к следующему зеркалу, как
                             при провале по размеру. Если НИ ОДИН checksum_url
                             не ответил (404 везде) — деградация до одобрения
                             по размеру с warn. По умолчанию None — обратная
                             совместимость, верификация не делается.
      checksum_algo:         Алгоритм хэширования для checksum_urls.
                             По умолчанию "sha256". Используется как
                             hashlib.new(checksum_algo) и как суффикс
                             в ожидаемом имени файла (.sha256sum).
    """

    name: str
    filename_builder: Callable[..., str]
    mirror_urls_builder: Callable[..., list[str]]
    install_dests: list[Path]
    manual_incoming_dir: Path = Path("/root")
    min_size: int = 0
    post_install: Optional[Callable[[Path, list[Path]], bool]] = None
    checksum_urls: Optional[list[str]] = None
    checksum_algo: str = "sha256"

    def __post_init__(self):
        # КРИТИЧЕСКИЙ ИНВАРИАНТ: ручная директория НЕ должна совпадать
        # ни с одной install_dest. Это воспроизводит защиту от бага 21d7baf
        # на уровне конструктора — spec с коллизией просто не создаётся.
        for dest in self.install_dests:
            assert self.manual_incoming_dir != dest, (
                f"PackageSpec({self.name!r}): manual_incoming_dir "
                f"({self.manual_incoming_dir}) не может совпадать ни с одним "
                f"install_dest ({dest}) — это воспроизводит баг из geo_files.py "
                f"(регрессия 21d7baf): после первой успешной установки файл "
                f"лежит в install_dests, повторный вызов найдёт свой же файл "
                f"и никогда не проверит сеть"
            )


# ============================================================================
#  fetch_package — основная функция скачивания
# ============================================================================

def fetch_package(
    spec: PackageSpec,
    *,
    dry_run: bool = False,
    print_hint_on_failure: bool = True,
    progress_label: str = "",
    **filename_kwargs,
) -> bool:
    """Скачивает пакет по spec.

    Алгоритм:
      1. filename = spec.filename_builder(**filename_kwargs)
      2. Проверка manual_incoming_dir / filename — если есть и size >= min_size,
         копирует, вызывает post_install (если задан), возвращает True.
         СЕТЬ НЕ ТРОГАЕТ.
      3. Иначе — перебор mirror_urls по очереди через urllib.
         connect-timeout=15s, max-time=180s, без бесконечных ретраев.
         При успехе — копирует во ВСЕ install_dests, post_install, True.
      4. При полном провале — print_manual_hint(spec, filename=...), False
         (если print_hint_on_failure=True).

    Параметры:
      spec:                  PackageSpec с описанием пакета.
      dry_run:               True — не делать реальных сетевых вызовов и
                             копирований. Возвращает False (для тестов).
      print_hint_on_failure: True (по умолчанию) — печатать инструкцию для
                             ручного скачивания при провале всех зеркал.
                             False — вызывающий код сам напечатает свою
                             подсказку (например geo_files использует
                             _geo_print_manual_download_hint с полным
                             списком путей).
      progress_label:        Если непустая строка — печатать прогресс
                             скачивания (какое зеркало пробуется, размер
                             скачанного). Полезно для больших файлов
                             (geo .dat ~30MB) чтобы пользователь видел
                             что процесс не завис. По умолчанию "" —
                             молча (для внутренних вызовов вроде .dgst).
      **filename_kwargs:     Дополнительные аргументы для filename_builder и
                             mirror_urls_builder.

    Возвращает:
      True при успехе (файл найден локально ИЛИ скачан).
      False при провале (все зеркала упали, /root/ пуст).
    """
    filename = spec.filename_builder(**filename_kwargs)
    manual_path = spec.manual_incoming_dir / filename

    # ── 1) Проверка ручного размещения (только manual_incoming_dir!) ────────
    # ВАЖНО: НЕ проверяем install_dests здесь — это физически невозможно
    # благодаря __post_init__ assert. После первой установки файл лежит в
    # install_dests, но мы его НЕ трогаем — идём в сеть.
    if not dry_run:
        try:
            if manual_path.exists():
                _manual_size = manual_path.stat().st_size
                if _manual_size >= spec.min_size:
                    # Файл найден локально — используем без сети
                    if progress_label:
                        print(
                            f"  {progress_label} ✓ найден локальный файл: "
                            f"{manual_path} ({_manual_size} байт) — скачивание не требуется",
                            flush=True,
                        )
                    if spec.post_install is not None:
                        ok = spec.post_install(manual_path, spec.install_dests)
                        if not ok:
                            # Файл найден и валиден, но post_install упал
                            # (сборка/распаковка/установка зависимостей).
                            # Это НЕ "не удалось скачать" — это "сборка упала".
                            # Сообщение про зеркала здесь НЕ нужно — оно вводит
                            # юзера в заблуждение. post_install уже напечатал
                            # конкретную ошибку (например "[ERR] Rust toolchain
                            # недоступен" или "[ERR] Сборка не удалась: ...").
                            if progress_label:
                                print(
                                    f"  {progress_label} ✗ файл найден, но "
                                    f"post_install упал — смотрите ошибку выше",
                                    flush=True,
                                )
                            return False
                    else:
                        _default_copy_to_dests(manual_path, spec.install_dests)
                    return True
                else:
                    #  логируем если ручной файл слишком маленький —
                    # пользователь мог положить устаревшую/обрезанную копию.
                    if progress_label:
                        print(
                            f"  {progress_label} ⚠ ручной файл {manual_path} "
                            f"({_manual_size} байт < {spec.min_size} минимум) — "
                            f"игнорируем, идём в сеть",
                            flush=True,
                        )
        except (PermissionError, OSError):
            # manual_incoming_dir может быть недоступен (например /root/
            # при запуске не от root) — просто пропускаем, идём в сеть
            pass

    # ── 2) Сетевое скачивание — перебор зеркал ─────────────────────────────
    urls = spec.mirror_urls_builder(filename=filename, **filename_kwargs)

    if dry_run:
        # В dry_run режиме возвращаем False — реальных сетевых вызовов нет
        return False

    tmp_path = Path("/tmp") / f"_download_mgr_{filename}"
    tmp_path.unlink(missing_ok=True)

    # ──  Эталонный хэш получаем ОДИН РАЗ перед циклом ──────────────
    # Раньше (v5.0.0- : для КАЖДОГО кандидата .dat/.geoip-файла вызывалась
    # _verify_checksum(), которая заново перебирала ВСЕ 19 checksum_urls.
    # Это было избыточно (эталон один и тот же для всех попыток) и небезопасно
    # (CDN мог отдать устаревший .sha256sum, и все кандидаты отбраковывались).
    #
    # Теперь: _fetch_reference_hash() берёт КОРОТКИЙ приоритетный список
    # (raw.githubusercontent.com → release-assets → cdn.statically.io),
    # скачивает .sha256sum с первого ответившего, парсит hex-хэш.
    # Возвращает None если все 3 источника недоступны (деградация — см. ниже).
    #
    # Внутри цикла for url_idx, url ... — простое сравнение actual_hash
    # с reference_hash (одной строкой). НЕ повторный запрос .sha256sum.
    reference_hash: Optional[str] = None
    if spec.checksum_urls:
        reference_hash = _fetch_reference_hash(
            spec.checksum_urls, spec.checksum_algo,
            progress_label=progress_label,
        )
        # reference_hash is None → деградация (см. ниже в цикле: проверка
        # хэша пропускается, файл принимается по размеру с warn).

    for url_idx, url in enumerate(urls, 1):
        # Прогресс-индикатор: показываем какое зеркало пробуется.
        # Важно для больших файлов (geo .dat ~30MB) — без этого пользователь
        # видит "Загрузка geosite.dat..." и ждёт 30-60с без обратной связи.
        if progress_label:
            host = url.split("/")[2] if "://" in url else url[:40]
            print(f"  {progress_label} → зеркало {url_idx}/{len(urls)}: {host}...", flush=True)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Chimera-Project"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                # Content-Length для прогресс-бара (не все серверы отдают)
                total = r.headers.get("Content-Length")
                total_int = int(total) if total else 0
                downloaded = 0
                with open(tmp_path, 'wb') as f:
                    while True:
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Прогресс каждые ~1MB (16 chunks × 64KB ≈ 1MB)
                        if progress_label and downloaded % (65536 * 16) == 0:
                            if total_int:
                                pct = downloaded * 100 // total_int
                                print(f"    {downloaded // 1024} КБ / {total_int // 1024} КБ ({pct}%)", flush=True)
                            else:
                                print(f"    {downloaded // 1024} КБ", flush=True)

            if tmp_path.exists() and tmp_path.stat().st_size >= spec.min_size:
                if progress_label:
                    sz = tmp_path.stat().st_size
                    print(f"  {progress_label} ✓ скачано ({sz // 1024} КБ)", flush=True)

                # ──  сравнение с эталонным хэшем (прямое, не _verify_checksum)
                # reference_hash получен ОДИН РАЗ перед циклом (см. выше).
                # Здесь — просто считаем actual_hash скачанного кандидата
                # и сравниваем строкой. НЕ повторный запрос .sha256sum.
                #
                # Если reference_hash is None (деградация — все 3 приоритетных
                # источника недоступны) — пропускаем проверку хэша, принимаем
                # файл по размеру. Это лучше чем блокировать всю загрузку.
                #
                # КРИТИЧНО: несовпадение хэша у ОДНОГО кандидата НЕ должно
                # прекращать проверку остальных. Здесь continue (а не return)
                # — пробуем следующее зеркало с ТЕМ ЖЕ reference_hash.
                if spec.checksum_urls and reference_hash is not None:
                    try:
                        actual_hash = _compute_hash(tmp_path, spec.checksum_algo)
                    except Exception as e:
                        if progress_label:
                            print(
                                f"  {progress_label} ⚠ не удалось вычислить "
                                f"{spec.checksum_algo} ({e}) — пробуем следующее зеркало",
                                flush=True,
                            )
                        tmp_path.unlink(missing_ok=True)
                        continue

                    if actual_hash != reference_hash:
                        # Хэш НЕ совпал — отбраковываем ЭТОГО кандидата.
                        # НЕ прекращаем цикл — переходим к следующему зеркалу.
                        # reference_hash уже получен, повторный запрос не нужен.
                        if progress_label:
                            print(
                                f"  {progress_label} ⚠ {spec.checksum_algo} НЕ совпал — "
                                f"ожидался {reference_hash[:16]}…, "
                                f"получен {actual_hash[:16]}… — "
                                f"пробуем следующее зеркало {url_idx + 1}/{len(urls)}",
                                flush=True,
                            )
                        tmp_path.unlink(missing_ok=True)
                        continue
                    # Хэш совпал — принимаем файл, идём дальше к copy_to_dests.
                    if progress_label:
                        print(
                            f"  {progress_label} ✓ {spec.checksum_algo} совпал",
                            flush=True,
                        )
                # else: spec.checksum_urls is None ИЛИ reference_hash is None
                # → проверка хэша пропущена (деградация), файл принят по размеру.

                # ── Переименование tmp_path в каноническое имя ────────────
                #  FIX (критический баг с 10.07.2026, коммит fbb2285):
                # tmp_path строится как /tmp/_download_mgr_{filename} —
                # post_install callback'и (_post_install_geo, _default_copy_to_dests,
                # и любые другие, использующие src.name) копировали файл под
                # именем '_download_mgr_{filename}' вместо канонического
                # {filename}. Это означало что geosite.dat, geoip.dat и др.
                # NEVER не попадали в /etc/xray/ под правильным именем —
                # вместо этого создавался _download_mgr_geosite.dat РЯДОМ со
                # старым нетронутым geosite.dat. Все обновления с 10.07.2026
                # были no-op по факту.
                #
                # Решение: переименовать tmp_path в /tmp/{filename} ПЕРЕД
                # вызовом post_install/_default_copy_to_dests. Тогда src.name
                # будет каноническим именем, и все post_install callback'и
                # (~15 штук в проекте) автоматически заработают правильно
                # без изменения их сигнатуры или кода.
                canonical_tmp = Path("/tmp") / filename
                if canonical_tmp != tmp_path:
                    canonical_tmp.unlink(missing_ok=True)
                    try:
                        tmp_path.rename(canonical_tmp)
                    except OSError:
                        # На некоторых FS rename через /tmp может упасть
                        # (например, cross-device). Fallback: copy2 + unlink.
                        shutil.copy2(str(tmp_path), str(canonical_tmp))
                        tmp_path.unlink(missing_ok=True)
                    tmp_path = canonical_tmp

                # Скачано успешно — копируем во все install_dests
                if spec.post_install is not None:
                    ok = spec.post_install(tmp_path, spec.install_dests)
                    if not ok:
                        tmp_path.unlink(missing_ok=True)
                        continue  # пробуем следующее зеркало
                else:
                    _default_copy_to_dests(tmp_path, spec.install_dests)

                tmp_path.unlink(missing_ok=True)
                return True

            # Файл слишком маленький — пробуем следующее зеркало.
            #  логируем реальный размер vs порог, чтобы при отладке
            # было видно что именно произошло (а не только "не удалось").
            # Это критично для диагностики случаев когда CDN отдаёт устаревшую
            # копию файла (был инцидент с geosite.dat: 10 МБ вместо 73 МБ,
            # прошёл старый порог 3 МБ — см. geo_mirrors.MIN_SIZES).
            _actual_size = tmp_path.stat().st_size if tmp_path.exists() else 0
            if progress_label:
                print(
                    f"  {progress_label} ⚠ зеркало {url_idx}/{len(urls)} отдало "
                    f"{_actual_size} байт (< {spec.min_size} минимум) — "
                    f"пробуем следующее зеркало",
                    flush=True,
                )
            tmp_path.unlink(missing_ok=True)

        except Exception:
            tmp_path.unlink(missing_ok=True)
            continue

    # ── 3) Все зеркала провалились — подсказка ─────────────────────────────
    tmp_path.unlink(missing_ok=True)
    if print_hint_on_failure:
        # Диагностика: показываем, искали ли manual-файл и что нашли.
        # Это помогает юзеру понять, почему сеть вообще запустилась.
        _print_manual_diagnostic(spec, manual_path, filename)
        print_manual_hint(spec, filename=filename, **filename_kwargs)
    return False


def _print_manual_diagnostic(spec: PackageSpec, manual_path: Path, filename: str) -> None:
    """Печатает диагностику состояния manual-файла перед show manual hint.
    
    Показывает:
    - Где искали manual-файл (manual_incoming_dir / filename)
    - Найден ли файл и какого размера
    - Свободное место на диске
    
    Это помогает юзеру понять, почему fetch_package вообще пошёл в сеть
    (например, если файл был удалён или имеет слишком маленький размер).
    """
    # Color setup (как в print_manual_hint — через importlib чтобы избежать circular import)
    import importlib
    try:
        core = importlib.import_module("chimera._core")
        YELLOW = core.YELLOW
        NC = core.NC
        DIM = core.DIM
    except Exception:
        YELLOW = NC = DIM = ""

    print()
    print(f"  {YELLOW}─── Диагностика ───{NC}")
    print(f"  {DIM}manual_incoming_dir:{NC} {spec.manual_incoming_dir}")
    print(f"  {DIM}expected filename:{NC}   {filename}")
    print(f"  {DIM}expected path:{NC}       {manual_path}")
    if manual_path.exists():
        ms = manual_path.stat().st_size
        verdict = (f"{YELLOW}✓ достаточно (>= {spec.min_size} байт){NC}"
                   if ms >= spec.min_size
                   else f"{YELLOW}✗ меньше минимума {spec.min_size}{NC}")
        print(f"  {DIM}manual file found:{NC}   ДА ({ms} байт) — {verdict}")
        if ms >= spec.min_size:
            print(f"  {YELLOW}⚠ файл существует и валиден, но не был использован —{NC}")
            print(f"  {YELLOW}  значит post_install упал. Смотрите ошибку выше (до этого блока).{NC}")
    else:
        print(f"  {DIM}manual file found:{NC}   НЕТ")
        print(f"  {YELLOW}→ чтобы пропустить зеркала, скачайте файл вручную{NC}")
        print(f"  {YELLOW}  и положите в: {manual_path}{NC}")
    # Свободное место на диске
    try:
        import shutil as _sh
        total, used, free = _sh.disk_usage(str(spec.manual_incoming_dir))
        free_mb = free // (1024 * 1024)
        total_mb = total // (1024 * 1024)
        print(f"  {DIM}disk free:{NC}           {free_mb} MB (из {total_mb} MB)")
    except Exception:
        pass
    print()


# ============================================================================
#  Вспомогательные функции
# ============================================================================

def _default_copy_to_dests(src: Path, dests: list[Path]) -> None:
    """Копирует src во все dests с chmod 0o644.

     src.name теперь гарантированно каноническое (без префикса
    _download_mgr_), потому что fetch_package() переименовывает tmp_path
    в /tmp/{filename} перед вызовом этой функции (см. строку ~281 в
    fetch_package). Раньше src.name был '_download_mgr_{filename}' и
    файлы копировались под неправильным именем — критический баг с 10.07.2026.
    """
    for dest_dir in dests:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        try:
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o644)
        except Exception:
            pass


# ============================================================================
#  sha256-верификация 
# ============================================================================
# Реализована как отдельный helper, а не инлайн в fetch_package, чтобы:
#   1. Была тестируемой (mock urlopen с разными ответами checksum).
#   2. Не раздувала основной цикл fetch_package.
#   3. Логика парсинга .sha256sum (терпимость к разным форматам) жила
#      отдельно от цикла скачивания.
#
# Возвращает Optional[bool]:
#   True  — хэш совпал, файл валиден
#   False — хэш НЕ совпал, файл отбракован (вызывающий код идёт к след. зеркалу)
#   None  — ни один checksum_url не ответил (404 везде) — деградация,
#           вызывающий код принимает файл по размерной проверке

# Regex для извлечения hex-хэша из .sha256sum.
# Терпим к разным форматам:
#   "<hex>  <filename>"   (стандартный sha256sum вывод)
#   "<hex> <filename>"    (один пробел)
#   "<hex>"               (только хэш, без имени)
#   "<hex>\n"             (только хэш с переводом строки)
# Допускает как нижний, так и верхний регистр hex.
_HEX_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")


def _parse_checksum_content(content: str) -> Optional[str]:
    """Парсит содержимое .sha256sum файла.

    Возвращает hex-хэш в нижнем регистре (без имени файла, без пробелов).
    Возвращает None если в содержимом нет 64-символьной hex-строки.

    Поддерживаемые форматы (все встречавшиеся у разных генераторов sha256sum):
      "abc123...  geosite.dat\\n"        — стандартный sha256sum
      "abc123... geosite.dat\\n"         — один пробел
      "abc123...\\n"                     — только хэш
      "  abc123...  \\n"                 — с пробелами по краям
      "# comment\\nabc123...\\n"         — с комментариями
    """
    match = _HEX_RE.search(content)
    if match:
        return match.group(1).lower()
    return None


def _compute_hash(file_path: Path, algo: str = "sha256") -> str:
    """Считает хэш файла чанками по 64 КБ (не загружая весь файл в память).

    Возвращает hex-строку в нижнем регистре.
    """
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _fetch_reference_hash(
    checksum_urls: list[str],
    algo: str = "sha256",
    *,
    progress_label: str = "",
) -> Optional[str]:
    """Получает ЭТАЛОННЫЙ хэш ОДИН РАЗ с КОРОТКОГО приоритетного списка
    источников (не всех 19!).

     заменяет старую _verify_checksum() которая для КАЖДОГО кандидата
    .dat-файла заново перебирала ВСЕ 19 checksum_urls. Это было избыточно
    (эталонный хэш один и тот же для всех попыток) и небезопасно (CDN
    мог отдать устаревший .sha256sum, и все кандидаты отбраковывались
    одинаково — см. инцидент 2026-07-24).

    ПРИОРИТЕТНЫЙ КОРОТКИЙ СПИСОК (выбирается из полного checksum_urls):

      1. raw.githubusercontent.com — самый авторитетный, содержимое
         напрямую из git (не кэш стороннего CDN).
      2. github.com/.../releases/latest/download/... — GitHub release
         assets (тоже авторитетный, не сторонний кэш). URL редиректит
         на release-assets.githubusercontent.com.
      3. cdn.statically.io — последний fallback, независимый от jsDelivr
         CDN. Берётся из существующего списка checksum_urls.

    НЕ включаются в короткий список:
      • Все 4 бэкенда jsDelivr (cdn/gcore/fastly/testingcf) — это ОДИН
        CDN с общим кэшем .sha256sum, который как раз и рассинхронизируется
        с .dat-файлом (см. инцидент 2026-07-24).
      • Все gh-proxy (ghproxy.net, ghproxy.com, ...) — это прокси-кэши
        GitHub, та же проблема кэш-рассинхрона.
      • jsd.cooluc.ru — РФ-зеркало jsDelivr, общий кэш.

    АЛГОРИТМ:
      1. Из полного checksum_urls извлекаем URLs по hostname:
         raw.githubusercontent.com → приоритет 1
         github.com (без ghproxy/jsdelivr в URL) с releases/latest/download
           → приоритет 2
         cdn.statically.io → приоритет 3
      2. Перебираем приоритетный список по очереди:
         • Скачиваем .sha256sum (~100 байт).
         • Парсим hex-хэш через _parse_checksum_content().
         • При успехе — возвращаем хэш (НЕ продолжаем перебор).
      3. Если все 3 источника из короткого списка не ответили или парсинг
         не удался — возвращаем None (деградация, см. fetch_package).

    ВАЖНО: функция НЕ перебирает все 19 checksum_urls. Короткий список
    максимум 3 URL. Это критично для производительности (3 запроса вместо
    19*N, где N — число кандидатов .dat-файла) и для надёжности (если
    все 3 авторитетных источника недоступны — это деградация, а не отказ).

    Аргументы:
      checksum_urls:   Полный список URL .sha256sum (как в PackageSpec).
                       Функция извлечёт из него короткий приоритетный список.
      algo:            Алгоритм хэширования ("sha256" по умолчанию).
      progress_label:  Если непусто — печатать прогресс.

    Возвращает:
      hex-строку хэша в нижнем регистре — если получен с любого источника.
      None — если все источники из короткого списка недоступны
            (деградация до проверки по размеру в вызывающем коде).
    """
    if not checksum_urls:
        return None

    # ── 1) Извлекаем короткий приоритетный список из полного checksum_urls
    raw_github_url: Optional[str] = None
    release_github_url: Optional[str] = None
    statically_url: Optional[str] = None

    for url in checksum_urls:
        # Приоритет 1: raw.githubusercontent.com (прямой доступ к git)
        if "raw.githubusercontent.com" in url and raw_github_url is None:
            raw_github_url = url
            continue
        # Приоритет 2: github.com/.../releases/latest/download/... (release assets)
        # НО исключаем gh-proxy и jsDelivr-обёртки — они не авторитетны.
        # Идентифицируем по hostname github.com И пути releases/latest/download.
        if (release_github_url is None
                and "github.com" in url
                and "releases/latest/download" in url
                and "ghproxy" not in url
                and "jsdelivr" not in url
                and "/https://github.com/" not in url):  # gh-proxy pattern
            release_github_url = url
            continue
        # Приоритет 3: cdn.statically.io (независимый CDN)
        if "cdn.statically.io" in url and statically_url is None:
            statically_url = url
            continue

    # Собираем приоритетный список в нужном порядке
    priority_urls: list[str] = []
    if raw_github_url:
        priority_urls.append(raw_github_url)
    if release_github_url:
        priority_urls.append(release_github_url)
    if statically_url:
        priority_urls.append(statically_url)

    # Edge case: в checksum_urls нет ни одного URL из приоритетных хостов
    # (например, тестовый spec с зеркалами example.com). В этом случае
    # fallback: используем первые 2 URL из полного списка (best-effort).
    if not priority_urls:
        priority_urls = checksum_urls[:2]

    if progress_label:
        print(
            f"  {progress_label} → запрос эталонного {algo} "
            f"({len(priority_urls)} приоритетных источника)",
            flush=True,
        )

    # ── 2) Перебираем приоритетный список — возвращаем хэш с первого ответившего
    for url in priority_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Chimera-Project"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                # .sha256sum файлы маленькие (~100 байт), читаем целиком.
                # decode utf-8 с errors='replace' — терпимость к BOM/мусору.
                content = r.read().decode("utf-8", errors="replace")

            expected_hash = _parse_checksum_content(content)
            if expected_hash is None:
                # Скачали, но не смогли распарсить — пробуем следующий источник.
                if progress_label:
                    host = url.split("/")[2] if "://" in url else url[:40]
                    print(
                        f"  {progress_label} ⚠ {host}: checksum скачан, "
                        f"но hex не распарсен — пробуем следующий источник",
                        flush=True,
                    )
                continue

            # Успех — возвращаем хэш с первого ответившего источника
            if progress_label:
                host = url.split("/")[2] if "://" in url else url[:40]
                print(
                    f"  {progress_label} → эталонный {algo}: "
                    f"{expected_hash[:16]}… (с {host})",
                    flush=True,
                )
            return expected_hash

        except Exception:
            # 404 / network error / timeout — пробуем следующий источник
            continue

    # ── 3) Все источники из короткого списка недоступны → None (деградация)
    if progress_label:
        print(
            f"  {progress_label} ⚠ не удалось получить эталонный {algo} "
            f"ни с одного из {len(priority_urls)} приоритетных источников "
            f"— принято по размеру",
            flush=True,
        )
    return None




def print_manual_hint(spec: PackageSpec, *, filename: str, **filename_kwargs) -> None:
    """Печатает инструкцию для ручного скачивания.

    Формат — как в существующих print_*_manual_download_hint() функциях.
    Использует цвета из _core (через importlib), с fallback на пустые.

    filename_kwargs передаются в mirror_urls_builder чтобы отображаемые URL
    совпадали с теми, которые реально пытался скачать fetch_package (tag,
    tarball_filename и т.д.). Без этого print_manual_hint показывал URL с
    дефолтными параметрами (например tag="0.7.6" вместо реального "1.13.14").
    """
    import importlib
    try:
        core = importlib.import_module("chimera._core")
        YELLOW = core.YELLOW
        NC = core.NC
        BOLD = core.BOLD
        WHITE = core.WHITE
        CYAN = core.CYAN
        GREEN = core.GREEN
        DIM = core.DIM
    except Exception:
        YELLOW = NC = BOLD = WHITE = CYAN = GREEN = DIM = ""

    # Собираем URLs для отображения (с теми же filename_kwargs, что и при реальной попытке)
    try:
        urls = spec.mirror_urls_builder(filename=filename, **filename_kwargs)
    except Exception:
        urls = []

    sep = f"{YELLOW}{'─' * 64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}Не удалось скачать {spec.name} автоматически.{NC}")
    print(f"{WHITE}   Скачайте файл вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}Файл: {filename}{NC}")
    if urls:
        print(f"{DIM}({len(urls)} зеркал в fallback){NC}")
        for i, url in enumerate(urls, 1):
            print(f"    {DIM}{i:>2}){NC} {url}")
    print()
    print(f"{CYAN}Разместите файл в:{NC}")
    print(f"    {BOLD}{GREEN}{spec.manual_incoming_dir}/{NC}  "
          f"{BOLD}{GREEN}← рекомендуется (WinSCP-friendly){NC}")
    print()
    if urls:
        print(f"{WHITE}Команда для скачивания на сервере:{NC}")
        print(f"    {DIM}curl -fL \"{urls[0]}\" -o "
              f"{spec.manual_incoming_dir}/{filename}{NC}")
    print()
    print(f"{WHITE}Или SCP с вашего ПК:{NC}")
    print(f"    {DIM}scp {filename} root@<IP>:{spec.manual_incoming_dir}/{NC}")
    print()
    print(f"{WHITE}После размещения файла повторите операцию.{NC}")
    print()
    print(sep)
    print()
