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
        min_size=20_000_000,  # v4.25.1: example only — use MIN_SIZES from geo_mirrors.py
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
                    if spec.post_install is not None:
                        ok = spec.post_install(manual_path, spec.install_dests)
                        if not ok:
                            return False
                    else:
                        _default_copy_to_dests(manual_path, spec.install_dests)
                    return True
                else:
                    # v4.25.1: логируем если ручной файл слишком маленький —
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

                # ── sha256-верификация (если spec.checksum_urls задан) ──────
                # v4.25.2: размерная проверка не ловит случаи, когда CDN
                # закэшировал устаревший, но достаточно большой файл. Контроль
                # суммы однозначно отбраковывает такой файл. Если НИ ОДИН
                # checksum_url не отвечает (404 везде — апстрим перестал
                # публиковать) — деградация до одобрения по размеру с warn.
                if spec.checksum_urls:
                    verify_result = _verify_checksum(
                        tmp_path, spec.checksum_urls, spec.checksum_algo,
                        progress_label=progress_label,
                    )
                    if verify_result is False:
                        # Явная отбраковка — хэш не совпал. Лог уже внутри
                        # _verify_checksum. Переходим к следующему зеркалу.
                        tmp_path.unlink(missing_ok=True)
                        continue
                    # verify_result is None — checksum недоступен со всех
                    # зеркал, деградация до размерной проверки (warn уже
                    # внутри _verify_checksum). Принимаем файл.
                    # verify_result is True — хэш совпал, принимаем.

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
            # v4.25.1: логируем реальный размер vs порог, чтобы при отладке
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
        print_manual_hint(spec, filename=filename, **filename_kwargs)
    return False


# ============================================================================
#  Вспомогательные функции
# ============================================================================

def _default_copy_to_dests(src: Path, dests: list[Path]) -> None:
    """Копирует src во все dests с chmod 0o644."""
    for dest_dir in dests:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        try:
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o644)
        except Exception:
            pass


# ============================================================================
#  sha256-верификация (v4.25.2)
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


def _verify_checksum(
    file_path: Path,
    checksum_urls: list[str],
    algo: str = "sha256",
    *,
    progress_label: str = "",
) -> Optional[bool]:
    """Верифицирует file_path по .sha256sum, скачанному с checksum_urls.

    Алгоритм:
      1. Считает хэш file_path (algo, по умолчанию sha256) чанками.
      2. Перебирает checksum_urls по порядку, скачивает .sha256sum.
         ВАЖНО: перебор идёт НЕЗАВИСИМО от того, какое зеркало дало сам файл.
         Это гарантирует, что мы верифицируем то что РЕАЛЬНО пришло, а не
         то что зеркало "должно" было отдать.
      3. При успехе скачивания .sha256sum — парсит hex-хэш, сравнивает.
         • Совпал → return True
         • Не совпал → return False (отбраковка, log warn)
      4. Если НИ ОДИН checksum_url не ответил (404 везде — апстрим перестал
         публиковать) → return None (деградация, warn "не удалось проверить").

    Аргументы:
      file_path:       Путь к скачанному файлу для верификации.
      checksum_urls:   Список URL .sha256sum файлов (в порядке приоритета).
      algo:            Алгоритм хэширования ("sha256" по умолчанию).
      progress_label:  Если непусто — печатать прогресс верификации.

    Возвращает:
      True  — хэш совпал, файл валиден
      False — хэш НЕ совпал, файл отбракован
      None  — checksum недоступен со всех зеркал (деградация)
    """
    # 1) Считаем хэш скачанного файла
    try:
        actual_hash = _compute_hash(file_path, algo)
    except Exception as e:
        if progress_label:
            print(
                f"  {progress_label} ⚠ не удалось вычислить {algo} "
                f"({e}) — пропуск верификации",
                flush=True,
            )
        return None  # деградация, не отбраковка

    if progress_label:
        print(
            f"  {progress_label} → верификация {algo}: "
            f"{actual_hash[:16]}… перебор {len(checksum_urls)} checksum-зеркал",
            flush=True,
        )

    # 2) Перебираем checksum_urls по порядку
    checksum_obtained = False
    for idx, checksum_url in enumerate(checksum_urls, 1):
        try:
            req = urllib.request.Request(
                checksum_url,
                headers={"User-Agent": "Chimera-Project"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                # .sha256sum файлы маленькие (~100 байт), читаем целиком.
                # decode utf-8 с errors='replace' — терпимость к BOM/мусору.
                content = r.read().decode("utf-8", errors="replace")
            checksum_obtained = True

            expected_hash = _parse_checksum_content(content)
            if expected_hash is None:
                # Скачали, но не смогли распарсить — пробуем следующий URL.
                if progress_label:
                    host = checksum_url.split("/")[2] if "://" in checksum_url else checksum_url[:40]
                    print(
                        f"  {progress_label} ⚠ checksum с {host}: "
                        f"не удалось распарсить hex — пробуем следующее",
                        flush=True,
                    )
                continue

            if actual_hash == expected_hash:
                if progress_label:
                    host = checksum_url.split("/")[2] if "://" in checksum_url else checksum_url[:40]
                    print(
                        f"  {progress_label} ✓ {algo} совпал (зеркало {idx}/{len(checksum_urls)}: {host})",
                        flush=True,
                    )
                return True
            else:
                # Хэш НЕ совпал — ОТБРАКОВКА.
                host = checksum_url.split("/")[2] if "://" in checksum_url else checksum_url[:40]
                if progress_label:
                    print(
                        f"  {progress_label} ⚠ {host}: {algo} НЕ совпал — "
                        f"ожидался {expected_hash[:16]}…, получен {actual_hash[:16]}… "
                        f"— файл отбракован, пробуем следующее зеркало",
                        flush=True,
                    )
                return False

        except Exception:
            # 404 / network error / timeout — пробуем следующий URL
            continue

    # 3) Ни один checksum_url не ответил
    if not checksum_obtained:
        if progress_label:
            print(
                f"  {progress_label} ⚠ не удалось получить {algo} ни с одного "
                f"зеркала ({len(checksum_urls)} попыток) — принято по размеру",
                flush=True,
            )
        return None  # деградация, не отбраковка

    # 4) checksum_obtained=True, но ни один не распарсился — деградация
    if progress_label:
        print(
            f"  {progress_label} ⚠ checksum скачан, но hex не распарсен ни "
            f"из одного — принято по размеру",
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
