#!/usr/bin/env python3
"""
chimera/scripts/upstream_awg_sync.py
───────────────────────────────────────────────────────────────────────────────
Дев-инструмент синка Химеры с апстримом bivlked/amneziawg-installer.

Химера — ПЕРЕПИСАННЫЙ порт (bash → Python), а не форк: git-merge
апстрима невозможен в принципе. Этот скрипт автоматизирует всё, что
автоматизируется, и репортит остальное:

  1. CHECK (дефолт). Сравнивает AWGS_UPSTREAM_SYNCED_TAG (единая точка
     правды в awg_constants.py) с тегами апстрима (git ls-remote — без
     GitHub API и его рейт-лимитов). Есть новые теги →
       • вытаскивает из CHANGELOG.md апстрима секции новых версий;
       • классифицирует изменённые файлы (git diff --name-status между
         тегами, shallow-clone во временный каталог): какие модули
         Химеры затрагивает каждое изменение;
       • печатает отчёт «что появилось / куда переносить».
  2. --apply-ru-zone. Механический синк снимка РФ-подсетей: качает
     cascade/ru.zone тега-последователя, валидирует формат и заменяет
     assets/awg/ru.zone.fallback + переписывает тег в
     AWGS_RU_ZONE_FALLBACK_GH. Прозу-комментарий (дата снимка, число
     подсетей) обновляет человек/агент — скрипт печатает готовый текст.

Коды выхода: 0 — апстрим синкается; 1 — есть новые версии (для cron/CI);
2 — ошибка (сеть/парсинг).

Запуск:  python3 chimera/scripts/upstream_awg_sync.py [--report PATH]
         [--apply-ru-zone] [--json]
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from chimera.modules.awg_constants import (  # noqa: E402
    AWGS_UPSTREAM_SYNCED_TAG, AWGS_RU_ZONE_FALLBACK_GH,
)

UPSTREAM_URL = "https://github.com/bivlked/amneziawg-installer.git"
UPSTREAM_OWNER_REPO = "bivlked/amneziawg-installer"
RAW_BASE = "https://raw.githubusercontent.com/" + UPSTREAM_OWNER_REPO

RU_ZONE_ASSET = PROJECT_ROOT / "assets" / "awg" / "ru.zone.fallback"
AWG_CONSTANTS_PATH = PROJECT_ROOT / "chimera" / "modules" / "awg_constants.py"

# Минимум валидного снимка ipdeny: РФ-агрегат исторически 8600-8800
# подсетей; меньше 8000 — файл битый/неполный, REFUSE.
RU_ZONE_MIN_SUBNETS = 8000
_IPV4_CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

# Карта «файл/префикс апстрима → цель в Химере». Порядок важен: первым
# матчится более конкретный префикс.
FILE_TARGETS: list = [
    ("cascade/ru.zone", "auto",
     "assets/awg/ru.zone.fallback + AWGS_RU_ZONE_FALLBACK_GH "
     "(awg_constants.py) — синкается --apply-ru-zone"),
    ("cascade/", "port",
     "chimera/modules/awg_cascade.py, awg_cascade_mirrors.py, "
     "awg_cascade_lb.py, awg_split_direction.py"),
    ("install_amneziawg.sh", "port",
     "chimera/modules/awg_standalone.py (install-flow: PPA/dpkg/модуль)"),
    ("awg_common.sh", "port",
     "chimera/modules/awg_{presets,qr,peers,apply,backup,expires,"
     "net_common,constants}.py + awg_diagnose.py"),
    ("manage_amneziawg.sh", "port",
     "chimera/modules/awg_{peers,diagnose,uninstall,backup}.py"),
    ("CHANGELOG", "info", "источник синк-отчёта (сами секции ниже)"),
    ("docs/", "ignore", "—"),
    ("signing/", "ignore", "—"),
    ("tests/", "ignore", "—"),
    ("scripts/", "ignore", "—"),
    ("README", "ignore", "—"),
    ("ADVANCED", "ignore", "—"),
    ("CASCADE", "ignore", "—"),
    ("INSTALL_VPS", "ignore", "—"),
    ("WARP-RU", "ignore", "—"),
    ("KEYS.txt", "ignore", "—"),
    ("LICENSE", "ignore", "—"),
    ("CODE_OF_CONDUCT", "ignore", "—"),
    ("CONTRIBUTING", "ignore", "—"),
    ("SECURITY", "ignore", "—"),
]

VERDICT_LABEL = {
    "auto":  "СИНК АВТОМАТИЧЕСКИ (--apply-ru-zone)",
    "port":  "ТРЕБУЕТСЯ ПОРТ-АНАЛИЗ",
    "info":  "справочно",
    "ignore": "не переносить",
}


# ── Версии и теги ────────────────────────────────────────────────────────────

def parse_tag(tag: str):
    """'v6.3.9' → (6, 3, 9); None если тег не семверный."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", tag.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def tags_after(tags: list, synced: str) -> list:
    """Семверные теги строго ПОСЛЕ synced, по возрастанию (хронология)."""
    s = parse_tag(synced)
    if s is None:
        return []
    out = [t for t in tags if (p := parse_tag(t)) and p > s]
    return sorted(out, key=parse_tag)


def list_remote_tags() -> list:
    """git ls-remote --tags: все теги апстрима (без GitHub API)."""
    r = subprocess.run(
        ["git", "ls-remote", "--tags", UPSTREAM_URL],
        capture_output=True, text=True, timeout=60, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git ls-remote не удался: {r.stderr[:300]}")
    tags = []
    for line in r.stdout.splitlines():
        # '<sha>\trefs/tags/v6.3.9' + аннотированные 'refs/tags/v6.3.9^{}'
        m = re.search(r"refs/tags/([^\s]+?)\^\{\}$", line.strip())
        if m:
            continue  # deref-строки аннотированных тегов
        m = re.search(r"refs/tags/(.+)$", line.strip())
        if m:
            tags.append(m.group(1))
    # Только семверные (vX.Y.Z): исторические 'v4.0'/'arm-packages' и т.п.
    # в хронологию синка не входят — сортировка по tuple без None.
    return sorted((t for t in set(tags) if parse_tag(t)), key=parse_tag)


# ── Changelog-секции ────────────────────────────────────────────────────────

def extract_changelog_sections(text: str, versions: list) -> dict:
    """Из CHANGELOG.md апстрима — секции '## [X.Y.Z] …' до следующей '## ['.

    Возвращает {version: section_text}. Версии не из списка — мимо.
    """
    sections: dict = {}
    # '^## [' с многострочным захватом до следующего заголовка '## ['
    for m in re.finditer(r"^## \[([^\]]+)\][^\n]*\n(.*?)(?=^## \[|\Z)",
                         text, re.M | re.S):
        ver = m.group(1).strip()
        if ver in versions:
            sections[ver] = m.group(2).strip()
    return sections


def fetch_url(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Chimera-Sync"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ── Классификация файлов ────────────────────────────────────────────────────

def classify_path(path: str):
    """Путь апстрима → (вердикт, цель в Химере)."""
    # Бинарные/графические ассеты (logo.jpg, AmneziaWG20.jpg) — не код
    if path.lower().endswith((".jpg", ".jpeg", ".png", ".svg", ".gz",
                              ".webp", ".ico")):
        return "ignore", "—"
    for prefix, verdict, target in FILE_TARGETS:
        if path == prefix or path.startswith(prefix):
            return verdict, target
    # Неизвестный файл — консервативно: показать человеку.
    return "port", f"НОВЫЙ файл апстрима, маппинга нет — глянуть вручную: {path}"


def diff_files_between_tags(clone_dir: str, from_tag: str, to_tag: str) -> list:
    """Изменённые файлы между тегами в локальном клоне (name-status)."""
    r = subprocess.run(
        ["git", "-C", clone_dir, "diff", "--name-status",
         f"{from_tag}..{to_tag}"],
        capture_output=True, text=True, timeout=120, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git diff {from_tag}..{to_tag}: {r.stderr[:300]}")
    files = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            # 'M\tpath' | 'R100\told\tnew' (берём последний путь)
            files.append(parts[-1].strip())
    return sorted(set(files))


def shallow_clone(dest: str) -> str:
    """Клон апстрима для diff'ов (репозиторий — единицы МБ)."""
    r = subprocess.run(
        ["git", "clone", "--quiet", UPSTREAM_URL, dest],
        capture_output=True, text=True, timeout=300, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git clone: {r.stderr[:300]}")
    return dest


# ── ru.zone-применение ──────────────────────────────────────────────────────

def validate_ru_zone(data: bytes):
    """Снимок ipdeny валиден: >= RU_ZONE_MIN_SUBNETS строк-CIDR, без мусора.

    Возвращает (ok, n_subnets, err).
    """
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        return False, 0, f"не UTF-8: {e}"
    subnets = 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not _IPV4_CIDR.match(s):
            return False, 0, f"не CIDR-строка: {s[:50]!r}"
        subnets += 1
    if subnets < RU_ZONE_MIN_SUBNETS:
        return False, subnets, (
            f"подсетей {subnets} < минимума {RU_ZONE_MIN_SUBNETS}")
    return True, subnets, ""


def apply_ru_zone(tag: str) -> bool:
    """Заменяет assets/awg/ru.zone.fallback снимком тега + бампит тег
    в AWGS_RU_ZONE_FALLBACK_GH. Прозу-комментарий печатает текстом
    (дату снимка и число подсетей обновляет человек/агент)."""
    url = f"{RAW_BASE}/{tag}/cascade/ru.zone"
    print(f"[sync] качаю {url} ...")
    try:
        data = fetch_url(url)
    except Exception as e:
        print(f"[ERR] скачать ru.zone не удалось: {e}")
        return False
    ok, n, err = validate_ru_zone(data)
    if not ok:
        print(f"[ERR] ru.zone {tag} не прошёл валидацию: {err}")
        return False
    if not RU_ZONE_ASSET.exists():
        print(f"[ERR] актива нет на месте: {RU_ZONE_ASSET}")
        return False
    RU_ZONE_ASSET.write_bytes(data)
    print(f"[OK] assets/awg/ru.zone.fallback заменён: {n} подсетей (тег {tag})")

    # Бамп тега в AWGS_RU_ZONE_FALLBACK_GH (хирургическая замена строки)
    src = AWG_CONSTANTS_PATH.read_text(encoding="utf-8")
    new_src, n_repl = re.subn(
        r"(amneziawg-installer/\"\n    \")v[\d.]+(/cascade/ru\.zone\")",
        rf"\g<1>{tag}\g<2>", src)
    if n_repl == 1:
        AWG_CONSTANTS_PATH.write_text(new_src, encoding="utf-8")
        print(f"[OK] AWGS_RU_ZONE_FALLBACK_GH → тег {tag}")
    else:
        print(f"[WARN] AWGS_RU_ZONE_FALLBACK_GH не переписан "
              f"(паттерн нашёл {n_repl} вхождений) — поправьте вручную")
    print()
    print("[NOTE] Обновите прозу-комментарий над AWGS_RU_ZONE_FALLBACK_GH "
          "в awg_constants.py (дата снимка + число подсетей) и прогоните:")
    print("       tests.test_wave5_mirrors  (тег в тестах зеркалит константу)")
    return True


# ── Отчёт ───────────────────────────────────────────────────────────────────

def build_report(synced: str, latest: str, new_tags: list,
                 changelog_sections: dict, changed_files: list) -> dict:
    """Собирает отчёт-структуру (для текста и --json)."""
    file_verdicts = {}
    for f in changed_files:
        verdict, target = classify_path(f)
        file_verdicts.setdefault(verdict, []).append({"file": f, "target": target})
    return {
        "synced": synced,
        "latest": latest,
        "new_tags": new_tags,
        "changelog": changelog_sections,
        "files": file_verdicts,
        "needs_port": bool(file_verdicts.get("port")),
        "ru_zone_changed": any(f == "cascade/ru.zone" for f in changed_files),
    }


def render_report(rep: dict) -> str:
    lines = []
    lines.append(f"Синк Химеры ← {UPSTREAM_OWNER_REPO}")
    lines.append(f"Перенесено до: {rep['synced']} | У апстрима: {rep['latest']}")
    if not rep["new_tags"]:
        lines.append("Новых версий нет — AWG-стек синкается.")
        return "\n".join(lines)
    lines.append(f"Новые версии: {', '.join(rep['new_tags'])}")
    lines.append("")
    for tag in rep["new_tags"]:
        section = rep["changelog"].get(tag)
        lines.append(f"── {tag} " + "─" * max(0, 60 - len(tag)))
        if section:
            # Первые строки секции — жирная выжимка + заголовки блоков
            head = [ln for ln in section.splitlines() if ln.strip()][:6]
            lines.extend(head)
        else:
            lines.append("(секция CHANGELOG не найдена — глянуть вручную)")
        lines.append("")
    if rep["files"]:
        lines.append("Изменённые файлы → цели в Химере:")
        for verdict in ("auto", "port", "info"):
            for item in rep["files"].get(verdict, []):
                lines.append(f"  [{VERDICT_LABEL[verdict]}] {item['file']}")
                lines.append(f"      → {item['target']}")
        if rep["files"].get("ignore"):
            ign = ", ".join(f["file"] for f in rep["files"]["ignore"])
            lines.append(f"  [не переносить] {ign}")
    else:
        lines.append("(дифф файлов недоступен — офлайн? смотрите CHANGELOG выше)")
    if rep["ru_zone_changed"]:
        lines.append("")
        lines.append(">>> cascade/ru.zone изменился: обновите снимок — "
                     "python3 chimera/scripts/upstream_awg_sync.py --apply-ru-zone")
    if rep["needs_port"]:
        lines.append("")
        lines.append(">>> Есть изменения с вердиктом «порт-анализ». Перенесите "
                     "нужное и бампните AWGS_UPSTREAM_SYNCED_TAG в "
                     "awg_constants.py до последнего перенесённого тега.")
    return "\n".join(lines)


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Синк-трекер bivlked/amneziawg-installer для AWG-стека Химеры")
    ap.add_argument("--report", metavar="PATH",
                    help="записать отчёт в файл (markdown-совместимый текст)")
    ap.add_argument("--json", action="store_true",
                    help="машиночитаемый JSON вместо текста (stdout)")
    ap.add_argument("--apply-ru-zone", action="store_true",
                    help="заменить ru.zone.fallback снимком свежего тега")
    args = ap.parse_args()

    synced = AWGS_UPSTREAM_SYNCED_TAG
    try:
        all_tags = list_remote_tags()
    except Exception as e:
        print(f"[ERR] {e}")
        return 2
    latest = all_tags[-1] if all_tags else synced
    new_tags = tags_after(all_tags, synced)

    if args.apply_ru_zone:
        tag = new_tags[-1] if new_tags else None
        if not tag:
            print(f"[OK] новых тегов нет ({synced} — последняя версия) — "
                  f"ru.zone обновлять нечем")
            return 0
        return 0 if apply_ru_zone(tag) else 2

    if not new_tags:
        msg = (f"Апстрим синкается: перенесено {synced}, у апстрима {latest}.")
        print(msg)
        if args.report:
            Path(args.report).write_text(msg + "\n", encoding="utf-8")
        return 0

    # Есть новые версии: changelog + дифф
    changelog_sections = {}
    try:
        raw = fetch_url(f"{RAW_BASE}/{latest}/CHANGELOG.md").decode("utf-8", "replace")
        changelog_sections = extract_changelog_sections(raw, new_tags)
    except Exception as e:
        print(f"[WARN] CHANGELOG не скачался: {e}")

    changed_files = []
    try:
        with tempfile.TemporaryDirectory(prefix="awg-upstream-") as tmp:
            shallow_clone(tmp)
            changed_files = diff_files_between_tags(tmp, synced, latest)
    except Exception as e:
        print(f"[WARN] дифф файлов недоступен ({e}) — отчёт по CHANGELOG")

    rep = build_report(synced, latest, new_tags,
                       changelog_sections, changed_files)
    text = render_report(rep)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(text)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
        print(f"\n[OK] отчёт: {args.report}")
    # 1 = есть обновления (для cron/CI), это НЕ ошибка скрипта
    return 1


if __name__ == "__main__":
    sys.exit(main())
