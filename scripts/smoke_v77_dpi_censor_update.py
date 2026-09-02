#!/usr/bin/env python3
"""
scripts/smoke_v77_dpi_censor_update.py
───────────────────────────────────────────────────────────────────────────────
End-to-end смоук автообновления модуля «Проверка цензуры провайдера»
(Runnin4ik/dpi-detector) — v77.

Сценарии (БЕЗ запуска самого инструмента — только обвязка Химеры):
  1. БАЗЛАЙН   — активная копия = вендорная 3.3.0 (реальная, из git-дерева);
  2. LIVE-чек  — _latest_upstream_version(force=True) по реальной сети
                 (GitHub API → фолбэк git ls-remote; в песочнице API часто
                 rate-limited — это и проверяет цепочку фолбэка);
  3. INSTALL   — _download_and_install("4.1.0") с РЕАЛЬНЫМ tarball codeload
                 (~2 MB); при мёртвой сети — локальный фолбэк-фикстур;
  4. СОДЕРЖИМОЕ — runtime-копия без images/.github/Dockerfile, с cli/core/utils;
                 старые версии и staging вычищены; state записан;
  5. МЕНЮ      — шапка «Версия:/Обновление:», пункт [4], предложение
                 обновления перед запуском, запуск идёт из runtime-копии.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE_TARBALL = Path("/tmp/dpid_test/v41.tar.gz")  # локальный фолбэк

PASS, FAIL = [], []


def check(name: str, cond: bool, extra: str = "") -> None:
    tag = "OK  " if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {extra}" if extra else ""))
    (PASS if cond else FAIL).append(name)


def main() -> int:
    import chimera.modules.dpi_censor_check as m

    tmp = Path(tempfile.mkdtemp(prefix="smoke-v77-"))
    rt_root = tmp / "rt"
    state_file = tmp / "dpi_censor_check.json"
    # старая версия + мусор — должны быть вычищены после установки
    old_dir = rt_root / "3.0.0"      # СТАРЬЕ вендорной 3.3.0 — активной быть не должна
    old_dir.mkdir(parents=True)
    (old_dir / "dpi_detector.py").write_text('CURRENT_VERSION = "3.0.0"\n')
    junk = rt_root / ".staging-junk"
    junk.mkdir()
    stranger = rt_root / "my-notes"
    stranger.mkdir()
    (stranger / "notes.txt").write_text("не трогай")

    base = [
        patch.object(m, "_RUNTIME_ROOT", rt_root),
        patch.object(m, "_STATE_FILE", state_file),
    ]
    for p in base:
        p.start()

    print("== 1. БАЗЛАЙН: активная копия — вендорная ==")
    copy = m._installed_copy()
    check("вендорная копия найдена", bool(copy), f"v{copy.get('version', '?')} ({copy.get('source')})")
    check("версия вендорной 3.3.0", copy.get("version") == "3.3.0")
    check("активная — вендорная (runtime 3.0.0 младше)",
          copy.get("source") == "vendor")
    check("runtime 3.0.0 виден, но не активен",
          any(v == "3.0.0" for _, v in m._runtime_copies()))
    check("активный entry — вендорный", m._active_entry() == m._ENTRY)

    print("== 2. LIVE-проверка последней версии (API → ls-remote) ==")
    latest = m._latest_upstream_version(force=True)
    check("последняя версия получена", bool(latest), f"latest = {latest or '—'}")
    if latest:
        check("это ожидаемый тег апстрима (4.x)", latest.startswith("4."), latest)
        check("обновление доступно (latest > 3.3.0)", bool(m._update_available("3.3.0", latest)))

    print("== 3. УСТАНОВКА v4.1.0 (реальный codeload tarball) ==")
    ok, msg = m._download_and_install("4.1.0")
    if not ok:
        # сеть мертва → локальный фикстур (та же логика, что в проде не нужна)
        print(f"  [WARN] реальное скачивание не удалось ({msg}); пробую локальный фикстур")
        if FIXTURE_TARBALL.exists():
            def fake_dl(version, dest):
                shutil.copy2(FIXTURE_TARBALL, dest)
                return True
            with patch.object(m, "_download_tarball", side_effect=fake_dl):
                ok, msg = m._download_and_install("4.1.0")
        else:
            print("  [WARN] фикстур недоступен — сценарий установки пропущен")
    check("установка прошла", ok, msg)

    final = rt_root / "4.1.0"
    if ok:
        print("== 4. СОДЕРЖИМОЕ runtime-копии ==")
        check("dpi_detector.py на месте", (final / "dpi_detector.py").is_file())
        check("cli/ на месте", (final / "cli" / "runners.py").is_file())
        check("core/ на месте", (final / "core" / "dns_scanner.py").is_file())
        check("utils/ на месте", (final / "utils" / "files.py").is_file())
        check("requirements.txt на месте", (final / "requirements.txt").is_file())
        check("config.yml / domains.txt / tcp16.json на месте",
              (final / "config.yml").is_file() and (final / "domains.txt").is_file()
              and (final / "tcp16.json").is_file())
        for bad in ("images", ".github", "Dockerfile", "Dockerfile.web",
                    "docker-compose.yml", ".gitignore"):
            check(f"без {bad}/", not (final / bad).exists())
        check("версия в установленной копии — 4.1.0",
              m._parse_entry_version(final / "dpi_detector.py") == "4.1.0")
        check("старая 3.0.0 вычищена", not old_dir.exists())
        check("staging-мусор вычищен", not junk.exists())
        check("чужие файлы не тронуты", (stranger / "notes.txt").exists())
        check("staging каталогов не осталось", not list(rt_root.glob(".staging-*")))
        data = json.loads(state_file.read_text()) if state_file.exists() else {}
        check("state: installed_version=4.1.0", data.get("installed_version") == "4.1.0")

        print("== 5. АКТИВНАЯ КОПИЯ после обновления ==")
        copy2 = m._installed_copy()
        check("активная — runtime 4.1.0",
              copy2.get("source") == "runtime" and copy2.get("version") == "4.1.0",
              str(copy2.get("dir", "")))
        check("_active_entry указывает в runtime", m._active_entry() == final / "dpi_detector.py")
        check("_active_reqs указывает в runtime", m._active_reqs() == final / "requirements.txt")
        check("git-дерево вендорной копии не тронуто (версия та же)",
              m._parse_entry_version(m._ENTRY) == "3.3.0")

    print("== 6. МЕНЮ: шапка, [4], предложение перед запуском ==")
    menu_copy = {
        "dir": m._VENDOR_DIR, "version": "3.3.0", "source": "vendor",
        "entry": m._ENTRY, "reqs": m._REQS,
    }
    # latest из живой проверки (или «4.1.0», если сеть молчала — рисуем честно)
    show_latest = latest or "4.1.0"
    buf = io.StringIO()
    with patch.object(m, "_installed_copy", return_value=menu_copy), \
         patch.object(m, "_latest_upstream_version", return_value=show_latest), \
         patch("os.system", return_value=0), \
         patch("builtins.input", return_value="q"), \
         redirect_stdout(buf):
        m.do_dpi_censor_check_menu()
    out = buf.getvalue()
    check("шапка: строка «Версия:»", "Версия:" in out)
    check("шапка: строка «Обновление:»", "Обновление:" in out)
    check("шапка: установленная 3.3.0", "3.3.0" in out)
    check(f"шапка: доступная v{show_latest}", f"v{show_latest}" in out)
    check("пункт [4] с «Обновить до»", "[4]" in out and "Обновить до" in out)

    # предложение обновиться перед запуском (отказ — запуск на текущей)
    run_mock = MagicMock(return_value=0)
    install_mock = MagicMock(return_value=(True, str(final)))
    buf2 = io.StringIO()
    with patch.object(m, "_installed_copy", return_value=menu_copy), \
         patch.object(m, "_latest_upstream_version", return_value="4.1.0"), \
         patch.object(m, "_download_and_install", install_mock), \
         patch.object(m, "_ensure_deps", return_value=True), \
         patch.object(m, "_run_vendor", run_mock), \
         patch("os.system", return_value=0), \
         patch("builtins.input", side_effect=["1", "n", "n", ""]), \
         redirect_stdout(buf2):
        m.do_dpi_censor_check_menu()
    out2 = buf2.getvalue()
    check("предложение обновления перед запуском", "Доступна новая версия" in out2)
    check("после отказа тест запущен на текущей версии", run_mock.call_count == 1)
    check("установка при отказе не вызывалась", install_mock.call_count == 0)

    # согласие → установка вызвана, и ЗАПУСК пошёл бы из runtime-копии
    install_mock2 = MagicMock(return_value=(True, str(final)))
    buf3 = io.StringIO()
    with patch.object(m, "_installed_copy", return_value=menu_copy), \
         patch.object(m, "_latest_upstream_version", return_value="4.1.0"), \
         patch.object(m, "_download_and_install", install_mock2), \
         patch.object(m, "_ensure_deps", return_value=True), \
         patch.object(m, "_run_vendor", run_mock), \
         patch("os.system", return_value=0), \
         patch("builtins.input", side_effect=["1", "y", "n", ""]), \
         redirect_stdout(buf3):
        m.do_dpi_censor_check_menu()
    check("согласие → скачивание вызвано", install_mock2.call_count == 1)
    check("сообщение «Обновлено… запускаю обновлённую»", "Обновлено" in buf3.getvalue())

    for p in base:
        p.stop()
    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print(f"ИТОГ: {len(PASS)} OK, {len(FAIL)} FAIL")
    if FAIL:
        for f in FAIL:
            print(f"  ✗ {f}")
        return 1
    print("SMOKE v77: ВСЁ ЗЕЛЁНОЕ ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
