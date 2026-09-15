#!/usr/bin/env python3
"""smoke_v88_csqtt_version.py — смоук v88: явный номер версии CSQTT.

Юзеры просили явно указывать НОМЕР ВЕРСИИ, а не только sha-хэш
ревизии. Сценарии:

  1. Свежая установка из исходников: record_first_install СРАЗУ
     пишет в state ревизию + версию (до v88 — «legacy»-режим до
     первого ручного обновления). Версия — реальный опрос бинарника
     --version (фейк-бинарь = скрипт, печатающий «csqtt 2.1.9»,
     как настоящий clap-бинарь апстрима).
  2. Шапка меню CSQTT: строка «Версия: v2.1.9 (rev …)», рамки
     бокса целы (каждая строка ║…║), «Обновление:» — с rev-префиксом.
  3. Меню обновлений: «Установлено: v2.1.9 (rev abc123def456)».
  4. Доступно обновление: «rev … → … доступно» в статус-строке.
  5. Ручной бинарь: LAST_BUILD_INFO очищена (v88), ревизия честно
     НЕ записывается, версия — только если бинарь сам её отдаёт.
"""
from __future__ import annotations

import io
import re
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chimera.modules import upstream_updates as uu
from chimera.modules import csqtt_packages
from chimera.modules import csqtt as csqtt_mod

_ANSI = re.compile(r"\033\[[0-9;]*m")


def clap_bin(path: Path, ver: str = "2.1.9") -> Path:
    """Фейк-«clap-бинарь»: печатает версию, как настоящий csqtt-server."""
    path.write_text(f'#!/bin/sh\necho "csqtt {ver}"\n', encoding="utf-8")
    path.chmod(0o755)
    return path


def elf_bin(path: Path, machine: int = 62, size: int = 2_000_000) -> Path:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2
    h[5] = 1
    h[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(h) + b"\x00" * (size - 20))
    return path


def fake_systemctl(cmd, **kw):
    rc = MagicMock()
    rc.returncode = 5            # systemctl is-active → не активен
    rc.stdout = "inactive"
    rc.stderr = ""
    return rc


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    state_file = tmp / "upstream-updates.json"
    bin_path = clap_bin(tmp / "csqtt-server")

    orig = {
        "state": uu.STATE_FILE,
        "bin": uu.UPSTREAM_TARGETS["csqtt"]["binary"],
        "dirs": csqtt_packages._MANUAL_BIN_DIRS,
        "home": csqtt_packages._MANUAL_BIN_HOME,
        "cbin": csqtt_packages._CSQTT_BIN_PATH,
    }
    uu.STATE_FILE = state_file
    uu.UPSTREAM_TARGETS["csqtt"]["binary"] = bin_path

    checks = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        checks.append(cond)
        mark = "[OK]  " if cond else "[FAIL]"
        print(f"  {mark} {name}" + ("" if cond else f"  ← {detail}"))

    try:
        # ── Сценарий 1: свежая установка из исходников ───────────────
        print("=== 1. Свежая установка: record_first_install (rev+версия сразу) ===")
        csqtt_packages.LAST_BUILD_INFO.clear()
        csqtt_packages.LAST_BUILD_INFO.update({
            "tarball_sha256": "f" * 64,
            "layout": "known:rust-server",
            "rust_required": "1.97.1",
            "upstream_version": "2.1.9",
        })
        with patch.object(uu, "fetch_latest", return_value="abc123def456"):
            uu.record_first_install("csqtt")
        st = uu.read_state()["csqtt"]
        check("ревизия записана сразу (не «legacy»)",
              st.get("installed_rev") == "abc123def456", str(st))
        check("версия записана сразу (реальный опрос --version)",
              st.get("installed_version") == "2.1.9", str(st))
        check("Cargo-версия сборки в state",
              st.get("upstream_version") == "2.1.9", str(st))

        # ── Сценарий 2: шапка меню + целостность рамок ───────────────
        print("=== 2. Шапка меню: «Версия:» + рамки целы ===")
        # убиваем кэш версии — проверяем ленивый RE-опрос бинарника
        uu.update_state("csqtt", installed_version=None)
        ver_disp = uu.get_version_display("csqtt")
        check("get_version_display после ленивого re-probe",
              ver_disp == "v2.1.9 (rev abc123def456)", ver_disp)

        buf = io.StringIO()
        with redirect_stdout(buf):
            csqtt_mod._box_top("CSQTT  •  RTP/TURN Tunnel")
            csqtt_mod._box_row()
            csqtt_mod._box_kv("Статус:", f"{csqtt_mod.GREEN}● активен{csqtt_mod.NC}")
            csqtt_mod._box_kv("Версия:", f"{csqtt_mod.WHITE}{ver_disp}{csqtt_mod.NC}")
            csqtt_mod._box_kv("Обновление:", uu.get_update_status_line("csqtt"))
            csqtt_mod._box_row()
            csqtt_mod._box_bot()
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        plain = [_ANSI.sub("", l) for l in lines]
        # контентные строки — строго ║…║; бордюры ╔╠╚╗╣╝ — своя пара
        content = [p for p in plain if p.startswith("║")]
        frame_ok = (len(content) >= 5
                    and all(p.rstrip().endswith("║") for p in content)
                    and all(len(p) == len(content[0]) for p in plain))
        check("рамки бокса целы (контент ║…║, ширина едина)", frame_ok,
              "\n".join(plain))
        check("«Версия: v2.1.9 (rev …)» в шапке",
              any("Версия:" in p and "v2.1.9 (rev abc123def456)" in p
                  for p in plain), "\n".join(plain))
        check("«Обновление:» с rev-префиксом и «(актуален)»",
              any("Обновление:" in p and "rev abc123def456" in p
                  and "(актуален)" in p for p in plain), "\n".join(plain))
        print("      " + "\n      ".join(plain))

        # ── Сценарий 3: меню обновлений ──────────────────────────────
        print("=== 3. Меню обновлений: «Установлено: v2.1.9 (rev …)» ===")
        # fetch_latest из state-кэша (без сети — детерминизм смоука)
        with patch.object(uu, "fetch_latest", return_value="abc123def456"):
            row = uu._fmt_target_row("csqtt")
        row_plain = _ANSI.sub("", row)
        check("строка «Установлено: v2.1.9 (rev abc123def456)»",
              "Установлено: v2.1.9 (rev abc123def456)" in row_plain
              and "актуален" in row_plain,
              row_plain)
        print("      " + "\n      ".join(row_plain.splitlines()))

        # Тот же рендер при недоступном GitHub API: версия всё равно
        # видна (фикс: installed_version считается ДО раннего return).
        with patch.object(uu, "fetch_latest", return_value=None):
            row = uu._fmt_target_row("csqtt")
        row_plain = _ANSI.sub("", row)
        check("API недоступен → «Установлено:» всё равно с версией",
              "Установлено: v2.1.9 (rev abc123def456)" in row_plain,
              row_plain)

        # ── Сценарий 4: доступно обновление ──────────────────────────
        print("=== 4. Доступно обновление: «rev … → … доступно» ===")
        uu.update_state("csqtt", latest="bbb999888777")
        line = _ANSI.sub("", uu.get_update_status_line("csqtt"))
        check("статус-строка со стрелкой и rev-префиксом",
              "rev abc123def456 → bbb999888777 доступно" in line, line)
        print("      " + line)

        # ── Сценарий 5: ручной бинарь ────────────────────────────────
        print("=== 5. Ручной бинарь: LAST_BUILD_INFO чиста, rev не пишется ===")
        root = tmp / "root"; root.mkdir()
        dest_dir = tmp / "usr-local-bin"; dest_dir.mkdir()
        dest = dest_dir / "csqtt-server"
        csqtt_packages._MANUAL_BIN_DIRS = (root,)
        csqtt_packages._MANUAL_BIN_HOME = tmp / "no-home"
        csqtt_packages._CSQTT_BIN_PATH = dest
        elf_bin(root / "csqtt-server")
        # до этого в процессе была сборка из исходников — инфа устарела
        csqtt_packages.LAST_BUILD_INFO.update(
            {"tarball_sha256": "a" * 64, "upstream_version": "1.0.0"})
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages.subprocess, "run",
                          side_effect=fake_systemctl):
            ok = csqtt_packages.install_manual_binary(verbose=False)
        check("ручной бинарь установлен без сборки", ok)
        check("LAST_BUILD_INFO очищена (v88 — нет stale sha/версии)",
              csqtt_packages.LAST_BUILD_INFO == {},
              str(csqtt_packages.LAST_BUILD_INFO))

        # record_first_install на ручном бинаре: fake-ELF не отвечает
        # на --version → версии нет; sha сборки нет → ревизии нет.
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = dest
        state_file.unlink()
        with patch.object(uu, "fetch_latest", return_value="abc123def456"):
            uu.record_first_install("csqtt")
        st = uu.read_state().get("csqtt", {})
        check("ручной бинарь: ревизия честно НЕ записана",
              "installed_rev" not in st, str(st))
        check("ручной бинарь: версии fake-ELF тоже нет",
              "installed_version" not in st, str(st))
        check("get_version_display → «—»",
              uu.get_version_display("csqtt") == "—",
              uu.get_version_display("csqtt"))
    finally:
        uu.STATE_FILE = orig["state"]
        uu.UPSTREAM_TARGETS["csqtt"]["binary"] = orig["bin"]
        csqtt_packages._MANUAL_BIN_DIRS = orig["dirs"]
        csqtt_packages._MANUAL_BIN_HOME = orig["home"]
        csqtt_packages._CSQTT_BIN_PATH = orig["cbin"]
        csqtt_packages.LAST_BUILD_INFO.clear()

    total, ok_n = len(checks), sum(1 for c in checks if c)
    print(f"\n{'='*60}\n  СМОУК v88: {ok_n}/{total} проверок "
          f"{'ПРОЙДЕН' if ok_n == total else 'ПРОВАЛЕН'}\n{'='*60}")
    return 0 if ok_n == total else 1


if __name__ == "__main__":
    sys.exit(main())
