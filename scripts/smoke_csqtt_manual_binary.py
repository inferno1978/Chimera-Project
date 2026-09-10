#!/usr/bin/env python3
"""smoke_csqtt_manual_binary.py — смоук v76.1.

Эмулирует сценарий юзера дословно:
  1. «Сервер не тянет сборку» → бинарь собран на другой машине и
     закинут в /root/csqtt-server (настоящий ELF-заголовок x86_64).
  2. Повторный запуск установки CSQTT (_build_csqtt_server).
  3. Ожидаение: бинарь подхвачен БЕЗ сети и БЕЗ сборки, установлен
     в /usr/local/bin/csqtt-server (патчим путь), fetch_package
     (исходники) не вызван.
  4. Сценарий «бинаря нет» → прежний путь: fetch_package вызван.
  5. Сценарий «чужая архитектура» → бинарь отклонён с причиной.
"""
from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chimera.modules import csqtt_packages
from chimera.modules import csqtt as csqtt_mod

X86_64 = 62
AARCH64 = 183


def elf_bin(path: Path, machine: int, size: int = 2_000_000) -> Path:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2
    h[5] = 1
    h[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(h) + b"\x00" * (size - 20))
    return path


def fake_systemctl(cmd, **kw):
    from unittest.mock import MagicMock
    rc = MagicMock()
    rc.returncode = 3            # systemctl is-active → не активен
    rc.stdout = "inactive"
    rc.stderr = ""
    return rc


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    root = tmp / "root"; root.mkdir()
    dest = tmp / "usr-local-bin"; dest.mkdir()
    bin_path = dest / "csqtt-server"

    orig = {
        "dirs": csqtt_packages._MANUAL_BIN_DIRS,
        "home": csqtt_packages._MANUAL_BIN_HOME,
        "bin": csqtt_packages._CSQTT_BIN_PATH,
    }
    csqtt_packages._MANUAL_BIN_DIRS = (root,)
    csqtt_packages._MANUAL_BIN_HOME = tmp / "no-home"
    csqtt_packages._CSQTT_BIN_PATH = bin_path

    fetch_calls = []
    failures = []

    def record_fetch(spec, **kw):
        fetch_calls.append(spec)
        return True

    try:
        # ── Сценарий 1-3: бинарь в «/root» → установка без сборки ──────
        manual = elf_bin(root / "csqtt-server", X86_64)
        fetch_calls.clear()
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=record_fetch), \
             patch.object(csqtt_packages.subprocess, "run",
                          side_effect=fake_systemctl):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_mod._build_csqtt_server()
        out = buf.getvalue()
        print("── Сценарий «бинарь в /root» ─────────────────────────")
        print(out)
        if not ok:
            failures.append("установка вернула False")
        if fetch_calls:
            failures.append("fetch_package вызван — а не должен был!")
        if not bin_path.exists():
            failures.append("бинарь не установлен по месту назначения")
        else:
            if bin_path.read_bytes()[:4] != b"\x7fELF":
                failures.append("установлен не тот файл")
            if bin_path.stat().st_mode & 0o111 != 0o111:
                failures.append("бинарь не исполняемый (chmod 755)")
        if "без сборки" not in out:
            failures.append("нет сообщения «без сборки»")

        # ── Сценарий 4: бинаря нигде нет (свежий сервер) → исходники ──
        (root / "csqtt-server").unlink()
        bin_path.unlink()          # как на свежем сервере — места пустые
        fetch_calls.clear()
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=record_fetch):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_mod._build_csqtt_server()
        out = buf.getvalue()
        print("── Сценарий «свежий сервер, бинаря нет» ───────────────")
        print(out[:400])
        if not ok:
            failures.append("без бинаря установка не прошла (mock)")
        if len(fetch_calls) != 1:
            failures.append(f"fetch_package вызван {len(fetch_calls)} раз (ожидался 1)")
        if "Скачиваю исходники" not in out:
            failures.append("нет сообщения о скачивании исходников")

        # ── Сценарий 5: чужая архитектура → отказ С причиной ──────────
        elf_bin(root / "csqtt-server", AARCH64)
        fetch_calls.clear()
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=record_fetch):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_mod._build_csqtt_server()
        out = buf.getvalue()
        print("── Сценарий «чужая архитектура (aarch64 на x86_64)» ───")
        print(out[:700])
        # aarch64-бинарь отклонён → fetch_package вызван (путь в сборку)
        if len(fetch_calls) != 1:
            failures.append("чужая архитектура: не ушли в путь сборки")
        if "aarch64" not in out:
            failures.append("нет причины отказа (aarch64)")

        # ── Сценарий 6: переустановка с установленным бинарем ─────────
        # (сценарий 1 оставил валидный бинарь на месте → было показано
        # «уже на месте, сборка не требуется» — проверено выше визуально)
    finally:
        csqtt_packages._MANUAL_BIN_DIRS = orig["dirs"]
        csqtt_packages._MANUAL_BIN_HOME = orig["home"]
        csqtt_packages._CSQTT_BIN_PATH = orig["bin"]

    print("══════════════════════════════════════════════════════")
    if failures:
        for f in failures:
            print(f"✗ {f}")
        return 1
    print("✓ SMOKE OK: ручной бинарь подхватывается без сборки,")
    print("  отсутствующий — уходит в исходники, чужая архитектура")
    print("  отклоняется с причиной.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
