#!/usr/bin/env python3
"""
tests/test_csqtt_manual_binary.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты ГОТОВЫЙ бинарь csqtt-server, собранный на другой машине
и загруженный на сервер вручную (scp/WinSCP).

Покрывает:
  1. _elf_arch — ELF-заголовок → архитектура (x86_64/aarch64, endian,
     не-ELF, обрезанный, неизвестная машина).
  2. _validate_manual_binary — размер / ELF / соответствие архитектуре
     сервера; человекочитаемые причины отказа.
  3. _scan_manual_bin_candidates — директории, точные имена vs
     glob-шаблоны, приоритет /root, /home/<юзер>/, исключение
     архивов/текстов, директории-обманки.
  4. find_manual_binary — первый валидный + список отклонённых.
  5. install_manual_binary — атомарная установка; «уже на месте»
     (/usr/local/bin); ничего не найдено → False (путь в сборку).
  6. csqtt._build_csqtt_server — ручной бинарь ПЕРЕД fetch_package
     (интеграция: без сборки, сеть не трогается).
  7. Блок ошибки установки — инструкция «куда класть бинарь».
  8. upstream_updates.update_target("csqtt") — подсказка про ручной
     бинарь при провале обновления.
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import csqtt_packages
from chimera.modules import csqtt as csqtt_mod


def _elf_bytes(machine: int, *, endian: str = "<") -> bytes:
    """Минимальный ELF-заголовок (20 байт) под данную e_machine."""
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2                                   # EI_CLASS: 64-bit
    h[5] = 2 if endian == ">" else 1           # EI_DATA: BE / LE
    h[18:20] = machine.to_bytes(2,
                                "big" if endian == ">" else "little")
    return bytes(h)


_X86_64 = 62
_AARCH64 = 183


def _fake_bin(path: Path, machine: int = _X86_64,
              size: int = 2_000_000, *, endian: str = "<") -> Path:
    """Пишет файл-«бинарь»: ELF-заголовок + паддинг до size."""
    blob = _elf_bytes(machine, endian=endian)
    blob = blob + b"\x00" * (size - len(blob))
    path.write_bytes(blob)
    return path


class _ManualDirsMixin:
    """Перенаправляет константы скана во временную директорию."""

    def setUp(self):
        super().setUp()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._root = self._tmpdir / "root";   self._root.mkdir()
        self._tmp = self._tmpdir / "tmp";     self._tmp.mkdir()
        self._opt = self._tmpdir / "opt";     self._opt.mkdir()
        self._src = self._tmpdir / "src";     self._src.mkdir()
        self._home = self._tmpdir / "home";   self._home.mkdir()
        self._dest = self._tmpdir / "csqtt-server-dest"
        self._orig = {
            "dirs": csqtt_packages._MANUAL_BIN_DIRS,
            "home": csqtt_packages._MANUAL_BIN_HOME,
            "bin":  csqtt_packages._CSQTT_BIN_PATH,
        }
        csqtt_packages._MANUAL_BIN_DIRS = (
            self._root, self._tmp, self._opt, self._src)
        csqtt_packages._MANUAL_BIN_HOME = self._home
        csqtt_packages._CSQTT_BIN_PATH = self._dest

    def tearDown(self):
        csqtt_packages._MANUAL_BIN_DIRS = self._orig["dirs"]
        csqtt_packages._MANUAL_BIN_HOME = self._orig["home"]
        csqtt_packages._CSQTT_BIN_PATH = self._orig["bin"]
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        super().tearDown()


# ══════════════════════════════════════════════════════════════════════════════
#  1. ELF-заголовок
# ══════════════════════════════════════════════════════════════════════════════
class TestElfArch(unittest.TestCase):

    def test_x86_64(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(_elf_bytes(_X86_64))
            self.assertEqual(csqtt_packages._elf_arch(p), "x86_64")

    def test_aarch64(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(_elf_bytes(_AARCH64))
            self.assertEqual(csqtt_packages._elf_arch(p), "aarch64")

    def test_big_endian(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(_elf_bytes(_X86_64, endian=">"))
            self.assertEqual(csqtt_packages._elf_arch(p), "x86_64")

    def test_not_elf(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(b"\x1f\x8b\x08\x00garbage-gzip")
            self.assertIsNone(csqtt_packages._elf_arch(p))

    def test_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(b"\x7fELF\x02\x01\x01\x00")   # 8 байт < 20
            self.assertIsNone(csqtt_packages._elf_arch(p))

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(b"")
            self.assertIsNone(csqtt_packages._elf_arch(p))

    def test_unknown_machine(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b"
            p.write_bytes(_elf_bytes(99))
            self.assertIsNone(csqtt_packages._elf_arch(p))


# ══════════════════════════════════════════════════════════════════════════════
#  2. Валидация бинаря
# ══════════════════════════════════════════════════════════════════════════════
class TestValidateManualBinary(unittest.TestCase):

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_valid_x86_64_on_x86_64(self):
        p = _fake_bin(self._tmpdir / "csqtt-server", _X86_64)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            ok, why = csqtt_packages._validate_manual_binary(p)
        self.assertTrue(ok)
        self.assertIn("x86_64", why)

    def test_valid_aarch64_on_aarch64(self):
        p = _fake_bin(self._tmpdir / "csqtt-server", _AARCH64)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="aarch64"):
            ok, why = csqtt_packages._validate_manual_binary(p)
        self.assertTrue(ok)

    def test_wrong_arch_rejected(self):
        """Бинарь, собранный на M1 Mac, не молча встанет на x86_64-VPS."""
        p = _fake_bin(self._tmpdir / "csqtt-server", _AARCH64)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            ok, why = csqtt_packages._validate_manual_binary(p)
        self.assertFalse(ok)
        self.assertIn("aarch64", why)
        self.assertIn("x86_64", why)

    def test_too_small_rejected(self):
        p = _fake_bin(self._tmpdir / "csqtt-server", _X86_64, size=500_000)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            ok, why = csqtt_packages._validate_manual_binary(p)
        self.assertFalse(ok)
        self.assertIn("маленький", why)

    def test_not_elf_rejected(self):
        """Tarball/скрипт под именем csqtt-server — не бинарь."""
        p = self._tmpdir / "csqtt-server"
        p.write_bytes(b"\x1f\x8b" + b"A" * 2_000_000)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            ok, why = csqtt_packages._validate_manual_binary(p)
        self.assertFalse(ok)
        self.assertIn("не ELF", why)


# ══════════════════════════════════════════════════════════════════════════════
#  3. Скан директорий
# ══════════════════════════════════════════════════════════════════════════════
class TestScanCandidates(_ManualDirsMixin, unittest.TestCase):

    def test_exact_name_in_first_dir(self):
        _fake_bin(self._root / "csqtt-server")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [self._root / "csqtt-server"])

    def test_exact_csqtt_alias(self):
        _fake_bin(self._root / "csqtt")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [self._root / "csqtt"])

    def test_priority_first_dir_over_later(self):
        _fake_bin(self._root / "csqtt-server")
        _fake_bin(self._tmp / "csqtt-server")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands[0], self._root / "csqtt-server")

    def test_exact_beats_glob(self):
        """Точное имя в ПОСЛЕДНЕЙ директории бьёт glob в ПЕРВОЙ."""
        _fake_bin(self._root / "csqtt-server-x86_64-musl")
        _fake_bin(self._src / "csqtt-server")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands[0], self._src / "csqtt-server")

    def test_glob_target_suffix(self):
        """cargo-zigbuild даёт имя с target-суффиксом — находим."""
        _fake_bin(self._root /
                  "csqtt-server-x86_64-unknown-linux-musl")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(len(cands), 1)
        self.assertIn("musl", cands[0].name)

    def test_archives_and_texts_excluded(self):
        for name in ("csqtt-server-linux.tar.gz", "csqtt-server.txt",
                     "csqtt-server.zip", "csqtt-server.md"):
            (self._root / name).write_bytes(b"x" * 100)
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [])

    def test_tarball_manual_source_ignored(self):
        """Исходный tarball (csqtt-main.tar.gz) — не кандидат."""
        (self._root / "csqtt-main.tar.gz").write_bytes(b"x" * 100)
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [])

    def test_directory_named_csqtt_skipped(self):
        """git clone в /root/csqtt — это директория, не бинарь."""
        (self._root / "csqtt").mkdir()
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [])

    def test_home_user_scanned(self):
        user = self._home / "ivan"; user.mkdir()
        _fake_bin(user / "csqtt-server")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [user / "csqtt-server"])

    def test_home_missing_ok(self):
        """/home отсутствует (редкие образы) — скан не падает."""
        csqtt_packages._MANUAL_BIN_HOME = self._tmpdir / "no-home"
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands, [])

    def test_no_duplicates_exact_vs_glob(self):
        p = _fake_bin(self._root / "csqtt-server")
        cands = csqtt_packages._scan_manual_bin_candidates()
        self.assertEqual(cands.count(p), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  4. find_manual_binary
# ══════════════════════════════════════════════════════════════════════════════
class TestFindManualBinary(_ManualDirsMixin, unittest.TestCase):

    def test_found_valid(self):
        p = _fake_bin(self._root / "csqtt-server")
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            found, rejects = csqtt_packages.find_manual_binary()
        self.assertEqual(found, p)
        self.assertEqual(rejects, [])

    def test_rejects_collected_with_reason(self):
        bad = self._root / "csqtt-server"
        bad.write_bytes(b"\x1f\x8b" + b"A" * 2_000_000)   # не ELF
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            found, rejects = csqtt_packages.find_manual_binary()
        self.assertIsNone(found)
        self.assertEqual(len(rejects), 1)
        self.assertEqual(rejects[0][0], bad)
        self.assertIn("не ELF", rejects[0][1])

    def test_first_valid_wins(self):
        wrong = _fake_bin(self._root / "csqtt-server", _AARCH64)
        good = _fake_bin(self._tmp / "csqtt-server", _X86_64)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            found, rejects = csqtt_packages.find_manual_binary()
        self.assertEqual(found, good)
        self.assertEqual(len(rejects), 1)
        self.assertEqual(rejects[0][0], wrong)

    def test_nothing(self):
        found, rejects = csqtt_packages.find_manual_binary()
        self.assertIsNone(found)
        self.assertEqual(rejects, [])


# ══════════════════════════════════════════════════════════════════════════════
#  5. install_manual_binary
# ══════════════════════════════════════════════════════════════════════════════
class TestInstallManualBinary(_ManualDirsMixin, unittest.TestCase):

    def test_installs_found_binary(self):
        p = _fake_bin(self._root / "csqtt-server")
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True) as m_rep:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary()
        self.assertTrue(ok)
        m_rep.assert_called_once_with(
            p, self._dest, "csqtt",
            csqtt_packages._CSQTT_SERVICE_FILE)
        self.assertIn("без сборки", buf.getvalue())

    def test_replace_failure_returns_false(self):
        _fake_bin(self._root / "csqtt-server")
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=False):
            ok = csqtt_packages.install_manual_binary()
        self.assertFalse(ok)

    def test_nothing_found_returns_false(self):
        """Нет ручного бинаря, нет бинаря на месте → путь в сборку."""
        with patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True) as m_rep:
            ok = csqtt_packages.install_manual_binary()
        self.assertFalse(ok)
        m_rep.assert_not_called()

    def test_already_in_place_skips_copy(self):
        """Бинарь уже в /usr/local/bin (или переустановка) — не копируем."""
        _fake_bin(self._dest)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True) as m_rep:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary()
        self.assertTrue(ok)
        m_rep.assert_not_called()
        self.assertIn("уже на месте", buf.getvalue())
        self.assertIn("сборка не требуется", buf.getvalue())

    def test_invalid_in_place_falls_through(self):
        """На месте битый файл → НЕ считаем установленным (путь в сборку)."""
        self._dest.write_bytes(b"\x1f\x8b" + b"A" * 2_000_000)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            ok = csqtt_packages.install_manual_binary()
        self.assertFalse(ok)

    def test_verbose_false_silent(self):
        _fake_bin(self._root / "csqtt-server")
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary(verbose=False)
        self.assertTrue(ok)
        self.assertEqual(buf.getvalue(), "")

    def test_exception_in_replace_caught(self):
        _fake_bin(self._root / "csqtt-server")
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          side_effect=RuntimeError("boom")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary()
        self.assertFalse(ok)
        self.assertIn("boom", buf.getvalue())

    def test_rejects_printed_even_when_not_found(self):
        """Юзер закинул бинарь чужой архитектуры — видит ПРИЧИНУ,
        а не молчаливый уход в сборку (смоук-находка)."""
        p = _fake_bin(self._root / "csqtt-server", _AARCH64)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary()
        self.assertFalse(ok)
        out = buf.getvalue()
        self.assertIn(str(p), out)
        self.assertIn("aarch64", out)
        self.assertIn("отклонён", out)

    def test_manual_beats_in_place(self):
        """Свежий бинарь в /root обновляет уже установленный."""
        _fake_bin(self._dest, machine=_X86_64, size=1_500_000)
        fresh = _fake_bin(self._root / "csqtt-server", size=3_000_000)
        with patch.object(csqtt_packages, "_detect_arch",
                          return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True) as m_rep:
            ok = csqtt_packages.install_manual_binary()
        self.assertTrue(ok)
        m_rep.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
#  6. Интеграция: _build_csqtt_server — ручной бинарь ПЕРЕД fetch_package
# ══════════════════════════════════════════════════════════════════════════════
class TestBuildServerManualFirst(_ManualDirsMixin, unittest.TestCase):

    def test_manual_binary_skips_fetch(self):
        """Ручной бинарь найден → fetch_package (сеть/сборка) НЕ вызывается."""
        fetch_calls = []
        with patch.object(csqtt_packages, "install_manual_binary",
                          return_value=True) as m_imb, \
             patch("chimera.modules.download_manager.fetch_package",
                   side_effect=lambda *a, **k:
                       fetch_calls.append(1) or True):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_mod._build_csqtt_server()
        self.assertTrue(ok)
        m_imb.assert_called_once()
        self.assertEqual(fetch_calls, [])
        self.assertIn("без сборки", buf.getvalue())

    def test_falls_to_fetch_when_no_manual(self):
        """Ручного нет → прежний путь: fetch_package (исходники → сборка)."""
        with patch.object(csqtt_packages, "install_manual_binary",
                          return_value=False), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as m_fetch:
            ok = csqtt_mod._build_csqtt_server()
        self.assertTrue(ok)
        m_fetch.assert_called_once()
        spec = m_fetch.call_args[0][0]
        self.assertIs(spec, csqtt_packages.CSQTT_SOURCE_SPEC)

    def test_manual_scan_exception_does_not_break(self):
        """Скан упал → установка не рушится, идёт в сборку (как раньше)."""
        with patch.object(csqtt_packages, "install_manual_binary",
                          side_effect=PermissionError("denied")), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as m_fetch:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_mod._build_csqtt_server()
        self.assertTrue(ok)
        m_fetch.assert_called_once()
        self.assertIn("Проверка ручного бинаря упала", buf.getvalue())

    def test_both_fail_returns_false(self):
        with patch.object(csqtt_packages, "install_manual_binary",
                          return_value=False), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=False):
            ok = csqtt_mod._build_csqtt_server()
        self.assertFalse(ok)


# ══════════════════════════════════════════════════════════════════════════════
#  7. Инструкция при сбое установки
# ══════════════════════════════════════════════════════════════════════════════
class TestManualBinaryHint(unittest.TestCase):

    def test_hint_mentions_dirs_and_names(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            csqtt_packages.print_manual_binary_hint()
        out = buf.getvalue()
        for sub in ("/root/", "/tmp/", "/opt/", "/usr/local/src/",
                    "/home/<юзер>/", "csqtt-server", "cargo build --release",
                    "Повторите установку"):
            self.assertIn(sub, out)

    def test_failure_box_contains_manual_hint(self):
        """Блок ошибки установки: приоритетная подсказка «бинарь без сборки»."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            csqtt_mod._print_install_failure_box()
        out = buf.getvalue()
        for sub in ("Не удалось собрать csqtt-server",
                    "Без сборки",
                    "/root/", "/tmp/", "/opt/", "/usr/local/src/",
                    "/home/<юзер>/",
                    "повторном запуске установки",
                    "Повторите установку CSQTT"):
            self.assertIn(sub, out)


# ══════════════════════════════════════════════════════════════════════════════
#  8. upstream_updates: подсказка при провале обновления csqtt
# ══════════════════════════════════════════════════════════════════════════════
class TestUpdateFailureHint(unittest.TestCase):
    """update_target("csqtt") при провале — подсказка про ручной бинарь."""

    def test_csqtt_failure_prints_manual_hint(self):
        from chimera.modules import upstream_updates as uu
        tmpdir = Path(tempfile.mkdtemp())
        bin_path = tmpdir / "csqtt-server"
        bin_path.write_bytes(b"\x7fELF-fake")
        orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        orig_state = uu.STATE_FILE
        uu.STATE_FILE = tmpdir / "state.json"
        try:
            uu.UPSTREAM_TARGETS["csqtt"]["binary"] = bin_path
            info = {"latest": "newrev00001", "installed": "oldrev00001",
                    "update_available": True}
            with patch.object(uu, "check_target", return_value=info), \
                 patch.object(uu, "_svc_active", return_value=False), \
                 patch.object(uu, "_backup_binary", return_value=None), \
                 patch.object(uu, "_spec_for", return_value=MagicMock()), \
                 patch("chimera.modules.download_manager.fetch_package",
                       return_value=False):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    ok = uu.update_target("csqtt", interactive=False)
            self.assertFalse(ok)
            out = buf.getvalue()
            self.assertIn("Альтернатива без сборки", out)
            self.assertIn("/root/", out)
            self.assertIn("csqtt-server", out)
        finally:
            uu.UPSTREAM_TARGETS.clear()
            uu.UPSTREAM_TARGETS.update(orig_targets)
            uu.STATE_FILE = orig_state
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_turnable_failure_no_csqtt_hint(self):
        """Подсказка — только для csqtt (тяжёлая Rust-сборка)."""
        from chimera.modules import upstream_updates as uu
        tmpdir = Path(tempfile.mkdtemp())
        bin_path = tmpdir / "turnable"
        bin_path.write_bytes(b"\x7fELF-fake")
        orig_targets = {k: dict(v) for k, v in uu.UPSTREAM_TARGETS.items()}
        orig_state = uu.STATE_FILE
        uu.STATE_FILE = tmpdir / "state.json"
        try:
            uu.UPSTREAM_TARGETS["turnable"]["binary"] = bin_path
            info = {"latest": "0.6.0", "installed": "0.4.1",
                    "update_available": True}
            with patch.object(uu, "check_target", return_value=info), \
                 patch.object(uu, "_svc_active", return_value=False), \
                 patch.object(uu, "_backup_binary", return_value=None), \
                 patch.object(uu, "_spec_for", return_value=MagicMock()), \
                 patch("chimera.modules.download_manager.fetch_package",
                       return_value=False):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    ok = uu.update_target("turnable", interactive=False)
            self.assertFalse(ok)
            self.assertNotIn("Альтернатива без сборки", buf.getvalue())
        finally:
            uu.UPSTREAM_TARGETS.clear()
            uu.UPSTREAM_TARGETS.update(orig_targets)
            uu.STATE_FILE = orig_state
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
