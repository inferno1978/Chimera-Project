#!/usr/bin/env python3
"""
tests/test_csqtt_packages.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/csqtt_packages.py.

Покрывает:
  1. _post_install_csqtt_source — выбор серверной директории:
     v74.2 (csqtt-layout-fix): upstream amurcanov/csqtt переименовал
     csqtt-uring → rust-server; поддерживаются оба layout.
  2. Диагностика ошибки: сообщение показывает содержимое архива.
"""
from __future__ import annotations

import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает _core.py в sys.modules (модули csqtt_* требуют _core)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestPostInstallLayout(unittest.TestCase):
    """v74.2: rust-server (новый upstream) и csqtt-uring (старый) собираются."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cargo_cwds = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_tarball(self, sub: str) -> Path:
        pkg = self._tmpdir / "pkg" / "csqtt-main"
        (pkg / sub).mkdir(parents=True)
        (pkg / sub / "Cargo.toml").write_text("[package]\nname = \"csqtt\"\n")
        tb = self._tmpdir / "csqtt-main.tar.gz"
        with tarfile.open(tb, "w:gz") as tf:
            tf.add(pkg, arcname="csqtt-main")
        return tb

    def _run_post(self, tb: Path):
        from chimera.modules import csqtt_packages
        orig_run = csqtt_packages.subprocess.run

        def fake_run(cmd, **kw):
            if "zigbuild" in cmd:
                self._cargo_cwds.append(kw.get("cwd", ""))
                # cargo кладёт бинарь в target/<triple>/release/csqtt
                cwd = Path(kw.get("cwd", ""))
                target_dir = cwd / "target"
                for triple_dir in (target_dir / "x86_64-unknown-linux-musl",
                                   target_dir):
                    (triple_dir / "release").mkdir(parents=True, exist_ok=True)
                    (triple_dir / "release" / "csqtt").write_bytes(b"\x7fELF")
                rc = MagicMock()
                rc.returncode = 0
                rc.stderr = ""
                return rc
            return orig_run(cmd, **kw)

        with patch.object(csqtt_packages, "_ensure_rust_toolchain", return_value=True), \
             patch.object(csqtt_packages, "_ensure_zig", return_value=True), \
             patch.object(csqtt_packages, "_ensure_cargo_zigbuild", return_value=True), \
             patch.object(csqtt_packages, "_ensure_swap_and_pick_jobs", return_value=2), \
             patch.object(csqtt_packages, "_detect_arch", return_value="x86_64"), \
             patch.object(csqtt_packages, "_atomic_replace_binary", return_value=True), \
             patch.object(csqtt_packages.subprocess, "run", side_effect=fake_run):
            ok = csqtt_packages._post_install_csqtt_source(tb, [self._tmpdir])
        return ok

    def test_new_layout_rust_server(self):
        """Upstream от 02.09: csqtt-main/rust-server (csqtt-uring больше нет)."""
        ok = self._run_post(self._make_tarball("rust-server"))
        self.assertTrue(ok)
        self.assertEqual(len(self._cargo_cwds), 1)
        self.assertTrue(self._cargo_cwds[0].endswith("rust-server"),
                        self._cargo_cwds[0])

    def test_old_layout_csqtt_uring_fallback(self):
        """Старые архивы: csqtt-main/csqtt-uring — тоже собираются."""
        ok = self._run_post(self._make_tarball("csqtt-uring"))
        self.assertTrue(ok)
        self.assertEqual(len(self._cargo_cwds), 1)
        self.assertTrue(self._cargo_cwds[0].endswith("csqtt-uring"),
                        self._cargo_cwds[0])

    def test_unknown_layout_fails_with_diagnostics(self):
        """Нет ни rust-server, ни csqtt-uring → False (архив распакован)."""
        import io
        from contextlib import redirect_stdout
        pkg = self._tmpdir / "pkg2" / "csqtt-main"
        (pkg / "rust-client").mkdir(parents=True)
        tb = self._tmpdir / "csqtt-main.tar.gz"
        with tarfile.open(tb, "w:gz") as tf:
            tf.add(pkg, arcname="csqtt-main")
        buf = io.StringIO()
        with redirect_stdout(buf):
            ok = self._run_post(tb)
        self.assertFalse(ok)
        self.assertIn("rust-client", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
