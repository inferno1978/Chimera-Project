#!/usr/bin/env python3
"""
tests/test_hysteria2_dnscrypt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров Волны 3:
  • chimera/modules/hysteria2_mirrors.py
  • chimera/modules/hysteria2_packages.py::HYSTERIA2_SPEC
  • chimera/modules/dnscrypt_mirrors.py
  • chimera/modules/dnscrypt_packages.py::DNSCRYPT_SPEC

Покрывает:
  • Корректность URL-шаблонов
  • Что все URL — HTTPS
  • Что URL содержат owner/repo/filename
  • КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_incoming_dir != install_dests (баг 21d7baf)
  • Что post_install установлен и валиден
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse
import subprocess

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


# ============================================================================
#  hysteria2_mirrors — реестр зеркал Hysteria2 binary
# ============================================================================
class TestHysteria2Mirrors(unittest.TestCase):
    """hysteria2_mirrors — 10 зеркал для hysteria-linux-{arch}."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_10_urls(self):
        from chimera.modules.hysteria2_mirrors import (
            get_hysteria2_mirrors, HYSTERIA2_MIRRORS_COUNT,
        )
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        self.assertEqual(len(urls), 10)
        self.assertEqual(HYSTERIA2_MIRRORS_COUNT, 10)

    def test_all_urls_are_https(self):
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        for url in get_hysteria2_mirrors(tag="latest", arch="amd64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_filename(self):
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        for url in get_hysteria2_mirrors(tag="latest", arch="amd64"):
            self.assertIn("apernet", url)
            self.assertIn("hysteria", url)
            self.assertIn("hysteria-linux-amd64", url)

    def test_has_release_github_url(self):
        """release GitHub URL присутствует (основной путь для binary)."""
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        self.assertTrue(
            any("github.com/apernet/hysteria/releases/latest/download/" in u
                for u in urls),
            f"Нет release/latest/download URL: {urls}"
        )

    def test_has_jsdelivr_cdn(self):
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        jsdelivr_count = sum(1 for u in urls if "jsdelivr.net" in u)
        self.assertGreaterEqual(jsdelivr_count, 1)

    def test_has_gh_proxy(self):
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        proxy_domains = ["ghproxy", "gh-proxy", "gh.llkk"]
        has_proxy = any(any(d in u for d in proxy_domains) for u in urls)
        self.assertTrue(has_proxy)

    def test_arm64_arch(self):
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="arm64")
        for url in urls:
            self.assertIn("hysteria-linux-arm64", url)

    def test_pinned_tag(self):
        """Конкретный tag 'app/v2.9.3' формирует /releases/download/app/v2.9.3/."""
        from chimera.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="app/v2.9.3", arch="amd64")
        self.assertTrue(
            any("/releases/download/app/v2.9.3/" in u for u in urls),
            f"Нет /releases/download/app/v2.9.3/ URL для pinned tag: {urls}"
        )

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.hysteria2_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  dnscrypt_mirrors — реестр зеркал dnscrypt-proxy tarball
# ============================================================================
class TestDnscryptMirrors(unittest.TestCase):
    """dnscrypt_mirrors — 10 зеркал для dnscrypt-proxy-{arch}-{tag}.tar.gz."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_10_urls(self):
        from chimera.modules.dnscrypt_mirrors import (
            get_dnscrypt_mirrors, DNSCRYPT_MIRRORS_COUNT,
        )
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64")
        self.assertEqual(len(urls), 10)
        self.assertEqual(DNSCRYPT_MIRRORS_COUNT, 10)

    def test_all_urls_are_https(self):
        from chimera.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        for url in get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_filename_and_tag(self):
        from chimera.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        for url in get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64"):
            self.assertIn("DNSCrypt", url)
            self.assertIn("dnscrypt-proxy", url)
            self.assertIn("dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz", url)
            self.assertIn("2.1.5", url)

    def test_has_release_github_url(self):
        from chimera.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64")
        self.assertTrue(
            any("/releases/download/2.1.5/" in u for u in urls)
        )

    def test_empty_tag_returns_empty_list(self):
        from chimera.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        self.assertEqual(get_dnscrypt_mirrors(tag="", arch="linux_x86_64"), [])

    def test_arm64_arch(self):
        from chimera.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_arm64")
        for url in urls:
            self.assertIn("dnscrypt-proxy-linux_arm64-2.1.5.tar.gz", url)

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.dnscrypt_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  HYSTERIA2_SPEC — инварианты PackageSpec
# ============================================================================
class TestHysteria2SpecInvariants(unittest.TestCase):
    """КРИТИЧЕСКИЕ инварианты HYSTERIA2_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_manual_dir_is_root(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        for dest in HYSTERIA2_SPEC.install_dests:
            self.assertNotEqual(HYSTERIA2_SPEC.manual_incoming_dir, dest)

    def test_install_dests_is_usr_local_bin(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_min_size_is_1mb(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.min_size, 1_000_000)

    def test_post_install_is_set(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertIsNotNone(HYSTERIA2_SPEC.post_install)


# ============================================================================
#  HYSTERIA2_SPEC post_install — runtime-проверка ДО atomic-replace
# ============================================================================
# Regression-тест: h2_update_apply проверял запуск ДО замены; после Wave 3
# миграции проверка ушла в post_install, но только ELF magic недостаточен.
# Теперь post_install запускает `<binary> version` ДО unlink старого.
class TestHysteria2PostInstallRuntimeCheck(unittest.TestCase):
    """post_install HYSTERIA2_SPEC — runtime-проверка ДО atomic-replace.

    КРИТИЧЕСКИЙ regression-тест: если бинарник проходит ELF magic но не
    запускается (битый/несовместимый) — post_install должен вернуть False
    БЕЗ удаления старого бинарника.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # Создаём "старый" бинарник в install_dest — он НЕ должен быть удалён
        # если новый не проходит runtime-проверку.
        self._install_dir = self._tmpdir / "install"
        self._install_dir.mkdir()
        self._old_binary = self._install_dir / "hysteria"
        self._old_binary.write_bytes(b'\x7fELF' + b'old_binary' * 1000)
        self._old_binary.chmod(0o755)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_elf_that_fails_version(self) -> Path:
        """Создаёт ELF-бинарник который проходит magic-check но падает при запуске."""
        # Это просто ELF header + мусор — не реальный исполняемый файл.
        # `subprocess.run([path, "version"])` вернёт ненулевой returncode.
        src = self._tmpdir / "hysteria-linux-amd64"
        src.write_bytes(b'\x7fELF' + b'\x00' * 1000)
        return src

    def test_post_install_returns_false_when_version_check_fails(self):
        """Бинарник проходит ELF magic но не запускается → False, старый не тронут."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        src = self._make_elf_that_fails_version()
        ok = HYSTERIA2_SPEC.post_install(src, [self._install_dir])
        self.assertFalse(ok, "post_install должен вернуть False если binary не запускается")
        # Старый бинарник должен быть сохранён
        self.assertTrue(self._old_binary.exists(),
                        "Старый бинарник НЕ должен быть удалён при неудачной runtime-проверке")
        # Содержимое старого бинарника не изменено
        self.assertIn(b'old_binary', self._old_binary.read_bytes())

    def test_post_install_preserves_old_when_runtime_check_fails(self):
        """Двойная проверка: старый бинарник survives неудачную попытку."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        old_size = self._old_binary.stat().st_size
        src = self._make_elf_that_fails_version()
        ok = HYSTERIA2_SPEC.post_install(src, [self._install_dir])
        self.assertFalse(ok)
        self.assertTrue(self._old_binary.exists())
        self.assertEqual(self._old_binary.stat().st_size, old_size,
                         "Старый бинарник не должен быть изменён")

    def test_post_install_replaces_when_runtime_check_passes(self):
        """Если бинарник запускается успешно — atomic-replace выполняется."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        # Создаём "бинарник" который успешно запускается.
        # Используем /bin/true (всегда returncode 0) как заглушку.
        import shutil as _shutil
        true_bin = _shutil.which("true") or "/bin/true"
        src = self._tmpdir / "hysteria-linux-amd64"
        _shutil.copy2(true_bin, src)
        # Добавляем ELF magic в начало чтобы пройти magic-check.
        # /bin/true уже ELF, так что magic есть.
        ok = HYSTERIA2_SPEC.post_install(src, [self._install_dir])
        self.assertTrue(ok, "post_install должен вернуть True если binary запускается")
        # Старый бинарник заменён новым
        self.assertTrue(self._old_binary.exists())  # путь существует
        # Содержимое изменилось (больше не содержит 'old_binary')
        new_content = self._old_binary.read_bytes()
        self.assertNotIn(b'old_binary', new_content)


# ============================================================================
#  DNSCRYPT_SPEC — инварианты PackageSpec
# ============================================================================
class TestDnscryptSpecInvariants(unittest.TestCase):
    """КРИТИЧЕСКИЕ инварианты DNSCRYPT_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_manual_dir_is_root(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        for dest in DNSCRYPT_SPEC.install_dests:
            self.assertNotEqual(DNSCRYPT_SPEC.manual_incoming_dir, dest)

    def test_install_dests_is_usr_local_bin(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_min_size_is_100kb(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.min_size, 100_000)

    def test_post_install_is_set(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertIsNotNone(DNSCRYPT_SPEC.post_install)


# ============================================================================
#  post_install — ELF-проверка для Hysteria2
# ============================================================================
class TestPostInstallHysteria2ELFCheck(unittest.TestCase):
    """post_install HYSTERIA2_SPEC — ELF magic проверка + atomic-replace."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_elf(self, name: str = "fake-hysteria") -> Path:
        """Создаёт валидный ELF-бинарник который РЕАЛЬНО запускается.

        Используем /bin/true (всегда returncode 0) — это проходит и ELF
        magic-check, и runtime-проверку (`<binary> version` → returncode 0).
        После Wave 3 fix post_install проверяет не только ELF magic, но и
        реальный запуск бинарника.
        """
        import shutil as _shutil
        p = self._tmpdir / name
        _shutil.copy2(_shutil.which("true") or "/bin/true", p)
        return p

    def _make_non_elf(self, name: str = "fake-html") -> Path:
        p = self._tmpdir / name
        p.write_bytes(b'<html>404 Not Found</html>' * 100)
        return p

    def test_post_install_copies_elf_to_hysteria(self):
        """post_install копирует валидный ELF → install_dests/hysteria (chmod 0o755).

        После Wave 3 fix: 'валидный' = проходит ELF magic И запускается
        (`<binary> version` → returncode 0). Используем /bin/true.
        """
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "install"
        src = self._make_elf("hysteria-linux-amd64")
        # НЕ мокаем subprocess.run полностью — runtime-проверка должна
        # реально запустить бинарник. Мокаем только systemctl is-active/stop/start
        # чтобы не трогать реальный hysteria-server сервис.
        _orig_run = subprocess.run
        def _mock_run(cmd, *a, **kw):
            if cmd and cmd[0] == "systemctl":
                return unittest.mock.MagicMock(returncode=1)  # service not active
            return _orig_run(cmd, *a, **kw)
        with patch("subprocess.run", side_effect=_mock_run):
            ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        dest = install_dir / "hysteria"
        self.assertTrue(dest.exists())
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_post_install_rejects_non_elf(self):
        """Не-ELF файл → False (даёт fetch_package шанс попробовать другое зеркало)."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "install"
        src = self._make_non_elf("hysteria-linux-amd64")
        ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_post_install_creates_install_dir(self):
        """install_dest создаётся если не существует (с реальным /bin/true)."""
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "deeply" / "nested" / "install"
        src = self._make_elf("hysteria-linux-amd64")
        # Мокаем только systemctl, runtime-проверка идёт через реальный subprocess
        _orig_run = subprocess.run
        def _mock_run(cmd, *a, **kw):
            if cmd and cmd[0] == "systemctl":
                return unittest.mock.MagicMock(returncode=1)
            return _orig_run(cmd, *a, **kw)
        with patch("subprocess.run", side_effect=_mock_run):
            ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        self.assertTrue(install_dir.exists())


# ============================================================================
#  post_install — tarball-обработка для dnscrypt
# ============================================================================
class TestPostInstallDnscryptArchive(unittest.TestCase):
    """post_install DNSCRYPT_SPEC — extract + rglob + copy2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_non_tarball(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC

        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)
        ok = DNSCRYPT_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_returns_false_on_empty_file(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC

        src = self._tmpdir / "empty.tar.gz"
        src.write_bytes(b"")
        ok = DNSCRYPT_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  mirror_urls_builder — сигнатура совместимости с PackageSpec API
# ============================================================================
class TestMirrorUrlsBuilderSignature(unittest.TestCase):
    """mirror_urls_builder принимает filename= и **kwargs."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_hysteria2_builder_accepts_filename_and_arch(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        urls = HYSTERIA2_SPEC.mirror_urls_builder(
            filename="hysteria-linux-amd64", arch="amd64",
        )
        self.assertGreater(len(urls), 0)

    def test_hysteria2_builder_uses_arch_in_urls(self):
        from chimera.modules.hysteria2_packages import HYSTERIA2_SPEC
        urls = HYSTERIA2_SPEC.mirror_urls_builder(
            filename="ignored", arch="arm64",
        )
        for url in urls:
            self.assertIn("hysteria-linux-arm64", url)

    def test_dnscrypt_builder_accepts_filename_tag_and_arch(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="ignored", tag="2.1.5", arch="linux_x86_64",
        )
        self.assertGreater(len(urls), 0)

    def test_dnscrypt_builder_uses_tag_and_arch_in_urls(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="ignored", tag="2.1.5", arch="linux_arm64",
        )
        for url in urls:
            self.assertIn("dnscrypt-proxy-linux_arm64-2.1.5.tar.gz", url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
