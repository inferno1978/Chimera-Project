#!/usr/bin/env python3
"""
tests/test_mieru_download.py
───────────────────────────────────────────────────────────────────────────────
Тесты для multi-mirror логики скачивания mita/mieru в vless_installer/modules/mieru.py.

Покрывает:
  • _download_with_mirrors() — перебирает зеркала, fallback на следующее
  • _download_with_mirrors() — находит ручное размещение в /root/ (WinSCP)
  • _install_mita_package() — deb/rpm/tar.gz пути с multi-mirror
  • _download_binary() — принимает список URL (новая сигнатура) + обратная
    совместимость со строкой (старая сигнатура)

Это regression-тесты на баг "Telemt отвалился у двоих пользователей":
до патча mieru.py использовал ОДИН прямой URL github.com/... и падал
при блокировке GitHub. Теперь перебирает 9 зеркал + проверяет /root/.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py в sys.modules как fake module (стандартный паттерн тестов)."""
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestDownloadWithMirrors(unittest.TestCase):
    """_download_with_mirrors — перебор зеркал."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mieru
        cls.mieru = mieru

    def test_returns_true_when_first_mirror_works(self):
        """Если первое зеркало отдаёт файл — возвращаем True без попыток других."""
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "mita.deb"
            urls = [
                "https://github.com/enfein/mieru/releases/download/v1.0/mita.deb",
                "https://ghproxy.net/https://github.com/enfein/mieru/.../mita.deb",
            ]
            # Мокаем urlopen так, чтобы первый URL вернул контент
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"fake deb content", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            with patch("vless_installer.modules.mieru.urllib.request.urlopen",
                       return_value=mock_resp), \
                 patch("vless_installer.modules.mieru._find_mieru_manual_upload",
                       return_value=None):
                result = self.mieru._download_with_mirrors(urls, dest, "mita.deb")
            self.assertTrue(result)
            self.assertTrue(dest.exists())
            self.assertGreater(dest.stat().st_size, 0)

    def test_falls_through_to_second_mirror_when_first_fails(self):
        """Если первое зеркало падает (URLError) — пробуем второе."""
        from urllib.error import URLError
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "mita.deb"
            urls = [
                "https://github.com/enfein/mieru/.../mita.deb",  # упадёт
                "https://ghproxy.net/https://github.com/.../mita.deb",  # ок
            ]
            mock_resp_ok = MagicMock()
            mock_resp_ok.read.side_effect = [b"fake deb content", b""]
            mock_resp_ok.__enter__ = lambda self: self
            mock_resp_ok.__exit__ = lambda self, *a: None

            call_count = [0]
            def fake_urlopen(req, timeout):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise URLError("connection refused")
                return mock_resp_ok

            with patch("vless_installer.modules.mieru.urllib.request.urlopen",
                       side_effect=fake_urlopen), \
                 patch("vless_installer.modules.mieru._find_mieru_manual_upload",
                       return_value=None):
                result = self.mieru._download_with_mirrors(urls, dest, "mita.deb")
            self.assertTrue(result)
            self.assertEqual(call_count[0], 2)  # оба зеркала были попытаны

    def test_returns_false_when_all_mirrors_fail(self):
        """Если все зеркала упали — возвращаем False."""
        from urllib.error import URLError
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "mita.deb"
            urls = [
                "https://github.com/.../mita.deb",
                "https://ghproxy.net/.../mita.deb",
                "https://ghproxy.com/.../mita.deb",
            ]
            with patch("vless_installer.modules.mieru.urllib.request.urlopen",
                       side_effect=URLError("blocked")), \
                 patch("vless_installer.modules.mieru._find_mieru_manual_upload",
                       return_value=None):
                result = self.mieru._download_with_mirrors(urls, dest, "mita.deb")
            self.assertFalse(result)

    def test_uses_manual_upload_when_file_in_root(self):
        """Если файл лежит в /root/ (WinSCP) — берём его без скачивания."""
        with tempfile.TemporaryDirectory() as td:
            # Создаём "ручной" файл
            manual_dir = Path(td) / "manual"
            manual_dir.mkdir()
            manual_file = manual_dir / "mita.deb"
            manual_file.write_bytes(b"manually placed deb")

            dest = Path(td) / "mita.deb"
            urls = ["https://github.com/.../mita.deb"]

            # urlopen НЕ должен вызываться — файл уже есть локально
            with patch("vless_installer.modules.mieru.urllib.request.urlopen",
                       side_effect=AssertionError("urlopen не должен вызываться когда файл уже в /root/")), \
                 patch("vless_installer.modules.mieru._find_mieru_manual_upload",
                       return_value=manual_file):
                result = self.mieru._download_with_mirrors(urls, dest, "mita.deb")
            self.assertTrue(result)
            self.assertEqual(dest.read_bytes(), b"manually placed deb")


class TestDownloadBinarySignature(unittest.TestCase):
    """_download_binary — новая сигнатура принимает список URL.

    Также проверяем обратную совместимость: если передать строку вместо
    списка, функция обёрнёт в список из одного элемента.
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mieru
        cls.mieru = mieru

    def test_accepts_list_of_urls(self):
        """Новая сигнатура: _download_binary(urls: list[str], dest, name)."""
        # Мокаем _download_with_mirrors чтобы вернуть True, и tar, и ELF-проверку
        with tempfile.TemporaryDirectory() as td:
            # Создаём фейковый tar.gz с ELF-бинарником
            import tarfile, io
            tar_path = Path(td) / "mita.tar.gz"
            bin_content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
            with tarfile.open(tar_path, "w:gz") as tar:
                info = tarfile.TarInfo(name="mita")
                info.size = len(bin_content)
                tar.addfile(info, io.BytesIO(bin_content))

            dest = Path(td) / "mita"
            urls = ["https://github.com/.../mita.tar.gz"]

            # _download_with_mirrors запишет tar_path в archive
            def fake_dl(urls, archive, name):
                shutil_copy = __import__("shutil").copy2
                shutil_copy(str(tar_path), str(archive))
                return True

            with patch.object(self.mieru, "_download_with_mirrors",
                              side_effect=fake_dl):
                result = self.mieru._download_binary(urls, dest, "mita")
            self.assertTrue(result)

    def test_accepts_single_string_url_backward_compat(self):
        """Обратная совместимость: _download_binary(url: str, dest, name)."""
        with tempfile.TemporaryDirectory() as td:
            import tarfile, io
            tar_path = Path(td) / "mita.tar.gz"
            bin_content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
            with tarfile.open(tar_path, "w:gz") as tar:
                info = tarfile.TarInfo(name="mita")
                info.size = len(bin_content)
                tar.addfile(info, io.BytesIO(bin_content))

            dest = Path(td) / "mita"
            single_url = "https://github.com/.../mita.tar.gz"

            def fake_dl(urls, archive, name):
                # Проверяем что urls — это список (после нормализации в _download_binary)
                assert isinstance(urls, list), f"Ожидался list, получили {type(urls)}"
                assert len(urls) == 1
                __import__("shutil").copy2(str(tar_path), str(archive))
                return True

            with patch.object(self.mieru, "_download_with_mirrors",
                              side_effect=fake_dl):
                # Передаём СТРОКУ, а не список — старая сигнатура
                result = self.mieru._download_binary(single_url, dest, "mita")
            self.assertTrue(result)


class TestInstallMitaPackageUsesMirrors(unittest.TestCase):
    """_install_mita_package — должен вызывать get_deb_mirrors/get_rpm_mirrors/get_mita_mirrors."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mieru
        cls.mieru = mieru

    def test_deb_path_uses_get_deb_mirrors(self):
        """Если есть dpkg — должен идти по .deb пути с multi-mirror."""
        with tempfile.TemporaryDirectory() as td:
            # Создаём фейковый deb-файл, который _download_with_mirrors "скачает"
            fake_deb = Path(td) / "fake.deb"
            fake_deb.write_bytes(b"fake deb content")

            deb_mirrors_called = [False]
            original_get_deb_mirrors = self.mieru.get_deb_mirrors

            def tracking_get_deb_mirrors(version):
                deb_mirrors_called[0] = True
                return original_get_deb_mirrors(version)

            # _run для dpkg вернёт успех, sys_bin существует
            def fake_run(cmd, *a, **kw):
                m = MagicMock()
                if "dpkg" in cmd and "-i" in cmd:
                    m.returncode = 0
                else:
                    m.returncode = 0
                return m

            def fake_dl(urls, dest, name):
                __import__("shutil").copy2(str(fake_deb), str(dest))
                return True

            with patch("vless_installer.modules.mieru.shutil.which",
                       lambda x: "/usr/bin/dpkg" if x == "dpkg" else None), \
                 patch.object(self.mieru, "get_deb_mirrors",
                              side_effect=tracking_get_deb_mirrors), \
                 patch.object(self.mieru, "_download_with_mirrors",
                              side_effect=fake_dl), \
                 patch.object(self.mieru, "_run", side_effect=fake_run), \
                 patch.object(self.mieru, "_atomic_install_binary"), \
                 patch("pathlib.Path.exists", lambda self: True if self.name == "mita" else Path.exists(self)):
                result = self.mieru._install_mita_package("3.33.0")
            self.assertTrue(deb_mirrors_called[0],
                            "get_deb_mirrors() не был вызван в .deb пути")

    def test_tar_gz_fallback_uses_get_mita_mirrors(self):
        """Если нет dpkg/rpm — должен идти по tar.gz пути с multi-mirror."""
        with tempfile.TemporaryDirectory() as td:
            # _download_with_mirrors вернёт False → _install_mita_package вернёт False,
            # но мы проверяем что get_mita_mirrors был вызван
            mita_mirrors_called = [False]
            original_get_mita_mirrors = self.mieru.get_mita_mirrors

            def tracking_get_mita_mirrors(version):
                mita_mirrors_called[0] = True
                return original_get_mita_mirrors(version)

            with patch("vless_installer.modules.mieru.shutil.which",
                       lambda x: None), \
                 patch.object(self.mieru, "get_mita_mirrors",
                              side_effect=tracking_get_mita_mirrors), \
                 patch.object(self.mieru, "_download_binary", return_value=False):
                result = self.mieru._install_mita_package("3.33.0")
            self.assertFalse(result)  # установка не удалась
            self.assertTrue(mita_mirrors_called[0],
                            "get_mita_mirrors() не был вызван в tar.gz fallback")


if __name__ == "__main__":
    unittest.main(verbosity=2)
