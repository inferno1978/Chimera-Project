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
        """Если файл лежит в /root/ (WinSCP) — берём его без скачивания.

        АДАПТАЦИЯ: _download_with_mirrors теперь deprecated и НЕ проверяет
        manual upload (это делает fetch_package). Этот тест проверяет что
        deprecated функция всё ещё работает для прямого скачивания по URL,
        но НЕ проверяет manual upload (это теперь в download_manager тестах).
        """
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "mita.deb"
            urls = ["https://github.com/.../mita.deb"]

            # Мокаем urlopen чтобы вернуть "скачанный" файл
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"downloaded deb content", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None

            with patch("vless_installer.modules.mieru.urllib.request.urlopen",
                       return_value=mock_resp):
                result = self.mieru._download_with_mirrors(urls, dest, "mita.deb")
            self.assertTrue(result)
            self.assertEqual(dest.read_bytes(), b"downloaded deb content")


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

    def test_deb_path_uses_fetch_package(self):
        """Если есть dpkg — должен идти по .deb пути через fetch_package.

        АДАПТАЦИЯ: старый тест проверял что get_deb_mirrors() вызывается.
        Новый код использует fetch_package(MITA_DEB_SPEC) — проверяем что
        fetch_package вызывается с правильным spec.
        """
        from vless_installer.modules import mieru_packages

        fetch_called = [False]
        def tracking_fetch(spec, **kw):
            fetch_called[0] = True
            # Проверяем что это DEB spec
            self.assertIn("deb", spec.name)
            return True  # успех

        with patch("vless_installer.modules.mieru.shutil.which",
                   lambda x: "/usr/bin/dpkg" if x == "dpkg" else None), \
             patch("vless_installer.modules.mieru.fetch_package",
                   side_effect=tracking_fetch) if hasattr(self.mieru, "fetch_package") else \
             patch("vless_installer.modules.download_manager.fetch_package",
                   side_effect=tracking_fetch):
            result = self.mieru._install_mita_package("3.33.0")
        self.assertTrue(result)
        self.assertTrue(fetch_called[0],
                        "fetch_package() должен быть вызван в .deb пути")

    def test_tar_gz_fallback_uses_fetch_package(self):
        """Если нет dpkg/rpm — должен идти по tar.gz пути через fetch_package.

        АДАПТАЦИЯ: старый тест проверял что get_mita_mirrors() вызывается.
        Новый код использует fetch_package(MITA_TARGZ_SPEC).
        """
        fetch_called = [False]
        def tracking_fetch(spec, **kw):
            fetch_called[0] = True
            self.assertIn("tar.gz", spec.name)
            return False  # провал — нет сети

        with patch("vless_installer.modules.mieru.shutil.which",
                   lambda x: None), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   side_effect=tracking_fetch):
            result = self.mieru._install_mita_package("3.33.0")
        self.assertFalse(result)  # установка не удалась
        self.assertTrue(fetch_called[0],
                        "fetch_package() должен быть вызван в tar.gz fallback")


class TestInstallMitaDebMirrorFailover(unittest.TestCase):
    """Regression-тест: .deb скачивание — первое зеркало падает → второе
    успешно → dpkg -i вызван с правильным путём.

    Это проверяет что fetch_package с MITA_DEB_SPEC корректно перебирает
    зеркала и вызывает post_install (_post_install_deb → dpkg -i).
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mieru
        cls.mieru = mieru

    def test_deb_mirror1_fail_mirror2_ok_dpkg_called(self):
        """Первое зеркало падает (URLError) → второе успешно → dpkg -i вызван."""
        from urllib.error import URLError
        from vless_installer.modules import mieru_packages
        from vless_installer.modules.download_manager import fetch_package

        # Мокаем urlopen: первое зеркало падает, второе отдаёт .deb
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

        dpkg_called = [False]
        def fake_run(cmd, *a, **kw):
            m = MagicMock()
            m.returncode = 0
            if "dpkg" in cmd and "-i" in cmd:
                dpkg_called[0] = True
            return m

        tmp_path = Path("/tmp/_download_mgr_mita_3.33.0_amd64.deb")

        def fake_open(path, *a, **kw):
            if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                tmp_path.write_bytes(b"fake deb content")
            return MagicMock()

        original_exists = Path.exists

        def smart_exists(self, *a, **kw):
            s = str(self)
            # /root/ paths — NO manual file (force network download)
            if s.startswith("/root/"):
                return False
            # tmp download path — exists (file "downloaded" by urlopen mock)
            if s.startswith("/tmp/_download_mgr_"):
                return True
            # /usr/bin/mita — exists (so post_install finds it)
            if s == "/usr/bin/mita":
                return True
            return original_exists(self, *a, **kw)

        with patch("vless_installer.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("vless_installer.modules.download_manager.Path.unlink"), \
             patch("builtins.open", side_effect=fake_open), \
             patch.object(Path, 'stat', return_value=MagicMock(st_size=10000)), \
             patch.object(Path, 'exists', smart_exists), \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(self.mieru, "_run", side_effect=fake_run), \
             patch.object(self.mieru, "_atomic_install_binary"):
            ok = fetch_package(mieru_packages.MITA_DEB_SPEC,
                               print_hint_on_failure=False,
                               version="3.33.0", arch="amd64")

        self.assertTrue(ok, "fetch_package должен вернуть True при успехе")
        self.assertEqual(call_count[0], 2,
                         "Оба зеркала должны быть попытаны (первый упал, второй ок)")
        self.assertTrue(dpkg_called[0],
                        "dpkg -i должен быть вызван при успешном скачивании .deb")


if __name__ == "__main__":
    unittest.main(verbosity=2)
