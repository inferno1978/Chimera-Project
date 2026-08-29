"""Тесты для chimera.modules.nginx_setup._cleanup_stale_chimera_vhosts.

FIX (commit): раньше setup_nginx_temp/final не удаляли старые Chimera vhost-файлы
при смене домена. Это приводило к:
  • Конфликту listen 443 в двух vhost-ах → nginx падал
  • Либо один из vhost-ов тихо игнорировался → клиент не подключался

Хелпер _cleanup_stale_chimera_vhosts сканирует sites-available/ и sites-enabled/,
находит Chimera-конфиги по маркерам (proxy_protocol, /dev/shm/, xver, realpath)
и удаляет те, что не совпадают с новым доменом.

Безопасность: НЕ трогает default, chimera-portal-nginx, chimera-telemt-panel-nginx
и любые чужие vhost-ы без Chimera-маркеров.
"""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core и регистрирует chimera.modules.

    Без этого chimera.modules.nginx_setup не может импортироваться.
    Использует тот же подход что test_chain_nodes.py (exec + патч Path).
    """
    # Регистрируем chimera пакет
    if "chimera" not in sys.modules:
        pkg = types.ModuleType("chimera")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera")]
        sys.modules["chimera"] = pkg
    # Регистрируем chimera.modules пакет
    if "chimera.modules" not in sys.modules:
        pkg = types.ModuleType("chimera.modules")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera" / "modules")]
        sys.modules["chimera.modules"] = pkg
    # Регистрируем фейковый chimera._core
    if "chimera._core" not in sys.modules:
        fake_core = types.ModuleType("chimera._core")
        fake_core.info = lambda *a, **kw: None
        fake_core.warn = lambda *a, **kw: None
        fake_core.success = lambda *a, **kw: None
        fake_core.NGINX_CONF_DIR = Path("/etc/nginx/sites-available")
        fake_core.NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
        fake_core.IS_IPV6_AVAILABLE = False
        sys.modules["chimera._core"] = fake_core
    return sys.modules["chimera._core"]


class TestCleanupStaleChimeraVhosts(unittest.TestCase):
    """_cleanup_stale_chimera_vhosts — корректное удаление старых vhost-ов."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        # Временные директории для sites-available и sites-enabled
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "sites-available"
        self._enabled_dir = self._tmpdir / "sites-enabled"
        self._conf_dir.mkdir(parents=True)
        self._enabled_dir.mkdir(parents=True)
        # Подменяем пути в фейковом ядре
        self._fake_core.NGINX_CONF_DIR = self._conf_dir
        self._fake_core.NGINX_ENABLED_DIR = self._enabled_dir

    def _write_vhost(self, directory: Path, name: str, content: str,
                     is_symlink: bool = False) -> Path:
        """Создаёт vhost-файл в directory с именем name и содержимым content.

        Если is_symlink=True — создаёт симлинк на sites-available/<name>.
        """
        if is_symlink:
            target = self._conf_dir / name
            link = self._enabled_dir / name
            link.symlink_to(target)
            return link
        path = directory / name
        path.write_text(content)
        return path

    def test_removes_old_chimera_vhost_with_proxy_protocol(self):
        """VLESS REALITY vhost с proxy_protocol удаляется при смене домена."""
        from chimera.modules import nginx_setup
        # Старый Chimera vhost
        self._write_vhost(self._conf_dir, "old-domain.ru",
                          "server {\n  listen unix:/dev/shm/x.socket ssl "
                          "proxy_protocol;\n  server_name old-domain.ru;\n}")
        # Новый домен
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new-domain.ru")
        self.assertEqual(removed, 1)
        self.assertFalse((self._conf_dir / "old-domain.ru").exists())

    def test_removes_old_chimera_vhost_with_dev_shm_path(self):
        """VLESS vhost с /dev/shm/ путём тоже распознаётся как Chimera."""
        from chimera.modules import nginx_setup
        self._write_vhost(self._conf_dir, "old.example.com",
                          "upstream backend {\n  server unix:/dev/shm/x.socket;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new.example.com")
        self.assertEqual(removed, 1)

    def test_keeps_new_domain_vhost(self):
        """Vhost с именем нового домена НЕ удаляется."""
        from chimera.modules import nginx_setup
        # Vhost нового домена (с Chimera-маркером)
        self._write_vhost(self._conf_dir, "new-domain.ru",
                          "server {\n  listen unix:/dev/shm/x.socket ssl "
                          "proxy_protocol;\n  server_name new-domain.ru;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new-domain.ru")
        self.assertEqual(removed, 0)
        self.assertTrue((self._conf_dir / "new-domain.ru").exists())

    def test_keeps_default_vhost(self):
        """'default' vhost НЕ удаляется, даже если содержит Chimera-маркеры.

        Это критично: default vhost — стандартный vhost Ubuntu/Debian.
        """
        from chimera.modules import nginx_setup
        self._write_vhost(self._conf_dir, "default",
                          "server {\n  listen 80 default_server;\n"
                          "  proxy_protocol;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("any-domain.ru")
        self.assertEqual(removed, 0)
        self.assertTrue((self._conf_dir / "default").exists())

    def test_keeps_portal_nginx_vhost(self):
        """chimera-portal-nginx НЕ удаляется — это отдельная фича."""
        from chimera.modules import nginx_setup
        self._write_vhost(self._conf_dir, "chimera-portal-nginx",
                          "server {\n  listen 80;\n  proxy_protocol;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("any-domain.ru")
        self.assertEqual(removed, 0)

    def test_keeps_telemt_nginx_vhost(self):
        """chimera-telemt-panel-nginx НЕ удаляется — это отдельная фича."""
        from chimera.modules import nginx_setup
        self._write_vhost(self._conf_dir, "chimera-telemt-panel-nginx",
                          "server {\n  listen 80;\n  proxy_protocol;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("any-domain.ru")
        self.assertEqual(removed, 0)

    def test_keeps_foreign_vhost_without_chimera_markers(self):
        """Чужой vhost без Chimera-маркеров НЕ удаляется.

        Это гарантирует что пользовательский сайт (например blog.example.com)
        останется нетронутым при переустановке Chimera.
        """
        from chimera.modules import nginx_setup
        self._write_vhost(self._conf_dir, "blog.example.com",
                          "server {\n  listen 80;\n"
                          "  server_name blog.example.com;\n"
                          "  root /var/www/blog;\n"
                          "  location / { proxy_pass http://127.0.0.1:8080; }\n"
                          "}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("chimera.ru")
        self.assertEqual(removed, 0)
        self.assertTrue((self._conf_dir / "blog.example.com").exists())

    def test_removes_symlink_in_sites_enabled(self):
        """Симлинк в sites-enabled/ на старый Chimera vhost удаляется."""
        from chimera.modules import nginx_setup
        # Создаём sites-available/old.ru + symlink sites-enabled/old.ru
        self._write_vhost(self._conf_dir, "old.ru",
                          "server {\n  proxy_protocol;\n}")
        self._write_vhost(self._enabled_dir, "old.ru",
                          "", is_symlink=True)
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new.ru")
        # Должен удалить и sites-available/old.ru (1), и sites-enabled/old.ru (2)
        self.assertEqual(removed, 2)
        self.assertFalse((self._conf_dir / "old.ru").exists())
        self.assertFalse((self._enabled_dir / "old.ru").exists())

    def test_handles_missing_directories_gracefully(self):
        """Если sites-enabled/ не существует — функция не падает."""
        from chimera.modules import nginx_setup
        # Удаляем sites-enabled/
        import shutil
        shutil.rmtree(self._enabled_dir)
        # Должно выполниться без ошибок
        removed = nginx_setup._cleanup_stale_chimera_vhosts("any.ru")
        self.assertEqual(removed, 0)

    def test_skips_hidden_files(self):
        """Скрытые файлы (.swp, .bak) не трогаются."""
        from chimera.modules import nginx_setup
        # Vim swap file с Chimera-маркером
        self._write_vhost(self._conf_dir, ".old.ru.swp",
                          "proxy_protocol;\n /dev/shm/x;\n xver;")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new.ru")
        self.assertEqual(removed, 0)
        self.assertTrue((self._conf_dir / ".old.ru.swp").exists())

    def test_multiple_stale_vhosts_removed(self):
        """Несколько старых Chimera vhost-ов удаляются за один вызов."""
        from chimera.modules import nginx_setup
        for name in ("old1.ru", "old2.ru", "old3.com"):
            self._write_vhost(self._conf_dir, name,
                              "server {\n  proxy_protocol;\n  xver;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new.ru")
        self.assertEqual(removed, 3)
        for name in ("old1.ru", "old2.ru", "old3.com"):
            self.assertFalse((self._conf_dir / name).exists())

    def test_mixed_scenario(self):
        """Смешанный сценарий: новый домен + чужой + Chimera-старый + default.

        Должен удалить ТОЛЬКО Chimera-старый.
        """
        from chimera.modules import nginx_setup
        # Новый домен (НЕ удалять)
        self._write_vhost(self._conf_dir, "new.ru",
                          "server {\n  proxy_protocol;\n}")
        # Чужой (НЕ удалять)
        self._write_vhost(self._conf_dir, "blog.example.com",
                          "server {\n  listen 80;\n  root /var/www/blog;\n}")
        # Старый Chimera (удалить)
        self._write_vhost(self._conf_dir, "old.ru",
                          "server {\n  proxy_protocol;\n  /dev/shm/x;\n}")
        # Default (НЕ удалять)
        self._write_vhost(self._conf_dir, "default",
                          "server {\n  listen 80 default_server;\n}")
        removed = nginx_setup._cleanup_stale_chimera_vhosts("new.ru")
        self.assertEqual(removed, 1)
        self.assertTrue((self._conf_dir / "new.ru").exists())
        self.assertTrue((self._conf_dir / "blog.example.com").exists())
        self.assertFalse((self._conf_dir / "old.ru").exists())
        self.assertTrue((self._conf_dir / "default").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
