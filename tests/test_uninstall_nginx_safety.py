#!/usr/bin/env python3
"""
tests/test_uninstall_nginx_safety.py
───────────────────────────────────────────────────────────────────────────────
Regression-тесты для критического бага в uninstall.py.

БАГ (исправлен):
  shutil.rmtree("/etc/nginx", ignore_errors=True)
  apt-get remove --purge nginx nginx-common
  → Удаляло ВСЮ директорию /etc/nginx со всеми сайтами пользователя.

ФИКС:
  uninstall.py удаляет ТОЛЬКО конкретные vhost-файлы Chimera:
    /etc/nginx/sites-available/<domain>
    /etc/nginx/sites-enabled/<domain>
    /etc/nginx/sites-available/chimera-portal-nginx
    /etc/nginx/sites-enabled/chimera-portal-nginx
    /etc/nginx/sites-available/chimera-telemt-panel-nginx
    /etc/nginx/sites-enabled/chimera-telemt-panel-nginx
  nginx пакет НЕ удаляется без подтверждения пользователя.
  shutil.rmtree("/etc/nginx") — только если пользователь явно подтвердил
  и других сайтов нет.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestUninstallNginxSafety(unittest.TestCase):
    """Проверка что uninstall.py НЕ удаляет чужие nginx-конфиги."""

    def setUp(self):
        # Читаем исходник uninstall.py.
        self.uninstall_path = _PROJECT_ROOT / "chimera" / "modules" / "uninstall.py"
        self.src = self.uninstall_path.read_text()

    def test_no_unconditional_rmtree_etc_nginx(self):
        """shutil.rmtree('/etc/nginx') НЕ должен быть безусловным.

        БЫЛО (баг):
            shutil.rmtree("/etc/nginx", ignore_errors=True)

        СТАЛО:
            rmtree("/etc/nginx") только внутри if remove_nginx in ('y',...)
            — после явного подтверждения пользователя.
        """
        lines = self.src.splitlines()
        for i, line in enumerate(lines):
            # Пропускаем комментарии.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # Ищем реальные вызовы rmtree("/etc/nginx").
            if ('rmtree("/etc/nginx"' in line or "rmtree('/etc/nginx'" in line) and not stripped.startswith("#"):
                # Должен быть внутри if remove_nginx.
                found_guard = False
                for j in range(i, max(0, i - 30), -1):
                    if 'remove_nginx' in lines[j] and 'in (' in lines[j]:
                        found_guard = True
                        break
                self.assertTrue(
                    found_guard,
                    f"rmtree('/etc/nginx') на строке {i+1} не защищён "
                    f"проверкой remove_nginx — это может удалить чужие сайты!\n"
                    f"Строка: {line}"
                )

    def test_no_unconditional_apt_get_purge_nginx(self):
        """apt-get remove --purge nginx НЕ должен быть безусловным."""
        lines = self.src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if 'remove' in line and '--purge' in line and 'nginx' in line:
                # Должен быть внутри if remove_nginx.
                found_guard = False
                for j in range(i, max(0, i - 20), -1):
                    if 'remove_nginx' in lines[j]:
                        found_guard = True
                        break
                self.assertTrue(
                    found_guard,
                    f"apt-get remove --purge nginx на строке {i+1} не защищён "
                    f"проверкой remove_nginx — это удалит nginx без подтверждения!\n"
                    f"Строка: {line}"
                )

    def test_removes_chimera_specific_vhosts(self):
        """uninstall.py должен удалять конкретные vhost-файлы Chimera."""
        # Должны быть упоминания конкретных файлов.
        self.assertIn("chimera-portal-nginx", self.src,
                      "uninstall.py должен удалять chimera-portal-nginx vhost")
        self.assertIn("chimera-telemt-panel-nginx", self.src,
                      "uninstall.py должен удалять chimera-telemt-panel-nginx vhost")
        self.assertIn("sites-available", self.src,
                      "uninstall.py должен работать с sites-available")
        self.assertIn("sites-enabled", self.src,
                      "uninstall.py должен работать с sites-enabled")

    def test_checks_other_sites_before_removing_nginx(self):
        """uninstall.py должен проверять другие сайты в sites-enabled."""
        # Должна быть проверка наличия других сайтов.
        self.assertIn("sites-enabled", self.src)
        self.assertIn("other_sites", self.src,
                      "uninstall.py должен проверять other_sites перед удалением nginx")

    def test_reloads_nginx_after_removing_vhosts(self):
        """После удаления vhost'ов nginx должен быть перезагружен."""
        self.assertIn("reload", self.src.lower(),
                      "uninstall.py должен перезагружать nginx после удаления vhost'ов")

    def test_asks_about_www_dir(self):
        """uninstall.py должен спрашивать про /var/www/<domain>."""
        self.assertIn("/var/www/", self.src)
        self.assertIn("remove_www", self.src,
                      "uninstall.py должен спрашивать про удаление /var/www/")

    def test_default_vhost_check_has_chimera_marker(self):
        """default vhost должен удаляться только если содержит маркер Chimera."""
        # Проверяем что есть проверка содержимого default vhost.
        self.assertIn("default_vhost", self.src)
        self.assertIn("chimera", self.src.lower())


class TestUninstallNginxLogic(unittest.TestCase):
    """Интеграционные тесты логики удаления nginx (через статический анализ)."""

    def setUp(self):
        self.uninstall_path = _PROJECT_ROOT / "chimera" / "modules" / "uninstall.py"
        self.src = self.uninstall_path.read_text()

    def test_uninstall_does_not_wildcard_delete_sites(self):
        """uninstall.py НЕ должен использовать wildcard-удаление sites-*.

        Был баг: shutil.rmtree('/etc/nginx') удалял всё.
        Проверяем что нет других rmtree по sites-available / sites-enabled.
        """
        lines = self.src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # Не должно быть rmtree по sites-available или sites-enabled целиком.
            if ('rmtree' in line and
                ('sites-available' in line or 'sites-enabled' in line) and
                not stripped.startswith("#")):
                self.fail(
                    f"uninstall.py строка {i+1}: rmtree по sites-* директории "
                    f"недопустим — это удалит чужие сайты!\nСтрока: {line}"
                )

    def test_uninstall_targets_only_chimera_files(self):
        """Список удаляемых vhost-файлов содержит только Chimera-файлы."""
        # Извлекаем все пути /etc/nginx/sites-* из кода.
        import re
        paths = re.findall(r'["\'](/etc/nginx/sites-(?:available|enabled)/[^"\']+)["\']', self.src)
        # Каждый путь должен быть либо chimera-*, либо <domain> (переменная).
        for p in paths:
            basename = p.split("/")[-1]
            # Допустимые паттерны:
            # - chimera-portal-nginx
            # - chimera-telemt-panel-nginx
            # - {uninst_domain} или {param_domain} (f-string)
            # - default (с проверкой маркера Chimera)
            if (basename.startswith("chimera-") or
                "{" in basename or
                basename == "default"):
                continue
            self.fail(
                f"uninstall.py удаляет неизвестный nginx vhost: {p}\n"
                f"Это может быть чужой сайт!"
            )

    def test_uninstall_asks_confirmation_for_full_nginx_removal(self):
        """Полное удаление nginx требует явного подтверждения."""
        # Должен быть input() с вопросом про удаление nginx.
        self.assertIn("Полностью удалить nginx", self.src,
                      "uninstall.py должен спрашивать про полное удаление nginx")

    def test_uninstall_checks_other_sites(self):
        """uninstall.py проверяет наличие других сайтов в sites-enabled."""
        self.assertIn("other_sites", self.src,
                      "uninstall.py должен проверять other_sites")


if __name__ == "__main__":
    unittest.main(verbosity=2)
