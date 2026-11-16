#!/usr/bin/env python3
"""Тесты для chimera.modules.nginx_setup.upgrade_vhosts_hsts.

FIX 16.11.2026 (РКН-волна): HSTS-апгрейд ЖИВЫХ vhost'ов — идемпотентный
мигратор для нод, чьи конфиги генерировались до 8824000 (шаблоны с HSTS).
Покрывает: вставку в заглушечные блоки (X-Robots-Tag без HSTS), отступ
как у соседа, симлинк sites-enabled → бэкап к target'у, идемпотентность
(повтор — no-op, без reload), отказ от двойного заголовка (фронты панелей),
игнор блоков без маркера (ACME :80 / default reject), dry-run, rollback
при провале nginx -t, отсутствие sites-enabled.
"""
from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_CHIMERA_SNAPSHOT = {k: v for k, v in sys.modules.items()
                     if k == "chimera" or k.startswith("chimera.")}


def tearDownModule():
    """Снять фейки sys.modules после модуля (анти-загрязнение сьюта)."""
    for k in [k for k in sys.modules
              if k == "chimera" or k.startswith("chimera.")]:
        if k not in _CHIMERA_SNAPSHOT:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = _CHIMERA_SNAPSHOT[k]


def _setup_core_in_sysmodules():
    """Фейковый chimera._core с патчабельными nginx-путями (как в
    test_nginx_cleanup_stale_vhosts)."""
    if "chimera" not in sys.modules:
        pkg = types.ModuleType("chimera")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera")]
        sys.modules["chimera"] = pkg
    if "chimera.modules" not in sys.modules:
        pkg = types.ModuleType("chimera.modules")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera" / "modules")]
        sys.modules["chimera.modules"] = pkg
    if "chimera._core" not in sys.modules:
        fake_core = types.ModuleType("chimera._core")
        fake_core.info = lambda *a, **kw: None
        fake_core.warn = lambda *a, **kw: None
        fake_core.success = lambda *a, **kw: None
        fake_core.log_to_file = lambda *a, **kw: None
        fake_core.find_nginx_bin = lambda: "/usr/sbin/nginx"
        sys.modules["chimera._core"] = fake_core
    return sys.modules["chimera._core"]


_STUB_VHOST = """\
# Main server: VLESS fallback via Unix socket
server {{
    listen unix:/dev/shm/{sock}.socket ssl http2 proxy_protocol;
    server_name {dom};

    ssl_certificate     /etc/letsencrypt/live/{dom}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{dom}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/{dom};
    index index.html;

    add_header X-Robots-Tag "noindex, nofollow" always;
    location / {{
        try_files $uri $uri/ =404;
    }}
}}

# Default server: reject all other SNI
server {{
    listen unix:/dev/shm/{sock}.socket ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}}
}}
"""

_ACME_BLOCK = """\
server {{
    listen 80;
    server_name {dom};
    location /.well-known/acme-challenge/ {{ root /var/www/{dom}; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""

_FRONT_WITH_HSTS = """\
server {{
    listen 9443 ssl;
    server_name panel.{dom};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Robots-Tag "noindex, nofollow" always;
    location / {{ proxy_pass http://127.0.0.1:9700; }}
}}
"""


class _HstsBase(unittest.TestCase):

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "sites-available"
        self._enabled_dir = self._tmpdir / "sites-enabled"
        self._conf_dir.mkdir()
        self._enabled_dir.mkdir()
        self._fake_core.NGINX_CONF_DIR = self._conf_dir
        self._fake_core.NGINX_ENABLED_DIR = self._enabled_dir
        self._run = MagicMock(
            return_value=SimpleNamespace(returncode=0, stderr="", stdout=""))
        self._fake_core._run = self._run

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _vhost(self, name: str, content: str, enabled: bool = True):
        """Файл в sites-available + симлинк в sites-enabled."""
        target = self._conf_dir / name
        target.write_text(content)
        if enabled:
            (self._enabled_dir / name).symlink_to(target)
        return target

    def _nginx_setup(self):
        from chimera.modules import nginx_setup
        return nginx_setup


class TestUpgradeVhostsHsts(_HstsBase):

    def test_adds_hsts_to_stub_vhost(self):
        """Заглушечный блок (X-Robots-Tag без HSTS) получает HSTS с тем же
        отступом; бэкап кладётся к target'у в sites-available."""
        ns = self._nginx_setup()
        dom = "stub.example"
        target = self._vhost(dom, _STUB_VHOST.format(sock="ab12", dom=dom))
        res = ns.upgrade_vhosts_hsts()
        self.assertTrue(res["ok"], res["report"])
        self.assertEqual(res["changed"], [dom])
        self.assertTrue(res["reloaded"])
        text = target.read_text()
        self.assertEqual(text.count("Strict-Transport-Security"), 1)
        # отступ совпадает со строкой X-Robots-Tag
        line = [l for l in text.splitlines()
                if "Strict-Transport-Security" in l][0]
        self.assertTrue(line.startswith("    add_header Strict-Transport"),
                        f"отступ не 4 пробела: {line!r}")
        # reject-блок и ACME не тронуты: ровно одна вставка
        baks = list(self._conf_dir.glob(f"{dom}.bak-hsts-*"))
        self.assertEqual(len(baks), 1)

    def test_idempotent_second_run_is_noop(self):
        """Повторный прогон: changed пуст, нового бэкапа нет, reload не зовётся."""
        ns = self._nginx_setup()
        dom = "stub.example"
        self._vhost(dom, _STUB_VHOST.format(sock="ab12", dom=dom))
        first = ns.upgrade_vhosts_hsts()
        self.assertEqual(first["changed"], [dom])
        self._run.reset_mock()
        second = ns.upgrade_vhosts_hsts()
        self.assertEqual(second["changed"], [])
        self.assertTrue(second["ok"])
        self.assertFalse(second["reloaded"])
        self.assertEqual(len(list(self._conf_dir.glob(f"{dom}.bak-hsts-*"))), 1)
        # ни nginx -t, ни reload при отсутствии изменений
        self.assertEqual(self._run.call_count, 0)

    def test_no_double_header_when_hsts_present(self):
        """Фронт панели (HSTS уже есть) не получает второй заголовок."""
        ns = self._nginx_setup()
        dom = "panel.example"
        target = self._vhost(dom, _FRONT_WITH_HSTS.format(dom="x"))
        before = target.read_text()
        res = ns.upgrade_vhosts_hsts()
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertEqual(before.count("Strict-Transport-Security"), 1)

    def test_ignores_blocks_without_marker(self):
        """ACME :80 и default reject (без X-Robots-Tag) не трогаются."""
        ns = self._nginx_setup()
        dom = "acme.example"
        target = self._vhost(dom, _ACME_BLOCK.format(dom=dom))
        before = target.read_text()
        res = ns.upgrade_vhosts_hsts()
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)

    def test_two_stub_blocks_in_one_file_both_patched(self):
        """Файл с двумя заглушечными блоками (own-site + REALITY-маска) —
        HSTS в обоих."""
        ns = self._nginx_setup()
        dom = "two.example"
        content = (_STUB_VHOST.format(sock="s1", dom=dom) + "\n"
                   + _STUB_VHOST.format(sock="s2", dom=dom))
        target = self._vhost(dom, content)
        res = ns.upgrade_vhosts_hsts()
        self.assertTrue(res["ok"])
        text = target.read_text()
        self.assertEqual(text.count("Strict-Transport-Security"), 2)
        self.assertIn("(2 блок(ов)", " ".join(res["report"]))

    def test_dry_run_does_not_touch_files(self):
        ns = self._nginx_setup()
        dom = "dry.example"
        target = self._vhost(dom, _STUB_VHOST.format(sock="ab", dom=dom))
        before = target.read_text()
        res = ns.upgrade_vhosts_hsts(apply=False)
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("БЫЛО БЫ" in r for r in res["report"]))
        self.assertEqual(self._run.call_count, 0)

    def test_nginx_t_failure_rolls_back(self):
        """Провал nginx -t: содержимое восстанавливается, ok=False."""
        ns = self._nginx_setup()
        dom = "fail.example"
        target = self._vhost(dom, _STUB_VHOST.format(sock="ab", dom=dom))
        before = target.read_text()
        self._run.return_value = SimpleNamespace(
            returncode=1, stderr="nginx: [emerg] unexpected end", stdout="")
        res = ns.upgrade_vhosts_hsts()
        self.assertFalse(res["ok"])
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("откачены" in r for r in res["report"]))

    def test_missing_sites_enabled(self):
        """sites-enabled нет (nginx не установлен) — ok, без исключений."""
        ns = self._nginx_setup()
        self._fake_core.NGINX_ENABLED_DIR = self._tmpdir / "nope"
        res = ns.upgrade_vhosts_hsts()
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed"], [])


if __name__ == "__main__":
    unittest.main()
