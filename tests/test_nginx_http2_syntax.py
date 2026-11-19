#!/usr/bin/env python3
"""Тесты HTTP/2-миграции: nginx_setup.upgrade_vhosts_http2_syntax + оба
генератора фронтов (panel_nginx_front / nginx_front_portal).

Волна 19.11 (перевод флота на nginx.org 1.30.7): параметр `http2` в listen
deprecated с nginx 1.25.1 — каждый nginx -t сыплет варнингом; живые vhost'ы
сгенерированы во времена дистрибутивных nginx (1.18/1.24), где inline-параметр
был единственным вариантом.

Покрывает:
  мигратор:
    • фронт панели: listen … ssl http2 → ssl + http2 on; (в т.ч. dual-stack
      [::] — одна директива на server-блок после ПОСЛЕДНЕЙ listen-строки);
    • REALITY-сокет: listen unix:… ssl http2 proxy_protocol → ssl
      proxy_protocol + http2 on;;
    • идемпотентность (повтор — no-op, 0 вызовов _run, без бэкапов);
    • чужой vhost (нет chimera-маркеров) — пропуск с записью в отчёт;
    • гейт версии: nginx < 1.25.1 → полный no-op (http2 on; там — unknown
      directive), nginx не читался → no-op;
    • dry-run не пишет файлы;
    • провал nginx -t → полный rollback;
    • отсутствие sites-enabled.
  генераторы:
    • _generate_vhost(http2_on=True) обоих модулей — новый синтаксис без
      deprecated-параметра; http2_on=False — прежний (дефолт, обратная
      совместимость тестов test_port_registry);
    • _nginx_supports_http2_on: порог 1.25.1 (не 1.25.0!), ошибки → False.
"""
from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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
    """Фейковый chimera._core с патчабельными nginx-путями."""
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


_FRONT_VHOST = """\
# Chimera — nginx front для b4-panel с TLS.
# Сгенерировано panel_nginx_front.py. НЕ редактировать вручную.
server {{
    listen {port} ssl http2;{v6}
    server_name {dom};
    ssl_certificate     /etc/letsencrypt/live/{dom}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{dom}/privkey.pem;
    add_header X-Robots-Tag "noindex, nofollow" always;
    location / {{ proxy_pass http://127.0.0.1:9700; }}
}}
"""

_REALITY_VHOST = """\
# Main server: VLESS fallback via Unix socket
server {{
    listen unix:/dev/shm/{sock}.socket ssl http2 proxy_protocol;
    server_name {dom};
    ssl_certificate     /etc/letsencrypt/live/{dom}/fullchain.pem;
    add_header X-Robots-Tag "noindex, nofollow" always;
    location / {{ try_files $uri $uri/ =404; }}
}}

# Default server: reject all other SNI
server {{
    listen unix:/dev/shm/{sock}.socket ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}}
"""

_FOREIGN_VHOST = """\
# чужой vhost (не Chimera)
server {
    listen 8443 ssl http2;
    server_name foreign.example;
    location / { proxy_pass http://10.0.0.1:8080; }
}
"""


class _Http2Base(unittest.TestCase):

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "sites-available"
        self._enabled_dir = self._tmpdir / "sites-enabled"
        self._conf_dir.mkdir()
        self._enabled_dir.mkdir()
        self._fake_core.NGINX_CONF_DIR = self._conf_dir
        self._fake_core.NGINX_ENABLED_DIR = self._enabled_dir
        # _run: nginx -v → 1.30.7 (миграция разрешена); прочее — rc 0.
        self._nginx_version = "1.30.7"
        self._run = MagicMock(side_effect=self._run_dispatch)
        self._fake_core._run = self._run

    def _run_dispatch(self, args, **kwargs):
        if len(args) >= 2 and args[1] == "-v":
            return SimpleNamespace(
                returncode=0, stderr=f"nginx version: nginx/{self._nginx_version}",
                stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _vhost(self, name: str, content: str, enabled: bool = True):
        target = self._conf_dir / name
        target.write_text(content)
        if enabled:
            (self._enabled_dir / name).symlink_to(target)
        return target

    def _nginx_setup(self):
        from chimera.modules import nginx_setup
        return nginx_setup


class TestUpgradeVhostsHttp2Syntax(_Http2Base):

    def test_front_vhost_migrated(self):
        """Фронт: оба listen (v4+[::]) чистятся, ОДНА http2 on; после
        последней listen-строки; бэкап — к target'у в sites-available."""
        ns = self._nginx_setup()
        dom = "front.example"
        content = _FRONT_VHOST.format(
            port=9743, v6="\n    listen [::]:9743 ssl http2;", dom=dom)
        target = self._vhost("chimera-b4-nginx", content)
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"], res["report"])
        self.assertEqual(res["changed"], ["chimera-b4-nginx"])
        self.assertTrue(res["reloaded"])
        text = target.read_text()
        self.assertIn("    listen 9743 ssl;\n    listen [::]:9743 ssl;\n"
                      "    http2 on;\n", text)
        self.assertNotIn("ssl http2", text)
        self.assertEqual(text.count("http2 on;"), 1)
        self.assertEqual(len(list(self._conf_dir.glob("*.bak-http2-*"))), 1)

    def test_reality_socket_migrated(self):
        """REALITY-сокет: ssl http2 proxy_protocol → ssl proxy_protocol;
        default_server-блок (без http2) не трогается и директиву не получает."""
        ns = self._nginx_setup()
        dom = "reality.example"
        target = self._vhost(dom, _REALITY_VHOST.format(sock="ab12", dom=dom))
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"])
        text = target.read_text()
        self.assertIn("listen unix:/dev/shm/ab12.socket ssl proxy_protocol;",
                      text)
        self.assertEqual(text.count("http2 on;"), 1)
        # default_server-блок без http2-параметра остался как был
        self.assertIn("ssl default_server;", text)

    def test_idempotent_second_run_is_noop(self):
        ns = self._nginx_setup()
        dom = "stub.example"
        self._vhost(dom, _REALITY_VHOST.format(sock="ab12", dom=dom))
        first = ns.upgrade_vhosts_http2_syntax()
        self.assertEqual(first["changed"], [dom])
        self._run.reset_mock()
        second = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(second["ok"])
        self.assertEqual(second["changed"], [])
        self.assertFalse(second["reloaded"])
        # ни nginx -t, ни reload при отсутствии изменений (но -v для
        # гейта версии был)
        for call in self._run.call_args_list:
            self.assertNotIn("-t", call.args[0])
        self.assertEqual(
            len(list(self._conf_dir.glob(f"{dom}.bak-http2-*"))), 1)

    def test_foreign_vhost_skipped_with_report(self):
        """Чужой vhost (нет ни одного chimera-маркера) — пропуск + запись."""
        ns = self._nginx_setup()
        target = self._vhost("foreign-site", _FOREIGN_VHOST)
        before = target.read_text()
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("ПРОПУЩЕН" in r and "foreign-site" in r
                            for r in res["report"]))

    def test_old_nginx_noop(self):
        """nginx < 1.25.1 — полный no-op: там http2 on; = unknown directive,
        а deprecated-параметр легален (варнингов старый nginx не пишет)."""
        ns = self._nginx_setup()
        dom = "old.example"
        target = self._vhost(dom, _REALITY_VHOST.format(sock="ab12", dom=dom))
        before = target.read_text()
        self._nginx_version = "1.24.0"
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("1.24.0" in r and "не нужна" in r
                            for r in res["report"]))

    def test_nginx_unreadable_noop(self):
        """Версия не прочиталась (nginx -v rc=1) — миграция пропущена тихо."""
        ns = self._nginx_setup()
        self._nginx_version = "garbage-no-version"
        def _dispatch(args, **kw):
            if len(args) >= 2 and args[1] == "-v":
                return SimpleNamespace(returncode=1, stderr="boom", stdout="")
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        self._run.side_effect = _dispatch
        self._fake_core._run = self._run
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed"], [])
        self.assertTrue(any("не прочиталась" in r for r in res["report"]))

    def test_dry_run_does_not_touch_files(self):
        ns = self._nginx_setup()
        dom = "dry.example"
        target = self._vhost(dom, _REALITY_VHOST.format(sock="ab", dom=dom))
        before = target.read_text()
        res = ns.upgrade_vhosts_http2_syntax(apply=False)
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("БЫЛО БЫ" in r for r in res["report"]))
        # nginx -t не вызывался (только -v гейта версии)
        for call in self._run.call_args_list:
            self.assertNotIn("-t", call.args[0])

    def test_nginx_t_failure_rolls_back(self):
        ns = self._nginx_setup()
        dom = "fail.example"
        target = self._vhost(dom, _REALITY_VHOST.format(sock="ab", dom=dom))
        before = target.read_text()
        real_dispatch = self._run_dispatch

        def _dispatch(args, **kw):
            if len(args) >= 2 and args[1] == "-t":
                return SimpleNamespace(
                    returncode=1, stderr="nginx: [emerg] unexpected end",
                    stdout="")
            return real_dispatch(args, **kw)

        self._run.side_effect = _dispatch
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertFalse(res["ok"])
        self.assertEqual(res["changed"], [])
        self.assertEqual(target.read_text(), before)
        self.assertTrue(any("откачены" in r for r in res["report"]))

    def test_missing_sites_enabled(self):
        ns = self._nginx_setup()
        self._fake_core.NGINX_ENABLED_DIR = self._tmpdir / "nope"
        res = ns.upgrade_vhosts_http2_syntax()
        self.assertTrue(res["ok"])
        self.assertEqual(res["changed"], [])


class TestGeneratorsHttp2Syntax(unittest.TestCase):
    """Генераторы фронтов: http2_on=True/False + детектор версии."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _pnf(self):
        from chimera.modules import panel_nginx_front
        return panel_nginx_front

    def _nfp(self):
        from chimera.modules import nginx_front_portal
        return nginx_front_portal

    def test_panel_front_new_syntax(self):
        pnf = self._pnf()
        vhost = pnf._generate_vhost(
            port=9743, backend_port=9700,
            cert_path=Path("/c.pem"), key_path=Path("/k.pem"),
            domain="panel.example", panel_name_slug="b4",
            dual_stack=True, http2_on=True)
        self.assertIn("    listen 9743 ssl;\n"
                      "    listen [::]:9743 ssl;\n"
                      "    http2 on;\n", vhost)
        self.assertNotIn("ssl http2", vhost)

    def test_panel_front_old_syntax_default(self):
        pnf = self._pnf()
        vhost = pnf._generate_vhost(
            port=9443, backend_port=8443,
            cert_path=Path("/c.pem"), key_path=Path("/k.pem"),
            domain="portal.example", panel_name_slug="portal",
            dual_stack=True)
        self.assertIn("listen 9443 ssl http2;", vhost)
        self.assertIn("listen [::]:9443 ssl http2;", vhost)
        self.assertNotIn("http2 on;", vhost)

    def test_portal_new_syntax(self):
        nfp = self._nfp()
        vhost = nfp._generate_vhost(
            port=9443, backend_port=8443,
            cert_path=Path("/c.pem"), key_path=Path("/k.pem"),
            domain="user.example", http2_on=True)
        self.assertIn("    listen 9443 ssl;\n    http2 on;\n", vhost)
        self.assertNotIn("ssl http2", vhost)
        # остальной каркас vhost не потерян
        self.assertIn("proxy_pass http://127.0.0.1:8443", vhost)
        self.assertIn("Strict-Transport-Security", vhost)

    def test_portal_old_syntax_default(self):
        nfp = self._nfp()
        vhost = nfp._generate_vhost(
            port=9443, backend_port=8443,
            cert_path=Path("/c.pem"), key_path=Path("/k.pem"),
            domain="user.example")
        self.assertIn("listen 9443 ssl http2;", vhost)

    def _detect(self, version_output, which="/usr/sbin/nginx"):
        pnf = self._pnf()
        with patch.object(pnf.shutil, "which", return_value=which), \
             patch.object(pnf.subprocess, "run",
                          return_value=SimpleNamespace(
                              returncode=0, stderr=version_output,
                              stdout="")):
            return pnf._nginx_supports_http2_on()

    def test_http2_detector_threshold_1_25_1(self):
        """Порог — 1.25.1, НЕ 1.25: на 1.25.0 директивы http2 on; ещё нет."""
        self.assertTrue(self._detect("nginx version: nginx/1.25.1"))
        self.assertTrue(self._detect("nginx version: nginx/1.30.7"))
        self.assertFalse(self._detect("nginx version: nginx/1.25.0"))
        self.assertFalse(self._detect("nginx version: nginx/1.24.0"))

    def test_http2_detector_conservative_on_errors(self):
        """nginx не установлен / кривой вывод / исключение → False (старый
        синтаксис валиден везде, максимум — варнинг)."""
        self.assertFalse(self._detect("nginx version: nginx/1.30.7",
                                      which=None))
        self.assertFalse(self._detect("сломанный вывод без версии"))
        pnf = self._pnf()
        with patch.object(pnf.shutil, "which", return_value="/usr/sbin/nginx"), \
             patch.object(pnf.subprocess, "run",
                          side_effect=RuntimeError("timeout")):
            self.assertFalse(pnf._nginx_supports_http2_on())


if __name__ == "__main__":
    unittest.main()
