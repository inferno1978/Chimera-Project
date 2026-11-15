# -*- coding: utf-8 -*-
"""Dual-stack listen (v4+[::]) nginx-фронтов панелей — инцидент 15.11:
у домена панели есть AAAA, из дома по v6 домен пингуется, но веб-морда
по v6 не открывается — фронт слушал только 0.0.0.0:порт, v6-путь был
чёрен (браузер/клиенты с v6-first не откатываются на v4, особенно в
туннеле). Фикс — в общем генераторе panel_nginx_front.py (9 потребителей:
B4, Triple, WPP, User Portal, Telemt, subscription, CSQTT, LibreChat,
dpi_bypass), а не в отдельных панелях.

Покрывает:
  1. _generate_vhost(dual_stack=) — [::]-listen только при dual_stack;
     дефолт False — чужие панели и v4-only ноды не меняются.
  2. _node_has_global_ipv6() — глобальный v6 → True; link-local
     (fe80)/v4-mapped/пустой вывод/ошибки → False.
  3. _ipv6_listen_ok() — ss-парсинг [::]:port с границей порта
     ([::]:97430 ≠ порт 9743).
  4. panel_nginx_front_install(dual_stack=None/True/False) — авто-детект
     доезжает до vhost-файла и state.json («ipv6»: bool).
  5. _iptables_fallback_open(also_v6=) / _iptables_fallback_close() —
     ip6tables только при dual-stack (симметрия ufw, который открывает
     порт сразу в обоих стеках).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Компилирует _core.py в фейковый модуль (как test_panel_nginx_front_input)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    import types as _types
    with patch.object(Path, 'mkdir', lambda s, *a, **kw: None), \
         patch.object(Path, 'touch', lambda s, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda s, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = _types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _load_pnf():
    """Импортирует chimera.modules.panel_nginx_front с подготовленным _core."""
    _setup_core_in_sysmodules()
    import importlib
    return importlib.import_module("chimera.modules.panel_nginx_front")


# ══════════════════════════════════════════════════════════════════════════════
#  1. _generate_vhost: dual-stack listen
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateVhostDualStack(unittest.TestCase):
    """_generate_vhost: [::]-listen появляется только при dual_stack=True."""

    @classmethod
    def setUpClass(cls):
        cls.pnf = _load_pnf()

    def _vhost(self, **kw) -> str:
        return self.pnf._generate_vhost(
            port=9743, backend_port=9700,
            cert_path=Path("/etc/nginx/ssl/test-front.crt"),
            key_path=Path("/etc/nginx/ssl/test-front.key"),
            domain="panel.example.com",
            panel_name_slug="test-front",
            **kw)

    def test_dual_stack_true_adds_v6_listen(self):
        v = self._vhost(dual_stack=True)
        self.assertIn("    listen 9743 ssl http2;", v)
        self.assertIn("    listen [::]:9743 ssl http2;", v)
        # v6-строка идёт сразу за v4-строкой (в одном server-блоке)
        self.assertLess(v.index("listen 9743 ssl"),
                        v.index("listen [::]:9743"))

    def test_default_no_v6_listen(self):
        """КРИТИЧНО: дефолт не меняет чужие панели и v4-only ноды."""
        v = self._vhost()
        self.assertIn("    listen 9743 ssl http2;", v)
        self.assertNotIn("[::]:9743", v)

    def test_explicit_false_no_v6_listen(self):
        v = self._vhost(dual_stack=False)
        self.assertNotIn("[::]:9743", v)

    def test_dual_stack_with_mcp_and_ws(self):
        """Сочетание параметров не ломает шаблон (b4 использует mcp_proxy)."""
        v = self._vhost(dual_stack=True, mcp_proxy=True,
                        websocket_origin_rewrite=True)
        self.assertIn("listen [::]:9743 ssl http2;", v)
        self.assertIn("location /api/mcp {", v)
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", v)


# ══════════════════════════════════════════════════════════════════════════════
#  2. _node_has_global_ipv6: детект глобального IPv6 ноды
# ══════════════════════════════════════════════════════════════════════════════

class TestNodeHasGlobalIpv6(unittest.TestCase):
    """_node_has_global_ipv6: только настоящие глобальные адреса.

    Адреса в тестах — doc-диапазоны (2001:db8::/32 RFC 3849,
    203.0.113.0/24 RFC 5737), реальных нод-адресов здесь нет.
    """

    @classmethod
    def setUpClass(cls):
        cls.pnf = _load_pnf()

    def _detect(self, stdout="", rc=0, exc=None) -> bool:
        fake = MagicMock()
        fake.returncode = rc
        fake.stdout = stdout
        def _run(cmd, **kw):
            if exc is not None:
                raise exc
            return fake
        with patch.object(self.pnf.subprocess, "run", side_effect=_run):
            return self.pnf._node_has_global_ipv6()

    def test_global_v6_true(self):
        out = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
               "    inet6 2001:db8:1234:5678::2/64 scope global\n"
               "       valid_lft forever preferred_lft forever\n")
        self.assertTrue(self._detect(stdout=out))

    def test_global_v6_with_flags_true(self):
        # флаги (dynamic/deprecated) идут после «scope global» — матчатся
        out = "    inet6 2001:db8::1/64 scope global dynamic mngtmpaddr\n"
        self.assertTrue(self._detect(stdout=out))

    def test_link_local_false(self):
        # даже если бы fe80 попал в вывод (дикие настройки) — не глобальный
        out = "    inet6 fe80::1/64 scope global\n"
        self.assertFalse(self._detect(stdout=out))

    def test_v4_mapped_false(self):
        out = "    inet6 ::ffff:203.0.113.7/64 scope global\n"
        self.assertFalse(self._detect(stdout=out))

    def test_empty_output_false(self):
        self.assertFalse(self._detect(stdout=""))

    def test_nonzero_rc_false(self):
        self.assertFalse(self._detect(stdout="    inet6 2001:db8::1/64 scope global\n",
                                       rc=1))

    def test_timeout_false(self):
        self.assertFalse(self._detect(
            exc=subprocess.TimeoutExpired(cmd=["ip"], timeout=10)))

    def test_no_ip_binary_false(self):
        self.assertFalse(self._detect(exc=FileNotFoundError(2, "ip")))


# ══════════════════════════════════════════════════════════════════════════════
#  3. _ipv6_listen_ok: ss-парсинг слушателя [::]:port
# ══════════════════════════════════════════════════════════════════════════════

class TestIpv6ListenOk(unittest.TestCase):
    """_ipv6_listen_ok: граница порта — [::]:97430 ≠ порт 9743."""

    @classmethod
    def setUpClass(cls):
        cls.pnf = _load_pnf()

    def _ok(self, stdout="", exc=None) -> bool:
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = stdout
        def _run(cmd, **kw):
            if exc is not None:
                raise exc
            return fake
        with patch.object(self.pnf.subprocess, "run", side_effect=_run):
            return self.pnf._ipv6_listen_ok(9743)

    def test_listening_true(self):
        out = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
               "LISTEN 0 511 0.0.0.0:9743 0.0.0.0:*\n"
               "LISTEN 0 511 [::]:9743 [::]:*\n")
        self.assertTrue(self._ok(stdout=out))

    def test_port_prefix_not_confused(self):
        # [::]:97430 — ДРУГОЙ порт: требуем \s после номера
        out = "LISTEN 0 511 [::]:97430 [::]:*\n"
        self.assertFalse(self._ok(stdout=out))

    def test_v4_only_false(self):
        out = "LISTEN 0 511 0.0.0.0:9743 0.0.0.0:*\n"
        self.assertFalse(self._ok(stdout=out))

    def test_timeout_false(self):
        self.assertFalse(self._ok(
            exc=subprocess.TimeoutExpired(cmd=["ss"], timeout=10)))


# ══════════════════════════════════════════════════════════════════════════════
#  4. panel_nginx_front_install: авто-детект → vhost-файл + state.json
# ══════════════════════════════════════════════════════════════════════════════

class TestInstallDualStackFunctional(unittest.TestCase):
    """install(): functional-песочница (фейковые nginx/systemctl в PATH,
    sites-available → tmp, port_registry замокан) — авто-детект доезжает
    до файла vhost и state.json.
    """

    def setUp(self):
        self.pnf = _load_pnf()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.tmp = tmp

        # фейковые nginx/systemctl (exit 0) — шаги 5 (nginx -t, reload)
        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        for name in ("nginx", "systemctl"):
            p = fake_bin / name
            p.write_text("#!/bin/sh\nexit 0\n")
            p.chmod(0o755)
        self._new_path = f"{fake_bin}:{os.environ.get('PATH', '')}"

        # sites-available/enabled → tmp
        self.av = tmp / "sites-available"
        self.en = tmp / "sites-enabled"
        self.av.mkdir()
        self.en.mkdir()

        # сертификат (fake): install найдёт его через патч _find_ssl_cert
        self.crt = tmp / "front.crt"
        self.key = tmp / "front.key"
        self.crt.write_text("cert")
        self.key.write_text("key")

        self.state_file = tmp / "front.json"

    def _install(self, **kw):
        import chimera.modules.port_registry as pr
        with patch.dict(os.environ, {"PATH": self._new_path}), \
             patch.object(self.pnf, "NGINX_SITES_AVAILABLE", self.av), \
             patch.object(self.pnf, "NGINX_SITES_ENABLED", self.en), \
             patch.object(self.pnf, "check_port_via_registry",
                          return_value=(True, [])), \
             patch.object(self.pnf, "_find_ssl_cert",
                          return_value=(self.crt, self.key)), \
             patch.object(self.pnf, "_ipv6_listen_ok", return_value=True), \
             patch.object(self.pnf, "time", MagicMock()), \
             patch.object(pr, "ufw_open_port", return_value=(True, "ok")), \
             patch.object(pr, "port_register", return_value=(True, "ok")):
            return self.pnf.panel_nginx_front_install(
                service_tag="web_panel_nginx",
                port=9743,
                backend_port=9700,
                site_name="chimera-test-front",
                state_file=self.state_file,
                title="Test",
                use_self_signed=False,
                domain="panel.example.com",
                **kw)

    def _vhost_text(self) -> str:
        return (self.en / "chimera-test-front").read_text(encoding="utf-8")

    def test_auto_detect_v6_writes_dual_vhost_and_state(self):
        with patch.object(self.pnf, "_node_has_global_ipv6",
                          return_value=True):
            ok, msg = self._install()
        self.assertTrue(ok), msg
        v = self._vhost_text()
        self.assertIn("    listen 9743 ssl http2;", v)
        self.assertIn("    listen [::]:9743 ssl http2;", v)
        state = json.loads(self.state_file.read_text())
        self.assertTrue(state["ipv6"])
        self.assertEqual(state["port"], 9743)

    def test_auto_detect_no_v6_v4_only(self):
        with patch.object(self.pnf, "_node_has_global_ipv6",
                          return_value=False):
            ok, msg = self._install()
        self.assertTrue(ok), msg
        v = self._vhost_text()
        self.assertIn("    listen 9743 ssl http2;", v)
        self.assertNotIn("[::]:9743", v)
        state = json.loads(self.state_file.read_text())
        self.assertFalse(state["ipv6"])

    def test_explicit_false_overrides_v6_node(self):
        """Явный dual_stack=False перекрывает авто-детект (override)."""
        with patch.object(self.pnf, "_node_has_global_ipv6",
                          return_value=True):
            ok, msg = self._install(dual_stack=False)
        self.assertTrue(ok), msg
        self.assertNotIn("[::]:9743", self._vhost_text())
        state = json.loads(self.state_file.read_text())
        self.assertFalse(state["ipv6"])


# ══════════════════════════════════════════════════════════════════════════════
#  5. firewall fallback: ip6tables только при dual-stack
# ══════════════════════════════════════════════════════════════════════════════

class TestIptablesFallbackDualStack(unittest.TestCase):
    """_iptables_fallback_open/close: фейковые iptables/ip6tables в PATH
    пишут вызовы в файл; -C → rc=1 (правила нет), -I/-D → rc=0.
    """

    def setUp(self):
        self.pnf = _load_pnf()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.tmp = tmp
        bin_ = tmp / "bin"
        bin_.mkdir()
        self.calls = tmp / "calls.txt"
        for name in ("iptables", "ip6tables", "netfilter-persistent"):
            p = bin_ / name
            p.write_text(
                "#!/bin/sh\n"
                'echo "$(basename \"$0\") $*" >> "$CALLS"\n'
                'case "$1" in -C) exit 1;; *) exit 0;; esac\n')
            p.chmod(0o755)
        self._new_path = f"{bin_}:{os.environ.get('PATH', '')}"

    def _calls(self) -> str:
        return self.calls.read_text() if self.calls.exists() else ""

    def test_open_dual_opens_both_stacks(self):
        with patch.dict(os.environ,
                        {"PATH": self._new_path, "CALLS": str(self.calls)}):
            self.pnf._iptables_fallback_open(9743, also_v6=True)
        c = self._calls()
        self.assertIn("-C INPUT -p tcp --dport 9743 -j ACCEPT", c)
        self.assertIn("iptables -I INPUT 1", c)
        self.assertIn("ip6tables -I INPUT 1", c)
        self.assertIn("save", c)  # netfilter-persistent persist

    def test_open_v4_only_skips_ip6tables(self):
        with patch.dict(os.environ,
                        {"PATH": self._new_path, "CALLS": str(self.calls)}):
            self.pnf._iptables_fallback_open(9743, also_v6=False)
        c = self._calls()
        self.assertIn("iptables -I INPUT 1", c)
        self.assertNotIn("ip6tables", c)

    def test_close_passes_both_stacks(self):
        """Закрытие симметрично: чекает оба стека (правил нет — только -C)."""
        # -C → rc=1 (правила нет) → break без -D
        with patch.dict(os.environ,
                        {"PATH": self._new_path, "CALLS": str(self.calls)}):
            self.pnf._iptables_fallback_close(9743)
        c = self._calls()
        self.assertIn("iptables -C INPUT", c)
        self.assertIn("ip6tables -C INPUT", c)
        self.assertNotIn("-D INPUT", c)

    def test_close_removes_rule_in_both_stacks(self):
        """Правило есть (-C → rc=0) → -D по обоим стекам."""
        bin_ = self.tmp / "bin"
        for name in ("iptables", "ip6tables"):
            p = bin_ / name
            p.write_text(
                "#!/bin/sh\n"
                'echo "$(basename \"$0\") $*" >> "$CALLS"\n'
                "exit 0\n")
            p.chmod(0o755)
        with patch.dict(os.environ,
                        {"PATH": self._new_path, "CALLS": str(self.calls)}):
            self.pnf._iptables_fallback_close(9743)
        c = self._calls()
        self.assertIn("iptables -D INPUT", c)
        self.assertIn("ip6tables -D INPUT", c)


if __name__ == "__main__":
    unittest.main(verbosity=2)
