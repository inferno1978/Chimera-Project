#!/usr/bin/env python3
"""
tests/test_agh_le_cert_order.py
───────────────────────────────────────────────────────────────────────────────
: «Fresh-сервер: AGH поставился, LE-сертификат НЕ выпустился
self-signed fallback» (инцидент: server.example).

КОРНЕВАЯ ПРИЧИНА (порядок установки + отсутствие ACME-endpoint):
  • certbot у Chimera работает в режиме --webroot: ОН НЕ СЛУШАЕТ :80 сам —
    ему нужен веб-сервер, отдающий /.well-known/acme-challenge/ из webroot
    домена. Такой endpoint создаёт setup_nginx_temp(domain) (паттерн
    VLESS/mtproto/telemt, fix v4.20.3);
  • в do_full_install install_aghome() стоит РАНЬШЕ setup_nginx_temp() и
    РАНЬШЕ configure_firewall(): nginx к моменту AGH-финализации уже стоит
    (install_dependencies), но с ДЕФОЛТНЫМ vhost → челлендж получает 404;
    UFW ещё не настроен → :80 может быть закрыт;
  • итог: LE-выпуск внутри AGH падал ВСЕГДА (404/refused/filtered) →
    молчаливый self-signed fallback.

AGH порт 80 НЕ занимает (web :3000, TLS :30443, DoT :853, DNS :53 loopback;
80 ∈ AGH_WEB_PORT_RESERVED) — гипотеза «AGH съел :80» не подтвердилась,
но подозрение о неверном ПОРЯДКЕ установки было верным.

Фикс 
  1. aghome_setup._ensure_acme_http80(domain): ДО certbot — certbot ставится
     при отсутствии, PARAM_EMAIL → admin@<domain> (certbot падает на --email ""),
     setup_nginx_temp(domain) (nginx+vhost ACME), UFW allow 80/tcp (правило
     идентично network_setup.configure_firewall — не дублируется);
  2. _prepare_tls_cert: _ensure_acme_http80 вызывается ДО obtain_ssl_cert;
  3. do_full_install: configure_firewall() перенесена ДО install_aghome.

Тестируем:
  1. _ensure_acme_http80: setup_nginx_temp(domain=…), установка certbot,
     email-дефолт (не перезаписывает существующий), UFW :80 с тем же
     комментарием, что в network_setup;
  2. _prepare_tls_cert (LE, сертификата нет): порядок
     _ensure_acme_http80 → obtain_ssl_cert → (fallback self-signed);
  3. Статические пины: порядок в do_full_install (firewall до AGH),
     порядок в _prepare_tls_cert (ACME до certbot), идентичность UFW-правила.
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_agh_ratelimit_heal)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


_CORE = _setup_core_in_sysmodules()

from chimera.modules import aghome_setup


def _read(rel: str) -> str:
    return (_PROJECT_ROOT / rel).read_text()


# ─────────────────────────────────────────────────────────────────────────────
#  1. _ensure_acme_http80
# ─────────────────────────────────────────────────────────────────────────────
class TestEnsureAcmeHttp80(unittest.TestCase):
    """Хелпер гарантирует ACME-endpoint ДО certbot (все 4 подсистемы)."""

    def setUp(self):
        import tempfile
        import shutil as _shutil
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(_shutil.rmtree, self._tmpdir, ignore_errors=True)
        _CORE.PARAM_EMAIL = ""

    def _fake_nginx_module(self, calls: list):
        m = types.ModuleType("chimera.modules.nginx_setup")
        m.setup_nginx_temp = MagicMock(
            side_effect=lambda domain=None, **kw: calls.append(("nginx", domain)))
        return m

    def test_full_sequence_certbot_present(self):
        """Всё на месте → setup_nginx_temp(domain) + ufw allow 80."""
        calls = []
        fake_nginx = self._fake_nginx_module(calls)
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx}), \
             patch.object(aghome_setup.shutil, "which",
                          side_effect=lambda b: "/usr/bin/" + b), \
             patch.object(aghome_setup.subprocess, "run") as sub_run:
            aghome_setup._ensure_acme_http80("v66.example.com")

        self.assertEqual(calls, [("nginx", "v66.example.com")])
        # UFW: правило идентично network_setup.configure_firewall (дедуп ufw)
        ufw_calls = [c for c in sub_run.call_args_list
                     if c.args and c.args[0][:2] == ["ufw", "allow"]]
        self.assertEqual(len(ufw_calls), 1)
        self.assertEqual(ufw_calls[0].args[0],
                         ["ufw", "allow", "80/tcp", "comment",
                          "HTTP (certbot ACME)"])
        # apt НЕ запускался (certbot уже есть)
        self.assertFalse(any(
            c.args and c.args[0][:2] == ["apt-get", "install"]
            for c in sub_run.call_args_list))
        # email-дефолт для LE-регистрации
        self.assertEqual(_CORE.PARAM_EMAIL, "admin@v66.example.com")

    def test_certbot_missing_installs_it(self):
        """certbot отсутствует → apt-get install certbot (паттерн h2_cert_mgr)."""
        calls = []
        fake_nginx = self._fake_nginx_module(calls)
        # which: certbot→None (нет), ufw→есть
        def _which(binary):
            return None if binary == "certbot" else "/usr/sbin/ufw"
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx}), \
             patch.object(aghome_setup.shutil, "which", side_effect=_which), \
             patch.object(aghome_setup.subprocess, "run") as sub_run:
            sub_run.return_value = MagicMock(returncode=0)
            aghome_setup._ensure_acme_http80("v66.example.com")

        apt_calls = [c for c in sub_run.call_args_list
                     if c.args and c.args[0][:2] == ["apt-get", "install"]]
        self.assertEqual(len(apt_calls), 1)
        self.assertIn("certbot", apt_calls[0].args[0])
        self.assertEqual(calls, [("nginx", "v66.example.com")])

    def test_existing_email_not_overwritten(self):
        """PARAM_EMAIL уже задан → не перезаписываем."""
        _CORE.PARAM_EMAIL = "admin@existing.example"
        fake_nginx = self._fake_nginx_module([])
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx}), \
             patch.object(aghome_setup.shutil, "which",
                          side_effect=lambda b: "/usr/bin/" + b), \
             patch.object(aghome_setup.subprocess, "run"):
            aghome_setup._ensure_acme_http80("v66.example.com")
        self.assertEqual(_CORE.PARAM_EMAIL, "admin@existing.example")

    def test_nginx_temp_failure_does_not_raise(self):
        """setup_nginx_temp упал → warn и продолжаем (не raise)."""
        fake_nginx = types.ModuleType("chimera.modules.nginx_setup")
        fake_nginx.setup_nginx_temp = MagicMock(
            side_effect=RuntimeError("boom"))
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx}), \
             patch.object(aghome_setup.shutil, "which",
                          side_effect=lambda b: "/usr/bin/" + b), \
             patch.object(aghome_setup.subprocess, "run"):
            aghome_setup._ensure_acme_http80("v66.example.com")  # не упал

    def test_no_ufw_binary_skips_firewall_step(self):
        """ufw отсутствует → шаг файрволла молча пропущен."""
        fake_nginx = self._fake_nginx_module([])
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx}), \
             patch.object(aghome_setup.shutil, "which",
                          side_effect=lambda b: "/usr/bin/certbot"
                          if b == "certbot" else None), \
             patch.object(aghome_setup.subprocess, "run") as sub_run:
            aghome_setup._ensure_acme_http80("v66.example.com")
        self.assertFalse(any(
            c.args and c.args[0] and c.args[0][0] == "ufw"
            for c in sub_run.call_args_list))


# ─────────────────────────────────────────────────────────────────────────────
#  2. _prepare_tls_cert: порядок ACME-endpoint → certbot
# ─────────────────────────────────────────────────────────────────────────────
class TestPrepareTlsCertOrder(unittest.TestCase):
    """LE-ветка: сертификата нет → сначала endpoint, потом certbot."""

    def setUp(self):
        import tempfile
        import shutil as _shutil
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(_shutil.rmtree, self._tmpdir, ignore_errors=True)
        _CORE.PARAM_EMAIL = ""

    def test_missing_cert_acme_endpoint_before_certbot(self):
        order = []
        fake_nginx = types.ModuleType("chimera.modules.nginx_setup")
        fake_nginx.setup_nginx_temp = MagicMock(
            side_effect=lambda domain=None, **kw: order.append("acme80"))
        fake_ssl = types.ModuleType("chimera.modules.ssl_certbot")
        fake_ssl.obtain_ssl_cert = MagicMock(
            side_effect=lambda domain=None: order.append("certbot"))
        domain = "missing.example"
        # LE-файлов нет (/etc/letsencrypt/live/<domain>/ не существует)
        self.assertFalse(
            Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").exists())
        with patch.dict(sys.modules, {
                "chimera._core": _CORE,
                "chimera.modules.nginx_setup": fake_nginx,
                "chimera.modules.ssl_certbot": fake_ssl}), \
             patch.object(aghome_setup, "AGH_CERTS_DIR", self._tmpdir), \
             patch.object(aghome_setup, "_ensure_acme_http80",
                          side_effect=lambda d: order.append("acme80")), \
             patch.object(aghome_setup, "_generate_self_signed_tls",
                          return_value=(None, None)) as gen_ss:
            res = aghome_setup._prepare_tls_cert(
                aghome_setup.AGH_WEB_HTTPS_LE, domain)
        # порядок: endpoint ДО certbot (сертификат так и не появился →
        # self-signed fallback — прежнее поведение сохранено)
        self.assertEqual(order, ["acme80", "certbot"])
        self.assertEqual(res, (None, None))
        gen_ss.assert_called_once_with(domain)


# ─────────────────────────────────────────────────────────────────────────────
#  3. Статические пины порядка установки
# ─────────────────────────────────────────────────────────────────────────────
class TestStaticPinsV66(unittest.TestCase):
    def test_firewall_before_agh_in_do_full_install(self):
        """configure_firewall() идёт ДО install_aghome (UFW готов к LE)."""
        src = _read("chimera/_core.py")
        idx_dfi = src.index("def do_full_install(")
        idx_fw = src.index("configure_firewall();", idx_dfi)
        idx_agh = src.index("install_aghome(", idx_dfi)
        self.assertLess(idx_fw, idx_agh,
                        "configure_firewall должна идти ДО install_aghome")

    def test_prepare_tls_cert_acme_before_certbot(self):
        """_ensure_acme_http80 вызывается ДО obtain_ssl_cert и только
        внутри ветки «сертификата нет»."""
        src = _read("chimera/modules/aghome_setup.py")
        idx_fn = src.index("def _prepare_tls_cert(")
        idx_missing = src.index("if not (le_cert.exists() and le_key.exists()):",
                                idx_fn)
        idx_acme = src.index("_ensure_acme_http80(domain)", idx_fn)
        idx_certbot = src.index("obtain_ssl_cert(domain)", idx_fn)
        self.assertGreater(idx_acme, idx_missing)
        self.assertLess(idx_acme, idx_certbot)

    def test_ufw_rule_identical_to_network_setup(self):
        """Правило :80 в AGH-хелпере байт-в-байт совпадает с
        network_setup.configure_firewall → ufw не дублирует."""
        agh = _read("chimera/modules/aghome_setup.py")
        net = _read("chimera/modules/network_setup.py")
        rule = '"HTTP (certbot ACME)"'
        self.assertIn(rule, agh)
        self.assertIn(rule, net)
        self.assertIn('["ufw", "allow", "80/tcp", "comment", '
                      '"HTTP (certbot ACME)"]', agh)

    def test_agh_web_port_reserved_contains_80(self):
        """AGH НИКОГДА не биндит :80 — порт в reserved-наборе Web UI."""
        src = _read("chimera/modules/aghome_setup.py")
        self.assertIn("AGH_WEB_PORT_RESERVED = {22, 53, 80, 443, 853, 5300, 30443}",
                      src)


if __name__ == "__main__":
    unittest.main()
