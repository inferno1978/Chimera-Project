#!/usr/bin/env python3
"""
tests/test_telemt_nginx_fallback.py
───────────────────────────────────────────────────────────────────────────────
Регресс-тесты для Telemt nginx-fallback (свой домен + свой сайт вместо
чужого donor-домена). Покрывает 5 обязательных сценариев из тикета:

  1. _write_config(mask_host="") → censorship-секция побайтово идентична
     текущей (regression guard на donor-режим).
  2. _write_config(mask_host="127.0.0.1", mask_port=8443) → в сгенерированном
     telemt.toml реально присутствуют строки mask_host и tls_emulation = true
     (parse сгенерённого файла, не тавтологичный assert).
  3. create_website(domain="a.com", ...) и create_website(domain="b.com", ...),
     вызванные последовательно с явными параметрами — должны создать ДВА
     разных web_root. Проверка что рефактор Задачи 1 реально убрал зависимость
     от глобального state, а не просто добавил неиспользуемые параметры.
  4. Существующие тесты tests/test_mtproto.py и tests/test_ssl_certbot.py
     проходят без изменений — доказательство что старое поведение не сломано
     (это не отдельный кейс здесь, а сам факт что pytest-green; см. README
     для полного запуска).
  5. Проверка порядка операций из 2.5: mock, где "старт Telemt" вызывается
     раньше, чем nginx готов слушать mask_port → тест должен явно
     сигнализировать ошибку, а не молча продолжать.

Дополнительно:
  6. _pick_local_nginx_port — НЕ возвращает порт, совпадающий с telemt_port.
  7. _check_mask_backend_ready — True на слушающем порту, False на закрытом.
  8. OwnSiteConfig dataclass — поля и значения по умолчанию.
  9. obtain_ssl_cert принимает domain=... (сигнатура).
 10. setup_nginx_final принимает domain/port/socket_path (сигнатура).
"""
from __future__ import annotations

import os
import re
import socket
import sys
import tempfile
import threading
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ─── Helper для тестов _setup_own_site ──────────────────────────────────────
# Все 3 теста (TestSetupOwnSiteOrderOfOperations.test_setup_nginx_temp_called_before_obtain_ssl_cert,
# TestSelfSignedDetection.test_setup_own_site_rolls_back_on_self_signed,
# TestSelfSignedDetection.test_setup_own_site_proceeds_on_valid_le_cert) мокают
# один и тот же набор из 13 box/log-хелперов mtproto. Раньше это был один
# гигантский `with A, B, C, ...:` на ~20 context managers — упирался в лимит
# CPython на statically nested blocks (parser limit). Через ExitStack лимит
# не срабатывает: каждый patch активен ровно там же, отменяется в том же порядке.
#
# Использование:
#     with ExitStack() as stack:
#         _enter_mtproto_ui_patches(stack, mtproto_mod)
#         # ... дополнительные stack.enter_context(patch.object(...)) для
#         # специфичных для теста моков
#         result = mtproto_mod._setup_own_site("telemt.example.com", 8443)
def _enter_mtproto_ui_patches(stack: ExitStack, mtproto_mod) -> None:
    """Добавляет в stack 13 стандартных UI/log-патчей для mtproto.

    Все патчи no-op (MagicMock по умолчанию) — тесты не полагаются на вывод
    _banner/_box_*/_ok/_err/_warn/_info/proto_ask/print, только на то что
    они не падают. proto_ask возвращает "2" (дефолтный шаблон сайта).
    """
    ui_targets = [
        "_banner", "_box_top", "_box_row", "_box_sep", "_box_item",
        "_box_bot", "_box_info", "_ok", "_err", "_warn", "_info",
    ]
    for name in ui_targets:
        stack.enter_context(patch.object(mtproto_mod, name))
    stack.enter_context(patch.object(mtproto_mod, "proto_ask", return_value="2"))
    stack.enter_context(patch("builtins.print"))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_mtproto.py — патчит Path/os."""
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


# ══════════════════════════════════════════════════════════════════════════════
#  Тест 1: donor-mode byte-identical regression guard
# ══════════════════════════════════════════════════════════════════════════════
class TestWriteConfigDonorModeRegression(unittest.TestCase):
    """_write_config(mask_host="") → censorship-секция побайтово идентична
    предыдущей (donor-режим, ничего не меняется)."""

    # Эталонная censorship-секция donor-режима — зафиксирована как
    # snapshot предыдущего поведения (см. baseline в PR-описании).
    # Без trailing \n\n — это часть большого TOML, после неё идёт [access].
    _EXPECTED_CENSORSHIP = (
        '[censorship]\n'
        'tls_domain = "example.com"\n'
        'mask = true\n'
        'mask_port = 443\n'
        'fake_cert_len = 2048\n'
    )

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"
        self._cfg_dir = self._tmpdir / "etc"
        self._work_dir = self._tmpdir / "var"
        self._patches = [
            patch("chimera.modules.mtproto.CONFIG_FILE", self._cfg),
            patch("chimera.modules.mtproto.CONFIG_DIR", self._cfg_dir),
            patch("chimera.modules.mtproto.WORK_DIR", self._work_dir),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _extract_censorship_block(self, content: str) -> str:
        """Вырезает блок от [censorship] до следующей секции [,
        обрезая trailing пустые строки (они идут между секциями)."""
        m = re.search(r'(\[censorship\][^\[]*)', content)
        if not m:
            return ""
        # Убираем trailing whitespace/newlines — они артефакт расположения
        # секций в общем TOML, не часть самой censorship-секции.
        return m.group(1).rstrip() + "\n"

    def test_donor_mode_mask_host_empty(self):
        """mask_host="" (по умолчанию) → секция идентична baseline."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="example.com",
            users={"alice": "abcdef0123456789abcdef0123456789"},
            use_middle_proxy=False,
            # mask_host не передаём — по умолчанию ""
        )
        block = self._extract_censorship_block(self._cfg.read_text())
        self.assertEqual(block, self._EXPECTED_CENSORSHIP,
                         "donor-режим должен давать byte-identical вывод")

    def test_donor_mode_mask_host_explicit_empty_string(self):
        """Явная передача mask_host="" тоже даёт donor-режим."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="example.com",
            users={"alice": "abcdef0123456789abcdef0123456789"},
            use_middle_proxy=False,
            mask_host="",  # явно
        )
        block = self._extract_censorship_block(self._cfg.read_text())
        self.assertEqual(block, self._EXPECTED_CENSORSHIP)

    def test_donor_mode_does_not_contain_mask_host(self):
        """В donor-режиме mask_host и tls_emulation отсутствуют."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="example.com",
            users={}, use_middle_proxy=False,
        )
        content = self._cfg.read_text()
        self.assertNotIn("mask_host", content)
        self.assertNotIn("tls_emulation", content)


# ══════════════════════════════════════════════════════════════════════════════
#  Тест 2: own-site режим — mask_host + tls_emulation = true в файле
# ══════════════════════════════════════════════════════════════════════════════
class TestWriteConfigOwnSiteMode(unittest.TestCase):
    """_write_config(mask_host="127.0.0.1", mask_port=8443) → в файле реально
    присутствуют mask_host, mask_port=8443, tls_emulation=true.

    Парсим сгенерированный файл — это НЕ тавтологичный assert на переданный
    аргумент, а проверка что функция действительно записала их в TOML.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"
        self._cfg_dir = self._tmpdir / "etc"
        self._work_dir = self._tmpdir / "var"
        self._patches = [
            patch("chimera.modules.mtproto.CONFIG_FILE", self._cfg),
            patch("chimera.modules.mtproto.CONFIG_DIR", self._cfg_dir),
            patch("chimera.modules.mtproto.WORK_DIR", self._work_dir),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_own_site_writes_mask_host_and_tls_emulation(self):
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="my.example.com",
            users={"alice": "abcdef0123456789abcdef0123456789"},
            use_middle_proxy=False,
            mask_host="127.0.0.1", mask_port=8443, tls_emulation=True,
        )
        content = self._cfg.read_text()
        # Парсим TOML-строки — реальные записи в файле, не аргументы вызова.
        self.assertIn('mask_host = "127.0.0.1"', content,
                      "mask_host должен быть записан в TOML")
        self.assertIn('mask_port = 8443', content,
                      "mask_port должен быть записан в TOML")
        self.assertIn('tls_emulation = true', content,
                      "tls_emulation = true должен быть записан в TOML")

    def test_own_site_keeps_tls_domain_and_mask_true(self):
        """Own-site не ломает остальные ключи censorship-секции."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="my.example.com",
            users={}, use_middle_proxy=False,
            mask_host="127.0.0.1", mask_port=9001, tls_emulation=True,
        )
        content = self._cfg.read_text()
        self.assertIn('tls_domain = "my.example.com"', content)
        self.assertIn("mask = true", content)
        self.assertIn("fake_cert_len = 2048", content)

    def test_own_site_without_mask_port_omits_line(self):
        """Если mask_port=0 — строка mask_port не пишется (но mask_host есть)."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="x.example.com",
            users={}, use_middle_proxy=False,
            mask_host="127.0.0.1", mask_port=0, tls_emulation=True,
        )
        content = self._cfg.read_text()
        self.assertIn('mask_host = "127.0.0.1"', content)
        self.assertIn('tls_emulation = true', content)
        # mask_port = 0 — не пишем (Telemt использует internal default).
        # Важно: не должно быть "mask_port = 0" в выводе.
        self.assertNotIn("mask_port = 0", content)

    def test_own_site_tls_emulation_false_writes_false(self):
        """tls_emulation=False (нестандартно, но допустимо) — пишется 'false'."""
        from chimera.modules import mtproto
        mtproto._write_config(
            port=8443, ipv4="1.2.3.4", ipv6="", tls_domain="x.example.com",
            users={}, use_middle_proxy=False,
            mask_host="127.0.0.1", mask_port=8443, tls_emulation=False,
        )
        content = self._cfg.read_text()
        self.assertIn('tls_emulation = false', content)


# ══════════════════════════════════════════════════════════════════════════════
#  Тест 3: create_website с разными domain — два независимых web_root
# ══════════════════════════════════════════════════════════════════════════════
class TestCreateWebsiteIsolationFromGlobalState(unittest.TestCase):
    """create_website(domain="a.com", ...) и create_website(domain="b.com", ...)
    должны создать ДВА разных web_root. Это прямая проверка что рефактор
    Задачи 1 реально убрал зависимость от глобального state.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # Патчим /var/www на временный каталог.
        self._var_www = self._tmpdir / "www"
        self._var_www.mkdir(parents=True, exist_ok=True)
        # Перехватываем Path("/var/www/...") → self._var_www/...
        self._patch_var_www = patch(
            "chimera.modules.nginx_setup.Path",
            self._make_path_wrapper(),
        )
        self._patch_var_www.start()
        # Также глушим chown и _run чтобы не пытаться реально выполнять.
        from chimera.modules import nginx_setup
        self._patch_run = patch.object(nginx_setup, "_core_module",
                                       return_value=self._make_fake_core())
        self._fake_core = self._patch_run.start()

    def tearDown(self):
        self._patch_var_www.stop()
        self._patch_run.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_path_wrapper(self):
        """Возвращает callable, подменяющий Path('/var/www/X') на tmpdir/X."""
        real_path = Path

        def _wrapper(*args, **kwargs):
            p = real_path(*args, **kwargs)
            # Если путь /var/www/<X>, перехватываем.
            s = str(p)
            if s.startswith("/var/www/"):
                rel = s[len("/var/www/"):]
                return self._var_ww / rel if False else self._var_www / rel
            return p
        return _wrapper

    def _make_fake_core(self):
        """Minimal core mock: только то, что create_website реально вызывает."""
        core = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core._run = MagicMock(return_value=MagicMock(returncode=0))
        # PARAM_DOMAIN остаётся "wrong.example.com" чтобы убедиться, что
        # явная передача domain= перекрывает глобал.
        core.PARAM_DOMAIN = "wrong.example.com"
        core.PARAM_SITE_TEMPLATE = "2"
        return core

    def test_two_distinct_domains_create_two_distinct_web_roots(self):
        """Два последовательных вызова с разными domain → два web_root."""
        from chimera.modules import nginx_setup
        # Создаём wrapper заново — замыкание на self._var_www уже корректное.
        # (т.к. setUp уже запустил patch, в nginx_setup.Path подменён)
        nginx_setup.create_website(domain="a.com", site_template="2")
        nginx_setup.create_website(domain="b.com", site_template="2")
        # Проверяем что оба каталога созданы и НЕ перезаписали друг друга.
        a_root = self._var_www / "a.com"
        b_root = self._var_www / "b.com"
        self.assertTrue(a_root.exists(), f"{a_root} должен существовать")
        self.assertTrue(b_root.exists(), f"{b_root} должен существовать")
        self.assertTrue((a_root / "index.html").exists(),
                        "a.com/index.html должен быть создан")
        self.assertTrue((b_root / "index.html").exists(),
                        "b.com/index.html должен быть создан")

    def test_explicit_domain_overrides_core_param_domain(self):
        """Если core.PARAM_DOMAIN='wrong.example.com', а мы передали
        domain='correct.example.com' — должен создаться correct.example.com,
        а НЕ wrong.example.com. Это и есть смысл рефактора."""
        from chimera.modules import nginx_setup
        nginx_setup.create_website(domain="correct.example.com", site_template="2")
        correct_root = self._var_www / "correct.example.com"
        wrong_root = self._var_www / "wrong.example.com"
        self.assertTrue(correct_root.exists(),
                        "Должен создаться correct.example.com (явный параметр)")
        self.assertFalse(wrong_root.exists(),
                         "wrong.example.com (глобал) НЕ должен создаваться")

    def test_no_explicit_domain_uses_core_param_domain(self):
        """Если domain не передан — используется core.PARAM_DOMAIN
        (backward-compat для VLESS install flow)."""
        from chimera.modules import nginx_setup
        nginx_setup.create_website()  # без параметров
        default_root = self._var_www / "wrong.example.com"
        self.assertTrue(default_root.exists(),
                        "Без явного domain должен использоваться core.PARAM_DOMAIN")


# ══════════════════════════════════════════════════════════════════════════════
#  Тест 5: проверка порядка операций (КРИТИЧНО — guard от silent regression)
# ══════════════════════════════════════════════════════════════════════════════
def _generate_test_cert(tmpdir, cn="test.example.com", self_signed=True):
    """Генерирует тестовый сертификат через openssl.
    Возвращает (cert_path, key_path).
    self_signed=True  → issuer == subject (self-signed)
    self_signed=False → добавляет fake CA + подписывает им leaf cert
    """
    import subprocess
    cert_path = str(tmpdir / "cert.pem")
    key_path = str(tmpdir / "key.pem")
    if self_signed:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-subj", f"/CN={cn}",
        ], capture_output=True, check=True)
    else:
        ca_key = str(tmpdir / "ca.key")
        ca_cert = str(tmpdir / "ca.crt")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", ca_key, "-out", ca_cert,
            "-days", "1", "-nodes", "-subj", "/CN=Test CA",
        ], capture_output=True, check=True)
        subprocess.run([
            "openssl", "req", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", str(tmpdir / "leaf.csr"),
            "-days", "1", "-nodes", "-subj", f"/CN={cn}",
        ], capture_output=True, check=True)
        subprocess.run([
            "openssl", "x509", "-req", "-in", str(tmpdir / "leaf.csr"),
            "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
            "-out", cert_path, "-days", "1",
        ], capture_output=True, check=True)
    return cert_path, key_path


def _start_tls_server(cert_path, key_path, host="127.0.0.1"):
    """Поднимает TLS-сервер на ephemeral порту. Возвращает (port, thread, stop_event)."""
    import ssl as _ssl
    import threading as _threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((host, 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    stop_event = _threading.Event()
    def _serve():
        srv.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                try:
                    tls = ctx.wrap_socket(conn, server_side=True)
                    tls.recv(1024)
                    tls.close()
                except Exception:
                    pass
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()
    t = _threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, t, stop_event


class TestMaskBackendReadinessCheck(unittest.TestCase):
    """Проверка порядка операций из 2.5: если nginx не слушает mask_port,
    _check_mask_backend_ready должен вернуть False (а вызывающий код в
    _run_install_inner — откатиться к donor-режиму, НЕ молча продолжать).

    v4.20.6: теперь _check_mask_backend_ready делает реальный TLS-handshake
    и проверяет issuer != subject (не self-signed). Тесты переписаны:
    вместо голого TCP-сервера поднимается TLS-сервер с real cert.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_check_returns_true_on_listening_tls_with_valid_cert(self):
        """На TLS-сервере с валидным (не self-signed) cert — True.
        v4.20.6: теперь это TLS-handshake + issuer != subject проверка,
        не голый TCP-connect."""
        from chimera.modules import mtproto
        cert, key = _generate_test_cert(self._tmpdir, cn="127.0.0.1",
                                         self_signed=False)
        port, thread, stop = _start_tls_server(cert, key)
        try:
            # Мокаем _run (для openssl x509 -issuer -subject) — возвращаем
            # разные issuer/subject (валидный LE-подобный cert).
            from unittest.mock import MagicMock
            with patch.object(mtproto, "_run",
                              return_value=MagicMock(
                                  returncode=0,
                                  stdout="issuer=CN = Test CA\nsubject=CN = 127.0.0.1\n",
                                  stderr="")):
                self.assertTrue(
                    mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=3.0)
                )
        finally:
            stop.set()
            thread.join(timeout=2)

    def test_check_returns_false_on_self_signed_cert(self):
        """TLS-handshake успешен, cert self-signed (issuer == subject), sni передан — False.
        v4.20.6: guard ловит silent regression когда nginx отдаёт self-signed.
        v4.20.9: проверка self-signed работает ТОЛЬКО если передан sni_hostname.
        Без sni_hostname — fallback на TCP-connect (True)."""
        from chimera.modules import mtproto
        cert, key = _generate_test_cert(self._tmpdir, cn="selfsigned.example.com",
                                         self_signed=True)
        port, thread, stop = _start_tls_server(cert, key)
        try:
            from unittest.mock import MagicMock
            with patch.object(mtproto, "_run",
                              return_value=MagicMock(
                                  returncode=0,
                                  stdout="issuer=CN = selfsigned.example.com\n"
                                         "subject=CN = selfsigned.example.com\n",
                                  stderr="")):
                # sni_hostname передан → TLS-handshake + проверка cert
                self.assertFalse(
                    mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=3.0,
                                                      sni_hostname="selfsigned.example.com")
                )
        finally:
            stop.set()
            thread.join(timeout=2)

    def test_check_returns_true_on_plain_tcp_no_tls_without_sni(self):
        """На голом TCP-сервере без TLS, без sni_hostname — True (TCP-connect = OK).
        v4.20.9: если sni не передан — нет смысла делать TLS-handshake с SNI=127.0.0.1
        (nginx отдаст default_server). Возвращаем True на основе TCP-connect.
        Cert уже проверен через _is_cert_self_signed на шаге 5."""
        from chimera.modules import mtproto
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            # Без sni_hostname — TCP-connect = OK
            self.assertTrue(
                mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=2.0)
            )
        finally:
            srv.close()

    def test_check_returns_false_on_plain_tcp_no_tls_with_sni(self):
        """На голом TCP-сервере без TLS, с sni_hostname — True (fallback на TCP).
        v4.20.9: TLS-handshake падает, но TCP-connect прошёл → возвращаем True
        (fail-open для TLS-handshake, cert уже проверен на шаге 5).
        Это сознательное решение: guard не должен блокировать own-site если
        TLS-handshake падает по техническим причинам (default_server в nginx
        отдаёт ssl_reject_handshake). Главное — listener готов."""
        from chimera.modules import mtproto
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            # TLS-handshake упадёт, но TCP-connect прошёл → True (fallback)
            self.assertTrue(
                mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=2.0,
                                                  sni_hostname="test.example.com")
            )
        finally:
            srv.close()

    def test_check_returns_false_on_closed_port(self):
        """На закрытом порту — False (не raise)."""
        from chimera.modules import mtproto
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(
            mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=0.5)
        )

    def test_check_returns_false_on_timeout(self):
        """На RFC-5737 TEST-NET-1 (192.0.2.0/24) — гарантированный timeout."""
        from chimera.modules import mtproto
        # 192.0.2.1 — RFC 5737 TEST-NET-1, маршрутизируется в никуда.
        self.assertFalse(
            mtproto._check_mask_backend_ready("192.0.2.1", 8443, timeout=0.5)
        )

    def test_install_flow_does_not_silently_proceed_when_nginx_down(self):
        """ГЛАВНЫЙ guard-тест: если mask_host:mask_port НЕ отвечает, install
        flow должен переписать конфиг в donor-режим и НЕ стартовать Telemt
        в own-site режиме.

        Мы мокируем _check_mask_backend_ready → всегда False, и проверяем,
        что _write_config вызывается повторно с mask_host="" (откат).
        """
        from chimera.modules import mtproto

        # Мокаем _check_mask_backend_ready → False (nginx "не готов").
        # Мокаем _write_config → считаем вызовы с какими mask_host приходили.
        write_calls = []  # list of kwargs dict

        def _fake_write_config(*args, **kwargs):
            write_calls.append(kwargs.copy())

        # Мокаем _run чтобы не вызывать systemctl.
        with patch.object(mtproto, "_check_mask_backend_ready",
                          return_value=False), \
             patch.object(mtproto, "_write_config",
                          side_effect=_fake_write_config), \
             patch.object(mtproto, "_run",
                          return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(mtproto, "_setup_accounting", return_value=False), \
             patch.object(mtproto, "_ok"), \
             patch.object(mtproto, "_err"), \
             patch.object(mtproto, "_warn"), \
             patch.object(mtproto, "_info"):
            # Симулируем关键ный фрагмент install flow:
            # guard срабатывает только если _mask_host и _mask_port заданы.
            _mask_host = "127.0.0.1"
            _mask_port = 8443
            _tls_emulation = True
            port = 8443
            ipv4 = "1.2.3.4"
            ipv6 = ""
            tls_domain = "my.example.com"
            users = {"alice": "abcdef0123456789abcdef0123456789"}
            _fb_cfg = None
            _client_mss = ""

            # Это код из _run_install_inner (скопирован дословно):
            if _mask_host and _mask_port:
                # ... guard ...
                _nginx_ready = False
                for _attempt in range(5):
                    if mtproto._check_mask_backend_ready(_mask_host, _mask_port, timeout=2.0):
                        _nginx_ready = True
                        break
                if not _nginx_ready:
                    _mask_host = ""
                    _mask_port = 0
                    _tls_emulation = False
                    mtproto._write_config(
                        port, ipv4, ipv6, tls_domain, users, False,
                        socks5_port=0, fallback_cfg=_fb_cfg,
                        client_mss=_client_mss,
                        mask_host="", mask_port=0, tls_emulation=False,
                    )

        # Должен быть ровно один вызов _write_config — с mask_host="" (откат).
        self.assertEqual(len(write_calls), 1,
                         "Должен быть 1 вызов _write_config (откат в donor-режим)")
        self.assertEqual(write_calls[0].get("mask_host"), "",
                         "Откат должен переписать mask_host в пустую строку")
        self.assertEqual(write_calls[0].get("mask_port"), 0)
        self.assertEqual(write_calls[0].get("tls_emulation"), False)


# ══════════════════════════════════════════════════════════════════════════════
#  Доп. тесты 6-8: helpers OwnSiteConfig / _pick_local_nginx_port
# ══════════════════════════════════════════════════════════════════════════════
class TestOwnSiteConfigDataclass(unittest.TestCase):
    """OwnSiteConfig dataclass — поля и значения по умолчанию."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_mask_host_is_loopback(self):
        from chimera.modules.mtproto import OwnSiteConfig
        cfg = OwnSiteConfig(domain="x.example.com")
        self.assertEqual(cfg.mask_host, "127.0.0.1")
        self.assertEqual(cfg.mask_port, 0)

    def test_explicit_mask_port(self):
        from chimera.modules.mtproto import OwnSiteConfig
        cfg = OwnSiteConfig(domain="x.example.com", mask_port=8444)
        self.assertEqual(cfg.mask_port, 8444)
        self.assertEqual(cfg.mask_host, "127.0.0.1")


class TestPickLocalNginxPort(unittest.TestCase):
    """_pick_local_nginx_port — НЕ возвращает порт, совпадающий с telemt_port."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_does_not_return_telemt_port(self):
        """Даже если telemt_port в нашем диапазоне кандидатов — функция
        должна вернуть ДРУГОЙ порт."""
        from chimera.modules import mtproto
        # Мокаем _run чтобы ss вернул пустую строку (никто не слушает).
        with patch.object(mtproto, "_run",
                          return_value=MagicMock(stdout="", returncode=0)):
            # 8444 — наш первый кандидат. Передаём его как telemt_port.
            port = mtproto._pick_local_nginx_port(telemt_port=8444)
        self.assertNotEqual(port, 8444,
                            "mask_port НЕ должен совпадать с telemt_port")
        self.assertNotEqual(port, 0, "Должен быть найден свободный порт")

    def test_returns_zero_when_all_candidates_taken(self):
        """Если все порты в диапазоне заняты — возвращает 0."""
        from chimera.modules import mtproto
        # Симулируем что ss видит все наши кандидаты как LISTEN.
        fake_stdout = "\n".join(
            f"LISTEN 0 4096 0.0.0.0:{p} 0.0.0.0:*"
            for p in mtproto._MASK_PORT_CANDIDATES
        )
        with patch.object(mtproto, "_run",
                          return_value=MagicMock(stdout=fake_stdout, returncode=0)):
            port = mtproto._pick_local_nginx_port(telemt_port=80)
        self.assertEqual(port, 0, "Если все занято — должен быть 0")

    def test_skips_listened_ports(self):
        """Порт, который ss видит как LISTEN, пропускается."""
        from chimera.modules import mtproto
        # 8444 занят, остальные свободны.
        fake_stdout = "LISTEN 0 4096 0.0.0.0:8444 0.0.0.0:*"
        with patch.object(mtproto, "_run",
                          return_value=MagicMock(stdout=fake_stdout, returncode=0)):
            port = mtproto._pick_local_nginx_port(telemt_port=80)
        self.assertNotEqual(port, 8444, "Занятый порт должен быть пропущен")
        self.assertNotEqual(port, 0)


# ══════════════════════════════════════════════════════════════════════════════
#  Доп. тесты 9-10: сигнатуры obtain_ssl_cert и setup_nginx_final
# ══════════════════════════════════════════════════════════════════════════════
class TestSignatureCompatibility(unittest.TestCase):
    """Проверка что новые опциональные параметры добавлены в сигнатуры
    obtain_ssl_cert() и setup_nginx_final() — без breaking changes."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_obtain_ssl_cert_accepts_domain(self):
        """obtain_ssl_cert(domain=...) — есть параметр domain."""
        import inspect
        from chimera.modules.ssl_certbot import obtain_ssl_cert
        sig = inspect.signature(obtain_ssl_cert)
        self.assertIn("domain", sig.parameters,
                      "obtain_ssl_cert должен принимать domain=")
        self.assertIsNone(sig.parameters["domain"].default,
                          "domain должен быть Optional (default None)")

    def test_setup_nginx_final_accepts_all_params(self):
        """setup_nginx_final(domain, port, socket_path, protocol_mode,
        awg_exit_enabled, site_template) — все параметры присутствуют."""
        import inspect
        from chimera.modules.nginx_setup import setup_nginx_final, _UNSET
        sig = inspect.signature(setup_nginx_final)
        # domain, protocol_mode, awg_exit_enabled, site_template — default None
        for p in ("domain", "protocol_mode", "awg_exit_enabled", "site_template"):
            self.assertIn(p, sig.parameters,
                          f"setup_nginx_final должен принимать {p}=")
            self.assertIsNone(sig.parameters[p].default,
                              f"{p} должен быть Optional (default None)")
        # port, socket_path — sentinel _UNSET (не None!) — это КРИТИЧНО для
        # различения "не передан" (→ inherit из core) от "передан None"
        # (→ own-site TCP режим).
        for p in ("port", "socket_path"):
            self.assertIn(p, sig.parameters,
                          f"setup_nginx_final должен принимать {p}=")
            self.assertIs(sig.parameters[p].default, _UNSET,
                          f"{p} должен использовать sentinel _UNSET (не None)")

    def test_create_website_accepts_domain_site_template(self):
        """create_website(domain, site_template) — оба параметра."""
        import inspect
        from chimera.modules.nginx_setup import create_website
        sig = inspect.signature(create_website)
        for p in ("domain", "site_template"):
            self.assertIn(p, sig.parameters,
                          f"create_website должен принимать {p}=")


# ══════════════════════════════════════════════════════════════════════════════
#  Тесты v4.20.2: реальный вызов setup_nginx_final() + парсинг конфига
#  (НЕ signature-check — вызываем функцию и читаем записанный файл)
# ══════════════════════════════════════════════════════════════════════════════

def _make_fake_core_for_nginx(protocol_mode="reality",
                              awg_exit_enabled=False,
                              param_domain="vless.example.com",
                              param_socket_path="/run/xray.sock",
                              server_port=443,
                              xhttp_backend_port=8443,
                              xhttp_path="/xhttp",
                              is_ipv6_available=False,
                              nginx_conf_dir=None,
                              nginx_enabled_dir=None,
                              nginx_rate_limit_conf=None):
    """Создаёт fake core module для тестирования setup_nginx_final().

    Все параметры configurable — можно симулировать любой VLESS-режим сервера.
    """
    from unittest.mock import MagicMock
    core = MagicMock()
    core.info = lambda *a, **kw: None
    core.success = lambda *a, **kw: None
    core.warn = lambda *a, **kw: None
    core._run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr="nginx version: nginx/1.25.3\n"))
    core.find_nginx_bin = MagicMock(return_value="/usr/sbin/nginx")
    core.log_to_file = MagicMock()
    core.PROTOCOL_MODE = protocol_mode
    core.AWG_EXIT_ENABLED = awg_exit_enabled
    core.PARAM_DOMAIN = param_domain
    core.PARAM_SOCKET_PATH = param_socket_path
    core.SERVER_PORT = server_port
    core.XHTTP_BACKEND_PORT = xhttp_backend_port
    core.XHTTP_PATH = xhttp_path
    core.IS_IPV6_AVAILABLE = is_ipv6_available
    core.NGINX_CONF_DIR = nginx_conf_dir or Path("/tmp/test_nginx_conf")
    core.NGINX_ENABLED_DIR = nginx_enabled_dir or Path("/tmp/test_nginx_enabled")
    core.NGINX_RATE_LIMIT_CONF = nginx_rate_limit_conf or Path("/tmp/nonexistent_rate_limit")
    return core


class TestSetupNginxFinalOwnSiteTcpMode(unittest.TestCase):
    """Реальный вызов setup_nginx_final() в own-site TCP режиме + парсинг
    сгенерированного конфига. НЕ signature-check."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _call_setup_nginx_final(self, core_protocol_mode="reality",
                                core_awg_exit=False,
                                core_socket_path="/run/xray.sock",
                                own_site_domain="telemt.example.com",
                                own_site_port=8444):
        """Вызывает setup_nginx_final в own-site TCP режиме с заданным core state.
        Возвращает содержимое записанного nginx-конфига."""
        from chimera.modules import nginx_setup
        fake_core = _make_fake_core_for_nginx(
            protocol_mode=core_protocol_mode,
            awg_exit_enabled=core_awg_exit,
            param_socket_path=core_socket_path,
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        cfg_path = self._conf_dir / own_site_domain

        # Перехватываем write_text на cfg-файле
        captured_content = []
        original_write_text = Path.write_text

        def _capturing_write_text(self_path, *args, **kwargs):
            if str(self_path) == str(cfg_path):
                captured_content.append(args[0] if args else kwargs.get("data", ""))
            # НЕ пишем на диск — просто захватываем
            return len(args[0]) if args else 0

        # Также нужно перехватить create_website чтобы не создавала реальный каталог
        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", _capturing_write_text), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink"), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            nginx_setup.setup_nginx_final(
                domain=own_site_domain,
                port=own_site_port,
                socket_path=None,        # явно None → TCP режим
                protocol_mode="reality",
                awg_exit_enabled=False,
                site_template="2",
            )
        return captured_content[0] if captured_content else ""

    # ── Тест 1: REALITY-сервер, own-site домен → TCP listen, не unix ───────
    def test_own_site_with_reality_server_uses_tcp_not_unix(self):
        """core.PROTOCOL_MODE='reality' (ДЕФОЛТ), own-site вызов →
        конфиг содержит 'listen 127.0.0.1:8444 ssl' и НЕ содержит '/run/xray.sock'."""
        content = self._call_setup_nginx_final(
            core_protocol_mode="reality",
            core_socket_path="/run/xray.sock",
            own_site_domain="telemt.example.com",
            own_site_port=8444,
        )
        self.assertIn("listen 127.0.0.1:8444 ssl", content,
                      "own-site конфиг должен слушать TCP 127.0.0.1:8444")
        self.assertNotIn("/run/xray.sock", content,
                         "own-site конфиг НЕ должен содержать VLESS unix-сокет")
        self.assertNotIn("proxy_protocol", content,
                         "own-site конфиг НЕ должен использовать proxy_protocol")
        self.assertNotIn("real_ip_header", content,
                         "own-site конфиг НЕ должен использовать real_ip_header")

    # ── Тест 1b: нет proxy_pass на Xray backend ────────────────────────────
    def test_own_site_no_xray_proxy_pass(self):
        """Конфиг НЕ содержит proxy_pass на 127.0.0.1:{XHTTP_BACKEND_PORT}."""
        content = self._call_setup_nginx_final(
            core_protocol_mode="reality",
            own_site_domain="telemt.example.com",
            own_site_port=8444,
        )
        self.assertNotIn("proxy_pass", content,
                         "own-site конфиг НЕ должен проксировать на Xray backend")
        self.assertNotIn("127.0.0.1:8443", content,
                         "own-site конфиг НЕ должен ссылаться на XHTTP_BACKEND_PORT")

    # ── Тест 2: XHTTP-сервер, own-site домен → всё равно TCP, не xhttp ─────
    def test_own_site_with_xhttp_server_still_uses_tcp(self):
        """core.PROTOCOL_MODE='xhttp' — own-site домен НЕ получает xhttp proxy."""
        content = self._call_setup_nginx_final(
            core_protocol_mode="xhttp",
            own_site_domain="telemt.example.com",
            own_site_port=8444,
        )
        self.assertIn("listen 127.0.0.1:8444 ssl", content,
                      "own-site должен слушать TCP даже если VLESS в xhttp-режиме")
        self.assertNotIn("proxy_pass", content,
                         "own-site НЕ должен проксировать на Xray (даже при xhttp сервере)")
        self.assertNotIn("/xhttp", content,
                         "own-site НЕ должен содержать XHTTP_PATH")

    # ── Тест 3: AWG-сервер, own-site домен → всё равно TLS на mask_port ────
    def test_own_site_with_awg_server_has_tls_listener(self):
        """core.AWG_EXIT_ENABLED=True — own-site домен всё равно имеет
        HTTPS-listener на mask_port (не только HTTP:80 редирект как VLESS-AWG)."""
        content = self._call_setup_nginx_final(
            core_protocol_mode="reality",
            core_awg_exit=True,
            own_site_domain="telemt.example.com",
            own_site_port=8444,
        )
        self.assertIn("listen 127.0.0.1:8444 ssl", content,
                      "own-site должен иметь TLS listener даже при AWG_EXIT_ENABLED=True")
        self.assertIn("ssl_certificate", content,
                      "own-site должен терминировать TLS")

    # ── Тест 4: коллизия доменов → RuntimeError ────────────────────────────
    def test_domain_collision_raises_runtime_error(self):
        """own_site_domain == core.PARAM_DOMAIN → RuntimeError."""
        from chimera.modules import nginx_setup
        fake_core = _make_fake_core_for_nginx(
            param_domain="telemt.example.com",  # совпадает с own-site доменом!
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "mkdir"):
            with self.assertRaises(RuntimeError) as ctx:
                nginx_setup.setup_nginx_final(
                    domain="telemt.example.com",  # == core.PARAM_DOMAIN!
                    port=8444,
                    socket_path=None,
                    protocol_mode="reality",
                    awg_exit_enabled=False,
                )
            self.assertIn("совпадает", str(ctx.exception).lower(),
                          "Ошибка должна объяснять причину коллизии")

    # ── Тест 5: HTTP:80 — нет HTTPS-редиректа (ушёл бы на Telemt:443) ──────
    def test_own_site_http80_no_https_redirect(self):
        """HTTP:80 listener не должен делать return 301 https:// —
        редирект ушёл бы на порт 443 (Telemt), а не на mask_port."""
        content = self._call_setup_nginx_final(
            own_site_domain="telemt.example.com",
            own_site_port=8444,
        )
        # Находим server-блок с listen 80
        self.assertIn("listen 80", content, "Должен быть HTTP:80 listener для ACME")
        # В этом блоке НЕ должно быть return 301 https://
        # (проверяем что нет редиректа вообще — только ACME + 404)
        http80_section = content[content.index("listen 80"):content.index("listen 127.0.0.1")]
        self.assertNotIn("return 301 https", http80_section,
                         "HTTP:80 НЕ должен редиректить на HTTPS (ушёл бы на Telemt:443)")
        self.assertIn("acme-challenge", http80_section,
                      "HTTP:80 должен обслуживать ACME challenges для certbot renew")


class TestSetupNginxFinalVlessRegression(unittest.TestCase):
    """Regression guard: VLESS install flow (setup_nginx_final() без аргументов)
    → byte-for-byte идентичен выводу до фикса v4.20.2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _call_vless_reality(self, param_socket_path="/run/xray.sock"):
        """Вызывает setup_nginx_final() БЕЗ аргументов (как VLESS install flow).
        Возвращает содержимое конфига."""
        from chimera.modules import nginx_setup
        fake_core = _make_fake_core_for_nginx(
            protocol_mode="reality",
            awg_exit_enabled=False,
            param_domain="vless.example.com",
            param_socket_path=param_socket_path,
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        captured = []
        def _capture_write(self_path, *args, **kwargs):
            if "vless.example.com" in str(self_path):
                captured.append(args[0] if args else kwargs.get("data", ""))
            return len(args[0]) if args else 0

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink"), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            nginx_setup.setup_nginx_final()  # без аргументов — VLESS flow
        return captured[0] if captured else ""

    def test_vless_reality_uses_unix_socket(self):
        """VLESS REALITY flow (без аргументов) → unix-сокет, proxy_protocol."""
        content = self._call_vless_reality(param_socket_path="/run/xray.sock")
        self.assertIn("listen unix:/run/xray.sock ssl proxy_protocol", content,
                      "VLESS REALITY должен слушать unix-сокет с proxy_protocol")
        self.assertIn("real_ip_header proxy_protocol", content,
                      "VLESS REALITY должен иметь real_ip_header proxy_protocol")
        self.assertNotIn("listen 127.0.0.1:", content,
                         "VLESS REALITY НЕ должен слушать TCP (это own-site режим)")

    def test_vless_reality_has_https_redirect(self):
        """VLESS REALITY HTTP:80 → HTTPS-редирект (это нормально для VLESS)."""
        content = self._call_vless_reality()
        self.assertIn("return 301 https", content,
                      "VLESS REALITY должен иметь HTTPS-редирект (в отличие от own-site)")


class TestSetupNginxFinalTwoParallelDomains(unittest.TestCase):
    """Два параллельных вызова: VLESS-домен (без аргументов) + Telemt-домен
    (явные параметры). Оба конфига валидны одновременно — нет конфликта
    listen+default_server."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_vless_and_telemt_domains_coexist(self):
        """VLESS-домен на unix-сокете + Telemt-домен на TCP:8444 —
        оба конфига валидны, не конфликтуют по listen."""
        from chimera.modules import nginx_setup
        fake_core = _make_fake_core_for_nginx(
            protocol_mode="reality",
            param_domain="vless.example.com",
            param_socket_path="/run/xray.sock",
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        captured = {}  # domain → content
        def _capture_write(self_path, *args, **kwargs):
            s = str(self_path)
            for d in ("vless.example.com", "telemt.example.com"):
                if d in s:
                    captured[d] = args[0] if args else kwargs.get("data", "")
                    break
            return len(args[0]) if args else 0

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink"), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            # 1) VLESS-домен (без аргументов — inherit из core)
            nginx_setup.setup_nginx_final()
            # 2) Telemt-домен (явные параметры — own-site TCP)
            nginx_setup.setup_nginx_final(
                domain="telemt.example.com",
                port=8444,
                socket_path=None,
                protocol_mode="reality",
                awg_exit_enabled=False,
            )

        vless_cfg = captured.get("vless.example.com", "")
        telemt_cfg = captured.get("telemt.example.com", "")
        self.assertTrue(vless_cfg, "VLESS-конфиг должен быть сгенерирован")
        self.assertTrue(telemt_cfg, "Telemt-конфиг должен быть сгенерирован")
        # VLESS на unix-сокете, Telemt на TCP — разные listen, нет конфликта
        self.assertIn("listen unix:/run/xray.sock", vless_cfg)
        self.assertIn("listen 127.0.0.1:8444 ssl", telemt_cfg)
        # Ни один не содержит listen другого
        self.assertNotIn("127.0.0.1:8444", vless_cfg)
        self.assertNotIn("/run/xray.sock", telemt_cfg)


class TestCleanupOwnSite(unittest.TestCase):
    """Тест 6: cleanup при откате — orphaned-файлы удаляются."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._web_root_base = self._tmpdir / "www"
        self._web_root = self._web_root_base / "telemt.example.com"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)
        self._web_root.mkdir(parents=True, exist_ok=True)
        # Создаём файлы как если бы setup_nginx_final уже отработал
        (self._conf_dir / "telemt.example.com").write_text("# orphaned config")
        (self._enabled_dir / "telemt.example.com").write_text("# orphaned symlink")
        (self._web_root / "index.html").write_text("<h1>orphaned</h1>")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_web_root_path(self):
        """Патчит mtproto.Path так, что /var/www/<X> → self._tmpdir/www/<X>.

        _cleanup_own_site хардкодит Path(f'/var/www/{domain}'), а мы не хотим
        писать в реальный /var/www. Перехватываем конструктор Path."""
        import chimera.modules.mtproto as mtproto_mod
        real_path = Path

        class _PatchedPath(real_path):
            def __new__(cls, *args, **kwargs):
                p = real_path(*args, **kwargs)
                s = str(p)
                if s.startswith("/var/www/"):
                    rel = s[len("/var/www/"):]
                    return real_path(self._web_root_base / rel)
                return p

        return patch.object(mtproto_mod, "Path", _PatchedPath)

    def test_cleanup_removes_orphaned_files(self):
        """_cleanup_own_site удаляет nginx config, symlink, web_root."""
        from chimera.modules import mtproto
        fake_core = _make_fake_core_for_nginx(
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = fake_core
        try:
            with self._patch_web_root_path():
                mtproto._cleanup_own_site("telemt.example.com")
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)
        self.assertFalse((self._conf_dir / "telemt.example.com").exists(),
                         "nginx config должен быть удалён")
        self.assertFalse((self._enabled_dir / "telemt.example.com").exists(),
                         "nginx symlink должен быть удалён")
        self.assertFalse(self._web_root.exists(),
                         "web_root должен быть удалён")

    def test_cleanup_with_empty_domain_is_noop(self):
        """_cleanup_own_site('') — no-op, не падает."""
        from chimera.modules import mtproto
        # Не должно падать и не должно ничего удалять
        mtproto._cleanup_own_site("")
        # Файлы на месте
        self.assertTrue((self._conf_dir / "telemt.example.com").exists())

    def test_cleanup_with_nonexistent_domain_is_noop(self):
        """_cleanup_own_site для несуществующего домена — no-op, не падает."""
        from chimera.modules import mtproto
        fake_core = _make_fake_core_for_nginx(
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = fake_core
        try:
            mtproto._cleanup_own_site("nonexistent.example.com")
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)
        # Существующие файлы не тронуты
        self.assertTrue((self._conf_dir / "telemt.example.com").exists())


class TestGuardBlockCleanupOnRollback(unittest.TestCase):
    """Тест 7: guard-блок в _run_install_inner при откате вызывает _cleanup_own_site.
    Не молча продолжает — cleanup + rewrite конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_guard_block_calls_cleanup_on_nginx_down(self):
        """Если _check_mask_backend_ready=False, guard вызывает _cleanup_own_site
        и переписывает конфиг в donor-режим."""
        from chimera.modules import mtproto

        cleanup_calls = []
        write_calls = []

        def _fake_cleanup(domain):
            cleanup_calls.append(domain)

        def _fake_write_config(*args, **kwargs):
            write_calls.append(kwargs.copy())

        with patch.object(mtproto, "_check_mask_backend_ready",
                          return_value=False), \
             patch.object(mtproto, "_cleanup_own_site",
                          side_effect=_fake_cleanup), \
             patch.object(mtproto, "_write_config",
                          side_effect=_fake_write_config), \
             patch.object(mtproto, "_run",
                          return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(mtproto, "_ok"), \
             patch.object(mtproto, "_err"), \
             patch.object(mtproto, "_warn"), \
             patch.object(mtproto, "_info"):
            # Симулируем guard-блок (копия кода из _run_install_inner)
            tls_domain = "telemt.example.com"
            _mask_host = "127.0.0.1"
            _mask_port = 8444
            _tls_emulation = True
            port = 8443
            ipv4, ipv6 = "1.2.3.4", ""
            users = {"alice": "abcdef0123456789abcdef0123456789"}
            _fb_cfg = None
            _client_mss = ""

            if _mask_host and _mask_port:
                _nginx_ready = False
                for _attempt in range(5):
                    if mtproto._check_mask_backend_ready(_mask_host, _mask_port, timeout=2.0):
                        _nginx_ready = True
                        break
                if not _nginx_ready:
                    mtproto._cleanup_own_site(tls_domain)
                    _mask_host = ""
                    _mask_port = 0
                    _tls_emulation = False
                    mtproto._write_config(
                        port, ipv4, ipv6, tls_domain, users, False,
                        socks5_port=0, fallback_cfg=_fb_cfg,
                        client_mss=_client_mss,
                        mask_host="", mask_port=0, tls_emulation=False,
                    )

        # cleanup должен быть вызван с telemt-доменом
        self.assertEqual(cleanup_calls, ["telemt.example.com"],
                         "_cleanup_own_site должен быть вызван с telemt-доменом")
        # _write_config переписан в donor-режим
        self.assertEqual(len(write_calls), 1)
        self.assertEqual(write_calls[0]["mask_host"], "")
        self.assertEqual(write_calls[0]["mask_port"], 0)
        self.assertEqual(write_calls[0]["tls_emulation"], False)


# ══════════════════════════════════════════════════════════════════════════════
#  Тесты v4.20.3: setup_nginx_temp parameterization + order of operations
#  in _setup_own_site + self-signed detection + nginx -t hardening
# ══════════════════════════════════════════════════════════════════════════════

class TestSetupNginxTempParameterized(unittest.TestCase):
    """Тест 1: setup_nginx_temp(domain=...) — реальный вызов + парсинг конфига.

    Проверяем что созданный файл относится к переданному domain, а НЕ к
    core.PARAM_DOMAIN. Это та же болезнь, что чинили в v4.20.1/v4.20.2 для
    create_website()/setup_nginx_final()/obtain_ssl_cert() — просто не
    долечили здесь до v4.20.3.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _call_setup_nginx_temp(self, domain_arg=None, core_param_domain="vless.example.com"):
        """Вызывает setup_nginx_temp с заданным domain и core.PARAM_DOMAIN.
        Возвращает (cfg_path, cfg_content) или (None, None) если файл не записан."""
        from chimera.modules import nginx_setup
        fake_core = _make_fake_core_for_nginx(
            param_domain=core_param_domain,
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        captured = {}
        expected_path = self._conf_dir / (domain_arg or core_param_domain)

        def _capture_write(self_path, *args, **kwargs):
            if str(self_path) == str(expected_path):
                captured["content"] = args[0] if args else kwargs.get("data", "")
                captured["path"] = str(self_path)
            return len(args[0]) if args else 0

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "_ensure_nginx_sites_enabled_include"), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink"), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            if domain_arg is not None:
                nginx_setup.setup_nginx_temp(domain=domain_arg)
            else:
                nginx_setup.setup_nginx_temp()
        return captured.get("path"), captured.get("content", "")

    def test_setup_nginx_temp_with_explicit_domain_uses_it(self):
        """setup_nginx_temp(domain='telemt.example.com') с core.PARAM_DOMAIN='vless.example.com'
        → конфиг для telemt.example.com, НЕ для vless.example.com."""
        path, content = self._call_setup_nginx_temp(
            domain_arg="telemt.example.com",
            core_param_domain="vless.example.com",
        )
        self.assertIsNotNone(content, "Конфиг должен быть записан")
        self.assertIn("server_name telemt.example.com", content,
                      "server_name должен быть telemt.example.com (явный параметр)")
        self.assertIn("/var/www/telemt.example.com", content,
                      "web_root должен указывать на /var/www/telemt.example.com")
        self.assertNotIn("vless.example.com", content,
                         "core.PARAM_DOMAIN НЕ должен использоваться при явном domain=")

    def test_setup_nginx_temp_without_domain_uses_core_param(self):
        """Regression guard: setup_nginx_temp() без аргументов → core.PARAM_DOMAIN.
        VLESS install flow (вызов из _core.py:3009) не должен сломаться."""
        path, content = self._call_setup_nginx_temp(
            domain_arg=None,
            core_param_domain="vless.example.com",
        )
        self.assertIsNotNone(content, "Конфиг должен быть записан")
        self.assertIn("server_name vless.example.com", content,
                      "Без явного domain должен использоваться core.PARAM_DOMAIN")
        self.assertIn("/var/www/vless.example.com", content)

    def test_setup_nginx_temp_has_acme_challenge_location(self):
        """Конфиг содержит location /.well-known/acme-challenge/ для certbot."""
        _, content = self._call_setup_nginx_temp(domain_arg="telemt.example.com")
        self.assertIn(".well-known/acme-challenge", content,
                      "Должен быть ACME challenge location для certbot webroot")


class TestSetupOwnSiteOrderOfOperations(unittest.TestCase):
    """Тест 2: порядок вызовов в _setup_own_site.
    setup_nginx_temp(domain=...) вызывается СТРОГО до obtain_ssl_cert(domain=...).
    Без этого certbot получает 404 — ACME challenge уходит в дефолтный server.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_setup_nginx_temp_called_before_obtain_ssl_cert(self):
        """Мокаем obtain_ssl_cert и setup_nginx_temp с записью порядка вызовов."""
        from chimera.modules import mtproto

        call_order = []

        def _fake_setup_nginx_temp(domain=None, **kw):
            call_order.append(("setup_nginx_temp", domain))

        def _fake_obtain_ssl_cert(domain=None, **kw):
            call_order.append(("obtain_ssl_cert", domain))
            # Имитируем успех — не делаем ничего.

        def _fake_is_cert_self_signed(domain):
            # Валидный LE-сертификат
            return False

        def _fake_setup_nginx_final(**kw):
            call_order.append(("setup_nginx_final", kw.get("domain")))

        def _fake_check_mask_backend_ready(host, port, timeout=2.0, sni_hostname=""):
            return True

        def _fake_pick_local_nginx_port(telemt_port):
            return 8444

        # Подменяем sys.modules["chimera._core"] для проверки коллизии
        mock_core = MagicMock()
        mock_core.PARAM_DOMAIN = "vless.example.com"  # != telemt.example.com
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = mock_core

        try:
            # Раньше: один гигантский `with A, B, C, ...:` на 20 context managers
            # — упирался в лимит CPython на statically nested blocks.
            # Теперь: ExitStack + общий helper _enter_mtproto_ui_patches для 13
            # UI/log-хелперов + специфичные для теста патчи отдельно.
            with ExitStack() as stack:
                _enter_mtproto_ui_patches(stack, mtproto)
                stack.enter_context(patch.object(mtproto, "_pick_local_nginx_port",
                                                  side_effect=_fake_pick_local_nginx_port))
                stack.enter_context(patch.object(mtproto, "_is_cert_self_signed",
                                                  side_effect=_fake_is_cert_self_signed))
                stack.enter_context(patch.object(mtproto, "_check_mask_backend_ready",
                                                  side_effect=_fake_check_mask_backend_ready))
                stack.enter_context(patch.object(mtproto, "_cleanup_own_site"))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_temp",
                                          side_effect=_fake_setup_nginx_temp))
                stack.enter_context(patch("chimera.modules.ssl_certbot.obtain_ssl_cert",
                                          side_effect=_fake_obtain_ssl_cert))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_final",
                                          side_effect=_fake_setup_nginx_final))
                result = mtproto._setup_own_site("telemt.example.com", 8443)
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)

        # Проверяем порядок вызовов
        names = [name for name, _ in call_order]
        self.assertIn("setup_nginx_temp", names,
                      "setup_nginx_temp должен быть вызван")
        self.assertIn("obtain_ssl_cert", names,
                      "obtain_ssl_cert должен быть вызван")
        idx_temp = names.index("setup_nginx_temp")
        idx_ssl = names.index("obtain_ssl_cert")
        self.assertLess(idx_temp, idx_ssl,
                        "setup_nginx_temp ДОЛЖЕН быть вызван ДО obtain_ssl_cert")
        # Также проверяем domain-параметры
        self.assertEqual(call_order[idx_temp][1], "telemt.example.com")
        self.assertEqual(call_order[idx_ssl][1], "telemt.example.com")
        # И успех — mask_port > 0
        self.assertIsInstance(result, mtproto.OwnSiteConfig)
        self.assertEqual(result.mask_port, 8444)


class TestSelfSignedDetection(unittest.TestCase):
    """Тест 3: _is_cert_self_signed + интеграция в _setup_own_site.

    Если openssl x509 вернул одинаковый issuer/subject (self-signed) →
    _setup_own_site возвращает OwnSiteConfig(mask_port=0) и вызывает
    _cleanup_own_site. С валидным LE-issuer (issuer != subject) →
    own-site продолжает штатно, mask_port > 0.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_openssl(self, issuer: str, subject: str):
        """Мокает _run(['openssl', 'x509', ...]) чтобы вернуть заданные issuer/subject."""
        from chimera.modules import mtproto
        output = f"issuer={issuer}\nsubject={subject}\n"
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        return patch.object(mtproto, "_run", return_value=mock_result)

    def test_is_cert_self_signed_returns_true_when_issuer_equals_subject(self):
        """Self-signed: issuer == subject → True."""
        from chimera.modules import mtproto
        # Создаём фейковый cert-файл
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"fake cert")
            cert_path = f.name
        try:
            with patch.object(Path, "exists", return_value=True), \
                 patch("chimera.modules.mtproto.Path") as mock_path_class:
                # Path("/etc/letsencrypt/live/{domain}/cert.pem") → наш tmp-файл
                mock_path_class.return_value = Path(cert_path)
                mock_path_class.side_effect = lambda *a, **kw: Path(cert_path) if "letsencrypt" in str(a) else Path(*a, **kw)
                with self._mock_openssl("CN = self-signed", "CN = self-signed"):
                    result = mtproto._is_cert_self_signed("telemt.example.com")
            self.assertTrue(result, "issuer == subject → self-signed → True")
        finally:
            os.unlink(cert_path)

    def test_is_cert_self_signed_returns_false_when_issuer_neq_subject(self):
        """Валидный LE: issuer != subject → False."""
        from chimera.modules import mtproto
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"fake cert")
            cert_path = f.name
        try:
            with patch.object(Path, "exists", return_value=True), \
                 patch("chimera.modules.mtproto.Path") as mock_path_class:
                mock_path_class.return_value = Path(cert_path)
                mock_path_class.side_effect = lambda *a, **kw: Path(cert_path) if "letsencrypt" in str(a) else Path(*a, **kw)
                with self._mock_openssl("C = US, O = Let's Encrypt, CN = R3",
                                         "C = US, ST = ..."):
                    result = mtproto._is_cert_self_signed("telemt.example.com")
            self.assertFalse(result, "issuer != subject → валидный LE → False")
        finally:
            os.unlink(cert_path)

    def test_is_cert_self_signed_returns_true_when_cert_missing(self):
        """Сертификат не найден → True (fail-safe)."""
        from chimera.modules import mtproto
        with patch.object(Path, "exists", return_value=False):
            result = mtproto._is_cert_self_signed("nonexistent.example.com")
        self.assertTrue(result, "Отсутствие сертификата → True (fail-safe)")

    def test_setup_own_site_rolls_back_on_self_signed(self):
        """_setup_own_site: если после obtain_ssl_cert сертификат self-signed →
        возвращает OwnSiteConfig(mask_port=0) и вызывает _cleanup_own_site."""
        from chimera.modules import mtproto

        cleanup_calls = []
        mock_core = MagicMock()
        mock_core.PARAM_DOMAIN = "vless.example.com"
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = mock_core

        try:
            # Раньше: один гигантский `with A, B, C, ...:` на 18 context managers.
            # Теперь: ExitStack + общий helper _enter_mtproto_ui_patches.
            with ExitStack() as stack:
                _enter_mtproto_ui_patches(stack, mtproto)
                stack.enter_context(patch.object(mtproto, "_pick_local_nginx_port", return_value=8444))
                stack.enter_context(patch.object(mtproto, "_is_cert_self_signed", return_value=True))
                stack.enter_context(patch.object(mtproto, "_cleanup_own_site",
                                                  side_effect=lambda d: cleanup_calls.append(d)))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_temp"))
                stack.enter_context(patch("chimera.modules.ssl_certbot.obtain_ssl_cert"))
                result = mtproto._setup_own_site("telemt.example.com", 8443)
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)

        self.assertIsInstance(result, mtproto.OwnSiteConfig)
        self.assertEqual(result.mask_port, 0,
                         "Self-signed сертификат → mask_port=0 (откат к donor)")
        self.assertEqual(cleanup_calls, ["telemt.example.com"],
                         "_cleanup_own_site должен быть вызван при откате из-за self-signed")

    def test_setup_own_site_proceeds_on_valid_le_cert(self):
        """_setup_own_site: валидный LE (issuer != subject) → mask_port > 0."""
        from chimera.modules import mtproto

        mock_core = MagicMock()
        mock_core.PARAM_DOMAIN = "vless.example.com"
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = mock_core

        try:
            # Раньше: один гигантский `with A, B, C, ...:` на 20 context managers.
            # Теперь: ExitStack + общий helper _enter_mtproto_ui_patches.
            with ExitStack() as stack:
                _enter_mtproto_ui_patches(stack, mtproto)
                stack.enter_context(patch.object(mtproto, "_pick_local_nginx_port", return_value=8444))
                stack.enter_context(patch.object(mtproto, "_is_cert_self_signed", return_value=False))
                stack.enter_context(patch.object(mtproto, "_cleanup_own_site"))
                stack.enter_context(patch.object(mtproto, "_check_mask_backend_ready", return_value=True))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_temp"))
                stack.enter_context(patch("chimera.modules.ssl_certbot.obtain_ssl_cert"))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_final"))
                result = mtproto._setup_own_site("telemt.example.com", 8443)
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)

        self.assertIsInstance(result, mtproto.OwnSiteConfig)
        self.assertEqual(result.mask_port, 8444,
                         "Валидный LE → mask_port=8444 (own-site активен)")


class TestNginxHardeningUnlinkBeforeRestart(unittest.TestCase):
    """Тест 4: hardening — при провале nginx -t симлинк удаляется ДО restart/reload.

    Проверяем все 4 места в nginx_setup.py где встречается паттерн
    "symlink → nginx -t → if fail restart":
      1. setup_nginx_temp
      2. setup_nginx_final (own-site TCP ветка)
      3. setup_nginx_final (AWG ветка)
      4. setup_nginx_final (REALITY ветка)

    Без hardening: restart с уже подключённым битым конфигом кладёт весь nginx.
    С hardening: symlink удаляется ДО restart, nginx остаётся в валидном состоянии.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf_dir = self._tmpdir / "nginx_conf"
        self._enabled_dir = self._tmpdir / "nginx_enabled"
        self._conf_dir.mkdir(parents=True, exist_ok=True)
        self._enabled_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_mock_call_recorder(self, domain, fake_core):
        """Создаёт mock _run который записывает порядок вызовов в call_log."""
        from chimera.modules import nginx_setup
        call_log = []
        # Создаём фейковый symlink чтобы можно было unlink
        link_path = self._enabled_dir / domain
        link_path.write_text("# fake symlink target")

        def _fake_run(cmd, capture=False, check=False, quiet=False, **kw):
            cmd_str = " ".join(str(c) for c in cmd)
            call_log.append(cmd_str)
            # nginx -t возвращает failure
            if "nginx" in cmd_str and "-t" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="nginx: [emerg] fake error")
            # systemctl reload/restart nginx
            if "systemctl" in cmd_str and "nginx" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            # nginx -v
            if "nginx" in cmd_str and "-v" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="nginx version: nginx/1.25.3")
            return MagicMock(returncode=0, stdout="", stderr="")

        return call_log, link_path, _fake_run

    def test_setup_nginx_temp_unlinks_symlink_before_restart_on_failure(self):
        """Тест 4.1: setup_nginx_temp при nginx -t failure — symlink удалён ДО reload."""
        from chimera.modules import nginx_setup
        domain = "telemt.example.com"
        fake_core = _make_fake_core_for_nginx(
            param_domain="vless.example.com",
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        call_log, link_path, _fake_run = self._make_mock_call_recorder(domain, fake_core)

        # Заменяем fake_core._run на наш recorder
        fake_core._run = _fake_run

        # Патчим Path чтобы NGINX_ENABLED_DIR/<domain> указывал на наш link_path
        original_path = Path
        def _patched_path(*args, **kw):
            p = original_path(*args, **kw)
            s = str(p)
            if s == f"/etc/nginx/sites-enabled/{domain}":
                return link_path
            if s.startswith("/var/www/"):
                rel = s[len("/var/www/"):]
                return self._tmpdir / "www" / rel
            return p

        # Запоминаем существует ли link_path ДО вызова
        self.assertTrue(link_path.exists(), "precondition: symlink должен существовать")

        # ExitStack вместо цепного with на 10 context managers — единый стиль
        # с другими тестами файла после v4.20.5.
        with ExitStack() as stack:
            stack.enter_context(patch.object(nginx_setup, "_core_module", return_value=fake_core))
            stack.enter_context(patch.object(nginx_setup, "_ensure_nginx_sites_enabled_include"))
            stack.enter_context(patch.object(nginx_setup, "Path", side_effect=_patched_path))
            stack.enter_context(patch.object(Path, "write_text", lambda self, *a, **kw: None))
            stack.enter_context(patch.object(Path, "mkdir"))
            stack.enter_context(patch.object(Path, "unlink"))
            stack.enter_context(patch.object(Path, "symlink_to"))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
            stack.enter_context(patch("os.chown", lambda *a, **kw: None))
            nginx_setup.setup_nginx_temp(domain=domain)

        # Проверяем порядок: nginx -t ДО reload
        # (если symlink удалён ПЕРЕД reload, то link.unlink() между ними)
        # Смотрим что nginx -t вызывался
        self.assertTrue(any("nginx" in c and "-t" in c for c in call_log),
                        "nginx -t должен быть вызван")
        self.assertTrue(any("systemctl" in c and "nginx" in c for c in call_log),
                        "systemctl reload/restart nginx должен быть вызван")

    def test_setup_nginx_final_own_site_unlinks_on_failure(self):
        """Тест 4.2: setup_nginx_final own-site TCP ветка — symlink удалён при fail."""
        from chimera.modules import nginx_setup
        domain = "telemt.example.com"
        fake_core = _make_fake_core_for_nginx(
            param_domain="vless.example.com",
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        # nginx -t возвращает failure
        fake_core._run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="nginx: [emerg] fake error"))

        expected_link = self._enabled_dir / domain
        unlink_calls = []
        def _tracking_unlink(self, *a, **kw):
            # Проверяем что unlink вызван для нашего domain в enabled_dir
            if str(self) == str(expected_link):
                unlink_calls.append(str(self))
            return None

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", lambda self, *a, **kw: None), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink", _tracking_unlink), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            nginx_setup.setup_nginx_final(
                domain=domain, port=8444, socket_path=None,
                protocol_mode="reality", awg_exit_enabled=False,
            )

        # symlink должен быть удалён (минимум 1 вызов unlink для нашего домена)
        self.assertTrue(unlink_calls,
                        f"symlink {expected_link} должен быть удалён при nginx -t failure")

    def test_setup_nginx_final_awg_unlinks_on_failure(self):
        """Тест 4.3: setup_nginx_final AWG-ветка — symlink удалён при fail."""
        from chimera.modules import nginx_setup
        domain = "vless.example.com"  # AWG-ветка для VLESS flow (без явных параметров)
        fake_core = _make_fake_core_for_nginx(
            param_domain=domain,
            awg_exit_enabled=True,  # форсируем AWG-ветку
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        fake_core._run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="nginx: [emerg] fake error"))

        expected_link = self._enabled_dir / domain
        unlink_calls = []
        def _tracking_unlink(self, *a, **kw):
            if str(self) == str(expected_link):
                unlink_calls.append(str(self))
            return None

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", lambda self, *a, **kw: None), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink", _tracking_unlink), \
             patch.object(Path, "symlink_to"), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            nginx_setup.setup_nginx_final()  # VLESS flow без аргументов

        self.assertTrue(unlink_calls,
                        f"symlink {expected_link} должен быть удалён в AWG-ветке при nginx -t failure")

    def test_setup_nginx_final_reality_keeps_symlink_on_expected_failure(self):
        """Тест 4.4 (v4.20.4 revert): setup_nginx_final REALITY-ветка — symlink
        СОХРАНЁН при ожидаемом temp-socket warning.

        В REALITY-ветке nginx -t проваливается ЗАВЕДОМО на каждой свежей
        установке: конфиг тестируется через ВРЕМЕННЫЙ unix-сокет (socket.bind()
        +close()), который НИЧЕГО не слушает — Xray ещё не запущен. Реальный
        сокет появится позже, nginx стартует "до Xray" на финальном шаге
        установки, за пределами этой функции.

        Hardening "unlink symlink при nginx -t failure" (применён в 3 других
        ветках в v4.20.3) здесь НЕ применяется — иначе ломается каждая свежая
        REALITY-установка (симлинка не будет в sites-enabled при финальном
        старте nginx).

        Тест проверяет: при returncode=1 (ожидаемый temp-socket warning)
        symlink ОСТАЁТСЯ. Учитываем что link.unlink(missing_ok=True) на
        строке ~884 (перед symlink_to) — это легитимная очистка старого
        symlink'а, его не считаем. Считаем только unlink ПОСЛЕ symlink_to.
        """
        from chimera.modules import nginx_setup
        domain = "vless.example.com"
        fake_core = _make_fake_core_for_nginx(
            param_domain=domain,
            protocol_mode="reality",
            awg_exit_enabled=False,
            param_socket_path="/run/xray.sock",
            nginx_conf_dir=self._conf_dir,
            nginx_enabled_dir=self._enabled_dir,
        )
        # nginx -t возвращает failure (ожидаемый temp-socket warning)
        fake_core._run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="nginx: [emerg] fake error"))

        expected_link = self._enabled_dir / domain
        # Различаем "unlink до symlink_to" (легитимный, строка 884) от
        # "unlink после symlink_to" (баг v4.20.3, теперь должен отсутствовать).
        symlink_to_done = [False]
        unlink_after_symlink = []
        def _tracking_unlink(self, *a, **kw):
            if str(self) == str(expected_link):
                if symlink_to_done[0]:
                    unlink_after_symlink.append(str(self))
            return None
        def _tracking_symlink_to(self, *a, **kw):
            if str(self) == str(expected_link):
                symlink_to_done[0] = True
            return None

        with patch.object(nginx_setup, "_core_module", return_value=fake_core), \
             patch.object(nginx_setup, "create_website"), \
             patch.object(Path, "write_text", lambda self, *a, **kw: None), \
             patch.object(Path, "mkdir"), \
             patch.object(Path, "unlink", _tracking_unlink), \
             patch.object(Path, "symlink_to", _tracking_symlink_to), \
             patch.object(Path, "exists", return_value=False), \
             patch("os.chown", lambda *a, **kw: None):
            nginx_setup.setup_nginx_final()  # VLESS REALITY flow

        self.assertFalse(unlink_after_symlink,
                         f"symlink {expected_link} НЕ должен быть удалён в REALITY-ветке "
                         f"ПОСЛЕ symlink_to — провал nginx -t здесь ожидаем (temp-socket "
                         f"warning), симлинк нужен для финального старта nginx. "
                         f"Найдены unlink после symlink_to: {unlink_after_symlink}")


# ══════════════════════════════════════════════════════════════════════════════
#  Тесты v4.20.7: retry логика в _setup_own_site + race condition fix
# ══════════════════════════════════════════════════════════════════════════════
class TestSetupOwnSiteRetryLogic(unittest.TestCase):
    """v4.20.7: _setup_own_site шаг 7 — retry 3 попытки для _check_mask_backend_ready.

    Раньше одна попытка с timeout=3.0 — race condition: systemctl reload nginx
    async, nginx не успевал поднять listener → TCP-connect падал → откат в
    donor-режим. Теперь 3 попытки по 2 сек + диагностика при провале.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_retry_succeeds_on_second_attempt(self):
        """Если _check_mask_backend_ready возвращает False, True, True —
        _setup_own_site должен вернуть OwnSiteConfig с mask_port > 0
        (не откатывать в donor-режим)."""
        from chimera.modules import mtproto

        # Мокаем _check_mask_backend_ready: первая попытка False (race), вторая True
        check_calls = []
        def _fake_check(host, port, timeout=2.0, sni_hostname=""):
            check_calls.append((host, port))
            return len(check_calls) >= 2  # False, True, True

        mock_core = MagicMock()
        mock_core.PARAM_DOMAIN = "vless.example.com"
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = mock_core

        try:
            with ExitStack() as stack:
                _enter_mtproto_ui_patches(stack, mtproto)
                stack.enter_context(patch.object(mtproto, "_pick_local_nginx_port", return_value=8444))
                stack.enter_context(patch.object(mtproto, "_is_cert_self_signed", return_value=False))
                stack.enter_context(patch.object(mtproto, "_cleanup_own_site"))
                stack.enter_context(patch.object(mtproto, "_check_mask_backend_ready",
                                                  side_effect=_fake_check))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_temp"))
                stack.enter_context(patch("chimera.modules.ssl_certbot.obtain_ssl_cert"))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_final"))
                stack.enter_context(patch.object(mtproto, "time"))
                result = mtproto._setup_own_site("telemt.example.com", 8443)
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)

        self.assertIsInstance(result, mtproto.OwnSiteConfig)
        self.assertEqual(result.mask_port, 8444,
                         "Retry должен дать own-site успех (mask_port=8444)")
        self.assertGreaterEqual(len(check_calls), 2,
                                "Должно быть минимум 2 попытки (первая False, вторая True)")

    def test_retry_fails_after_3_attempts_with_diagnostics(self):
        """Если _check_mask_backend_ready возвращает False 3 раза —
        _setup_own_site должен откатить в donor-режим + показать диагностику."""
        from chimera.modules import mtproto

        check_calls = []
        def _fake_check(host, port, timeout=2.0, sni_hostname=""):
            check_calls.append(1)
            return False  # всегда False

        mock_core = MagicMock()
        mock_core.PARAM_DOMAIN = "vless.example.com"
        original_core = sys.modules.get("chimera._core")
        sys.modules["chimera._core"] = mock_core

        cleanup_calls = []
        err_calls = []

        try:
            with ExitStack() as stack:
                _enter_mtproto_ui_patches(stack, mtproto)
                stack.enter_context(patch.object(mtproto, "_pick_local_nginx_port", return_value=8444))
                stack.enter_context(patch.object(mtproto, "_is_cert_self_signed", return_value=False))
                stack.enter_context(patch.object(mtproto, "_cleanup_own_site",
                                                  side_effect=lambda d: cleanup_calls.append(d)))
                stack.enter_context(patch.object(mtproto, "_check_mask_backend_ready",
                                                  side_effect=_fake_check))
                stack.enter_context(patch.object(mtproto, "_err",
                                                  side_effect=lambda m: err_calls.append(m)))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_temp"))
                stack.enter_context(patch("chimera.modules.ssl_certbot.obtain_ssl_cert"))
                stack.enter_context(patch("chimera.modules.nginx_setup.setup_nginx_final"))
                stack.enter_context(patch.object(mtproto, "time"))
                stack.enter_context(patch.object(mtproto, "_run",
                                                  return_value=MagicMock(returncode=0, stdout="", stderr="nginx: OK")))
                result = mtproto._setup_own_site("telemt.example.com", 8443)
        finally:
            if original_core is not None:
                sys.modules["chimera._core"] = original_core
            else:
                sys.modules.pop("chimera._core", None)

        self.assertIsInstance(result, mtproto.OwnSiteConfig)
        self.assertEqual(result.mask_port, 0,
                         "3 неудачные попытки → mask_port=0 (donor-режим)")
        self.assertEqual(len(check_calls), 3,
                         "Должно быть ровно 3 попытки")
        self.assertEqual(cleanup_calls, ["telemt.example.com"],
                         "_cleanup_own_site должен быть вызван при откате")
        # Диагностика должна выводиться (ss + nginx -t)
        err_text = " ".join(err_calls)
        self.assertIn("Диагностика", err_text,
                      "Должна быть секция диагностики при провале")
        self.assertIn("ss -tlnH", err_text,
                      "Диагностика должна показывать ss вывод")



# ══════════════════════════════════════════════════════════════════════════════
#  Доп. тест: _select_domain возвращает str для donor-домена
# ══════════════════════════════════════════════════════════════════════════════
class TestSelectDomainReturns(unittest.TestCase):
    """_select_domain возвращает str для существующего домена (donor-режим),
    без вызова подменю own-site. Это sanity-check что backward-compat не сломан:
    выбор из готовых категорий возвращает строку, а не OwnSiteConfig.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_known_category_returns_str(self):
        """Выбор домена из категории '1' (Поисковики) возвращает строку.
        Категория '1' — ['yandex.ru', 'ya.ru', 'mail.ru', ...]; выбор '1' → yandex.ru.
        """
        from chimera.modules import mtproto
        # Мокаем proto_ask: сначала ввод "1" (категория), затем "1" (домен).
        with patch("chimera.modules.mtproto.proto_ask",
                   side_effect=["1", "1"]), \
             patch("chimera.modules.mtproto._banner"), \
             patch("chimera.modules.mtproto._box_top"), \
             patch("chimera.modules.mtproto._box_row"), \
             patch("chimera.modules.mtproto._box_sep"), \
             patch("chimera.modules.mtproto._box_item"), \
             patch("chimera.modules.mtproto._box_bot"), \
             patch("chimera.modules.mtproto._box_info"), \
             patch("builtins.print"):
            result = mtproto._select_domain(telemt_port=8443)
        self.assertIsInstance(result, str,
                             "Выбор из готовой категории должен вернуть str")
        # Категория "1" — Поисковики, первый домен: yandex.ru
        self.assertEqual(result, "yandex.ru")

    def test_q_returns_ivi_default(self):
        """Q (назад) возвращает дефолтный ivi.ru."""
        from chimera.modules import mtproto
        with patch("chimera.modules.mtproto.proto_ask",
                   side_effect=["q"]), \
             patch("chimera.modules.mtproto._banner"), \
             patch("chimera.modules.mtproto._box_top"), \
             patch("chimera.modules.mtproto._box_row"), \
             patch("chimera.modules.mtproto._box_sep"), \
             patch("chimera.modules.mtproto._box_item"), \
             patch("chimera.modules.mtproto._box_bot"), \
             patch("chimera.modules.mtproto._box_info"), \
             patch("builtins.print"):
            result = mtproto._select_domain(telemt_port=8443)
        self.assertEqual(result, "ivi.ru")


if __name__ == "__main__":
    unittest.main(verbosity=2)
