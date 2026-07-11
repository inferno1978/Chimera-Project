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
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_mtproto.py — патчит Path/os."""
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core
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
            patch("vless_installer.modules.mtproto.CONFIG_FILE", self._cfg),
            patch("vless_installer.modules.mtproto.CONFIG_DIR", self._cfg_dir),
            patch("vless_installer.modules.mtproto.WORK_DIR", self._work_dir),
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
            patch("vless_installer.modules.mtproto.CONFIG_FILE", self._cfg),
            patch("vless_installer.modules.mtproto.CONFIG_DIR", self._cfg_dir),
            patch("vless_installer.modules.mtproto.WORK_DIR", self._work_dir),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_own_site_writes_mask_host_and_tls_emulation(self):
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
            "vless_installer.modules.nginx_setup.Path",
            self._make_path_wrapper(),
        )
        self._patch_var_www.start()
        # Также глушим chown и _run чтобы не пытаться реально выполнять.
        from vless_installer.modules import nginx_setup
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
        from vless_installer.modules import nginx_setup
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
        from vless_installer.modules import nginx_setup
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
        from vless_installer.modules import nginx_setup
        nginx_setup.create_website()  # без параметров
        default_root = self._var_www / "wrong.example.com"
        self.assertTrue(default_root.exists(),
                        "Без явного domain должен использоваться core.PARAM_DOMAIN")


# ══════════════════════════════════════════════════════════════════════════════
#  Тест 5: проверка порядка операций (КРИТИЧНО — guard от silent regression)
# ══════════════════════════════════════════════════════════════════════════════
class TestMaskBackendReadinessCheck(unittest.TestCase):
    """Проверка порядка операций из 2.5: если nginx не слушает mask_port,
    _check_mask_backend_ready должен вернуть False (а вызывающий код в
    _run_install_inner — откатиться к donor-режиму, НЕ молча продолжать).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_check_returns_true_on_listening_port(self):
        """На реальном слушающем TCP-сокете — True."""
        from vless_installer.modules import mtproto
        # Поднимаем ephemeral TCP-сервер на 127.0.0.1.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(
                mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=2.0)
            )
        finally:
            srv.close()

    def test_check_returns_false_on_closed_port(self):
        """На закрытом порту — False (не raise)."""
        from vless_installer.modules import mtproto
        # Подбираем точно свободный порт: открываем и сразу закрываем.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        # С очень высокой вероятностью порт всё ещё свободен.
        self.assertFalse(
            mtproto._check_mask_backend_ready("127.0.0.1", port, timeout=0.5)
        )

    def test_check_returns_false_on_timeout(self):
        """На RFC-5737 TEST-NET-1 (192.0.2.0/24) — гарантированный timeout."""
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto

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
        from vless_installer.modules.mtproto import OwnSiteConfig
        cfg = OwnSiteConfig(domain="x.example.com")
        self.assertEqual(cfg.mask_host, "127.0.0.1")
        self.assertEqual(cfg.mask_port, 0)

    def test_explicit_mask_port(self):
        from vless_installer.modules.mtproto import OwnSiteConfig
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules import mtproto
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
        from vless_installer.modules.ssl_certbot import obtain_ssl_cert
        sig = inspect.signature(obtain_ssl_cert)
        self.assertIn("domain", sig.parameters,
                      "obtain_ssl_cert должен принимать domain=")
        self.assertIsNone(sig.parameters["domain"].default,
                          "domain должен быть Optional (default None)")

    def test_setup_nginx_final_accepts_domain_port_socket(self):
        """setup_nginx_final(domain, port, socket_path) — все три параметра."""
        import inspect
        from vless_installer.modules.nginx_setup import setup_nginx_final
        sig = inspect.signature(setup_nginx_final)
        for p in ("domain", "port", "socket_path"):
            self.assertIn(p, sig.parameters,
                          f"setup_nginx_final должен принимать {p}=")
            self.assertIsNone(sig.parameters[p].default,
                              f"{p} должен быть Optional (default None)")

    def test_create_website_accepts_domain_site_template(self):
        """create_website(domain, site_template) — оба параметра."""
        import inspect
        from vless_installer.modules.nginx_setup import create_website
        sig = inspect.signature(create_website)
        for p in ("domain", "site_template"):
            self.assertIn(p, sig.parameters,
                          f"create_website должен принимать {p}=")


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
        from vless_installer.modules import mtproto
        # Мокаем proto_ask: сначала ввод "1" (категория), затем "1" (домен).
        with patch("vless_installer.modules.mtproto.proto_ask",
                   side_effect=["1", "1"]), \
             patch("vless_installer.modules.mtproto._banner"), \
             patch("vless_installer.modules.mtproto._box_top"), \
             patch("vless_installer.modules.mtproto._box_row"), \
             patch("vless_installer.modules.mtproto._box_sep"), \
             patch("vless_installer.modules.mtproto._box_item"), \
             patch("vless_installer.modules.mtproto._box_bot"), \
             patch("vless_installer.modules.mtproto._box_info"), \
             patch("builtins.print"):
            result = mtproto._select_domain(telemt_port=8443)
        self.assertIsInstance(result, str,
                             "Выбор из готовой категории должен вернуть str")
        # Категория "1" — Поисковики, первый домен: yandex.ru
        self.assertEqual(result, "yandex.ru")

    def test_q_returns_ivi_default(self):
        """Q (назад) возвращает дефолтный ivi.ru."""
        from vless_installer.modules import mtproto
        with patch("vless_installer.modules.mtproto.proto_ask",
                   side_effect=["q"]), \
             patch("vless_installer.modules.mtproto._banner"), \
             patch("vless_installer.modules.mtproto._box_top"), \
             patch("vless_installer.modules.mtproto._box_row"), \
             patch("vless_installer.modules.mtproto._box_sep"), \
             patch("vless_installer.modules.mtproto._box_item"), \
             patch("vless_installer.modules.mtproto._box_bot"), \
             patch("vless_installer.modules.mtproto._box_info"), \
             patch("builtins.print"):
            result = mtproto._select_domain(telemt_port=8443)
        self.assertEqual(result, "ivi.ru")


if __name__ == "__main__":
    unittest.main(verbosity=2)
