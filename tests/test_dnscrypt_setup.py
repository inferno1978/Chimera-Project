#!/usr/bin/env python3
"""
tests/test_dnscrypt_setup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dnscrypt_setup.py.

Покрывает:
  1. _get_dnscrypt_port — чтение порта из конфига
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestGetDnscryptPort(unittest.TestCase):
    """_get_dnscrypt_port — чтение порта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self, cfg_content=None):
        core = MagicMock()
        core.DNSCRYPT_CONF = self._cfg
        core.DNSCRYPT_LISTEN_PORT = 5300
        if cfg_content is not None:
            self._cfg.write_text(cfg_content)
        return core

    def test_returns_default_when_no_file(self):
        from chimera.modules import dnscrypt_setup
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core()):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_from_config(self):
        from chimera.modules import dnscrypt_setup
        cfg = "listen_addresses = ['127.0.0.1:5300']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_with_double_quotes(self):
        from chimera.modules import dnscrypt_setup
        cfg = 'listen_addresses = ["127.0.0.1:5353"]\n'
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5353)

    def test_returns_default_when_no_listen_addresses(self):
        from chimera.modules import dnscrypt_setup
        cfg = "server_names = ['cloudflare']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)


# ============================================================================
#  ТЕСТЫ DNSCRYPT_SPEC — sanity-проверки (Волна 3)
# ============================================================================
class TestDnscryptSpecSanity(unittest.TestCase):
    """Sanity-проверки DNSCRYPT_SPEC — что мигрированный spec корректен."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_dnscrypt_proxy(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.name, "dnscrypt-proxy")

    def test_filename_builder_uses_tag_and_arch(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(
            DNSCRYPT_SPEC.filename_builder(tag="2.1.5", arch="linux_x86_64"),
            "dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz",
        )
        self.assertEqual(
            DNSCRYPT_SPEC.filename_builder(tag="2.1.5", arch="linux_arm64"),
            "dnscrypt-proxy-linux_arm64-2.1.5.tar.gz",
        )

    def test_install_dests_is_usr_local_bin(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_manual_dir_is_root(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        for dest in DNSCRYPT_SPEC.install_dests:
            self.assertNotEqual(DNSCRYPT_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_100kb(self):
        """min_size = 100 KB — защита от 404 HTML-страниц (раньше не было)."""
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.min_size, 100_000)

    def test_post_install_is_set(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertIsNotNone(DNSCRYPT_SPEC.post_install)

    def test_mirror_urls_has_10_entries(self):
        """Сценарий 2: 10 зеркал для fallback (4 jsDelivr + raw + release + 3 proxy + Statically)."""
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz",
            tag="2.1.5", arch="linux_x86_64",
        )
        self.assertEqual(len(urls), 10)

    def test_post_install_returns_false_on_non_tarball(self):
        """post_install возвращает False на не-tar.gz файле."""
        import tempfile
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "fake.tar.gz"
            src.write_bytes(b"not a tarball" * 100)
            ok = DNSCRYPT_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_empty_file(self):
        from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "empty.tar.gz"
            src.write_bytes(b"")
            ok = DNSCRYPT_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ============================================================================
#  ТЕСТЫ apply_dnscrypt_tuning — TOML-зонность (кейс vds14808, 2026-09-20)
# ============================================================================
try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover — 3.10
    tomllib = None

import re as _re

_POOL_SYNC_CONFIG = """\
## dnscrypt-proxy.toml — Chimera Project (pool-sync)
## Синхронизирован: 2026-09-20 06:00:00

listen_addresses = ['127.0.0.1:5300']

server_names = ['quad9-dnscrypt-ip4-nofilter-pri']

ipv4_servers = true
doh_servers = true
force_tcp = false
timeout = 3000
lb_strategy = 'p2'
lb_estimator = true
reject_ttl = 10
cache = true
cache_size = 32768
cache_min_ttl = 300
fallback_resolvers = ['9.9.9.9:53', '77.88.8.8:53']
netprobe_timeout = 10

[sources]
  [sources.public-resolvers]
  urls = ['x']
  cache_file = 'public-resolvers.md'
  refresh_delay = 25

[anonymized_dns]
  routes = [
  { server_name='quad9-dnscrypt-ip4-nofilter-pri', via=['relay-1', 'relay-2'] },
  ]

[blocked_names]
[blocked_ips]
[allowed_names]
[allowed_ips]
[schedules]
[captive_portals]
[local_doh]
"""

# состояние конфига пользователя vds14808 после двух прогонов старого тюнинга
_BROKEN_CONFIG = _POOL_SYNC_CONFIG + """
## Добавлено apply_dnscrypt_tuning
odoh_servers = false
use_syslog = true

## Добавлено apply_dnscrypt_tuning
odoh_servers = false
use_syslog = true
"""


def _count_top_level_key(text: str, key: str) -> int:
    """Сколько раз key = встречается ВНЕ секций (top-level зона)."""
    n = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            break  # дальше пошли секции
        if _re.match(rf"^{key}\s*=", stripped):
            n += 1
    return n


def _tail_zone(text: str) -> str:
    """Строки после ПОСЛЕДНЕГО заголовка секции (зона старого бага)."""
    lines = text.splitlines()
    last = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("["):
            last = i
    return "\n".join(lines[last + 1:])


class TestApplyTuningTomlZones(unittest.TestCase):
    """apply_dnscrypt_tuning: недостающие ключи обязаны попадать в top-level.

    Регрессия кейса vds14808 (2026-09-20): pool-sync/advanced-конфиги не
    содержат use_syslog и заканчиваются секцией [local_doh]; старый тюнинг
    дописывал недостающие ключи В КОНЕЦ файла → local_doh.use_syslog →
    [FATAL] dnscrypt-proxy «Key 'local_doh.use_syslog' has already been
    defined» (дубль при повторном прогоне).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import types as _types
        self._saved_core = sys.modules.get("chimera._core")

        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "dnscrypt-proxy.toml"
        self._bin = self._tmpdir / "dnscrypt-proxy"
        self._bin.write_bytes(b"#!/bin/sh\n")

        core = _types.ModuleType("chimera._core")
        core.DNSCRYPT_BIN = self._bin
        core.DNSCRYPT_CONF = self._conf
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.dim = lambda *a, **kw: None
        run_result = MagicMock()
        run_result.stdout = ""  # is-active != active
        core._run = lambda cmd, **kw: run_result
        sys.modules["chimera._core"] = core

        from chimera.modules import dnscrypt_setup as _ds
        self._ds = _ds
        _sleep_patcher = patch.object(_ds.time, "sleep", lambda s: None)
        _sleep_patcher.start()
        self.addCleanup(_sleep_patcher.stop)

    def tearDown(self):
        sys.modules["chimera._core"] = self._saved_core
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _tune(self) -> None:
        self._ds.apply_dnscrypt_tuning()

    def _assert_valid_toml(self) -> None:
        text = self._conf.read_text()
        if tomllib is not None:
            parsed = tomllib.loads(text)  # raises при дублях ключей
            self.assertTrue(parsed.get("use_syslog"), "use_syslog должен быть top-level = true")
            self.assertEqual(parsed.get("local_doh"), {}, "local_doh должна остаться пустой секцией")
            return parsed
        # fallback (Python 3.10): структурные проверки без tomllib
        self.assertLessEqual(_count_top_level_key(text, "use_syslog"), 1)
        self.assertEqual(_count_top_level_key(text, "use_syslog"), 1)
        return None

    def test_pool_sync_config_keys_inserted_into_top_zone(self):
        """pool-sync конфиг (без use_syslog, хвост [local_doh]): ключи
        вставляются ПЕРЕД первой секцией, а не в хвост."""
        self._conf.write_text(_POOL_SYNC_CONFIG)
        self._tune()
        text = self._conf.read_text()
        parsed = self._assert_valid_toml()
        # вставка строго до первой секции
        first_section = text.index("[sources]")
        inserted_at = text.index("## Добавлено apply_dnscrypt_tuning")
        self.assertLess(inserted_at, first_section)
        # хвостовая зона чиста от TOP_PARAMS-ключей
        tail = _tail_zone(text)
        self.assertNotRegex(tail, r"use_syslog\s*=")
        self.assertNotRegex(tail, r"odoh_servers\s*=")
        if parsed is not None:
            self.assertIs(parsed["use_syslog"], True)

    def test_idempotent_double_run(self):
        """Повторный тюнинг не плодит дублей (старый код удваивал ключи)."""
        self._conf.write_text(_POOL_SYNC_CONFIG)
        self._tune()
        self._tune()
        text = self._conf.read_text()
        self._assert_valid_toml()
        self.assertEqual(len(_re.findall(r"^use_syslog\s*=", text, _re.M)), 1)

    def test_repairs_broken_user_config(self):
        """Битый конфиг пользователя (2 застрявших use_syslog после
        [local_doh]): один прогон тюнинга ремонтирует конфиг."""
        self._conf.write_text(_BROKEN_CONFIG)
        if tomllib is not None:
            with self.assertRaises(tomllib.TOMLDecodeError):
                tomllib.loads(self._conf.read_text())  # подтверждаю: файл бит
        self._tune()
        text = self._conf.read_text()
        self._assert_valid_toml()
        self.assertEqual(len(_re.findall(r"^use_syslog\s*=", text, _re.M)), 1)
        self.assertNotRegex(_tail_zone(text), r"## Добавлено apply_dnscrypt_tuning")

    def test_install_template_replaced_in_place(self):
        """Классический шаблон install (все ключи в top-level): замена
        in-place, структура не меняется, маркер-вставка не появляется."""
        cfg = """\
listen_addresses = ['127.0.0.1:5300']
max_clients = 250
doh_servers = true
odoh_servers = false
force_tcp = false
timeout = 5000
netprobe_timeout = 5
reject_ttl = 10
fallback_resolvers = ['9.9.9.9:53', '77.88.8.8:53']
lb_strategy = 'p2'
lb_estimator = true
use_syslog = true
cache = true
cache_size = 16384
cache_min_ttl = 300

[blocked_names]
  blocked_names_file = 'blocked-names.txt'
  log_file = 'blocked.log'

[sources]
  [sources.public-resolvers]
  cache_file = 'public-resolvers.md'
"""
        self._conf.write_text(cfg)
        self._tune()
        text = self._conf.read_text()
        for key in ("doh_servers", "odoh_servers", "timeout", "netprobe_timeout",
                    "cache", "cache_size", "use_syslog"):
            self.assertEqual(len(_re.findall(rf"^{key}\s*=", text, _re.M)), 1,
                             f"ключ {key} должен встречаться ровно один раз")
        self.assertNotIn("\n## Добавлено apply_dnscrypt_tuning\n", text)
        # log_file внутри [blocked_names] — легитимный, не удаляется
        self.assertIn("log_file = 'blocked.log'", text)
        if tomllib is not None:
            parsed = tomllib.loads(text)
            self.assertEqual(parsed["timeout"], 1500)
            self.assertEqual(parsed["cache_size"], 32768)
            self.assertTrue(parsed["use_syslog"])

    def test_top_level_log_file_removed(self):
        """top-level log_file удаляется (канон — journald), секционный живёт."""
        cfg = ("log_file = '/var/log/dnscrypt.log'\n"
               "use_syslog = true\n\n"
               "[blocked_names]\n  log_file = 'blocked.log'\n")
        self._conf.write_text(cfg)
        self._tune()
        text = self._conf.read_text()
        self.assertNotRegex(text, r"^log_file\s*=\s*'/var/log", _re.M)
        self.assertIn("log_file = 'blocked.log'", text)

    def test_config_without_sections_appends_at_end(self):
        """Вырожденный конфиг без секций: дозапись в конец = корректный
        top-level (не хвост какой-то секции)."""
        self._conf.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        self._tune()
        text = self._conf.read_text()
        self.assertEqual(len(_re.findall(r"^use_syslog\s*=", text, _re.M)), 1)
        if tomllib is not None:
            parsed = tomllib.loads(text)
            self.assertIs(parsed["use_syslog"], True)

    def test_config_starting_with_section_prepends_keys(self):
        """Файл начинается сразу секцией: ключи вставляются в начало
        (top-zone пуста), а не после последней секции."""
        self._conf.write_text("[local_doh]\n\n[sources]\n  cache_file = 'x'\n")
        self._tune()
        text = self._conf.read_text()
        self._assert_valid_toml()
        self.assertLess(text.index("## Добавлено apply_dnscrypt_tuning"),
                        text.index("[local_doh]"))

    def test_security_params_now_include_use_syslog(self):
        """Источник бага закрыт: _SECURITY_PARAMS (pool-sync/advanced
        генераторы) содержит use_syslog — тюнингу нечего дописывать."""
        from chimera.modules.dnscrypt_advanced import _SECURITY_PARAMS
        self.assertIn("use_syslog", _SECURITY_PARAMS)
        self.assertEqual(_SECURITY_PARAMS["use_syslog"], "true")


if __name__ == "__main__":
    unittest.main(verbosity=2)
