#!/usr/bin/env python3
"""
tests/test_v60_clean_install_no_warnings.py
───────────────────────────────────────────────────────────────────────────────
v60: чистая переустановка БЕЗ предупреждений (инцидент 203.0.113.109).

Лог переустановки на ноде без IPv6 содержал каскад ложных [WARN]:
  [WARN] AGH: системный DNS на 127.0.0.1:53 не отвечает (перед установкой
         AGH) — восстанавливаю          ← ложный: :53 пуст ДО старта AGH
  [OK]   DNS направлен на локальный DNSCrypt-proxy (127.0.0.1)
  [WARN] AGH: КРИТИЧНО — DNS по-прежнему мёртв после авто-восстановления
         ← «восстановление» САМО сломало рабочий DNS провайдера,
           направив resolv.conf на ещё не готовый dnscrypt
  [WARN] AGH: не удалось скачать AdGuardHome…  ← следствие мёртвого DNS
  [WARN] Обнаружен файрвол с политикой INPUT DROP ×4  ← авто-обработано
  [WARN] Порт 443/tcp может быть недоступен снаружи ×3 ← чек ДО старта xray
  [WARN] Xray 26.x — date-based версия…  ← норма для актуальных релизов
  [WARN] logrotate: проверьте конфиг вручную: xray-heavy ← валидный конфиг

Тесты фиксируют контракт v60:
  1. _system_dns_ok — системная проба (getent), а не только 127.0.0.1:53
  2. _ensure_system_dns_alive — молча при живом DNS провайдера
  3. _emergency_public_dns_fallback — публичный DNS последней ступенью
  4. Зеркала AGH: актуальный pinned-тег + доп. прокси + adtidy
  5. _get_latest_agh_tag — API-зеркало при флапе api.github.com
  6. _logrotate_debug_ok — валидация по 'error:'-строкам, не по rc
  7. Статические пины: авто-обрабатываемые ситуации больше не [WARN]
"""
from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_aghome_setup)."""
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


def _read(rel: str) -> str:
    return (_PROJECT_ROOT / rel).read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
#  1. _system_dns_ok — системная проба резолва
# ─────────────────────────────────────────────────────────────────────────────
class TestSystemDnsOk(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_getent_success(self):
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=0)
            self.assertTrue(self.mod._system_dns_ok())
            cmd = run.call_args[0][0]
            self.assertEqual(cmd[:2], ["getent", "hosts"])
            self.assertEqual(cmd[2], "github.com")

    def test_getent_failure(self):
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=2)  # NXDOMAIN/не найдено
            self.assertFalse(self.mod._system_dns_ok())

    def test_dig_fallback_without_server(self):
        """getent отсутствует → dig БЕЗ @server (путь resolv.conf)."""
        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            if cmd[0] == "getent":
                raise FileNotFoundError("getent")
            return MagicMock(returncode=0)

        with patch.object(self.mod.subprocess, "run",
                          side_effect=fake_run), \
             patch.object(self.mod.shutil, "which",
                          return_value="/usr/bin/dig"):
            self.assertTrue(self.mod._system_dns_ok())
        self.assertEqual(calls[0][:2], ["getent", "hosts"])
        self.assertEqual(calls[1][:2], ["dig", "github.com"])
        self.assertNotIn("@127.0.0.1", calls[1])

    def test_dig_fallback_dead(self):
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=9)  # no reply
            self.assertFalse(self.mod._system_dns_ok())

    def test_probe_with_settle_retries(self):
        """settle-проба: первая мертва, вторая жива → True (dnscrypt
        поднимается не мгновенно)."""
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, False, True]), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._probe_dns_with_settle())

    def test_probe_with_settle_all_dead(self):
        with patch.object(self.mod, "_system_dns_ok",
                          return_value=False), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertFalse(self.mod._probe_dns_with_settle())


# ─────────────────────────────────────────────────────────────────────────────
#  2. _ensure_system_dns_alive — молча при живом системном DNS
# ─────────────────────────────────────────────────────────────────────────────
class TestEnsureSystemDnsAliveSilentPass(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_fresh_install_provider_dns_silent(self):
        """Ядро v60: чистая установка — :53 пуст (AGH не ставился),
        dnscrypt на :5300, системный DNS = DNS провайдера и ЖИВ.
        Никаких предупреждений и никакого «восстановления»."""
        core = sys.modules["chimera._core"]
        warns = []
        with patch.object(self.mod, "_system_dns_ok", return_value=True), \
             patch.object(self.mod, "_dns_probe_ok", return_value=False), \
             patch.object(core, "warn", side_effect=lambda m: warns.append(m)), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost") as fix:
            self.assertTrue(
                self.mod._ensure_system_dns_alive("перед установкой AGH"))
        fix.assert_not_called()
        self.assertEqual(warns, [],
                         f"на живом системном DNS не должно быть warn: {warns}")

    def test_dead_dns_produces_warning_and_ladder(self):
        """Мёртвый системный DNS (v44: resolv.conf → мёртвый 127.0.0.1) —
        предупреждение + лестница восстановления запускается."""
        core = sys.modules["chimera._core"]
        warns = []
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, False, True]), \
             patch.object(core, "warn", side_effect=lambda m: warns.append(m)), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   return_value={"ok": True}), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive("тест"))
        self.assertTrue(any("не резолвит" in w for w in warns),
                        f"ожидался warn о мёртвом DNS: {warns}")


# ─────────────────────────────────────────────────────────────────────────────
#  3. _emergency_public_dns_fallback — публичный DNS последней ступенью
# ─────────────────────────────────────────────────────────────────────────────
class TestEmergencyPublicDnsFallback(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _map_path(self, p):
        if str(p) == "/etc/resolv.conf":
            return self.base / "resolv.conf"
        return Path(p)

    def test_writes_public_nameservers(self):
        resolv = self.base / "resolv.conf"
        with patch.object(self.mod, "Path", self._map_path):
            self.assertTrue(self.mod._emergency_public_dns_fallback())
        text = resolv.read_text()
        self.assertIn("nameserver 1.1.1.1", text)
        self.assertIn("nameserver 8.8.8.8", text)

    def test_backup_of_previous_resolv(self):
        resolv = self.base / "resolv.conf"
        resolv.write_text("nameserver 10.0.0.1\n")
        with patch.object(self.mod, "Path", self._map_path):
            self.assertTrue(self.mod._emergency_public_dns_fallback())
        bak = self.base / "resolv.conf.pre-public-fallback.bak"
        self.assertEqual(bak.read_text(), "nameserver 10.0.0.1\n")
        self.assertIn("1.1.1.1", resolv.read_text())

    def test_symlink_replaced_by_regular_file(self):
        target = self.base / "stub-target"
        target.write_text("nameserver 127.0.0.53\n")
        resolv = self.base / "resolv.conf"
        resolv.symlink_to(target)
        with patch.object(self.mod, "Path", self._map_path):
            self.assertTrue(self.mod._emergency_public_dns_fallback())
        self.assertFalse(resolv.is_symlink())
        self.assertTrue(resolv.is_file())
        self.assertIn("1.1.1.1", resolv.read_text())

    def test_write_failure_returns_false(self):
        def _boom(p):
            raise PermissionError("ro")
        with patch.object(self.mod, "Path", _boom):
            self.assertFalse(self.mod._emergency_public_dns_fallback())

    def test_help_box_mentions_public_dns(self):
        """Бокс ручного восстановления содержит вариант с публичным DNS."""
        core = sys.modules["chimera._core"]
        core.RED = core.CYAN = core.DIM = core.NC = ""
        core._box_top = lambda *a, **kw: None
        core._box_bottom = lambda *a, **kw: None
        rows = []
        core._box_row = lambda *a, **kw: rows.append(
            a[0] if a else kw.get("text", ""))
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.mod._dns_blackhole_help_box()
        out = "\n".join(rows)
        self.assertIn("1.1.1.1", out)
        self.assertIn("Вариант 2", out)  # локальный redirect остался


# ─────────────────────────────────────────────────────────────────────────────
#  4. Зеркала AGH — актуальный тег + расширенный набор
# ─────────────────────────────────────────────────────────────────────────────
class TestAghomeMirrorsV60(unittest.TestCase):
    def test_fallback_tag_actual(self):
        """v60: pinned-тег синхронизирован с release-каналом adtidy
        (v0.107.62 был устаревшим на 17 версий)."""
        from chimera.modules.aghome_mirrors import AGHOME_FALLBACK_TAG
        self.assertEqual(AGHOME_FALLBACK_TAG, "v0.107.79")

    def test_mirrors_extended_set(self):
        from chimera.modules.aghome_mirrors import get_aghome_mirrors
        from chimera.modules.github_mirrors import GITHUB_PROXY_HOSTS
        urls = get_aghome_mirrors("v0.107.79", "amd64")
        # 1 github-pinned + N общих прокси + 2 AGH-специфичных +
        # 1 adtidy + 1 github-latest
        expected = 1 + len(GITHUB_PROXY_HOSTS) + 2 + 1 + 1
        self.assertEqual(len(urls), expected, msg=str(urls))
        self.assertTrue(urls[0].endswith(
            "releases/download/v0.107.79/AdGuardHome_linux_amd64.tar.gz"))
        self.assertTrue(any("ghfast.top" in u for u in urls))
        self.assertTrue(any("gh.ddlc.top" in u for u in urls))
        self.assertTrue(any("static.adtidy.org" in u for u in urls))
        self.assertIn(
            "https://github.com/AdguardTeam/AdGuardHome/releases/latest/"
            "download/AdGuardHome_linux_amd64.tar.gz", urls)


# ─────────────────────────────────────────────────────────────────────────────
#  5. _get_latest_agh_tag — API-зеркало при флапе api.github.com
# ─────────────────────────────────────────────────────────────────────────────
class TestGetLatestAghTag(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_api_mirror_fallback(self):
        """api.github.com флапнул → зеркальный запрос через gh-proxy.com
        вернул тег (инцидент: «GitHub API недоступен» при живой сети)."""
        tried = []

        def fake_run(cmd, **kw):
            url = cmd[-1]
            tried.append(url)
            if url.startswith("https://api.github.com/"):
                return MagicMock(returncode=1, stdout="")
            return MagicMock(returncode=0,
                             stdout='{"tag_name": "v0.107.79"}')

        with patch.object(self.mod.subprocess, "run", side_effect=fake_run), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertEqual(self.mod._get_latest_agh_tag(), "v0.107.79")
        self.assertEqual(len(tried), 2)
        self.assertTrue(tried[0].startswith("https://api.github.com/"))
        self.assertIn("gh-proxy.com", tried[1])

    def test_all_api_dead_returns_empty(self):
        with patch.object(self.mod.subprocess, "run",
                          return_value=MagicMock(returncode=1, stdout="")), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertEqual(self.mod._get_latest_agh_tag(), "")


# ─────────────────────────────────────────────────────────────────────────────
#  6. _logrotate_debug_ok — валидация по 'error:'-строкам
# ─────────────────────────────────────────────────────────────────────────────
class TestLogrotateDebugOk(unittest.TestCase):
    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        # _logrotate_debug_ok ссылается на _run из exec-глобалов функции,
        # а не из атрибутов модуля — патчим через __globals__
        self._gl = self.core._logrotate_debug_ok.__globals__

    def _patch_run(self, ret=None, side_effect=None):
        mock = MagicMock(return_value=ret,
                         side_effect=side_effect)
        if side_effect is not None:
            mock = MagicMock(side_effect=side_effect)
        return patch.dict(self._gl, {"_run": mock})

    def test_rc_nonzero_warnings_only_is_valid(self):
        """rc=1 только с warning-строками (частые сборки logrotate) —
        конфиг ВАЛИДЕН, ложный [WARN] не должен появляться."""
        r = MagicMock(returncode=1,
                      stdout="warning: log /var/log/xray-watchdog.log "
                             "doesn't exist", stderr="")
        with self._patch_run(ret=r):
            self.assertTrue(self.core._logrotate_debug_ok(Path("/etc/logrotate.d/xray-heavy")))

    def test_error_lines_mean_invalid(self):
        r = MagicMock(returncode=1, stdout="",
                      stderr="error: /etc/logrotate.d/xray: 3 unknown "
                             "option 'dailyx'")
        with self._patch_run(ret=r):
            self.assertFalse(self.core._logrotate_debug_ok(Path("/etc/logrotate.d/xray")))

    def test_logrotate_missing_is_not_config_error(self):
        r = MagicMock(returncode=127, stdout="", stderr="command not found")
        with self._patch_run(ret=r):
            self.assertTrue(self.core._logrotate_debug_ok(Path("/etc/logrotate.d/xray")))

    def test_run_exception_is_not_config_error(self):
        with self._patch_run(side_effect=OSError("boom")):
            self.assertTrue(self.core._logrotate_debug_ok(Path("/etc/logrotate.d/xray")))

    def test_path_with_error_log_filename_not_false_positive(self):
        """Строка 'error.log' в выводе (путь лога) ≠ 'error:'-строка."""
        r = MagicMock(returncode=0,
                      stdout="rotating pattern: /var/log/xray/access.log "
                             "/var/log/xray/error.log", stderr="")
        with self._patch_run(ret=r):
            self.assertTrue(self.core._logrotate_debug_ok(Path("/etc/logrotate.d/xray")))

    def test_setup_logrotate_precreates_heavy_logs(self):
        """v60: логи autoban/watchdog предсоздаются до валидации."""
        src = _read("chimera/_core.py")
        self.assertIn("_lp.touch()", src)
        self.assertIn("_logrotate_debug_ok(LOGROTATE_XRAY)", src)
        self.assertIn("_logrotate_debug_ok(LOGROTATE_XRAY_HEAVY)", src)


# ─────────────────────────────────────────────────────────────────────────────
#  7. Статические пины — авто-обрабатываемые ситуации не [WARN]
# ─────────────────────────────────────────────────────────────────────────────
class TestNoFalseWarningsSources(unittest.TestCase):
    """Каждый [WARN] из лога переустановки 203.0.113.109 либо устранён,
    либо понижен до info (ситуация обрабатывается автоматически)."""

    def test_core_no_early_port_check(self):
        """«Порт 443/tcp может быть недоступен снаружи» — чек выполнялся
        ДО запуска xray и стучался в 127.0.1.1 → warn на чистой
        установке ВСЕГДА. Удалён: реальная проверка — финальная
        «Проверка сетевой доступности»."""
        src = _read("chimera/_core.py")
        self.assertNotIn("может быть недоступен снаружи", src)
        self.assertNotIn("gethostbyname(_sock.gethostname())", src)

    def test_network_setup_input_drop_is_info(self):
        src = _read("chimera/modules/network_setup.py")
        self.assertNotIn('warn("Обнаружен файрвол', src)
        self.assertIn('info("Обнаружен файрвол', src)

    def test_xray_install_installer_fallback_is_info(self):
        src = _read("chimera/modules/xray_install.py")
        self.assertNotIn('warn("Официальный установщик', src)
        self.assertNotIn('warn(f"Официальный установщик', src)
        self.assertIn('info("Официальный установщик недоступен', src)

    def test_xray_install_date_based_is_info(self):
        src = _read("chimera/modules/xray_install.py")
        self.assertNotIn('warn(f"Xray {ver_line.split()[1]} — date-based', src)
        self.assertIn('info(f"Xray {ver_line.split()[1]} — date-based', src)

    def test_xray_install_latest_retry_is_info(self):
        src = _read("chimera/modules/xray_install.py")
        self.assertNotIn('warn(f"  latest: попытка', src)

    def test_download_manager_fallback_noise_neutral(self):
        """Фолбэк на следующее зеркало — штатная операция: маркер «·»,
        а не «⚠» (403-шум jsdelivr не должен выглядеть варнингами).
        «⚠» остаётся только на hash mismatch (целостность!)."""
        src = _read("chimera/modules/download_manager.py")
        self.assertNotIn("⚠ зеркало", src)
        self.assertIn("· зеркало", src)
        self.assertIn("⚠ {spec.checksum_algo} НЕ совпал", src)

    def test_aghome_fetch_has_progress_label(self):
        """Попытки зеркал AGH видны пользователю (раньше 6 URL молча
        перебирались — «Не удалось скачать» без диагноза)."""
        src = _read("chimera/modules/aghome_setup.py")
        self.assertIn('progress_label="AGH"', src)

    def test_aghome_wizard_wait_uses_system_probe(self):
        import re as _re
        src = _read("chimera/modules/aghome_setup.py")
        m = _re.search(r"def _wait_wizard_completed.*?(?=\ndef )", src, _re.DOTALL)
        self.assertIsNotNone(m)
        self.assertIn("_system_dns_ok()", m.group(0))
        self.assertNotIn("_dns_probe_ok()", m.group(0))

    def test_aghome_no_localhost53_only_criterion(self):
        """Старый warn «системный DNS на 127.0.0.1:53 не отвечает»
        (ложный на чистой установке) заменён системной пробой."""
        src = _read("chimera/modules/aghome_setup.py")
        self.assertNotIn("системный DNS на 127.0.0.1:53 не отвечает", src)
        self.assertIn("AGH: системный DNS не резолвит", src)


if __name__ == "__main__":
    unittest.main()
