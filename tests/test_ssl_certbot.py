#!/usr/bin/env python3
"""
tests/test_ssl_certbot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ssl_certbot.py.

Покрывает:
  1. ensure_cert_fix_script — генерация bash-скрипта
  2. Certbot monitor v3 — контент сгенерированного скрипта:
     shebang с нулевого байта (v2 деплоился с 8-пробельным сдвигом),
     lock-retry 60/180/300с, sanity-gate (renew FAILED при валидном
     серте не алертит), живое время в log(), cron-слот 03:23/15:23;
     синтаксис проверяется bash -n и sh -n (dash: /etc/cron.d по
     умолчанию использует /bin/sh)
  3. Функциональные прогоны скрипта в песочнице (stub-certbot +
     подменённые пути): OK / lock-ретраи / sanity-молчание / алерт
     при отсутствующем серте / lock-истощение ретраев
  4. _remove_legacy_certbot_crontab — точечное удаление legacy-строки
     '0 3 * * * certbot renew --quiet' (инцидент 04.10.2026)
  5. setup_cert_renewal — legacy-строку больше НЕ ставит, зовёт cleanup
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_LEGACY_LINE = "0 3 * * * certbot renew --quiet"


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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestEnsureCertFixScript(unittest.TestCase):
    """ensure_cert_fix_script — генерация bash-скрипта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "fix-xray-certs.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_script_with_domain(self):
        """Тестируем через перехват Path — write_text/chmod на mock."""
        from chimera.modules import ssl_certbot
        captured_content = []

        def _fake_path(*args, **kwargs):
            p = Path(*args, **kwargs)
            if args and str(args[0]) == "/usr/local/bin/fix-xray-certs.sh":
                mock = MagicMock()
                mock.write_text = lambda content: captured_content.append(content)
                mock.chmod = lambda mode: None
                mock.__str__ = lambda: str(self._script)
                return mock
            return p

        with patch.object(ssl_certbot, "Path", side_effect=_fake_path):
            result = ssl_certbot.ensure_cert_fix_script("vpn.example.com")
        self.assertEqual(len(captured_content), 1)
        content = captured_content[0]
        self.assertIn("vpn.example.com", content)
        self.assertIn("DOMAIN=", content)

    def test_script_has_chmod_750(self):
        """Проверяем что chmod вызывается с 0o750."""
        from chimera.modules import ssl_certbot
        chmod_calls = []

        def _fake_path(*args, **kwargs):
            p = Path(*args, **kwargs)
            if args and str(args[0]) == "/usr/local/bin/fix-xray-certs.sh":
                mock = MagicMock()
                mock.write_text = lambda content: None
                mock.chmod = lambda mode: chmod_calls.append(mode)
                return mock
            return p

        with patch.object(ssl_certbot, "Path", side_effect=_fake_path):
            ssl_certbot.ensure_cert_fix_script("vpn.example.com")
        self.assertIn(0o750, chmod_calls)


# ─────────────────────────────────────────────────────────────────────────────
#  Хелперы для v3-тестов: фейковый core + рендер монитора в песочницу
# ─────────────────────────────────────────────────────────────────────────────
def _make_fake_core(crontab_stdout: str = "", crontab_rc: int = 1,
                    recorded: list | None = None):
    """Мок chimera._core: STATE_FILE вне песочницы, _run перехватывает crontab."""
    m = types.ModuleType("chimera._core")
    m.STATE_FILE = Path("/nonexistent-xray-state.json")

    def _success(msg):
        if recorded is not None:
            recorded.append(("success", msg))
    m.success = _success
    m.warn = lambda *a, **kw: None
    m.info = lambda *a, **kw: None

    def _fake_run(cmd, capture=False, check=False, quiet=False, input_text=None):
        if recorded is not None:
            recorded.append(("run", list(cmd), input_text))
        r = MagicMock()
        if list(cmd[:2]) == ["crontab", "-l"]:
            r.returncode = crontab_rc
            r.stdout = crontab_stdout
        else:
            r.returncode = 0
            r.stdout = ""
        return r
    m._run = _fake_run
    return m


def _render_monitor(tmpdir: Path, crontab_stdout: str = "", crontab_rc: int = 1,
                    recorded: list | None = None):
    """Вызывает _certbot_install_monitor_cron с путями в tmpdir.

    Возвращает (script_text, cron_text).
    """
    from chimera.modules import ssl_certbot
    script = tmpdir / "monitor.sh"
    cron = tmpdir / "cron.d"
    fake = _make_fake_core(crontab_stdout, crontab_rc, recorded)
    with patch.object(ssl_certbot, "_core_module", lambda: fake), \
         patch.object(ssl_certbot, "_CERTBOT_MONITOR_SCRIPT", script), \
         patch.object(ssl_certbot, "_CERTBOT_MONITOR_CRON", cron):
        ssl_certbot._certbot_install_monitor_cron()
    return script.read_text(), cron.read_text()


class TestMonitorV3Content(unittest.TestCase):
    """Контент сгенерированного v3-скрипта и cron-файла."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_shebang_at_byte_zero(self):
        """v2 деплоился с 8-пробельным сдвигом (dedent ломался о python-
        хердок на колонке 0) — шебанг обязан начинаться с байта 0."""
        script, _ = _render_monitor(self._tmpdir)
        self.assertTrue(script.startswith("#!/bin/bash\n"),
                        f"скрипт начинается с: {script[:40]!r}")
        self.assertNotIn("\n        #!/bin/bash", script)

    def test_lock_retry_present(self):
        """Ретраи при 'Another instance of Certbot is already running'."""
        script, _ = _render_monitor(self._tmpdir)
        self.assertIn('LOCK_RE="Another instance of Certbot is already running"', script)
        self.assertIn("sleep 60", script)
        self.assertIn("sleep 180", script)
        self.assertIn("sleep 300", script)
        self.assertIn("LOCK_TRY", script)

    def test_sanity_gate_present(self):
        """renew FAILED при валидном серте (>=14 дн.) не шлёт алерт."""
        script, _ = _render_monitor(self._tmpdir)
        self.assertIn("cert_days_left", script)
        self.assertIn("алерт не шлём", script)
        # sanity-порог = 14 дней (согласован с expire-warning)
        self.assertIn('"$DAYS" -ge 14', script)

    def test_log_uses_fresh_timestamp(self):
        """log() пишет время на момент строки, не замороженное $DATE."""
        script, _ = _render_monitor(self._tmpdir)
        self.assertIn("log() { echo \"[$(date '+%Y-%m-%d %H:%M:%S')] $1\" >> \"$LOG\"; }", script)
        self.assertNotIn("DATE=$(date", script)

    def test_cron_slot_0323(self):
        """Cron-слот 23 3,15 — вне top-of-hour зоны lock-гонок."""
        _, cron = _render_monitor(self._tmpdir)
        self.assertIn("23 3,15 * * * root", cron)
        self.assertNotIn("0 3,15", cron)

    def test_heredoc_at_column_zero(self):
        """python-хердок send_tg обязан остаться на колонке 0."""
        script, _ = _render_monitor(self._tmpdir)
        for ln in script.splitlines():
            if ln.lstrip().startswith("import json, socket"):
                self.assertEqual(ln, "import json, socket, subprocess, sys")
                break
        else:
            self.fail("python-хердок send_tg не найден в скрипте")

    def test_bash_and_dash_syntax(self):
        """bash -n (интерпретатор по шебангу) и sh -n (cron SHELL=/bin/sh)."""
        script, _ = _render_monitor(self._tmpdir)
        spath = self._tmpdir / "monitor.sh"
        for shell in ("bash", "sh"):
            r = subprocess.run([shell, "-n", str(spath)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0,
                             f"{shell} -n не прошёл: {r.stderr}")

    def test_legacy_crontab_cleanup_called_on_install(self):
        """Установка монитора вычищает legacy-строку из root crontab."""
        from chimera.modules import ssl_certbot
        recorded = []
        fake = _make_fake_core(_LEGACY_LINE + "\n0 5 * * * /other/job\n", 0, recorded)
        script = self._tmpdir / "m.sh"
        cron = self._tmpdir / "c"
        with patch.object(ssl_certbot, "_core_module", lambda: fake), \
             patch.object(ssl_certbot, "_CERTBOT_MONITOR_SCRIPT", script), \
             patch.object(ssl_certbot, "_CERTBOT_MONITOR_CRON", cron):
            ssl_certbot._certbot_install_monitor_cron()
        # crontab переустановлен без legacy-строки, вторая задача цела
        installs = [c for c in recorded
                    if c[0] == "run" and c[1][:2] == ["crontab", "-"]]
        self.assertEqual(len(installs), 1)
        self.assertNotIn(_LEGACY_LINE, installs[0][2])
        self.assertIn("0 5 * * * /other/job", installs[0][2])


class TestMonitorV3Functional(unittest.TestCase):
    """Функциональные прогоны v3-скрипта в песочнице.

    Реальный рендер + подмена путей (/var/log, /var/lib/xray-installer,
    /etc/letsencrypt/live) в tmpdir + stub-certbot с планом ответов.
    """

    DOMAIN = "func-test.example"

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._lib = self._tmpdir / "lib"                # /var/lib/xray-installer
        self._le = self._tmpdir / "le"                  # /etc/letsencrypt
        self._bin = self._tmpdir / "bin"                # PATH со stub-certbot
        self._lib.mkdir(parents=True)
        (self._le / "live").mkdir(parents=True)
        self._bin.mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_stub_certbot(self, plan: list[str]):
        """Stub-certbot: план ответов ('ok'/'lock'/'fail'), по одному на вызов;
        после исчерпания плана — 'ok' (чтобы тест не завис на ретраях)."""
        stub = self._bin / "certbot"
        stub.write_text(
            "#!/bin/bash\n"
            "PLAN='%s'\n"
            "N=$(cat '%s' 2>/dev/null || echo 0)\n"
            "N=$((N + 1)); echo $N > '%s'\n"
            "STEP=$(echo \"$PLAN\" | tr ' ' '\n' | sed -n \"${N}p\")\n"
            "[ -z \"$STEP\" ] && STEP=ok\n"
            "case \"$STEP\" in\n"
            "  ok) exit 0;;\n"
            "  lock) echo 'Another instance of Certbot is already running.' >&2; exit 1;;\n"
            "  fail) echo 'Some unexpected certbot error' >&2; exit 1;;\n"
            "esac\n" % (" ".join(plan), self._tmpdir / "calls",
                        self._tmpdir / "calls"))
        stub.chmod(0o755)

    def _make_cert(self, days: int):
        d = self._le / "live" / self.DOMAIN
        d.mkdir(parents=True, exist_ok=True)
        key = self._tmpdir / "key.pem"
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(d / "fullchain.pem"),
             "-days", str(days), "-subj", f"/CN={self.DOMAIN}"],
            capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def _sandboxify(self, script: str) -> Path:
        """Подменяет системные пути на tmpdir и кладёт state.json."""
        (self._lib / "state.json").write_text(json.dumps({"domain": self.DOMAIN}))
        s = script.replace("/var/log/xray-certbot-monitor.log",
                           str(self._tmpdir / "monitor.log"))
        s = s.replace("/var/lib/xray-installer", str(self._lib))
        s = s.replace("/etc/letsencrypt/live", str(self._le / "live"))
        # ретраи: секунды -> доли секунды (логика та же, тест не висит)
        s = s.replace("sleep 60", "sleep 0.2").replace("sleep 180", "sleep 0.2")
        s = s.replace("sleep 300", "sleep 0.2")
        p = self._tmpdir / "sandboxed-monitor.sh"
        p.write_text(s)
        p.chmod(0o750)
        return p

    def _run_monitor(self, p: Path):
        env = dict(os.environ)
        env["PATH"] = f"{self._bin}:{env.get('PATH', '')}"
        r = subprocess.run(["bash", str(p)], capture_output=True, text=True,
                           timeout=180, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return (self._tmpdir / "monitor.log").read_text()

    def test_ok_path(self):
        """Renew OK + валидный серт: лог OK, стампы вычищены."""
        script, _ = _render_monitor(self._tmpdir)
        self._make_stub_certbot(["ok"])
        self._make_cert(days=88)
        log = self._run_monitor(self._sandboxify(script))
        self.assertIn("certbot renew OK", log)
        self.assertIn("SSL days left:", log)
        self.assertNotIn("FAILED", log)
        self.assertFalse((self._lib / "cert-renew-fail.stamp").exists())

    def test_lock_race_retried_to_success(self):
        """Сценарий инцидента 04.10: два lock-фейла -> ретрай -> OK."""
        script, _ = _render_monitor(self._tmpdir)
        self._make_stub_certbot(["lock", "lock", "ok"])
        self._make_cert(days=88)
        log = self._run_monitor(self._sandboxify(script))
        self.assertIn("Another instance of Certbot is already running.", log)
        self.assertIn("certbot lock busy — ретрай 1/3", log)
        self.assertIn("certbot lock busy — ретрай 2/3", log)
        self.assertIn("certbot renew OK", log)
        self.assertFalse((self._lib / "cert-renew-fail.stamp").exists())

    def test_sanity_gate_silent_on_valid_cert(self):
        """Главный фикс: renew FAILED (не lock) при валидном серте 88 дн. —
        алерт НЕ шлётся, стамп не пишется, в логе объяснение."""
        script, _ = _render_monitor(self._tmpdir)
        self._make_stub_certbot(["fail"])
        self._make_cert(days=88)
        log = self._run_monitor(self._sandboxify(script))
        self.assertIn("certbot renew FAILED, но сертификат валиден ещё", log)
        self.assertIn("алерт не шлём", log)
        self.assertFalse((self._lib / "cert-renew-fail.stamp").exists())

    def test_alert_when_no_cert(self):
        """Renew FAILED и серта нет — алертная ветка: стамп дня записан."""
        script, _ = _render_monitor(self._tmpdir)
        self._make_stub_certbot(["fail"])
        # серт не создаём
        log = self._run_monitor(self._sandboxify(script))
        self.assertIn("certbot renew FAILED (сертификат: не найден)", log)
        self.assertTrue((self._lib / "cert-renew-fail.stamp").exists())

    def test_lock_exhaustion_with_valid_cert_stays_silent(self):
        """Все 3 ретрая исчерпаны, серт валиден — молчим (транзиент)."""
        script, _ = _render_monitor(self._tmpdir)
        self._make_stub_certbot(["lock", "lock", "lock", "lock"])
        self._make_cert(days=88)
        log = self._run_monitor(self._sandboxify(script))
        self.assertIn("ретрай 3/3", log)
        self.assertIn("certbot renew FAILED, но сертификат валиден ещё", log)
        self.assertFalse((self._lib / "cert-renew-fail.stamp").exists())


class TestRemoveLegacyCrontab(unittest.TestCase):
    """_remove_legacy_certbot_crontab — точечная чистка legacy-строки."""

    def _call(self, crontab_stdout: str, crontab_rc: int = 0):
        from chimera.modules import ssl_certbot
        recorded = []
        fake = _make_fake_core(crontab_stdout, crontab_rc, recorded)
        with patch.object(ssl_certbot, "_core_module", lambda: fake):
            removed = ssl_certbot._remove_legacy_certbot_crontab()
        return removed, recorded

    def test_removes_exact_line_keeps_others(self):
        cron = "# my jobs\n" + _LEGACY_LINE + "\n0 5 * * * /backup.sh\n"
        removed, recorded = self._call(cron)
        self.assertTrue(removed)
        installs = [c for c in recorded
                    if c[0] == "run" and c[1][:2] == ["crontab", "-"]]
        self.assertEqual(len(installs), 1)
        new_tab = installs[0][2]
        self.assertNotIn(_LEGACY_LINE, new_tab)
        self.assertIn("0 5 * * * /backup.sh", new_tab)
        self.assertIn("# my jobs", new_tab)
        # crontab -r не звался — осталось содержимое
        self.assertFalse(any(c[0] == "run" and c[1][:2] == ["crontab", "-r"]
                             for c in recorded))

    def test_only_legacy_line_removes_crontab_entirely(self):
        removed, recorded = self._call(_LEGACY_LINE + "\n")
        self.assertTrue(removed)
        self.assertTrue(any(c[0] == "run" and c[1][:2] == ["crontab", "-r"]
                            for c in recorded))

    def test_noop_when_absent(self):
        removed, recorded = self._call("0 5 * * * /backup.sh\n")
        self.assertFalse(removed)
        self.assertFalse(any(c[0] == "run" and c[1][:2] in (["crontab", "-"], ["crontab", "-r"])
                             for c in recorded))

    def test_noop_when_crontab_unreadable(self):
        removed, recorded = self._call("", crontab_rc=1)
        self.assertFalse(removed)
        self.assertFalse(any(c[0] == "run" and c[1][:2] in (["crontab", "-"], ["crontab", "-r"])
                             for c in recorded))

    def test_similar_but_different_line_untouched(self):
        """Похожая строка с другим временем/флагами не трогается."""
        similar = "0 5 * * * certbot renew --quiet --no-random-sleep-on-renew\n"
        removed, recorded = self._call(similar)
        self.assertFalse(removed)
        self.assertFalse(any(c[0] == "run" and c[1][:2] == ["crontab", "-"]
                             for c in recorded))


class TestSetupCertRenewalNoLegacy(unittest.TestCase):
    """setup_cert_renewal больше не добавляет legacy-строку в crontab."""

    def test_no_legacy_install_and_cleanup_called(self):
        from chimera.modules import ssl_certbot
        recorded = []
        fake = _make_fake_core("", 1, recorded)
        fake.PROTOCOL_MODE = "vless"
        fake.PARAM_DOMAIN = "vpn.example.com"
        tmpdir = Path(tempfile.mkdtemp())
        try:
            with patch.object(ssl_certbot, "_core_module", lambda: fake), \
                 patch.object(ssl_certbot, "Path",
                              side_effect=lambda *a, **kw:
                              tmpdir / ("p" + str(abs(hash(str(a[0]))) % 10**9))
                              if a and str(a[0]).startswith("/etc/letsencrypt")
                              else Path(*a, **kw)), \
                 patch.object(ssl_certbot, "_remove_legacy_certbot_crontab",
                              return_value=False) as mock_cleanup:
                ssl_certbot.setup_cert_renewal()
            mock_cleanup.assert_called_once()
            installs = [c for c in recorded
                        if c[0] == "run" and c[1][:2] == ["crontab", "-"]]
            self.assertEqual(installs, [],
                             "setup_cert_renewal не должен ставить crontab")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
