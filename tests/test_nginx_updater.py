#!/usr/bin/env python3
"""Тесты для chimera.modules.nginx_updater (меню 1 → 5f + хук установки).

Волна 19.11 (nginx-марафон по флоту, CVE-2026-123633/123007 HTTP/2 RCE):
модуль переводит дефолтный дистрибутивный nginx на свежую сборку nginx.org
с Chimera-гардами. Проверенный скелет — флотовый /root/nginx-upgrade.sh.

Покрывает:
  версии: parse_version (distro-суффиксы), is_fixed_version (пол 1.30.7 /
    1.31.9 / ≥1.32), current_nginx_version через мок _run;
  гард: include sites-enabled вставляется в nginx.org-конфиг, user nginx →
    www-data, logrotate create 640 www-data adm; уже-правильный конфиг —
    «на месте» без перезаписи;
  флоу nginx_upgrade (stateful-мок _run): happy path 1.24.0 → 1.30.7 с
    гардами и restart; уже свежее кандидата → no-op; кандидат без CVE-фикса
    → отказ ДО изменений; симуляция с неожидаемыми удалениями → отказ;
    провал nginx -t после установки → роллбек конфигов из tar + restart;
    расхождение listen/server_name → роллбек; не-root → отказ; не
    Debian/Ubuntu → отказ;
  хук offer_upgrade_after_install: уязвимый nginx → вопрос и апгрейд по Y;
    фиксованый → тихий no-op (input не зовётся); отказ n → подсказка меню;
    EOF → тихо; исключение внутри → установка не роняется;
  врезка 5f в _menu_install_system (_core.py): рендер + диспетчер.
"""
from __future__ import annotations

import io
import sys
import types
import unittest
from contextlib import redirect_stdout
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
        # info/warn печатают: хук-тесты ассертят на человекочитаемые строки
        fake_core.info = lambda msg, *a, **kw: print(str(msg))
        fake_core.warns: list = []

        def _warn(msg, *a, **kw):
            fake_core.warns.append(str(msg))
            print(str(msg))

        fake_core.warn = _warn
        fake_core.success = lambda msg, *a, **kw: print(str(msg))
        fake_core.log_to_file = lambda *a, **kw: None
        fake_core.find_nginx_bin = lambda: "/usr/sbin/nginx"
        for _c in ("CYAN", "NC", "DIM", "GREEN", "RED", "BOLD", "BLUE",
                   "YELLOW", "WHITE", "TITLE"):
            setattr(fake_core, _c, "")
        fake_core._box_top = lambda title="": print(title)
        fake_core._box_row = lambda text="": print(text if text else "")
        fake_core._box_sep = lambda: print()
        fake_core._box_item = lambda key, label: print(label)
        fake_core._box_back = lambda: print()
        fake_core._box_bottom = lambda: print()
        sys.modules["chimera._core"] = fake_core
    return sys.modules["chimera._core"]


# ── Версии ───────────────────────────────────────────────────────────────────

class TestVersionLogic(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import nginx_updater
        self.nu = nginx_updater

    def test_parse_version(self):
        pv = self.nu.parse_version
        self.assertEqual(pv("nginx version: nginx/1.30.7"), (1, 30, 7))
        self.assertEqual(pv("1.24.0-2ubuntu7.19"), (1, 24, 0))
        self.assertEqual(pv("1.31.9-1~noble"), (1, 31, 9))
        self.assertIsNone(pv(""))
        self.assertIsNone(pv("нет версии тут"))

    def test_is_fixed_version_cve_floor(self):
        """Пол CVE-2026-123633/123007: stable 1.30.7+, mainline 1.31.9+,
        всё ≥ 1.32.0; ниже — уязвимо."""
        fx = self.nu.is_fixed_version
        self.assertTrue(fx((1, 30, 7)))
        self.assertTrue(fx((1, 30, 8)))
        self.assertTrue(fx((1, 31, 9)))
        self.assertTrue(fx((1, 32, 0)))
        self.assertTrue(fx((2, 0, 0)))
        self.assertFalse(fx((1, 30, 6)))
        self.assertFalse(fx((1, 31, 8)))
        self.assertFalse(fx((1, 24, 0)))
        self.assertFalse(fx((1, 18, 0)))
        self.assertFalse(fx(None))

    def test_current_nginx_version_via_run(self):
        fake_core = _setup_core_in_sysmodules()
        fake_core._run = MagicMock(return_value=SimpleNamespace(
            returncode=0, stderr="nginx version: nginx/1.26.2", stdout=""))
        self.assertEqual(self.nu.current_nginx_version(), (1, 26, 2))

    def test_current_nginx_version_error(self):
        fake_core = _setup_core_in_sysmodules()
        fake_core._run = MagicMock(side_effect=RuntimeError("no exec"))
        self.assertIsNone(self.nu.current_nginx_version())


# ── Гард конфига (мины 1-3) ──────────────────────────────────────────────────

_NGINXORG_CONF = """\
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    include /etc/nginx/conf.d/*.conf;
}
"""

_DEBIAN_CONF = """\
user www-data;
worker_processes auto;

http {
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""


class TestChimeraGuard(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import nginx_updater
        self.nu = nginx_updater
        import tempfile
        self._tmpdir = Path(tempfile.mkdtemp())
        # пути гарда → tmp
        self._conf = self._tmpdir / "nginx.conf"
        self._logrotate = self._tmpdir / "logrotate-nginx"
        self._patch_c = patch.object(self.nu, "_NGINX_CONF", self._conf)
        self._patch_l = patch.object(self.nu, "_LOGROTATE_NGINX",
                                     self._logrotate)
        self._patch_c.start()
        self._patch_l.start()

    def tearDown(self):
        self._patch_c.stop()
        self._patch_l.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_nginxorg_conf_repaired(self):
        """Мина 1-2: nginx.org-конфиг без sites-enabled и с user nginx —
        гард возвращает include и www-data."""
        self._conf.write_text(_NGINXORG_CONF)
        applied = self.nu._guard_nginx_conf()
        text = self._conf.read_text()
        self.assertIn("include /etc/nginx/sites-enabled/*;", text)
        self.assertRegex(text, r"^user\s+www-data;", )
        self.assertTrue(any("include sites-enabled" in a for a in applied))
        self.assertTrue(any("user www-data: восстановлен" in a
                            for a in applied))

    def test_debian_conf_untouched(self):
        """Уже-правильный Debian-конфиг — «на месте», без перезаписи."""
        self._conf.write_text(_DEBIAN_CONF)
        before = self._conf.read_text()
        applied = self.nu._guard_nginx_conf()
        self.assertEqual(self._conf.read_text(), before)
        self.assertTrue(any("на месте" in a for a in applied))

    def test_logrotate_owner_fixed(self):
        """Мина 3: create 640 nginx adm → create 640 www-data adm."""
        self._conf.write_text(_DEBIAN_CONF)
        self._logrotate.write_text(
            "/var/log/nginx/*.log {\n    daily\n    create 640 nginx adm\n}\n")
        self.nu._guard_nginx_conf()
        self.assertIn("create 640 www-data adm", self._logrotate.read_text())
        self.assertNotIn("create 640 nginx adm", self._logrotate.read_text())

    def test_no_conf_reports_nothing_crashes(self):
        """nginx.conf отсутствует — гард не падает (отчёт с «упал»)."""
        applied = self.nu._guard_nginx_conf()
        self.assertIsInstance(applied, list)


# ── Флоу nginx_upgrade (stateful-мок _run) ───────────────────────────────────

_DUMP = """\
# configuration file /etc/nginx/nginx.conf:
http {
    server {
        listen 80;
        server_name example.com;
    }
    server {
        listen 443 ssl http2;
        server_name example.com;
    }
}
"""


class _UpgradeBase(unittest.TestCase):
    """База: фейковый core с stateful-диспетчером _run + tmp-пути."""

    INSTALLED = "1.24.0"     # что стоит «в системе»
    CANDIDATE = "1.30.7-1~noble"
    SIM_REMOVALS = ""        # вывод Remv-строк симуляции apt

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        import tempfile
        self._tmpdir = Path(tempfile.mkdtemp())
        from chimera.modules import nginx_updater
        self.nu = nginx_updater
        # состояние «системы»
        self._installed = self.INSTALLED
        self._nginx_t_rc = 0            # rc nginx -t
        self._after_count_diff = False  # портить ли число listen/server_name
        self._restart_rc = 0
        self._commands = []             # журнал вызовов _run
        self._fake_core._run = MagicMock(side_effect=self._dispatch)
        # раннеры CI — не root: для флоу-тестов считаем себя root'ом
        # (test_not_root_refused перекрывает своим патчем)
        self._patches = [
            patch("os.geteuid", return_value=0),
            patch.object(self.nu, "_NGINX_ORG_LIST",
                         self._tmpdir / "nginx.list"),
            patch.object(self.nu, "_NGINX_PIN_FILE",
                         self._tmpdir / "99nginx"),
            patch.object(self.nu, "_NGINX_CONF", self._tmpdir / "nginx.conf"),
            patch.object(self.nu, "_LOGROTATE_NGINX",
                         self._tmpdir / "logrotate"),
            patch.object(self.nu, "_backup_dir",
                         lambda ts: self._tmpdir / f"backup-{ts}"),
            patch.object(self.nu, "_os_release_fields",
                         lambda: {"ID": "ubuntu",
                                  "VERSION_CODENAME": "noble"}),
        ]
        for p in self._patches:
            p.start()
        # «живой» nginx.conf для гарда
        (self._tmpdir / "nginx.conf").write_text(_NGINXORG_CONF)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── stateful диспетчер ─────────────────────────────────────────────
    def _dispatch(self, args, **kwargs):
        self._commands.append(list(args))
        a = args
        if a and a[1:2] == ["-v"]:
            return SimpleNamespace(
                returncode=0,
                stderr=f"nginx version: nginx/{self._installed}", stdout="")
        if a and a[1:2] == ["-t"]:
            return SimpleNamespace(returncode=self._nginx_t_rc,
                                   stderr="" if not self._nginx_t_rc
                                   else "nginx: [emerg] broken", stdout="")
        if a and a[1:2] == ["-T"]:
            dump = _DUMP
            if self._after_count_diff and self._installed != self.INSTALLED:
                dump = _DUMP.replace("    listen 443 ssl http2;\n", "")
            return SimpleNamespace(returncode=0, stderr="", stdout=dump)
        if a[:2] == ["apt-cache", "policy"]:
            return SimpleNamespace(
                returncode=0, stderr="", stdout=(
                    "nginx:\n"
                    f"  Installed: {self._installed}-2ubuntu7.19\n"
                    f"  Candidate: {self.CANDIDATE}\n"
                    "  *** /var/lib/dpkg/status\n    100 1.24.0-2ubuntu7.19\n"
                    "     https://nginx.org/packages/ubuntu noble/nginx "
                    "amd64 Packages\n"))
        if a[:1] == ["tar"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if a[:1] == ["ss"]:
            return SimpleNamespace(
                returncode=0, stderr="",
                stdout="LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n")
        if a[:2] == ["apt-get", "-s"]:
            return SimpleNamespace(returncode=0, stderr="",
                                   stdout=self.SIM_REMOVALS)
        if a[:2] == ["apt-get", "install"]:
            if "nginx" in a and "-s" not in a:
                self._installed = self.CANDIDATE.split("-")[0]
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if a[:1] == ["systemctl"]:
            if "restart" in a:
                return SimpleNamespace(returncode=self._restart_rc,
                                       stderr="", stdout="")
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if a[:1] == ["bash"]:
            if "pgrep" in " ".join(a):
                return SimpleNamespace(
                    returncode=0, stderr="",
                    stdout="/usr/sbin/nginx")   # без «(deleted)»
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")


class TestNginxUpgradeFlow(_UpgradeBase):

    def test_happy_path(self):
        """1.24.0 (distro, уязвимый) → 1.30.7 (nginx.org): ok, upgraded,
        гард починил конфиг, restart выполнен, репо-файлы записаны."""
        res = self.nu.nginx_upgrade(apply=True)
        self.assertTrue(res["ok"], res["report"])
        self.assertTrue(res["upgraded"])
        self.assertEqual(res["before"], "1.24.0")
        self.assertEqual(res["after"], "1.30.7")
        self.assertTrue(res["restarted"])
        # репо nginx.org записано (tmp-пути)
        self.assertIn("nginx.org", (self._tmpdir / "nginx.list").read_text())
        self.assertIn("900", (self._tmpdir / "99nginx").read_text())
        # гард починил конфиг
        conf = (self._tmpdir / "nginx.conf").read_text()
        self.assertIn("sites-enabled", conf)
        self.assertRegex(conf, r"^user\s+www-data;")
        # бэкап-каталог создан
        backup = Path(res["backup"])
        self.assertTrue(backup.exists())
        # systemctl restart nginx был
        self.assertIn(["systemctl", "restart", "nginx"], self._commands)
        # гварды в отчёте
        self.assertTrue(any("гард:" in r for r in res["report"]))

    def test_already_fresh_is_noop(self):
        """Установлено 1.30.7 = кандидат → upgraded=False, apt install не
        выполнялся."""
        self._installed = "1.30.7"
        res = self.nu.nginx_upgrade(apply=True)
        self.assertTrue(res["ok"])
        self.assertFalse(res["upgraded"])
        self.assertFalse(any(a[:2] == ["apt-get", "install"]
                             and "nginx" in a and "-o" in a
                             for a in self._commands))

    def test_dry_run_touches_nothing(self):
        res = self.nu.nginx_upgrade(apply=False)
        self.assertTrue(res["ok"])
        self.assertFalse(res["upgraded"])
        self.assertIn("DRY-RUN", res["report"][0])
        self.assertFalse((self._tmpdir / "nginx.list").exists())
        self.assertFalse(any(a[:1] == ["tar"] for a in self._commands))

    def test_candidate_without_cve_refused(self):
        """Кандидат ниже CVE-пола → отказ ДО каких-либо изменений системы."""
        self.CANDIDATE = "1.24.0-2ubuntu7.20"
        self._tmpdir.joinpath  # noqa: B018 (читаемость)
        res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("CVE" in r or "без CVE-фикса" in r
                            for r in res["report"]))
        self.assertFalse((self._tmpdir / "nginx.list").exists())

    def test_unexpected_removals_refused(self):
        """Симуляция apt показывает удаление нестандартного пакета —
        отказ до изменений."""
        self.SIM_REMOVALS = ("Remv nginx-common [1.24.0]\n"
                             "Remv certbot-nginx [2.9]\n")
        res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("нестандартные пакеты" in r or "certbot-nginx" in r
                            for r in res["report"]))
        # реальная установка не стартовала (только -s симуляция)
        self.assertFalse(any(a[:2] == ["apt-get", "install"]
                             and "nginx" in a and "-s" not in a
                             and "-o" in a for a in self._commands))

    def test_nginx_t_fail_after_install_rolls_back(self):
        """nginx -t падает ПОСЛЕ установки → конфиги откатываются из tar,
        restart, ok=False (рука марафона: die «конфиг невалиден»)."""
        def _t_fail_on_new(args, **kw):
            r = self._dispatch(args, **kw)
            if args[1:2] == ["-t"] and self._installed != self.INSTALLED:
                return SimpleNamespace(returncode=1,
                                       stderr="nginx: [emerg] broken",
                                       stdout="")
            return r
        self._fake_core._run = MagicMock(side_effect=_t_fail_on_new)
        res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("nginx -t" in r and "провалился" in r
                            for r in res["report"]))
        # tar-откат конфигов был
        self.assertTrue(any(a[:1] == ["tar"] and "-xzf" in a
                            for a in self._commands))
        # restart после отката был
        self.assertIn(["systemctl", "restart", "nginx"], self._commands)

    def test_listen_count_diff_rolls_back(self):
        """Число listen/server_name «после» ≠ «до» (сайт выпал) → откат."""
        self._after_count_diff = True
        res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("listen/server_name" in r for r in res["report"]))
        self.assertTrue(any(a[:1] == ["tar"] and "-xzf" in a
                            for a in self._commands))

    def test_not_root_refused(self):
        with patch("os.geteuid", return_value=1000):
            res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("root" in r for r in res["report"]))

    def test_not_debian_refused(self):
        with patch.object(self.nu, "_os_release_fields",
                          lambda: {"ID": "almalinux"}):
            res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("Debian/Ubuntu" in r for r in res["report"]))

    def test_broken_current_config_refused(self):
        """Уже сломанный nginx -t «до» — апгрейд не начинается (не с чем
        сравнивать «после»)."""
        self._nginx_t_rc = 1
        res = self.nu.nginx_upgrade(apply=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("уже невалиден" in r for r in res["report"]))


# ── Хук конца установки ──────────────────────────────────────────────────────

class TestOfferUpgradeAfterInstall(unittest.TestCase):

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        from chimera.modules import nginx_updater
        self.nu = nginx_updater
        self._upgrade_calls = []
        self._patch_u = patch.object(
            self.nu, "nginx_upgrade",
            side_effect=lambda apply=True: self._upgrade_calls.append(apply)
            or {"ok": True, "upgraded": True, "before": "1.24.0",
                "after": "1.30.7", "report": ["Готово: 1.24.0 → 1.30.7"],
                "warnings": []})
        self._patch_u.start()

    def tearDown(self):
        self._patch_u.stop()

    def _version(self, ver):
        return patch.object(self.nu, "current_nginx_version",
                            lambda: ver)

    def test_vulnerable_nginx_prompts_and_yes_upgrades(self):
        """Дефолтный 1.24.0 → вопрос, Y → nginx_upgrade(apply=True)."""
        with self._version((1, 24, 0)), \
             patch("os.geteuid", return_value=0), \
             patch("builtins.input", return_value="Y"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.nu.offer_upgrade_after_install()
        self.assertEqual(self._upgrade_calls, [True])
        self.assertIn("CVE", buf.getvalue())

    def test_fixed_nginx_silent_noop(self):
        """1.30.7 (переустановка поверх живой ноды) → ни вопроса, ни вызова:
        install-флоу не меняется ни байтом."""
        with self._version((1, 30, 7)), \
             patch("os.geteuid", return_value=0), \
             patch("builtins.input",
                   side_effect=AssertionError("input не должен зваться")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.nu.offer_upgrade_after_install()
        self.assertEqual(self._upgrade_calls, [])
        self.assertEqual(buf.getvalue(), "")

    def test_no_nginx_silent_noop(self):
        with self._version(None), patch("os.geteuid", return_value=0):
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.nu.offer_upgrade_after_install()
        self.assertEqual(self._upgrade_calls, [])

    def test_decline_n_mentions_menu(self):
        with self._version((1, 24, 0)), \
             patch("os.geteuid", return_value=0), \
             patch("builtins.input", return_value="n"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.nu.offer_upgrade_after_install()
        self.assertEqual(self._upgrade_calls, [])
        self.assertIn("5f", buf.getvalue())

    def test_eof_silent(self):
        with self._version((1, 24, 0)), \
             patch("os.geteuid", return_value=0), \
             patch("builtins.input", side_effect=EOFError):
            self.nu.offer_upgrade_after_install()  # не падает
        self.assertEqual(self._upgrade_calls, [])

    def test_not_root_silent(self):
        with self._version((1, 24, 0)), \
             patch("os.geteuid", return_value=1000), \
             patch("builtins.input",
                   side_effect=AssertionError("input не должен зваться")):
            self.nu.offer_upgrade_after_install()
        self.assertEqual(self._upgrade_calls, [])

    def test_exception_never_crashes(self):
        """Исключение внутри хука проглатывается (установка важнее)."""
        with patch.object(self.nu, "current_nginx_version",
                          side_effect=RuntimeError("boom")):
            self.nu.offer_upgrade_after_install()  # не падает
        self.assertEqual(self._upgrade_calls, [])


# ── Врезка 5f в меню (_core.py) ──────────────────────────────────────────────

class TestMenuWiring5f(unittest.TestCase):

    def setUp(self):
        self._saved_core = sys.modules.get("chimera._core")
        self._saved_nu = sys.modules.get("chimera.modules.nginx_updater")
        sys.modules.pop("chimera.modules.nginx_updater", None)
        import importlib
        real_nu = importlib.import_module("chimera.modules.nginx_updater")
        self._calls = []
        self._patcher = patch.object(
            real_nu, "do_nginx_upgrade_interactive",
            lambda: self._calls.append("5f"))
        self._patcher.start()

        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        src = core_path.read_text()
        fake_core = types.ModuleType("chimera._core")
        sys.modules["chimera._core"] = fake_core
        with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'touch', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch('os.chown', lambda *a, **kw: None), \
             patch('os.geteuid', return_value=0):
            exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
        self.core = fake_core

    def tearDown(self):
        self._patcher.stop()
        if self._saved_core is None:
            sys.modules.pop("chimera._core", None)
        else:
            sys.modules["chimera._core"] = self._saved_core
        if self._saved_nu is None:
            sys.modules.pop("chimera.modules.nginx_updater", None)
        else:
            sys.modules["chimera.modules.nginx_updater"] = self._saved_nu

    def test_menu_renders_5f_item(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("5f"', src)
        self.assertIn("Обновить nginx", src)

    def test_menu_dispatches_5f(self):
        buf = io.StringIO()
        with patch("builtins.input", side_effect=["5f", "", "q"]), \
             redirect_stdout(buf):
            self.core._menu_install_system()
        self.assertEqual(self._calls, ["5f"])
        self.assertIn("Обновить nginx", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
