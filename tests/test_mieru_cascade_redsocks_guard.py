"""Unit-тесты redsocks-guard mieru_cascade (инцидент DNS 2026-10-03).

Root cause инцидента на ноде 203.0.113.103: debian-пакет redsocks
(зависимость каскада) ships дефолтный /etc/redsocks.conf с блоком dnstc —
fake-DNS сервером на 127.0.0.1:5300 (порт dnscrypt-proxy, upstream AGH),
и включает system redsocks.service в автозагрузку. После ребута сервисы
стартуют гонкой: redsocks занял :5300 → dnscrypt-proxy crash-loop
(exit 255, bind: address already in use, 3.8k рестартов) → DNS ноды мёртв.

Контракт фикса:
  • _redsocks_comment_dnstc — оборачивает dnstc-блок в C-комментарий,
    остальной конфиг байт-в-байт; идемпотентен (маркер-гвардр);
  • _neutralize_system_redsocks — stop/disable/reset-failed ТОЛЬКО
    plain redsocks.service (не mieru-cascade-redsocks@*), патчит конфиг;
  • _install_redsocks — вызывает нейтрализацию в ОБОИХ ветках
    (свежая установка и уже установленный пакет: мина могла быть
    взведена раньше и ждать ребута).
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from chimera.modules import mieru_cascade

# Дефолтный /etc/redsocks.conf debian-пакета redsocks 0.5-2build4 —
# дословно как на нодах флота (инцидент 2026-10-03)
DEBIAN_DEFAULT = """base {
\tlog = "syslog:daemon";
\tdaemon = on;
\tredirector = iptables;
}
redsocks {
\tlocal_ip = 127.0.0.1;
\tlocal_port = 12345;
\tip = 127.0.0.1;
\tport = 1080;
\ttype = socks5;
}
redudp {
\tlocal_ip = 127.0.0.1;
\tlocal_port = 10053;
\tdest_ip = 192.0.2.2;
\tdest_port = 53;
}
dnstc {
\t// fake and really dumb DNS server that returns "truncated answer" to
\t// every query via UDP, RFC-compliant resolver should repeat same query
\t// via TCP in this case.
\tlocal_ip = 127.0.0.1;
\tlocal_port = 5300;
}
// you can add more `redsocks' and `redudp' sections if you need.
"""


class TestRedsocksCommentDnstc(unittest.TestCase):
    """Чистая функция патча конфига."""

    def test_debian_default_dnstc_commented(self):
        out = mieru_cascade._redsocks_comment_dnstc(DEBIAN_DEFAULT)
        # dnstc-блок обёрнут в C-комментарий с маркером
        self.assertIn("/* chimera: dnstc disabled", out)
        # закрытие комментария после блока
        self.assertIn("*/", out)
        # сам блок остался на месте (внутри комментария)
        self.assertIn("dnstc {", out)
        self.assertIn("local_port = 5300;", out)

    def test_other_blocks_untouched(self):
        out = mieru_cascade._redsocks_comment_dnstc(DEBIAN_DEFAULT)
        # redsocks/redudp/base — байт-в-байт
        self.assertIn("redsocks {", out)
        self.assertIn("\tlocal_port = 12345;", out)
        self.assertIn("redudp {", out)
        self.assertIn("\tlocal_port = 10053;", out)
        # до dnstc-блока текст не менялся
        idx_redudp = out.index("redudp {")
        idx_marker = out.index("/* chimera: dnstc disabled")
        self.assertLess(idx_redudp, idx_marker)
        self.assertEqual(out[:idx_redudp], DEBIAN_DEFAULT[:idx_redudp])

    def test_idempotent_marker_guard(self):
        """Повторный вызов на уже пропатченном тексте — без изменений.

        C-комментарии НЕ вкладываются: повторный wrap закрыл бы
        блок на первом */ и раскомментировал dnstc обратно.
        """
        once = mieru_cascade._redsocks_comment_dnstc(DEBIAN_DEFAULT)
        twice = mieru_cascade._redsocks_comment_dnstc(once)
        self.assertEqual(once, twice)

    def test_idempotent_neutralizer_level(self):
        """_neutralize_system_redsocks не переписывает файл дважды."""
        with tempfile.TemporaryDirectory() as td:
            conf = Path(td) / "redsocks.conf"
            conf.write_text(DEBIAN_DEFAULT, encoding="utf-8")
            with patch.object(mieru_cascade, "_REDSOCKS_CONF", conf), \
                 patch.object(mieru_cascade, "shutil") as msh, \
                 patch.object(mieru_cascade, "_run") as mrun:
                msh.which.return_value = None
                mieru_cascade._neutralize_system_redsocks()
            first = conf.read_text(encoding="utf-8")
            mtime1 = conf.stat().st_mtime_ns
            with patch.object(mieru_cascade, "_REDSOCKS_CONF", conf), \
                 patch.object(mieru_cascade, "shutil") as msh, \
                 patch.object(mieru_cascade, "_run") as mrun:
                msh.which.return_value = None
                mieru_cascade._neutralize_system_redsocks()
            second = conf.read_text(encoding="utf-8")
            self.assertEqual(first, second)
            self.assertIn("/* chimera: dnstc disabled", first)

    def test_no_dnstc_untouched(self):
        """Конфиг без dnstc — текст без изменений."""
        text = DEBIAN_DEFAULT.replace("dnstc {", "redsocks2 {")
        self.assertEqual(mieru_cascade._redsocks_comment_dnstc(text), text)

    def test_one_liner_block(self):
        """Однострочный dnstc { ... } тоже оборачивается."""
        text = "redsocks {\n}\ndnstc { local_port = 5300; }\n"
        out = mieru_cascade._redsocks_comment_dnstc(text)
        self.assertIn("/* chimera: dnstc disabled", out)
        self.assertIn("*/", out)
        # однострочник не сломал остальной конфиг
        self.assertTrue(out.startswith("redsocks {"))


class TestNeutralizeSystemRedsocks(unittest.TestCase):
    """Системный юнит + конфиг: действия только по plain redsocks.service."""

    def test_service_actions_plain_unit_only(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

        with patch.object(mieru_cascade, "_run", side_effect=fake_run), \
             patch.object(mieru_cascade, "shutil") as msh:
            msh.which.return_value = "/usr/bin/systemctl"
            ok = mieru_cascade._neutralize_system_redsocks()
        self.assertTrue(ok)
        # все команды — тройки systemctl <verb> redsocks.service
        unit_cmds = [c for c in calls if isinstance(c, list) and len(c) == 3
                     and c[0] == "systemctl" and c[2] == "redsocks.service"]
        self.assertEqual(len(unit_cmds), 3, f"expected 3, got {calls}")
        verbs = {c[1] for c in unit_cmds}
        self.assertEqual(verbs, {"stop", "disable", "reset-failed"})
        # НИ ОДИН вызов не касается @-шаблонов каскада
        for c in calls:
            joined = " ".join(str(x) for x in c)
            self.assertNotIn("mieru-cascade-redsocks@", joined)

    def test_missing_conf_no_crash(self):
        """/etc/redsocks.conf отсутствует — тихо, без исключения."""
        with tempfile.TemporaryDirectory() as td:
            ghost = Path(td) / "redsocks.conf"
            with patch.object(mieru_cascade, "_REDSOCKS_CONF", ghost), \
                 patch.object(mieru_cascade, "shutil") as msh, \
                 patch.object(mieru_cascade, "_run") as mrun:
                msh.which.return_value = None
                self.assertTrue(mieru_cascade._neutralize_system_redsocks())
            self.assertFalse(ghost.exists())
            mrun.assert_not_called()

    def test_no_systemctl_available(self):
        """Без systemctl (контейнер) — только патч конфига, без _run."""
        with tempfile.TemporaryDirectory() as td:
            conf = Path(td) / "redsocks.conf"
            conf.write_text(DEBIAN_DEFAULT, encoding="utf-8")
            with patch.object(mieru_cascade, "_REDSOCKS_CONF", conf), \
                 patch.object(mieru_cascade, "shutil") as msh, \
                 patch.object(mieru_cascade, "_run") as mrun:
                msh.which.return_value = None
                self.assertTrue(mieru_cascade._neutralize_system_redsocks())
            mrun.assert_not_called()
            self.assertIn("/* chimera: dnstc disabled",
                          conf.read_text(encoding="utf-8"))


class TestInstallRedsocksNeutralize(unittest.TestCase):
    """_install_redsocks гасит мину в ОБЕИХ ветках."""

    def test_already_installed_path_neutralizes(self):
        """Бинарник уже есть (fast-path) — нейтрализация всё равно вызвана.

        Сценарий RU/91 на 03.10.2026: redsocks стоял с прошлых установок,
        dnstc-мина взведена (enabled) и ждала ребута.
        """
        with patch.object(mieru_cascade, "_redsocks_path",
                          return_value="/usr/sbin/redsocks"), \
             patch.object(mieru_cascade, "_neutralize_system_redsocks",
                          return_value=True) as mneu:
            self.assertTrue(mieru_cascade._install_redsocks())
        mneu.assert_called_once()

    def test_fresh_install_path_neutralizes(self):
        """Свежая установка через DM — нейтрализация после успеха."""
        mneu = MagicMock(return_value=True)
        # до установки бинарника нет, после — есть (установка «сработала»)
        path_calls = []

        def path_side():
            path_calls.append(1)
            return "/usr/sbin/redsocks" if len(path_calls) > 1 else None

        with patch.object(mieru_cascade, "_redsocks_path",
                          side_effect=path_side), \
             patch.object(mieru_cascade, "_neutralize_system_redsocks", mneu), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mfp, \
             patch("chimera.modules.mieru_cascade_packages."
                   "redsocks_candidates", return_value=["x.deb"]), \
             patch("chimera.modules.mieru_cascade_packages."
                   "redsocks_spec_for", return_value=MagicMock()):
            self.assertTrue(mieru_cascade._install_redsocks())
        mneu.assert_called_once()
        self.assertTrue(mfp.called)

    def test_install_failure_no_neutralize(self):
        """Ничего не установилось — False, нейтрализация не нужна."""
        with patch.object(mieru_cascade, "_redsocks_path",
                          return_value=None), \
             patch.object(mieru_cascade, "_neutralize_system_redsocks") as mneu, \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=False), \
             patch("chimera.modules.mieru_cascade_packages."
                   "redsocks_candidates", return_value=["x.deb"]), \
             patch("chimera.modules.mieru_cascade_packages."
                   "redsocks_spec_for", return_value=MagicMock()), \
             patch.object(mieru_cascade, "_run") as mrun:
            mrun.return_value = MagicMock(returncode=100)
            self.assertFalse(mieru_cascade._install_redsocks())
        mneu.assert_not_called()


if __name__ == "__main__":
    unittest.main()
