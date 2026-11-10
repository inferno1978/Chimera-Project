#!/usr/bin/env python3
"""
tests/test_failover.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/failover.py.

Покрывает:
  1. _failover_load / _failover_save — JSON I/O
  2. _auto_fallback_set_flag — установка флага авто-fallback
  3. Волна-3 (канон node_identity): генераторы watchdog/auto-fallback вшивают
     метки нод («alias · домен [IP](:порт)») и заголовок сервера
     «[имя · домен · IP] »; all-dead перечисляет все ноды метками.
     Проверяется ТЕКСТ сгенерированного скрипта (запуск — только bash -n;
     боевой TG из тестов не уходит: токен тестовый, send_tg не вызывается).
"""
from __future__ import annotations

import json
import os
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


class TestFailoverLoadSave(unittest.TestCase):
    """_failover_load / _failover_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "failover.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.failover._FAILOVER_STATE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.failover import _failover_load
        with self._patch():
            self.assertEqual(_failover_load(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.failover import _failover_load
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_failover_load(), {})

    def test_save_then_load(self):
        from chimera.modules.failover import _failover_load, _failover_save
        data = {"enabled": True, "last_fallback": "2026-07-10"}
        with self._patch():
            _failover_save(data)
            loaded = _failover_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["last_fallback"], "2026-07-10")


class TestAutoFallbackSetFlag(unittest.TestCase):
    """_auto_fallback_set_flag — установка флага."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_sets_flag_true(self):
        from chimera.modules import failover
        self._state.write_text(json.dumps({"uuid": "abc"}))
        mock_core = MagicMock()
        mock_core.STATE_FILE = self._state
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(True)
        state = json.loads(self._state.read_text())
        self.assertTrue(state["auto_fallback_to_direct"])
        self.assertEqual(state["uuid"], "abc")

    def test_sets_flag_false(self):
        from chimera.modules import failover
        self._state.write_text(json.dumps({"uuid": "abc", "auto_fallback_to_direct": True}))
        mock_core = MagicMock()
        mock_core.STATE_FILE = self._state
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(False)
        state = json.loads(self._state.read_text())
        self.assertFalse(state["auto_fallback_to_direct"])

    def test_warns_when_no_state_file(self):
        from chimera.modules import failover
        mock_core = MagicMock()
        mock_core.STATE_FILE = Path("/tmp/nonexistent_failover_state.json")
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(True)
        mock_core.warn.assert_called()


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-3 (канон node_identity): метки нод + заголовок сервера в генераторах
#  bash-скриптов. Метки резолвятся В МОМЕНТ ГЕНЕРАЦИИ (bash не умеет
#  DNS/алиасы), заголовок вшит вместе с токеном (единый стиль генератора).
#  Герметичность: node_identity state/TG/DNS-кэш/aliases — на tmp, прод-файлы
#  не протекают; проверяется текст скрипта, скрипт не запускается.
# ══════════════════════════════════════════════════════════════════════════════

_NODES = [
    {"host": "node-nl.example.com", "port": 443},
    {"host": "203.0.113.99", "port": 8443},
]


class _GeneratorBase(unittest.TestCase):
    """tmp-окружение: node_identity на tmp + мок core + пути скриптов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import time as _time
        from chimera.modules import failover as fo
        from chimera.modules import node_identity as _ni
        self.fo = fo
        self.ni = _ni
        self.now = _time.time()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        # node_identity: прод-файлы НЕ протекают (паттерн 652e692);
        # DNS — только через предзаполненный кэш (без getent/сети)
        (self.tmp / "telegram.json").write_text(json.dumps(
            {"server_name": "RU1", "server_ip": "203.0.113.10"}))
        (self.tmp / "state.json").write_text(json.dumps(
            {"domain": "entry-ru.example.com"}))
        (self.tmp / "node_dns_cache.json").write_text(json.dumps(
            {"node-nl.example.com": {"ip": "203.0.113.40",
                                     "ts": self.now}}))
        (self.tmp / "exit_traffic_watcher.json").write_text(json.dumps(
            {"aliases": {"node-nl.example.com:443": "NL"}}))
        for p in (
            patch.object(_ni, "TG_FILE", self.tmp / "telegram.json"),
            patch.object(_ni, "STATE_FILE", self.tmp / "state.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "exit_traffic_watcher.json"),
        ):
            p.start()
            self.addCleanup(p.stop)
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)
        # мок core: success тихий, пути скриптов в tmp
        core = MagicMock()
        core.success = lambda *a, **k: None
        core.STATE_FILE = self.tmp / "state.json"
        core._AUTO_FALLBACK_LOGFILE = self.tmp / "auto-fallback.log"
        core._AUTO_FALLBACK_SCRIPT = self.tmp / "auto-fallback.sh"
        core._AUTO_FALLBACK_CRON = self.tmp / "auto-fallback.cron"
        self.core = core
        self._cm = patch.object(fo, "_core_module", return_value=core)
        self._cm.start()
        self.addCleanup(self._cm.stop)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _install_watchdog(self):
        with patch.object(self.fo, "_FAILOVER_SCRIPT", self.tmp / "wd.sh"), \
             patch.object(self.fo, "_FAILOVER_CRON", self.tmp / "wd.cron"):
            self.fo._failover_install(_NODES, "TESTTOKEN", "12345")
        return (self.tmp / "wd.sh").read_text()

    def _install_autofallback(self):
        self.fo._auto_fallback_install(_NODES, "TESTTOKEN", "12345")
        return (self.tmp / "auto-fallback.sh").read_text()


class TestWatchdogScriptLabels(_GeneratorBase):
    """_failover_install: метки нод + заголовок в тексте watchdog-скрипта."""

    def test_labels_baked_into_script(self):
        script = self._install_watchdog()
        # домен-нода: алиас + IP из кэша, дефолтный :443 не пишется
        self.assertIn(
            "NODE_LABELS=('NL · node-nl.example.com [203.0.113.40]' "
            "203.0.113.99:8443)", script)
        # заголовок сервера — канон node_identity.server_header
        self.assertIn(
            "HDR_PREFIX='[RU1 · entry-ru.example.com · 203.0.113.10] '",
            script)

    def test_down_notify_uses_label_and_header(self):
        script = self._install_watchdog()
        self.assertIn(
            'send_tg "⚠️ ${HDR_PREFIX}VLESS Exit Node DOWN: $LABEL"', script)
        # прежний голый host:port из уведы ушёл
        self.assertNotIn('VLESS Exit Node DOWN: $HOST:$PORT', script)

    def test_fallback_label_when_no_identity(self):
        """node_identity недоступен → метки = host:port (прежний вид)."""
        with patch.dict(sys.modules,
                        {"chimera.modules.node_identity": None}):
            script = self._install_watchdog()
        self.assertIn("NODE_LABELS=(node-nl.example.com:443 "
                      "203.0.113.99:8443)", script)
        # заголовка нет — уведа в прежнем виде
        self.assertIn("HDR_PREFIX=''", script)

    def test_bash_syntax_ok_per_node_watchdog(self):
        """Сгенерированный per-node watchdog валиден для bash -n (волна-4).

        Мёртвый блок nodes_str («STATUS=$(check_node …» с незакрытой
        подстановкой) удалён: до фикса генерат не парсился ВООБЩЕ — скрипт
        никогда не работал, per-node DOWN уведы не уходили (эмпирически
        bash -n: «unexpected EOF while looking for matching ')'»)."""
        import subprocess as _sp
        script = self._install_watchdog()
        r = _sp.run(["bash", "-n", str(self.tmp / "wd.sh")],
                    capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f"bash -n: {r.stderr}")
        # мёртвые строки (check_node с голым host в аргументе) исчезли из
        # генерата; рабочий цикл — с переменными $HOST/$PORT — на месте
        self.assertNotIn('check_node "node-nl.example.com"', script)
        self.assertIn('STATUS=$(check_node "$HOST" "$PORT")', script)


class TestAutoFallbackScriptLabels(_GeneratorBase):
    """_auto_fallback_install: all-dead составом + заголовок в режимных уведах."""

    def test_all_dead_lists_all_labels_with_header(self):
        script = self._install_autofallback()
        self.assertIn(
            "ALL_LABELS='NL · node-nl.example.com [203.0.113.40], "
            "203.0.113.99:8443'", script)
        self.assertIn(
            "HDR_PREFIX='[RU1 · entry-ru.example.com · 203.0.113.10] '",
            script)
        self.assertIn(
            'send_tg "⚠️ ${HDR_PREFIX}VLESS: все exit-ноды DOWN '
            '(${ALL_LABELS}). Переключён в Режим A (прямой выход)."',
            script)

    def test_recovery_notify_has_header(self):
        script = self._install_autofallback()
        self.assertIn(
            'send_tg "✅ ${HDR_PREFIX}VLESS: exit-нода восстановлена. '
            'Возврат в Режим B (каскад)."', script)

    def test_bash_syntax_ok(self):
        """Сгенерированный auto-fallback скрипт валиден для bash -n.

        (per-node watchdog теперь тоже валиден — мёртвый блок nodes_str
        удалён волной-4, см. TestWatchdogScriptLabels.
        test_bash_syntax_ok_per_node_watchdog.)"""
        import subprocess as _sp
        self._install_autofallback()
        r = _sp.run(["bash", "-n", str(self.tmp / "auto-fallback.sh")],
                    capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f"bash -n: {r.stderr}")


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-5 (живой кейс окт.2026 №3): генераты зондируют exit-ноды полным
#  REALITY-зондом через мост main.py --hm-check; голый TCP к REALITY-порту —
#  бан-фуд fail2ban xray-reality + DPI-detector на ноде-цели — остаётся
#  только последним рубежом при поломке моста. Проверяется ТЕКСТ
#  генерата (+ bash -n); скрипт не запускается.
# ══════════════════════════════════════════════════════════════════════════════

class TestWatchdogWave5(_GeneratorBase):
    """Волна-5: watchdog зондирует полным REALITY-зондом через мост
    main.py --hm-check; голый TCP — только последний рубеж (живой кейс №3)."""

    def test_check_node_uses_hm_check_bridge(self):
        # зонд — мост main.py --hm-check под timeout; MAIN_PY/PYTHONPATH
        # вшиты генератором; контракт цикла (волна-4) не тронут
        script = self._install_watchdog()
        self.assertIn('--hm-check "$HOST:$PORT"', script)
        self.assertIn('timeout -k 5 60 python3 "$MAIN_PY"', script)
        self.assertIn('MAIN_PY=', script)
        self.assertNotIn('MAIN_PY=""', script)
        self.assertIn('export PYTHONPATH=', script)
        self.assertIn('STATUS=$(check_node "$HOST" "$PORT")', script)

    def test_bare_tcp_only_last_resort(self):
        # голый TCP — ровно ОДНО место (fallback check_node) и ПОСЛЕ моста
        script = self._install_watchdog()
        self.assertEqual(script.count("/dev/tcp/"), 1)
        self.assertLess(script.index("--hm-check"),
                        script.index("/dev/tcp/"))

    def test_flock_guard_present(self):
        # гард нахлёста раундов (полный зонд мёртвой ноды >60 c при
        # поминутном cron — гонка над failover.json и дубль DOWN-уведы)
        script = self._install_watchdog()
        self.assertIn("command -v flock", script)
        self.assertIn("flock -n 9 || exit 0", script)
        self.assertIn("/var/run/xray-failover-watch.lock", script)

    def test_bash_syntax_ok_wave5(self):
        import subprocess as _sp
        self._install_watchdog()
        r = _sp.run(["bash", "-n", str(self.tmp / "wd.sh")],
                    capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f"bash -n: {r.stderr}")

    def test_labels_and_notify_unchanged(self):
        # волна-3/4 функционал не потерян: метки + заголовок в DOWN-уведе
        script = self._install_watchdog()
        self.assertIn(
            "NODE_LABELS=('NL · node-nl.example.com [203.0.113.40]' "
            "203.0.113.99:8443)", script)
        self.assertIn(
            'send_tg "⚠️ ${HDR_PREFIX}VLESS Exit Node DOWN: $LABEL"', script)

    def test_shebang_at_byte0(self):
        """Shebang на байте 0 (регресс волны-5): python-хердоки и tg_block
        на колонке 0 обнуляли общий префикс textwrap.dedent → shebang с
        отступом → cron-execve не видит интерпретатор (ENOEXEC) → dash,
        а в dash нет bash-массивов NODE_LABELS — скрипт мёртв при живом
        bash -n. Проверяем с TG (многострочный tg_block) и без."""
        script = self._install_watchdog()
        self.assertTrue(script.startswith("#!/bin/bash"),
                        f"shebang не на байте 0: {script[:16]!r}")
        # хердок update_state — python-разметка (<8 пробелов) не тронута
        self.assertIn("\n    with open(p) as f: d = json.load(f)", script)
        # без TG (tg_block = no-op на колонке 0) — тот же гарант
        with patch.object(self.fo, "_FAILOVER_SCRIPT",
                          self.tmp / "wd-notg.sh"), \
             patch.object(self.fo, "_FAILOVER_CRON",
                          self.tmp / "wd-notg.cron"):
            self.fo._failover_install(_NODES, "", "")
        self.assertTrue((self.tmp / "wd-notg.sh").read_text()
                        .startswith("#!/bin/bash"))

    def test_update_state_heredoc_imports_sys(self):
        """Регресс волны-5 (латент баг волны-4): хердок update_state звал
        sys.exit без import sys → NameError → exit 1 ВСЕГДА → RET≠0 при
        любом статусе → DOWN-уведа улетала бы КАЖДУЮ минуту (спам),
        дедуп по смене статуса не работал (state при этом писался —
        до sys.exit). sys в импортах = честный 0/1 дедупа."""
        script = self._install_watchdog()
        self.assertIn("import json, os, sys, time", script)
        # контракт дедупа не тронут: 0 = статусы равны (молчим), 1 = смена
        self.assertIn("sys.exit(0 if prev.get('status') == '$STATUS' else 1)",
                      script)


class TestAutoFallbackWave5(_GeneratorBase):
    """Волна-5: ANY_UP-цикл auto-fallback — полный зонд через мост
    --hm-check, голый TCP — последний рубеж; режимные ветки не тронуты."""

    def test_any_up_loop_uses_hm_check(self):
        script = self._install_autofallback()
        self.assertIn('--hm-check "$HOST:$PORT"', script)
        # голый TCP — ровно одно место (fallback цикла)
        self.assertEqual(script.count("/dev/tcp/"), 1)
        # гард нахлёста (лок — отдельный от watchdog)
        self.assertIn("flock -n 9 || exit 0", script)
        self.assertIn("/var/run/xray-auto-fallback.lock", script)
        # режимные вызовы/уведы (волны-3/4) не тронуты
        self.assertIn('--switch-mode-a', script)
        self.assertIn('--switch-mode-b', script)
        self.assertIn('--pinned-fallback-check', script)
        self.assertIn('все exit-ноды DOWN (${ALL_LABELS})', script)
        self.assertIn('exit-нода восстановлена', script)

    def test_bash_syntax_ok_wave5(self):
        import subprocess as _sp
        self._install_autofallback()
        r = _sp.run(["bash", "-n", str(self.tmp / "auto-fallback.sh")],
                    capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f"bash -n: {r.stderr}")

    def test_shebang_at_byte0(self):
        """Shebang на байте 0 (регресс волны-5, см. TestWatchdogWave5):
        колонка-0 хердоков/tg_block убивала textwrap.dedent → cron-execve
        не видел интерпретатор → dash → скрипт мёртв. С TG и без."""
        script = self._install_autofallback()
        self.assertTrue(script.startswith("#!/bin/bash"),
                        f"shebang не на байте 0: {script[:16]!r}")
        # хердок чтения state.json — python-разметка не тронута
        self.assertIn("\n    d = json.load(open('$STATE_FILE'))", script)
        self.fo._auto_fallback_install(_NODES, "", "")
        self.assertTrue((self.tmp / "auto-fallback.sh").read_text()
                        .startswith("#!/bin/bash"))

    def test_script_var_absolute_main_py(self):
        """Регресс волны-5 (латент баг волны-3/4): SCRIPT был sys.argv[0]
        генератора — относительный «main.py» при установке из меню → cron
        (cwd=/) не находил файл → --switch-mode-a/b и
        --pinned-fallback-check никогда не срабатывали. Теперь —
        абсолютный путь (тот же _fo_installer_paths, что и мост)."""
        import re as _re
        script = self._install_autofallback()
        m = _re.search(r'SCRIPT="([^"]+)"', script)
        self.assertIsNotNone(m, "SCRIPT= не найден в генерате")
        self.assertTrue(m.group(1).startswith("/"),
                        f"SCRIPT не абсолютный: {m.group(1)!r}")
        self.assertTrue(m.group(1).endswith("/main.py"),
                        f"SCRIPT не main.py: {m.group(1)!r}")


class TestMainPyHmCheckFlag(unittest.TestCase):
    """main.py несёт мост --hm-check (конвенция test_user_lifecycle:
    проверка флага в исходнике main.py, без exec точек входа)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_flag_present(self):
        src = (_PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn('"--hm-check" in sys.argv', src)
        self.assertIn("hm_check_cli", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
