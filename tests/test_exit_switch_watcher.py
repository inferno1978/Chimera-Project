#!/usr/bin/env python3
"""
tests/test_exit_switch_watcher.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/exit_switch_watcher.py.

Контекст (кейс окт.2026 №8): после перехода ротации exit-нод на нативный
chain-balancer Xray уведомления о переключениях пропали — наблюдатель
возвращает их, опираясь на изменения эффективного состава ротации.

Покрывает (чистые функции, без сервера):
  1. _ew_merge_cfg       — слияние конфига с дефолтами
  2. _ew_quiet           — тихие часы (в т.ч. через полночь)
  3. _ew_gap_ok          — анти-спам пауза
  4. _ew_render          — шаблоны сообщений
  5. _ew_effective_set   — эффективный состав ротации
  6. _ew_diff_set        — детект изменений состава
  7. _ew_switch_kind     — классификация режимных переключений
  8. _ew_snapshot_text   — текст дайджеста
  9. load_cfg/save_cfg   — JSON I/O
 10. install/uninstall   — cron file I/O
 11. Интеграция с меню tg_bot: события наблюдателя присутствуют в
     ev_keys/ev_labels/event_labels (управляемость из «менюшки»)
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Регистрирует chimera._core в sys.modules (нужен exit_switch_watcher
    для TUI-импортов; паттерн test_node_health_monitor)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    from unittest.mock import MagicMock
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules.setdefault("chimera._core", fake_core)


# ─── фикстуры (примерные домены, не прод-инфра) ───────────────────────────────
ND_A = {"host": "node-a.example.com", "port": 443}
ND_B = {"host": "node-b.example.com", "port": 443}
ND_C = {"host": "node-c.example.com", "port": 8443, "via": "hop-x"}
KEY_A = "node-a.example.com:443"
KEY_B = "node-b.example.com:443"
KEY_C = "node-c.example.com:8443"


class TestMergeCfg(unittest.TestCase):
    """_ew_merge_cfg — слияние с дефолтами."""

    def test_empty_gives_defaults(self):
        from chimera.modules.exit_switch_watcher import _ew_merge_cfg, DEFAULTS
        out = _ew_merge_cfg(DEFAULTS, {})
        self.assertEqual(out["interval_min"], DEFAULTS["interval_min"])
        self.assertTrue(out["notify"]["exit_set_change"])

    def test_stored_overrides(self):
        from chimera.modules.exit_switch_watcher import _ew_merge_cfg, DEFAULTS
        out = _ew_merge_cfg(DEFAULTS, {"interval_min": 5, "enabled": False})
        self.assertEqual(out["interval_min"], 5)
        self.assertFalse(out["enabled"])

    def test_notify_new_events_added(self):
        """Конфиг, сохранённый до появления новых типов событий, добирает
        их как ВКЛ (обратная совместимость при обновлении)."""
        from chimera.modules.exit_switch_watcher import _ew_merge_cfg, DEFAULTS
        stored = {"notify": {"exit_set_change": True}}
        out = _ew_merge_cfg(DEFAULTS, stored)
        for ev in ("exit_switch", "exit_ip_change", "exit_snapshot"):
            self.assertTrue(out["notify"][ev])

    def test_nested_merge(self):
        from chimera.modules.exit_switch_watcher import _ew_merge_cfg, DEFAULTS
        out = _ew_merge_cfg(DEFAULTS, {"quiet_hours": {"from": "23:00"}})
        self.assertEqual(out["quiet_hours"]["from"], "23:00")
        self.assertEqual(out["quiet_hours"]["to"], "")


class TestQuietHours(unittest.TestCase):
    """_ew_quiet — тихие часы."""

    def test_disabled_when_empty(self):
        from chimera.modules.exit_switch_watcher import _ew_quiet
        self.assertFalse(_ew_quiet("23:30", {"from": "", "to": ""}))
        self.assertFalse(_ew_quiet("23:30", {}))

    def test_inside_interval_same_day(self):
        from chimera.modules.exit_switch_watcher import _ew_quiet
        q = {"from": "23:00", "to": "23:59"}
        self.assertTrue(_ew_quiet("23:30", q))

    def test_outside_interval_same_day(self):
        from chimera.modules.exit_switch_watcher import _ew_quiet
        q = {"from": "23:00", "to": "23:59"}
        self.assertFalse(_ew_quiet("12:00", q))

    def test_overnight_interval(self):
        """23:00-08:00 — интервал через полночь."""
        from chimera.modules.exit_switch_watcher import _ew_quiet
        q = {"from": "23:00", "to": "08:00"}
        self.assertTrue(_ew_quiet("23:59", q))
        self.assertTrue(_ew_quiet("00:30", q))
        self.assertTrue(_ew_quiet("07:59", q))
        self.assertFalse(_ew_quiet("08:00", q))
        self.assertFalse(_ew_quiet("12:00", q))

    def test_equal_from_to_disables(self):
        from chimera.modules.exit_switch_watcher import _ew_quiet
        self.assertFalse(_ew_quiet("10:00", {"from": "08:00", "to": "08:00"}))

    def test_garbage_input_not_crash(self):
        from chimera.modules.exit_switch_watcher import _ew_quiet
        self.assertFalse(_ew_quiet("10:00", {"from": "xx", "to": "yy"}))


class TestGapOk(unittest.TestCase):
    """_ew_gap_ok — анти-спам."""

    def test_no_last_always_ok(self):
        from chimera.modules.exit_switch_watcher import _ew_gap_ok
        self.assertTrue(_ew_gap_ok(0, 1000.0, 10))

    def test_gap_not_elapsed(self):
        from chimera.modules.exit_switch_watcher import _ew_gap_ok
        self.assertFalse(_ew_gap_ok(1000.0, 1000.0 + 5 * 60, 10))

    def test_gap_elapsed(self):
        from chimera.modules.exit_switch_watcher import _ew_gap_ok
        self.assertTrue(_ew_gap_ok(1000.0, 1000.0 + 10 * 60, 10))

    def test_zero_gap_disables(self):
        from chimera.modules.exit_switch_watcher import _ew_gap_ok
        self.assertTrue(_ew_gap_ok(1000.0, 1000.0 + 1, 0))


class TestRender(unittest.TestCase):
    """_ew_render — шаблоны."""

    def test_substitution(self):
        from chimera.modules.exit_switch_watcher import _ew_render
        out = _ew_render("<b>[{host}]</b> {detail}", host="srv", detail="ok")
        self.assertEqual(out, "<b>[srv]</b> ok")

    def test_unknown_placeholder_kept(self):
        from chimera.modules.exit_switch_watcher import _ew_render
        out = _ew_render("{detail} {unknown}", detail="d")
        self.assertEqual(out, "d {unknown}")

    def test_empty_template(self):
        from chimera.modules.exit_switch_watcher import _ew_render
        self.assertEqual(_ew_render("", detail="x"), "")


class TestEffectiveSet(unittest.TestCase):
    """_ew_effective_set — эффективный состав ротации."""

    def test_all_in_without_restrictions(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A, ND_B], [], [], {}, {}, -1)
        self.assertTrue(s[KEY_A]["in_set"])
        self.assertTrue(s[KEY_B]["in_set"])

    def test_empty_selector_means_no_rotation(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A], ["chain-exit-2"], [], {}, {}, -1)
        self.assertFalse(s[KEY_A]["in_set"])
        self.assertIn("selector", " ".join(s[KEY_A]["reasons"]))

    def test_selector_matches_by_exit_tag(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        # selector содержит теги chain-exit-N: нода с индексом 0 входит
        s = _ew_effective_set([ND_A, ND_B],
                              ["chain-exit-1", "chain-exit-2"], [], {}, {}, -1)
        self.assertTrue(s[KEY_A]["in_set"])
        self.assertTrue(s[KEY_B]["in_set"])
        # только второй тег — первая нода вне ротации
        s2 = _ew_effective_set([ND_A, ND_B], ["chain-exit-2"], [], {}, {}, -1)
        self.assertFalse(s2[KEY_A]["in_set"])
        self.assertTrue(s2[KEY_B]["in_set"])

    def test_lb_nodes_filter(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A, ND_B], [], [ND_B["host"]], {}, {}, -1)
        self.assertFalse(s[KEY_A]["in_set"])
        self.assertTrue(s[KEY_B]["in_set"])

    def test_quarantine_excludes(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A], [], [], {KEY_A: True}, {}, -1)
        self.assertFalse(s[KEY_A]["in_set"])
        self.assertIn("карантин", " ".join(s[KEY_A]["reasons"]))

    def test_hm_down_excludes(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A], [], [], {}, {KEY_A: {"up": False}}, -1)
        self.assertFalse(s[KEY_A]["in_set"])
        self.assertIn("DOWN", " ".join(s[KEY_A]["reasons"]))

    def test_hm_up_keeps(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A], [], [], {}, {KEY_A: {"up": True}}, -1)
        self.assertTrue(s[KEY_A]["in_set"])

    def test_pinned_single_node(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_A, ND_B], ["chain-exit-1", "chain-exit-2"],
                              [], {}, {}, 1)
        self.assertFalse(s[KEY_A]["in_set"])
        self.assertTrue(s[KEY_B]["in_set"])
        self.assertIn("pinned", s[KEY_B]["reasons"])

    def test_via_kept(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        s = _ew_effective_set([ND_C], [], [], {}, {}, -1)
        self.assertEqual(s[KEY_C]["via"], "hop-x")

    def test_empty_nodes(self):
        from chimera.modules.exit_switch_watcher import _ew_effective_set
        self.assertEqual(_ew_effective_set([], [], [], {}, {}, -1), {})


class TestDiffSet(unittest.TestCase):
    """_ew_diff_set — изменения состава."""

    def _set(self, keys_in, keys_all):
        return {k: {"in_set": k in keys_in, "reasons": []} for k in keys_all}

    def test_no_changes(self):
        from chimera.modules.exit_switch_watcher import _ew_diff_set
        old = self._set({KEY_A}, [KEY_A, KEY_B])
        new = self._set({KEY_A}, [KEY_A, KEY_B])
        self.assertEqual(_ew_diff_set(old, new), [])

    def test_node_removed(self):
        from chimera.modules.exit_switch_watcher import _ew_diff_set
        old = self._set({KEY_A, KEY_B}, [KEY_A, KEY_B])
        new = self._set({KEY_B}, [KEY_A, KEY_B])
        new[KEY_A]["reasons"] = ["карантин SmartBalancer"]
        d = _ew_diff_set(old, new)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["key"], KEY_A)
        self.assertEqual(d[0]["kind"], "removed")

    def test_node_added(self):
        from chimera.modules.exit_switch_watcher import _ew_diff_set
        old = self._set({KEY_B}, [KEY_A, KEY_B])
        new = self._set({KEY_A, KEY_B}, [KEY_A, KEY_B])
        d = _ew_diff_set(old, new)
        self.assertEqual(d[0]["kind"], "added")

    def test_first_snapshot_no_diff(self):
        """Первый запуск (prev пуст) — событие не генерируется."""
        from chimera.modules.exit_switch_watcher import _ew_diff_set
        new = self._set({KEY_A}, [KEY_A])
        self.assertEqual(_ew_diff_set({}, new), [])


class TestSwitchKind(unittest.TestCase):
    """_ew_switch_kind — классификация режимных переключений."""

    def test_no_change(self):
        from chimera.modules.exit_switch_watcher import _ew_switch_kind
        cur = {"strategy": "roundRobin", "active_node_idx": 0,
               "pinned": False, "selector": ["a"]}
        self.assertEqual(_ew_switch_kind(dict(cur), dict(cur)), "")

    def test_strategy_change(self):
        from chimera.modules.exit_switch_watcher import _ew_switch_kind
        prev = {"strategy": "roundRobin", "selector": [], "pinned": False}
        cur = {"strategy": "leastPing", "selector": [], "pinned": False}
        self.assertEqual(_ew_switch_kind(prev, cur), "strategy")

    def test_active_change(self):
        from chimera.modules.exit_switch_watcher import _ew_switch_kind
        prev = {"strategy": "", "active_node_idx": 0, "pinned": False,
                "selector": []}
        cur = dict(prev, active_node_idx=3)
        self.assertEqual(_ew_switch_kind(prev, cur), "active")

    def test_pin_toggled(self):
        from chimera.modules.exit_switch_watcher import _ew_switch_kind
        prev = {"strategy": "", "pinned": False, "selector": []}
        cur = {"strategy": "", "pinned": True, "selector": []}
        self.assertEqual(_ew_switch_kind(prev, cur), "pin")

    def test_selector_changed(self):
        from chimera.modules.exit_switch_watcher import _ew_switch_kind
        prev = {"strategy": "roundRobin", "pinned": False,
                "selector": ["chain-exit-1"]}
        cur = {"strategy": "roundRobin", "pinned": False,
               "selector": ["chain-exit-1", "chain-exit-2"]}
        self.assertEqual(_ew_switch_kind(prev, cur), "selector")


class TestSnapshotText(unittest.TestCase):
    """_ew_snapshot_text — дайджест."""

    def test_composition(self):
        from chimera.modules.exit_switch_watcher import _ew_snapshot_text
        eff = {
            KEY_A: {"in_set": True, "reasons": []},
            KEY_B: {"in_set": False, "reasons": ["карантин SmartBalancer"]},
        }
        mode = {"strategy": "roundRobin", "pinned": False}
        metrics = {KEY_A: {"lat_ms": 120.5}}
        text = _ew_snapshot_text(eff, mode, metrics, True)
        self.assertIn("roundRobin", text)
        self.assertIn("1", text)            # 1 из 2 в ротации
        self.assertIn(KEY_A, text)
        self.assertIn(KEY_B, text)
        self.assertIn("120", text)          # латентность
        self.assertIn("карантин", text)

    def test_metrics_can_be_disabled(self):
        from chimera.modules.exit_switch_watcher import _ew_snapshot_text
        eff = {KEY_A: {"in_set": True, "reasons": []}}
        text = _ew_snapshot_text(eff, {"strategy": ""}, {KEY_A: {"lat_ms": 120.0}},
                                 False)
        self.assertNotIn("120", text)

    def test_pinned_marked(self):
        from chimera.modules.exit_switch_watcher import _ew_snapshot_text
        text = _ew_snapshot_text({}, {"strategy": "roundRobin", "pinned": True},
                                 {}, True)
        self.assertIn("pinned", text)


class TestCfgIO(unittest.TestCase):
    """load_cfg / save_cfg — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_switch_watcher.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        import chimera.modules.exit_switch_watcher as ew
        return patch.multiple(ew, EW_CFG_FILE=self._cfg)

    def test_load_defaults_when_no_file(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            cfg = ew.load_cfg()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["snapshot_hours"], ew.DEFAULT_SNAPSHOT_HOURS)

    def test_load_defaults_when_corrupt(self):
        import chimera.modules.exit_switch_watcher as ew
        self._cfg.write_text("{invalid")
        with self._patch():
            cfg = ew.load_cfg()
        self.assertTrue(cfg["enabled"])

    def test_save_then_load_roundtrip(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            ew.save_cfg({"enabled": False, "interval_min": 7})
            cfg = ew.load_cfg()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["interval_min"], 7)

    def test_save_chmod_600(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            ew.save_cfg({"enabled": True})
        self.assertEqual(self._cfg.stat().st_mode & 0o777, 0o600)


class TestCronInstall(unittest.TestCase):
    """install_watcher / uninstall_watcher / is_installed — cron I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "xray-exit-watcher"
        self._script = self._tmpdir / "xray-exit-watcher.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        import chimera.modules.exit_switch_watcher as ew
        return patch.multiple(ew, CRON_FILE=self._cron, CRON_SCRIPT=self._script)

    def test_install_creates_files(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            ok, msg = ew.install_watcher(15)
            self.assertTrue(ok, msg)
            self.assertTrue(ew.is_installed())
            cron_text = self._cron.read_text()
        self.assertIn("*/15 * * * *", cron_text)
        self.assertIn("exit_switch_watcher", self._script.read_text())

    def test_interval_clamped(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            ok, _ = ew.install_watcher(999)
            self.assertTrue(ok)
            self.assertIn("*/60", self._cron.read_text())

    def test_uninstall_removes_files(self):
        import chimera.modules.exit_switch_watcher as ew
        with self._patch():
            ew.install_watcher(5)
            ok, _ = ew.uninstall_watcher()
            self.assertTrue(ok)
            self.assertFalse(ew.is_installed())


class TestTgBotMenuIntegration(unittest.TestCase):
    """Интеграция с «менюшкой» Telegram-уведомлений (управляемость
    событий наблюдателя — суть кейса №8)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_watcher_events_in_event_labels(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        m_labels = re.search(r"event_labels = \{(.*?)\}", src, re.S)
        self.assertIsNotNone(m_labels, "event_labels не найден")
        body = m_labels.group(1)
        for ev in ("exit_set_change", "exit_switch",
                   "exit_ip_change", "exit_snapshot",
                   "node_connect", "relay_failover",
                   "cascade_lb_change", "awg_failover"):
            self.assertIn(f'"{ev}"', body, f"{ev} отсутствует в event_labels")

    def test_ev_keys_labels_aligned(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        keys = re.findall(r'"([a-z_0-9]+)"',
                          re.search(r"ev_keys = \[(.*?)\]",
                                    src, re.S).group(1))
        labels = re.findall(r'"([^"]+)"',
                            re.search(r"ev_labels = \[(.*?)\]\n\s+events",
                                      src, re.S).group(1))
        self.assertEqual(len(keys), len(labels))
        self.assertIn("exit_set_change", keys)

    def test_icons_for_watcher_events(self):
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.tg_notify_event)
        for ev in ("exit_set_change", "exit_switch",
                   "exit_ip_change", "exit_snapshot",
                   "node_connect", "relay_failover",
                   "ttl_expiring", "ttl_expired"):
            self.assertIn(f'"{ev}"', src, f"нет иконки для {ev}")


class TestRunOnceDisabled(unittest.TestCase):
    """run_once: выключенный наблюдатель не делает ничего."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_switch_watcher.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_disabled_returns_empty(self):
        import chimera.modules.exit_switch_watcher as ew
        self._cfg.write_text(json.dumps({"enabled": False}))
        with patch.multiple(ew, EW_CFG_FILE=self._cfg):
            res = ew.run_once()
        self.assertEqual(res["events"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
