#!/usr/bin/env python3
"""
tests/test_status_awg_v3.py
───────────────────────────────────────────────────────────────────────────────
Тесты v3 статуса каскада в TG-боте (08.10.2026).

Покрывает:
  1. scripts/chimera-remote-status.py v3 — AWG-сегмент:
     entry (LB и single-exit), exit, отсутствие каскада (обратная
     совместимость: ключа awg нет), битый state, LB-фильтр lb_exits,
     регресс mieru v2;
     запуск — subprocess с патчем путей на tmp + PATH-шимы
     systemctl/awg/hostname/uptime (реальных команд не требуется).
  2. Рендер _format_status_line сгенерированного бота:
     AWG-сегмент (вход/выход/LB/hs), «Режим B» вместо «М=B»,
     дедуп hostname в имени пира, обратная совместимость без awg-ключа.
  3. Маркеры харденинга: параллельный SSH-сбор пиров (ThreadPoolExecutor
     + фолбэк), анти-задержка /status.

Принцип: сетевых вызовов нет; все фикстуры — TEST-NET/локальные имена.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_REMOTE_STATUS = _PROJECT_ROOT / "scripts" / "chimera-remote-status.py"

# Нейтральные имена экзитов (политика leak_guard: без гео-тегов)
_EXITS = ["exit-a", "exit-b", "exit-c", "exit-d", "exit-e"]


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    from unittest.mock import patch
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


# ─────────────────────────────────────────────────────────────────────────────
# 1. chimera-remote-status.py v3 (subprocess, tmp-патч путей + шимы)
# ─────────────────────────────────────────────────────────────────────────────
class _RemoteStatusEnv:
    """Tmp-окружение: state-файлы + PATH-шимы systemctl/awg/hostname/uptime."""

    def __init__(self, awg_state=None, mieru_state=None,
                 systemctl_map=None, awg_show_map=None):
        self.tmp = Path(tempfile.mkdtemp(prefix="rst_v3_"))
        varlib = self.tmp / "varlib"
        varlib.mkdir()
        (varlib / "state.json").write_text(json.dumps(
            {"protocol_mode": "reality", "server_port": 443,
             "install_mode": "B"}))
        if mieru_state is not None:
            (varlib / "mieru_cascade.json").write_text(
                json.dumps(mieru_state))
        if awg_state is not None:
            (varlib / "awg_standalone_state.json").write_text(
                json.dumps(awg_state))

        bin_ = self.tmp / "bin"
        bin_.mkdir()
        # systemctl: карта unit → статус (default inactive)
        default_map = {
            "xray": "active", "mita": "active",
            "awg-quick@awg1": "active", "awg-cascade-routing": "active",
            "awg-quick@awg0": "active",
        }
        svc = dict(default_map)
        if systemctl_map:
            svc.update(systemctl_map)
        case_body = "".join(
            f"  is-active@{u}) echo {s}; exit 0;;\n" for u, s in svc.items())
        self._shim(bin_ / "systemctl",
                   "#!/bin/sh\ncase \"$1@$2\" in\n" + case_body +
                   "esac\necho inactive; exit 3\n")
        # awg: карта iface → handshake-строка (default — rc 1)
        awg_body = ""
        for iface, hs_line in (awg_show_map or {}).items():
            awg_body += (f"if [ \"$2\" = \"{iface}\" ]; then\n"
                         f"  echo '{hs_line}'\n  exit 0\nfi\n")
        self._shim(bin_ / "awg", "#!/bin/sh\n" + awg_body + "exit 1\n")
        self._shim(bin_ / "hostname", "#!/bin/sh\necho testhost\n")
        self._shim(bin_ / "uptime",
                   "#!/bin/sh\necho 'up 2 weeks, 6 days'\n")

        code = _REMOTE_STATUS.read_text()
        code = code.replace("/var/lib/xray-installer/", str(varlib) + "/")
        self.runner = self.tmp / "runner.py"
        self.runner.write_text(code)

    @staticmethod
    def _shim(path: Path, body: str):
        path.write_text(body)
        path.chmod(0o755)

    def run(self) -> dict:
        env = dict(os.environ)
        env["PATH"] = f"{self.tmp / 'bin'}:{env['PATH']}"
        r = subprocess.run(["python3", str(self.runner)],
                           capture_output=True, text=True, env=env, timeout=30)
        assert r.returncode == 0, f"runner rc={r.returncode}: {r.stderr[:300]}"
        return json.loads(r.stdout.strip().splitlines()[-1])

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def _lb_entry_state(alive=None, lb_exits=None):
    return {
        "cascade_role": "entry",
        "cascade_active_exit": "exit-c",
        "cascade_exits": [{"name": n} for n in _EXITS],
        "lb_mode": True, "lb_strategy": "smart",
        "lb_exits": lb_exits if lb_exits is not None else [],
        "lb": {"alive": alive if alive is not None else list(_EXITS)},
    }


class TestRemoteStatusV3Entry(unittest.TestCase):
    """v3: роль entry — туннель/routing/hs/экзиты (+LB)."""

    def test_entry_lb_healthy(self):
        env = _RemoteStatusEnv(
            awg_state=_lb_entry_state(),
            awg_show_map={"awg1": "latest handshake: 1 minute, 10 seconds ago",
                          "awg2": "latest handshake: 45 seconds ago"})
        try:
            out = env.run()
        finally:
            env.close()
        awg = out["awg"]
        self.assertEqual(awg["role"], "entry")
        self.assertTrue(awg["awg1"])
        self.assertTrue(awg["routing"])
        self.assertEqual(awg["hs"], 45)      # минимальный возраст слотов
        self.assertEqual(awg["exits"], 5)
        self.assertTrue(awg["lb"])
        self.assertEqual(awg["strategy"], "smart")
        self.assertEqual(awg["slots"], 5)
        self.assertEqual(awg["alive"], 5)
        # базовые поля v1 не изменились
        self.assertEqual(out["host"], "testhost")
        self.assertEqual(out["xray"], "active")
        self.assertEqual(out["mode"], "B")

    def test_entry_single_exit_no_lb(self):
        """lb_mode выключен (< 2 эффективных) → ключа lb нет, есть active."""
        state = _lb_entry_state()
        state["lb_mode"] = False
        env = _RemoteStatusEnv(
            awg_state=state,
            awg_show_map={"awg1": "latest handshake: 30 seconds ago"})
        try:
            out = env.run()
        finally:
            env.close()
        awg = out["awg"]
        self.assertNotIn("lb", awg)
        self.assertEqual(awg["active"], "exit-c")
        self.assertEqual(awg["hs"], 30)

    def test_entry_lb_filter_subset(self):
        """lb_exits-фильтр: слоты считаются по ЭФФЕКТИВНОМУ составу."""
        env = _RemoteStatusEnv(
            awg_state=_lb_entry_state(alive=["exit-a", "exit-b"],
                                      lb_exits=["exit-a", "exit-b"]),
            awg_show_map={"awg1": "latest handshake: 50 seconds ago",
                          "awg2": "latest handshake: 2 minutes ago"})
        try:
            out = env.run()
        finally:
            env.close()
        awg = out["awg"]
        self.assertEqual(awg["slots"], 2)
        self.assertEqual(awg["alive"], 2)    # посторонние имена не считаются
        self.assertEqual(awg["hs"], 50)

    def test_entry_hs_absent_when_no_handshake(self):
        """Туннель свежий/мёртвый — hs=None (сегмент покажет ✗)."""
        env = _RemoteStatusEnv(
            awg_state=_lb_entry_state(lb_exits=["exit-a"]),
            awg_show_map={})                 # awg show всегда rc=1
        try:
            out = env.run()
        finally:
            env.close()
        self.assertIsNone(out["awg"]["hs"])

    def test_entry_tunnel_down(self):
        env = _RemoteStatusEnv(
            awg_state=_lb_entry_state(lb_exits=["exit-a"]),
            systemctl_map={"awg-quick@awg1": "failed"},
            awg_show_map={"awg1": "latest handshake: 5 seconds ago"})
        try:
            out = env.run()
        finally:
            env.close()
        self.assertFalse(out["awg"]["awg1"])


class TestRemoteStatusV3ExitAndCompat(unittest.TestCase):
    """v3: роль exit + обратная совместимость (нет/битый AWG-state)."""

    def test_exit_role_awg0(self):
        env = _RemoteStatusEnv(
            awg_state={"cascade_role": "exit"})
        try:
            out = env.run()
        finally:
            env.close()
        self.assertEqual(out["awg"], {"role": "exit", "awg0": True})

    def test_exit_role_awg0_down(self):
        env = _RemoteStatusEnv(
            awg_state={"cascade_role": "exit"},
            systemctl_map={"awg-quick@awg0": "inactive"})
        try:
            out = env.run()
        finally:
            env.close()
        self.assertEqual(out["awg"], {"role": "exit", "awg0": False})

    def test_no_awg_state_no_key(self):
        """AWG не настроен → ключа awg НЕТ (старый формат вывода)."""
        env = _RemoteStatusEnv()
        try:
            out = env.run()
        finally:
            env.close()
        self.assertNotIn("awg", out)

    def test_role_empty_no_key(self):
        env = _RemoteStatusEnv(awg_state={"cascade_role": ""})
        try:
            out = env.run()
        finally:
            env.close()
        self.assertNotIn("awg", out)

    def test_corrupted_awg_state_no_key(self):
        tmp = Path(tempfile.mkdtemp(prefix="rst_bad_"))
        try:
            varlib = tmp / "varlib"
            varlib.mkdir()
            (varlib / "state.json").write_text("{}")
            (varlib / "awg_standalone_state.json").write_text("{not json")
            code = _REMOTE_STATUS.read_text().replace(
                "/var/lib/xray-installer/", str(varlib) + "/")
            runner = tmp / "runner.py"
            runner.write_text(code)
            r = subprocess.run(["python3", str(runner)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0)
            out = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertNotIn("awg", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mieru_v2_regression(self):
        """Mieru-поля v2 не задеты внедрением v3."""
        env = _RemoteStatusEnv(
            awg_state=_lb_entry_state(lb_exits=["exit-a"]),
            mieru_state={"role": "entry", "exits": [
                {"name": "m1", "enabled": True, "healthy": True,
                 "last_check": "2026-10-08 13:46:00"},
                {"name": "m2", "enabled": True, "healthy": False,
                 "last_check": "2026-10-08 13:46:00"}]})
        try:
            out = env.run()
        finally:
            env.close()
        self.assertEqual(out["mieru"]["ok"], 1)
        self.assertEqual(out["mieru"]["total"], 2)
        self.assertEqual(out["mieru"]["mita"], "active")
        self.assertIn("awg", out)            # оба сегмента рядом


# ─────────────────────────────────────────────────────────────────────────────
# 2. Рендер _format_status_line / хелперы сгенерированного бота
# ─────────────────────────────────────────────────────────────────────────────
class _InnerBot:
    """exec сгенерированного скрипта бота → namespace с функциями."""

    def __init__(self):
        _setup_core_in_sysmodules()
        from chimera.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(
            {"token": "123456:ABC", "admin_id": "111111111",
             "allowed_users": [], "invite_tokens": {}},
            {"token": "", "chat_id": ""})
        self.ns = {}
        exec(compile(script, "inner_bot.py", "exec"), self.ns)


class TestStatusLineRenderV3(unittest.TestCase):
    """_format_status_line: AWG-сегмент, «Режим B», дедуп hostname."""

    @classmethod
    def setUpClass(cls):
        cls.bot = _InnerBot()
        # staticmethod: иначе функция из ns станет bound-методом тест-класса
        cls.fmt = staticmethod(cls.bot.ns["_format_status_line"])

    def _base(self, **kw):
        d = {"host": "testhost", "name": "Server 1 (testhost)",
             "ip": "203.0.113.10", "xray": "active", "proto": "reality",
             "port": 443, "mode": "B", "uptime": "up 2 weeks"}
        d.update(kw)
        return d

    def test_entry_lb_healthy_segment(self):
        s = self.fmt(self._base(awg={
            "role": "entry", "awg1": True, "routing": True, "hs": 70,
            "exits": 5, "lb": True, "strategy": "smart",
            "slots": 5, "alive": 5}))
        self.assertIn("🛡 AWG: вход ✓", s)
        self.assertIn("LB smart 5/5", s)
        self.assertIn("hs 70с", s)

    def test_entry_lb_partially_alive(self):
        s = self.fmt(self._base(awg={
            "role": "entry", "awg1": True, "routing": True, "hs": 70,
            "exits": 5, "lb": True, "strategy": "smart",
            "slots": 5, "alive": 3}))
        self.assertIn("LB smart 3/5", s)

    def test_entry_stale_hs_marks_unhealthy(self):
        """hs > 180с = туннель несвежий → ✗ (даже при active-юнитах)."""
        s = self.fmt(self._base(awg={
            "role": "entry", "awg1": True, "routing": True, "hs": 900,
            "exits": 2, "active": "exit-b"}))
        self.assertIn("вход ✗", s)
        self.assertIn("актив exit-b", s)
        self.assertIn("hs 15м", s)

    def test_entry_dead_tunnel(self):
        s = self.fmt(self._base(awg={
            "role": "entry", "awg1": False, "routing": False, "hs": None,
            "exits": 5, "lb": True, "strategy": "smart",
            "slots": 5, "alive": 0}))
        self.assertIn("вход ✗", s)
        self.assertIn("hs —", s)
        self.assertIn("LB smart 0/5", s)

    def test_exit_role_segment(self):
        s = self.fmt(self._base(awg={"role": "exit", "awg0": True}))
        self.assertIn("🛡 AWG: выход ✓", s)

    def test_exit_role_down(self):
        s = self.fmt(self._base(awg={"role": "exit", "awg0": False}))
        self.assertIn("🛡 AWG: выход ✗", s)

    def test_no_awg_key_backward_compat(self):
        s = self.fmt(self._base())
        self.assertNotIn("AWG", s)

    def test_mode_label_is_rezhim_not_m(self):
        """«М=B» → «Режим B» (понятное отображение режима установки)."""
        s = self.fmt(self._base())
        self.assertIn("Режим B", s)
        self.assertNotIn("М=B", s)

    def test_hostname_dedup_in_name(self):
        """Имя пира уже содержит «(host)» → не дублируем скобки."""
        s = self.fmt(self._base())
        self.assertIn("Server 1 (testhost)", s)
        self.assertNotIn("(testhost) (testhost)", s)

    def test_hostname_shown_when_not_in_name(self):
        s = self.fmt(self._base(name="Plain name"))
        self.assertIn("Plain name</b> (testhost)", s)

    def test_error_line_format(self):
        s = self.fmt({"name": "Server X", "host": "deadhost",
                      "ip": "203.0.113.99", "error": "timeout (>20s)"})
        self.assertIn("❌ timeout (>20s)", s)
        self.assertIn("deadhost", s)

    def test_mieru_segment_regression(self):
        s = self.fmt(self._base(mieru={
            "ok": 4, "total": 4, "mita": "active", "stalled": False}))
        self.assertIn("🧅 Mieru: 4/4 ✓", s)
        self.assertNotIn("[mita ✗]", s)

    def test_full_line_order(self):
        """AWG стоит между режимом и Mieru; строка читается целиком."""
        s = self.fmt(self._base(
            awg={"role": "entry", "awg1": True, "routing": True, "hs": 70,
                 "exits": 5, "lb": True, "strategy": "smart",
                 "slots": 5, "alive": 5},
            mieru={"ok": 4, "total": 4, "mita": "active", "stalled": False}))
        expected = ("Xray=active | REALITY:443 | Режим B | "
                    "🛡 AWG: вход ✓ · LB smart 5/5 · hs 70с | "
                    "🧅 Mieru: 4/4 ✓ | Апт: up 2 weeks")
        self.assertIn(expected, s)


class TestInnerHelpersV3(unittest.TestCase):
    """_awg_hs_age / _fmt_hs сгенерированного скрипта."""

    @classmethod
    def setUpClass(cls):
        cls.bot = _InnerBot()

    def test_hs_age_variants(self):
        f = self.bot.ns["_awg_hs_age"]
        self.assertEqual(f("latest handshake: 45 seconds ago"), 45)
        self.assertEqual(f("latest handshake: 1 minute, 10 seconds ago"), 70)
        self.assertEqual(f("latest handshake: 2 hours, 3 minutes ago"), 7380)
        self.assertEqual(f("latest handshake: 1 week ago"), 604800)
        self.assertIsNone(f("no handshake here"))
        self.assertIsNone(f(""))

    def test_fmt_hs_variants(self):
        f = self.bot.ns["_fmt_hs"]
        self.assertEqual(f(45), "45с")
        self.assertEqual(f(70), "70с")
        self.assertEqual(f(89), "89с")
        self.assertEqual(f(300), "5м")
        self.assertEqual(f(7200), "2ч")
        self.assertEqual(f(172800), "2д")
        self.assertEqual(f(None), "—")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Маркеры харденинга сгенерированного скрипта (анти-задержка /status)
# ─────────────────────────────────────────────────────────────────────────────
class TestGeneratedBotParallelFetch(unittest.TestCase):
    """Пиры опрашиваются параллельно; есть фолбэк на последовательный опрос."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from chimera.modules.tg_bot import _generate_bot_script
        cls.script = _generate_bot_script(
            {"token": "123456:ABC", "admin_id": "111",
             "allowed_users": [111], "invite_tokens": {}},
            {"token": "123456:ABC", "chat_id": "111", "events": {}})

    def test_thread_pool_import_and_use(self):
        self.assertIn("from concurrent.futures import ThreadPoolExecutor",
                      self.script)
        self.assertIn("ThreadPoolExecutor(", self.script)
        self.assertIn("ex.map(_remote_status_dict, CASCADE_PEERS)",
                      self.script)

    def test_sequential_fallback_present(self):
        self.assertIn(
            "results = [_remote_status_dict(p) for p in CASCADE_PEERS]",
            self.script)

    def test_awg_helpers_present(self):
        self.assertIn("def _awg_local_status()", self.script)
        self.assertIn("def _awg_hs_age(text)", self.script)
        self.assertIn("def _awg_svc_active(unit)", self.script)

    def test_local_status_collects_awg(self):
        self.assertIn('d["awg"] = _awg', self.script)

    def test_compiles(self):
        import ast
        ast.parse(self.script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
