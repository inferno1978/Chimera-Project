#!/usr/bin/env python3
"""
tests/test_nginx_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/nginx_watchdog.py.

Покрывает:
  1. _protocol_mode — чтение из state.json
  2. Волна-4 (канон уведомлений): генерация скрипта — мост --tg-event
     первым (port_blocked/xray_up/xray_down) + канон-фолбэк _notify_tg
     (creds/events из telegram.json, шапка server_name · домен · IP).
  3. Фолбэк-семантика: нет token/chat_id → молчим (как раньше);
     events-ключ выключен → молчим.
  4. Python-путь _nginx_watchdog_run: тексты без дублирующей шапки
     hostname (шапку/иконку даёт конвейер tg_notify_event).
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestNginxWatchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_protocol_mode_reality(self):
        from chimera.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"protocol_mode": "reality"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)
    def test_protocol_mode_default(self):
        from chimera.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"other": "x"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)


# ── Волна-4: канон-генерация скрипта ─────────────────────────────────────────

def _extract_notify_tg(script: str) -> str:
    """Извлекает bash-функцию _notify_tg из сгенерированного скрипта."""
    lines = script.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.strip().startswith("_notify_tg() {"))
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].strip() == "}")
    return "\n".join(lines[start:end + 1])


class TestWatchdogScriptCanon(unittest.TestCase):
    """Генерация: мост --tg-event первым, _notify_tg — канон-фолбэк."""

    def setUp(self):
        _setup_core()
        from chimera.modules import nginx_watchdog
        self.nw = nginx_watchdog
        self.script = nginx_watchdog._build_watchdog_script()

    def test_bridge_first_port_blocked(self):
        """port_blocked: мост первым (guard -x main.py), фолбэк _notify_tg."""
        self.assertIn('--tg-event port_blocked', self.script)
        self.assertIn('if [[ -x "', self.script)
        self.assertIn('_notify_tg port_blocked', self.script)

    def test_bridge_xray_up_down(self):
        """nginx перезапущен/НЕ поднялся: мост xray_up/xray_down + фолбэк."""
        self.assertIn('--tg-event xray_up', self.script)
        self.assertIn('--tg-event xray_down', self.script)
        self.assertIn('_notify_tg xray_up', self.script)
        self.assertIn('_notify_tg xray_down', self.script)

    def test_fallback_creds_from_telegram_json(self):
        """Креды фолбэка — telegram.json (token/chat_id/proxy), НЕ легаси state."""
        fn = _extract_notify_tg(self.script)
        self.assertIn('"/var/lib/xray-installer/telegram.json"', fn)
        self.assertIn("get('token','')", fn)
        self.assertIn("get('chat_id','')", fn)
        self.assertIn("get('proxy','')", fn)
        self.assertNotIn("tg_bot_token", self.script,
                         "легаси-креды state.json в _notify_tg")

    def test_fallback_events_filter(self):
        """events-фильтр в фолбэке: ключ выключен → молчим (как конвейер)."""
        fn = _extract_notify_tg(self.script)
        self.assertIn("d.get('events',{})", fn)
        self.assertIn("|| return", fn)

    def test_fallback_canonical_header(self):
        """Шапка фолбэка — канон: server_name · domain · server_ip (фолбэк host)."""
        fn = _extract_notify_tg(self.script)
        self.assertIn("get('server_name','')", fn)
        self.assertIn("get('domain','')", fn)
        self.assertIn("get('server_ip','')", fn)
        self.assertIn("H=\"$H · $DOM\"", fn)
        self.assertIn("H=\"$H · $SIP\"", fn)
        self.assertIn('text=${ICON} <b>[${H}]</b> ${MSG}', fn)

    def test_bash_syntax(self):
        """Сгенерированный скрипт проходит bash -n."""
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(self.script)
            p = f.name
        self.addCleanup(os.unlink, p)
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.returncode, 0, f"bash -n: {r.stderr}")

    def test_shebang_at_byte_zero(self):
        """Reality-режим (xray_reload != ''): dedent срезает отступ —
        shebang с байта 0, иначе systemd/cron не видит интерпретатор."""
        self.assertTrue(self.script.startswith("#!/bin/bash\n"),
                        f"скрипт начинается с: {self.script[:40]!r}")
        self.assertIn("systemctl reload xray", self.script)  # reality-блок есть


class TestPythonPathNoDuplicateHeader(unittest.TestCase):
    """_nginx_watchdog_run: тексты без hostname/иконки — их даёт конвейер."""

    def setUp(self):
        _setup_core()
        from chimera.modules import nginx_watchdog
        self.nw = nginx_watchdog

    def _run(self, active_after_restart: bool, recorded: list):
        with patch.object(self.nw, "_is_active",
                          side_effect=[False, active_after_restart]), \
             patch.object(self.nw, "_curl_localhost_http", lambda: ""), \
             patch.object(self.nw, "_run", lambda cmd: 0), \
             patch.object(self.nw, "_log", lambda *a: None), \
             patch.object(self.nw, "_tg_event",
                          side_effect=lambda ev, d: recorded.append((ev, d))), \
             patch.object(self.nw, "_protocol_mode", lambda: "vless"), \
             patch.object(self.nw, "_get_vless_port", lambda: 443), \
             patch.object(self.nw, "_hostname", lambda: "ZZZ-SHOULD-NOT-LEAK"), \
             patch.object(self.nw.time, "sleep", lambda s: None), \
             patch.object(self.nw.subprocess, "run",
                          return_value=MagicMock(stdout="")):
            self.nw._nginx_watchdog_run()

    def test_up_text_no_hostname_dup(self):
        recorded = []
        self._run(True, recorded)
        self.assertEqual(recorded, [("xray_up", "nginx-watchdog: nginx перезапущен")])
        self.assertNotIn("ZZZ-SHOULD-NOT-LEAK", recorded[0][1])

    def test_down_text_no_hostname_dup(self):
        recorded = []
        self._run(False, recorded)
        self.assertEqual(recorded,
                         [("xray_down", "nginx-watchdog: nginx НЕ запустился")])
        self.assertNotIn("ZZZ-SHOULD-NOT-LEAK", recorded[0][1])


# ── Волна-4: функциональный прогон канон-фолбэка _notify_tg ──────────────────

class _NotifyTgSandbox(unittest.TestCase):
    """Изолированный прогон bash-функции _notify_tg (tmp-пути, stub curl)."""

    def setUp(self):
        _setup_core()
        from chimera.modules import nginx_watchdog
        self.tmp = Path(tempfile.mkdtemp())
        self.lib = self.tmp / "lib"                      # /var/lib/xray-installer
        self.bindir = self.tmp / "bin"                   # PATH со стабами
        self.lib.mkdir(parents=True)
        self.bindir.mkdir(parents=True)
        script = nginx_watchdog._build_watchdog_script()
        fn = _extract_notify_tg(script)
        fn = fn.replace("/var/lib/xray-installer", str(self.lib))
        # state.json — источник домена (ленивое чтение, канон server_header)
        fn = fn.replace(str(Path("/var/lib/xray-installer/state.json")),
                        str(self.lib / "state.json"))
        # стаб curl: пишет аргументы в файл (боевой TG из тестов не зовётся)
        (self.bindir / "curl").write_text(
            "#!/bin/bash\nprintf '%s\\n' \"$@\" > '" + str(self.tmp / "curl.args") + "'\n"
        )
        (self.bindir / "curl").chmod(0o755)
        (self.bindir / "hostname").write_text("#!/bin/bash\necho testhost\n")
        (self.bindir / "hostname").chmod(0o755)
        self.mini = self.tmp / "mini.sh"
        self.mini.write_text(f"#!/bin/bash\n{fn}\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_tg(self, cfg: dict):
        (self.lib / "telegram.json").write_text(json.dumps(cfg, ensure_ascii=False))

    def _call(self, ev="xray_down", icon="🔴", msg="nginx-watchdog: nginx НЕ запустился"):
        self.mini.write_text(
            self.mini.read_text()
            + f'\n_notify_tg {ev} "{icon}" "{msg}"\n'
        )
        env = dict(os.environ)
        env["PATH"] = f"{self.bindir}:{env.get('PATH', '')}"
        r = subprocess.run(["bash", str(self.mini)], capture_output=True,
                           text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        f = self.tmp / "curl.args"
        return f.read_text() if f.exists() else ""

    def test_silent_when_no_token(self):
        """Фолбэк-семантика: нет token/chat_id → молчим (как раньше)."""
        self._write_tg({"token": "", "chat_id": ""})
        self.assertEqual(self._call(), "")

    def test_muted_when_event_disabled(self):
        """events.xray_down == false → молчим (фильтр конвейера в фолбэке);
        молчание = rc 0 (не маркер падения systemd-unit'а)."""
        self._write_tg({"token": "T", "chat_id": "C",
                        "events": {"xray_down": False, "xray_up": True}})
        self.assertEqual(self._call(), "")

    def test_sent_when_event_enabled(self):
        self._write_tg({"token": "T", "chat_id": "C",
                        "events": {"xray_down": True}})
        args = self._call()
        self.assertIn("sendMessage", args)

    def test_sent_when_no_events_key(self):
        """Нет ключа events → слать (нет ключа = ВКЛ, как конвейер)."""
        self._write_tg({"token": "T", "chat_id": "C"})
        self.assertIn("sendMessage", self._call())

    def test_canonical_header_and_format(self):
        """Шапка — server_name · домен · IP; формат {icon} <b>[H]</b> {detail}."""
        self._write_tg({"token": "T", "chat_id": "C",
                        "server_name": "RU1", "server_ip": "203.0.113.10"})
        (self.lib / "state.json").write_text(
            json.dumps({"domain": "node-ru1.example.com"}))
        args = self._call()
        self.assertIn("text=🔴 <b>[RU1 · node-ru1.example.com · 203.0.113.10]</b>"
                      " nginx-watchdog: nginx НЕ запустился", args)
        self.assertNotIn("testhost", args,
                         "фолбэк на hostname не нужен при заданном server_name")

    def test_fallback_hostname_when_no_server_name(self):
        """Нет server_name/domain → шапка из hostname (обратная совместимость)."""
        self._write_tg({"token": "T", "chat_id": "C", "server_ip": "203.0.113.10"})
        args = self._call()
        self.assertIn("text=🔴 <b>[testhost · 203.0.113.10]</b>", args)


# ── system_deps ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
