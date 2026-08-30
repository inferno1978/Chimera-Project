#!/usr/bin/env python3
"""
tests/test_v61_xray_dns_via_agh.py
───────────────────────────────────────────────────────────────────────────────
v61: порядок установки AGH→Xray + гарантия «запросы Xray идут через AGH».

Инцидент (переустановка 203.0.113.109, Режим B): AGH ставится ДО Xray,
финализация AGH пыталась перегенерировать конфиг Xray, которого ещё нет
(state.json пишется только в конце установки):
  [WARN] AGH: state.json не найден — конфиг Xray не перегенерирован
При этом оставалась неясность: пойдут ли DNS-запросы Xray через AGH,
DNSCrypt или системный резольвер.

Контракт v61:
  1. _regenerate_xray_config — mid-install (INSTALL_STARTED=True,
     INSTALL_COMPLETED=False) или state.json нет → INFO-пропуск, не WARN;
     _load_state_into_globals() НЕ вызывается (глобали установки не
     затираются старым state.json при переустановке поверх живой).
  2. Пост-инсталл (меню, INSTALL_COMPLETED=True) — регенерация как раньше.
  3. _xray_config_uses_agh_dns — первый DNS-сервер конфига = AGH:53.
  4. _verify_xray_dns_via_agh (конец do_full_install):
     • AGH не выбран → молча;
     • конфиг через AGH → success «DNS-путь подтверждён»;
     • конфиг мимо AGH, AGH мёртв → info-fallback (не warn — о факте
       уже предупредили на шаге 1.5);
     • конфиг мимо AGH, AGH жив → регенерация генератором из in-memory
       глобалей (Б/А-REALITY/А-xHTTP) + рестарт + повторная проверка.
  5. do_full_install: верификация ПОСЛЕ сохранения state.json и ДО
     run_full_health_check().
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_v60/test_aghome_setup)."""
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


def _rec():
    """Рекордер вызовов лог-функций."""
    calls: list = []

    def f(msg, *a, **kw):
        calls.append(msg)

    f.calls = calls
    return f


def _cfg(dns_servers) -> dict:
    return {"dns": {"servers": dns_servers}}


AGH_FIRST = [{"address": "127.0.0.1", "port": 53, "network": "udp",
              "skipFallback": False}]
DNSCRYPT_FIRST = [{"address": "127.0.0.1", "port": 5300, "network": "udp",
                   "skipFallback": False}]


# ─────────────────────────────────────────────────────────────────────────────
#  1. _regenerate_xray_config — порядок установки (INFO, не WARN)
# ─────────────────────────────────────────────────────────────────────────────
class TestRegenXrayConfigInstallOrder(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))

    def _core(self, started, completed):
        info, warn = _rec(), _rec()
        return SimpleNamespace(
            info=info, warn=warn,
            INSTALL_STARTED=started, INSTALL_COMPLETED=completed,
            _load_state_into_globals=MagicMock(),
        ), info, warn

    def _state(self):
        st = self._tmpdir / "state.json"
        st.write_text(json.dumps(
            {"protocol_mode": "reality", "install_mode": "B"}))
        return st

    def test_mid_install_skips_regen(self):
        """Идёт do_full_install (AGH до Xray) → пропуск с INFO; глобали
        установки НЕ затираются старым state.json (ключевой сценарий
        переустановки поверх живой установки)."""
        core, info, warn = self._core(started=True, completed=False)
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE", self._state()):
            self.assertTrue(self.mod._regenerate_xray_config())
        core._load_state_into_globals.assert_not_called()
        self.assertFalse(warn.calls, msg=f"warn не должен зваться: {warn.calls}")
        self.assertTrue(any("установка в процессе" in m for m in info.calls),
                        msg=str(info.calls))

    def test_fresh_install_no_state_skips_regen(self):
        """Чистая установка: state.json нет (он пишется в конце) → INFO,
        не WARN — конфиг создаст AGH-aware генератор установки."""
        core, info, warn = self._core(started=True, completed=False)
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE",
                          self._tmpdir / "missing.json"):
            self.assertTrue(self.mod._regenerate_xray_config())
        core._load_state_into_globals.assert_not_called()
        self.assertFalse(warn.calls, msg=str(warn.calls))
        self.assertTrue(any("AGH:" in m and "AGH:53" in m for m in info.calls),
                        msg=str(info.calls))

    def test_menu_no_install_session_skips_when_no_state(self):
        """Меню без установки в этом процессе + state.json нет → тот же
        INFO-пропск (Xray не установлен на этой машине)."""
        core, info, warn = self._core(started=False, completed=False)
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE",
                          self._tmpdir / "missing.json"):
            self.assertTrue(self.mod._regenerate_xray_config())
        self.assertFalse(warn.calls, msg=str(warn.calls))
        self.assertTrue(any("Xray ещё не установлен" in m for m in info.calls),
                        msg=str(info.calls))

    def test_post_install_menu_still_regenerates(self):
        """Меню ПОСЛЕ завершённой установки (INSTALL_COMPLETED=True) →
        регенерация выполняется как раньше (AGH включают поверх живой
        установки — конфиг обязан переключиться на AGH:53)."""
        core, info, warn = self._core(started=True, completed=True)
        fake_cn = types.ModuleType("chimera.modules.chain_nodes")
        fake_cn.generate_xray_config_chain_entry_multi = MagicMock()
        fake_xi = types.ModuleType("chimera.modules.xray_install")
        fake_xi.generate_xray_config = MagicMock()
        fake_xi.generate_xray_config_xhttp = MagicMock()
        import chimera.modules as cm_pkg
        saved = tuple(sys.modules.get(k) for k in
                      ("chimera.modules.chain_nodes",
                       "chimera.modules.xray_install"))
        saved_attrs = tuple(getattr(cm_pkg, a, None) for a in
                            ("chain_nodes", "xray_install"))
        sys.modules["chimera.modules.chain_nodes"] = fake_cn
        sys.modules["chimera.modules.xray_install"] = fake_xi
        cm_pkg.chain_nodes = fake_cn
        cm_pkg.xray_install = fake_xi
        self.addCleanup(self._restore, saved, saved_attrs)
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE", self._state()), \
             patch.object(self.mod, "_svc_is_active", return_value=True), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            self.assertTrue(self.mod._regenerate_xray_config())
        fake_cn.generate_xray_config_chain_entry_multi.assert_called_once()
        core._load_state_into_globals.assert_called_once()

    def _restore(self, saved, saved_attrs):
        import chimera.modules as cm_pkg
        for key, mod in zip(("chimera.modules.chain_nodes",
                             "chimera.modules.xray_install"), saved):
            if mod is not None:
                sys.modules[key] = mod
            else:
                sys.modules.pop(key, None)
        for attr, mod in zip(("chain_nodes", "xray_install"), saved_attrs):
            if mod is not None:
                setattr(cm_pkg, attr, mod)
            elif hasattr(cm_pkg, attr):
                delattr(cm_pkg, attr)


# ─────────────────────────────────────────────────────────────────────────────
#  2. _xray_config_uses_agh_dns — фактический config.json
# ─────────────────────────────────────────────────────────────────────────────
class TestXrayConfigUsesAghDns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = _setup_core_in_sysmodules()

    def _write(self, cfg) -> Path:
        d = Path(tempfile.mkdtemp())
        p = d / "config.json"
        p.write_text(json.dumps(cfg))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        return p

    def test_agh_first_server(self):
        p = self._write(_cfg(AGH_FIRST + DNSCRYPT_FIRST))
        self.assertTrue(self.core._xray_config_uses_agh_dns(p))

    def test_dnscrypt_first_server(self):
        p = self._write(_cfg(DNSCRYPT_FIRST))
        self.assertFalse(self.core._xray_config_uses_agh_dns(p))

    def test_public_dns_only(self):
        p = self._write(_cfg([{"address": "1.1.1.1", "port": 53}]))
        self.assertFalse(self.core._xray_config_uses_agh_dns(p))

    def test_port_53_wrong_address(self):
        p = self._write(_cfg([{"address": "127.0.0.53", "port": 53}]))
        self.assertFalse(self.core._xray_config_uses_agh_dns(p))

    def test_no_dns_section(self):
        p = self._write({"inbounds": []})
        self.assertFalse(self.core._xray_config_uses_agh_dns(p))

    def test_broken_json(self):
        d = Path(tempfile.mkdtemp())
        p = d / "config.json"
        p.write_text("{broken")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        self.assertFalse(self.core._xray_config_uses_agh_dns(p))


# ─────────────────────────────────────────────────────────────────────────────
#  3. _verify_xray_dns_via_agh — гарантия DNS-пути в конце установки
# ─────────────────────────────────────────────────────────────────────────────
class TestVerifyXrayDnsViaAgh(unittest.TestCase):
    def setUp(self):
        self.core = _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.ags = ags
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))
        # «серверная» айдентика: лог-функции и сервисы — рекордеры/моки
        self._success, self._info, self._warn = _rec(), _rec(), _rec()
        self._log = _rec()
        gl = self.core._verify_xray_dns_via_agh.__globals__
        self._gen = MagicMock()
        self._gen_xhttp = MagicMock()
        self._gen_chain = MagicMock()
        self._wait = MagicMock(return_value=True)
        self._run = MagicMock()
        self._base = patch.dict(gl, {
            "success": self._success, "info": self._info,
            "warn": self._warn, "log_to_file": self._log,
            "CONFIG_DIR": self._tmpdir,
            "PARAM_USE_AGHOME": True,
            "INSTALL_MODE": "B", "PROTOCOL_MODE": "reality",
            "generate_xray_config": self._gen,
            "generate_xray_config_xhttp": self._gen_xhttp,
            "generate_xray_config_chain_entry_multi": self._gen_chain,
            "_wait_service_active": self._wait,
            "_run": self._run,
        })
        self._base.start()
        self.addCleanup(self._base.stop)

    def _write_cfg(self, servers):
        (self._tmpdir / "config.json").write_text(json.dumps(_cfg(servers)))

    def test_agh_not_selected_silent(self):
        """AGH не выбран → проверка молча неактивна (no-op)."""
        gl = self.core._verify_xray_dns_via_agh.__globals__
        with patch.dict(gl, {"PARAM_USE_AGHOME": False}):
            self.assertFalse(self.core._verify_xray_dns_via_agh())
        self.assertFalse(self._success.calls)
        self.assertFalse(self._warn.calls)

    def test_no_config_silent(self):
        """config.json отсутствует → молчим (КРИТИЧНО выдаст финальная
        проверка do_full_install, не дублируем)."""
        self.assertFalse(self.core._verify_xray_dns_via_agh())
        self.assertFalse(self._warn.calls)
        self.assertFalse(self._success.calls)

    def test_config_with_agh_confirmed(self):
        """Первый DNS-сервер = AGH:53 → success, регенерация не нужна."""
        self._write_cfg(AGH_FIRST + DNSCRYPT_FIRST)
        self.assertTrue(self.core._verify_xray_dns_via_agh())
        self.assertTrue(any("подтверждён" in m for m in self._success.calls),
                        msg=str(self._success.calls))
        self.assertFalse(self._gen_chain.called)
        self.assertFalse(self._warn.calls)

    def test_config_not_agh_agh_dead_fallback(self):
        """Конфиг мимо AGH и AGH не поднялся → info-fallback без нового
        warn (об этом уже сообщили на шаге 1.5 запуска сервисов)."""
        self._write_cfg(DNSCRYPT_FIRST)
        with patch.object(self.ags, "aghome_dns_ready",
                          return_value=False):
            self.assertFalse(self.core._verify_xray_dns_via_agh())
        self.assertFalse(self._gen_chain.called)
        self.assertFalse(self._warn.calls, msg=str(self._warn.calls))
        self.assertTrue(any("fallback" in m for m in self._info.calls),
                        msg=str(self._info.calls))

    def test_config_not_agh_agh_alive_regenerates_mode_b(self):
        """Конфиг мимо AGH, AGH жив → регенерация chain-multi генератором,
        рестарт xray, повторная проверка → success «исправлен»."""
        self._write_cfg(DNSCRYPT_FIRST)

        def fake_gen():
            self._write_cfg(AGH_FIRST)

        self._gen_chain.side_effect = fake_gen
        with patch.object(self.ags, "aghome_dns_ready", return_value=True):
            self.assertTrue(self.core._verify_xray_dns_via_agh())
        self._gen_chain.assert_called_once()
        self.assertTrue(any("исправлен" in m for m in self._success.calls),
                        msg=str(self._success.calls))
        # рестарт через reset-failed (start-limit защита v57)
        restarts = [c for c in self._run.call_args_list
                    if c[0][0][:2] == ["systemctl", "restart"]]
        self.assertTrue(restarts, msg=str(self._run.call_args_list))
        self.assertTrue(any(
            c[0][0][:2] == ["systemctl", "reset-failed"]
            for c in self._run.call_args_list))

    def test_regen_generator_selection_mode_a_reality(self):
        gl = self.core._verify_xray_dns_via_agh.__globals__
        self._write_cfg(DNSCRYPT_FIRST)
        self._gen.side_effect = lambda: self._write_cfg(AGH_FIRST)
        with patch.dict(gl, {"INSTALL_MODE": "A",
                             "PROTOCOL_MODE": "reality"}), \
             patch.object(self.ags, "aghome_dns_ready", return_value=True):
            self.assertTrue(self.core._verify_xray_dns_via_agh())
        self._gen.assert_called_once()
        self._gen_chain.assert_not_called()

    def test_regen_generator_selection_mode_a_xhttp(self):
        gl = self.core._verify_xray_dns_via_agh.__globals__
        self._write_cfg(DNSCRYPT_FIRST)
        self._gen_xhttp.side_effect = lambda: self._write_cfg(AGH_FIRST)
        with patch.dict(gl, {"INSTALL_MODE": "A",
                             "PROTOCOL_MODE": "xhttp"}), \
             patch.object(self.ags, "aghome_dns_ready", return_value=True):
            self.assertTrue(self.core._verify_xray_dns_via_agh())
        self._gen_xhttp.assert_called_once()

    def test_regen_fails_real_warn(self):
        """Регенерация не помогла (генератор упал) → честный warn — это
        реальная проблема, не ложный сигнал."""
        self._write_cfg(DNSCRYPT_FIRST)
        self._gen_chain.side_effect = RuntimeError("boom")
        with patch.object(self.ags, "aghome_dns_ready", return_value=True):
            self.assertFalse(self.core._verify_xray_dns_via_agh())
        self.assertTrue(self._warn.calls, msg="ожидался warn о реальном сбое")
        self.assertTrue(any("fallback" in m for m in self._warn.calls))


# ─────────────────────────────────────────────────────────────────────────────
#  4. Статические пины — порядок do_full_install + исчезновение старого WARN
# ─────────────────────────────────────────────────────────────────────────────
class TestStaticPinsV61(unittest.TestCase):
    def test_do_full_install_order_state_verify_health(self):
        """Верификация DNS-пути: ПОСЛЕ сохранения state.json (генераторам
        регенерации он уже нужен) и ДО run_full_health_check (отчёт видит
        исправленный конфиг)."""
        src = _read("chimera/_core.py")
        idx_verify = src.index("_verify_xray_dns_via_agh()\n")
        idx_health = src.index("run_full_health_check()\n")
        idx_state = src.rindex("STATE_FILE.write_text", 0, idx_verify)
        self.assertLess(idx_state, idx_verify)
        self.assertLess(idx_verify, idx_health)

    def test_verify_call_guarded_by_param_use_aghome(self):
        """Вызов верификации — только при PARAM_USE_AGHOME (иначе тихо)."""
        src = _read("chimera/_core.py")
        idx_guard = src.index("if PARAM_USE_AGHOME:\n"
                              "        try:\n"
                              "            _verify_xray_dns_via_agh()")
        self.assertGreater(idx_guard, 0)

    def test_old_warn_string_gone(self):
        """Старый ложный WARN «state.json не найден — конфиг Xray не
        перегенерирован» исчез из aghome_setup.py."""
        src = _read("chimera/modules/aghome_setup.py")
        self.assertNotIn(
            "state.json не найден — конфиг Xray не перегенерирован", src)

    def test_mid_install_marker_used(self):
        """_regenerate_xray_config различает «идёт установка» и меню по
        INSTALL_STARTED/INSTALL_COMPLETED."""
        src = _read("chimera/modules/aghome_setup.py")
        self.assertIn("INSTALL_COMPLETED", src)
        self.assertIn("INSTALL_STARTED", src)


if __name__ == "__main__":
    unittest.main()
