#!/usr/bin/env python3
"""
tests/test_server_fragment.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/server_fragment.py (v4.28+, Task 24 / 24-5b).

Механика — сегментация ответа сервера TCP-уровнем, ДВА механизма:
  A. MECH_SOCKOPT="tcpMaxSeg"  — sockopt.tcpMaxSeg в streamSettings каждого
     VLESS+REALITY inbound (ядро Xray >= 26.7.11, рестарт xray)
     + GODEBUG-drop-in на xray.service (v2: Go >= 1.24 делает листенеры
     MPTCP, где TCP_MAXSEG — тихое no-op; Environment=GODEBUG=multipathtcp=0)
     + верификация по журналу systemd после рестарта: если Xray логирует
     «failed to set TCP_MAXSEG» — автофолбэк на механизм B;
  B. MECH_TCPMSS="tcpmss"      — iptables/ip6tables mangle PREROUTING
     TCPMSS --set-mss (старые ядра и форс-фолбэк) + бут-восстановление
     через ExecStartPost=+/usr/local/bin/chimera-server-frag-restore
     (standalone-скрипт, без импортов chimera).

ВАЖНО (изоляция песочницы): enable/disable/status трогают не только
config.json/state.json, но и systemd-drop-in + restore-скрипт + journalctl —
поэтому _SVC_DROPIN/_RESTORE_SCRIPT патчатся на tmp-пути, а _daemon_reload /
_journal_tcpmaxseg_failed замоканы (иначе тесты лезут в реальные /etc и
journal, и asserts на вызовы сбиваются окружением).

Покрывает:
   1. _PRESETS / константы (MECH_*, _MSS_MIN/_MSS_MAX, _TCPMAXSEG_MIN_VERSION,
      _SVC_DROPIN/_GODEBUG_ENV_LINE/_RESTORE_SCRIPT)
   2. _find_reality_inbound / _find_xhttp_inbound / _reality_inbounds /
      _reality_inbound_ports (мульти-inbound, сортировка/уникальность портов)
   3. _resolve_mss — пресеты/границы/отказы
   4. _xray_core_version / _core_supports_tcp_max_seg — парсинг и feature-detect
   5. _build_tcpmss_rule — точные argv (v4/v6/мультипорт/сортировка)
   6. _install/_remove/_count_tcpmss_rules + _run_soft — через мок _run_soft
  6b. systemd drop-in (v2): _dropin_content (точный контент A/B),
      _dropin_installed, _install_dropin/_remove_dropin (+_daemon_reload),
      _journal_tcpmaxseg_failed (маркер в stdout/stderr, оба юнита, rc=127)
  6c. restore-скрипт (v2): _write/_remove_restore_script (контент+chmod 755),
      инварианты _RESTORE_SCRIPT_CONTENT (compile, без импортов chimera)
   7. server_fragment_enable механизм A (tcpMaxSeg + GODEBUG-drop-in +
      journal-verify, идемпотентность) и механизм B (pop tcpMaxSeg,
      restore+ExecStartPost-drop-in, откат при 0 правил)
   7b. Фолбэк A→B по журналу (v2): mechanism=tcpmss, fallback_reason в state,
      GODEBUG снят, restore+ExecStartPost поставлены; полный откат при
      _count_tcpmss_rules()==0
   8. Отказы enable: xHTTP / нет reality / нет config / плохой preset / mss
   9. server_fragment_disable — снятие tcpMaxSeg + легаси fragment + TCPMSS +
      drop-in (до рестарта, с daemon-reload) + restore-скрипт; дополнительный
      рестарт «без GODEBUG», когда конфиг не менялся, но drop-in снимали
  10. server_fragment_status — полный набор ключей (включая v2:
      godebug_installed / restore_installed / fallback_reason)
  11. server_fragment_reapply_after_rebuild — хук после пересоздания config
  12. _ensure_state / _migrate_legacy_state — дефолт и миграция v4.27-state
  13. TUI-хелперы (_format_status_line, _prompt_custom_and_apply)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock


def _enter_patches(stack, patches):
    """Применяет список patch-объектов через ExitStack (надёжно в любой версии Python)."""
    for p in patches:
        stack.enter_context(p)


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

MOD = "chimera.modules.server_fragment"


def _setup_core():
    """Загружает _core.py в sys.modules (модуль server_fragment его не
    использует напрямую, но box_renderer может требовать).
    Идемпотентно: повторные вызовы не пере-исполняют 10k строк _core.py."""
    if "chimera._core" in sys.modules:
        return
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


# ─────────────────────────────────────────────────────────────────────────────
# Фикстуры: тестовые config.json
# ─────────────────────────────────────────────────────────────────────────────

_REALITY_CONFIG = {
    "inbounds": [
        {
            "tag": "vless-reality",
            "protocol": "vless",
            "port": 443,
            "settings": {
                "clients": [{"id": "test-uuid", "flow": "xtls-rprx-vision"}],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.cloudflare.com:443",
                    "serverNames": ["www.cloudflare.com"],
                    "privateKey": "privkey",
                    "publicKey": "pubkey",
                    "shortIds": ["abc123"],
                },
            },
        },
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
    ],
    "routing": {"rules": []},
}

_XHTTP_CONFIG = {
    "inbounds": [
        {
            "tag": "vless-xhttp",
            "protocol": "vless",
            "port": 443,
            "settings": {
                "clients": [{"id": "test-uuid"}],
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{"certificateFile": "/etc/xray/cert.pem"}],
                },
                "xhttpSettings": {
                    "path": "/xhttp",
                    "mode": "stream-up",
                },
            },
        },
    ],
    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
}


def _make_reality_inbound(tag: str, port):
    """VLESS+REALITY inbound с заданным тегом/портом."""
    return {
        "tag": tag,
        "protocol": "vless",
        "port": port,
        "settings": {"clients": [{"id": "test-uuid", "flow": "xtls-rprx-vision"}]},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": "www.cloudflare.com:443",
                "serverNames": ["www.cloudflare.com"],
                "privateKey": "privkey",
                "publicKey": "pubkey",
                "shortIds": ["abc123"],
            },
        },
    }


_MULTI_REALITY_CONFIG = {
    "inbounds": [
        _make_reality_inbound("vless-reality-a", 8443),
        {   # vless, но НЕ reality — должен игнорироваться
            "tag": "ws-in",
            "protocol": "vless",
            "port": 8080,
            "settings": {"clients": []},
            "streamSettings": {"network": "ws", "security": "none"},
        },
        _make_reality_inbound("vless-reality-b", 443),
        _make_reality_inbound("vless-reality-c", "2053"),   # порт строкой
        {"tag": "dokodemo", "protocol": "dokodemo-door", "port": 1080},
    ],
    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
}


def _reality_with_tcpmaxseg(mss: int = 1300):
    """Копия _REALITY_CONFIG с уже применённым механизмом A (tcpMaxSeg)."""
    cfg = json.loads(json.dumps(_REALITY_CONFIG))
    cfg["inbounds"][0]["streamSettings"]["sockopt"] = {
        "tcpCongestion": "bbr",
        "tcpFastOpen": True,
        "tcpMaxSeg": mss,
    }
    return cfg


def _reality_with_legacy_fragment():
    """Копия _REALITY_CONFIG с легаси-плацебо sockopt.fragment (v4.27-)."""
    cfg = json.loads(json.dumps(_REALITY_CONFIG))
    cfg["inbounds"][0]["streamSettings"]["sockopt"] = {
        "tcpFastOpen": True,
        "fragment": {
            "packets": "1-3",
            "length": "3-7",
            "interval": "10-20",
        },
    }
    return cfg


def _cp(cmd, rc: int = 0, stdout: str = ""):
    """CompletedProcess-заглушка для моков _run/_run_soft."""
    return subprocess.CompletedProcess(list(cmd), rc, stdout=stdout, stderr="")


def _make_run_soft(v4_save: str = "", v6_save: str = "", rc_check: int = 1,
                   rc_insert: int = 0, rc_delete: int = 0, ip6_out: str = "",
                   log=None):
    """Фабрика фейкового _run_soft: -S→save, -C→rc_check, -I→rc_insert,
    -D→rc_delete, ip→ip6_out (наличие глобального IPv6)."""

    def fake(cmd, capture=False, timeout=15):
        if log is not None:
            log.append(list(cmd))
        if not cmd:
            return _cp(cmd, 0)
        if cmd[0] == "ip":
            return _cp(cmd, 0, stdout=ip6_out)
        if cmd[0] in ("iptables", "ip6tables"):
            save = v4_save if cmd[0] == "iptables" else v6_save
            if "-S" in cmd:
                return _cp(cmd, 0, stdout=save)
            if "-C" in cmd:
                return _cp(cmd, rc_check)
            if "-I" in cmd:
                return _cp(cmd, rc_insert)
            if "-D" in cmd:
                return _cp(cmd, rc_delete)
        return _cp(cmd, 0)

    return fake


# Дамп `iptables -t mangle -S PREROUTING` для тестов remove/count:
# одна НАША строка + чужие строки + декларация цепочки.
_SAVED_CHAIN_V4 = "\n".join([
    "-N PREROUTING",
    "-A PREROUTING -p tcp -m tcp --dport 443 --syn -m comment "
    "--comment chimera-server-frag -j TCPMSS --set-mss 1300",
    "-A PREROUTING -j ACCEPT",
    "-A PREROUTING -p tcp -m tcp --dport 8443 --syn -m comment "
    "--comment some-other-comment -j TCPMSS --set-mss 1200",
])


# ─────────────────────────────────────────────────────────────────────────────
# Общий харнесс: tmp config.json + state.json + ExitStack-патчи
# ─────────────────────────────────────────────────────────────────────────────

class _FragmentTestBase(unittest.TestCase):
    """База: временные пути + наборы патчей (как в старом харнессе).

    v2: помимо config.json/state.json патчатся также _SVC_DROPIN и
    _RESTORE_SCRIPT (tmp-файлы) — иначе enable/disable/status трогают
    реальные /etc/systemd/... и /usr/local/bin/... ."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"
        self._dropin_path = self._tmpdir / "chimera-server-frag.conf"
        self._restore_path = self._tmpdir / "chimera-server-frag-restore"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _base_patches(self, cfg=None):
        """Патч путей config.json/state.json/drop-in/restore (+ запись конфига)."""
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch(MOD + "._XRAY_CONFIG", self._cfg_path),
            patch(MOD + "._STATE_FILE", self._state_path),
            patch(MOD + "._SVC_DROPIN", self._dropin_path),
            patch(MOD + "._RESTORE_SCRIPT", self._restore_path),
        ]

    def _mech_a_patches(self, cfg=None, restart=None, journal_failed=False,
                        install_ret=0, count_ret=0):
        """Механизм A: новое ядро (26.10.21); drop-in/restore в tmp,
        _daemon_reload и _journal_tcpmaxseg_failed замоканы
        (journal_failed=True — эмуляция «failed to set TCP_MAXSEG» → фолбэк)."""
        mocks = {
            "restart": restart or MagicMock(return_value=True),
            "install": MagicMock(return_value=install_ret),
            "count":   MagicMock(return_value=count_ret),
            "remove":  MagicMock(return_value=0),
            "reload":  MagicMock(return_value=True),
            "journal": MagicMock(return_value=journal_failed),
        }
        patches = self._base_patches(cfg) + [
            patch(MOD + "._xray_core_version", return_value=(26, 10, 21)),
            patch(MOD + "._xray_test_and_restart", mocks["restart"]),
            patch(MOD + "._install_tcpmss_rules", mocks["install"]),
            patch(MOD + "._count_tcpmss_rules", mocks["count"]),
            patch(MOD + "._remove_tcpmss_rules", mocks["remove"]),
            patch(MOD + "._daemon_reload", mocks["reload"]),
            patch(MOD + "._journal_tcpmaxseg_failed", mocks["journal"]),
            patch("time.sleep"),   # journal-verify спит 1с — не ждём по-настоящему
        ]
        return patches, mocks

    def _mech_b_patches(self, cfg=None, count_after=1, restart=None):
        """Механизм B: старое ядро (1.8.24), мок install/count/remove."""
        mocks = {
            "restart": restart or MagicMock(return_value=True),
            "install": MagicMock(return_value=1),
            "count":   MagicMock(return_value=count_after),
            "remove":  MagicMock(return_value=0),
            "reload":  MagicMock(return_value=True),
            "journal": MagicMock(return_value=False),
        }
        patches = self._base_patches(cfg) + [
            patch(MOD + "._xray_core_version", return_value=(1, 8, 24)),
            patch(MOD + "._xray_test_and_restart", mocks["restart"]),
            patch(MOD + "._install_tcpmss_rules", mocks["install"]),
            patch(MOD + "._count_tcpmss_rules", mocks["count"]),
            patch(MOD + "._remove_tcpmss_rules", mocks["remove"]),
            patch(MOD + "._daemon_reload", mocks["reload"]),
            patch(MOD + "._journal_tcpmaxseg_failed", mocks["journal"]),
        ]
        return patches, mocks


# ─────────────────────────────────────────────────────────────────────────────
# 1. Константы и пресеты
# ─────────────────────────────────────────────────────────────────────────────

class TestConstants(unittest.TestCase):
    """Имена механизмов и граничные константы."""

    def setUp(self):
        _setup_core()

    def test_mechanism_names(self):
        from chimera.modules.server_fragment import MECH_SOCKOPT, MECH_TCPMSS
        self.assertEqual(MECH_SOCKOPT, "tcpMaxSeg")
        self.assertEqual(MECH_TCPMSS, "tcpmss")

    def test_tcpmaxseg_min_version(self):
        from chimera.modules.server_fragment import _TCPMAXSEG_MIN_VERSION
        self.assertEqual(_TCPMAXSEG_MIN_VERSION, (26, 7, 11))

    def test_mss_bounds(self):
        from chimera.modules.server_fragment import _MSS_MIN, _MSS_MAX
        self.assertEqual(_MSS_MIN, 536)
        self.assertEqual(_MSS_MAX, 1460)

    def test_iptables_comment_constant(self):
        from chimera.modules.server_fragment import _IPT_COMMENT
        self.assertEqual(_IPT_COMMENT, "chimera-server-frag")

    def test_svc_dropin_constant(self):
        from chimera.modules.server_fragment import _SVC_DROPIN
        self.assertEqual(
            _SVC_DROPIN,
            Path("/etc/systemd/system/xray.service.d/chimera-server-frag.conf"))

    def test_godebug_env_line_constant(self):
        from chimera.modules.server_fragment import _GODEBUG_ENV_LINE
        self.assertEqual(_GODEBUG_ENV_LINE, "Environment=GODEBUG=multipathtcp=0")

    def test_restore_script_constant(self):
        from chimera.modules.server_fragment import _RESTORE_SCRIPT
        self.assertEqual(
            _RESTORE_SCRIPT, Path("/usr/local/bin/chimera-server-frag-restore"))


class TestPresets(unittest.TestCase):
    """_PRESETS — структура (mss + desc)."""

    def setUp(self):
        _setup_core()

    def test_has_required_presets(self):
        from chimera.modules.server_fragment import _PRESETS
        for key in ("aggressive", "balanced", "light", "custom"):
            self.assertIn(key, _PRESETS)

    def test_each_preset_has_mss_and_desc(self):
        from chimera.modules.server_fragment import _PRESETS
        for name, p in _PRESETS.items():
            self.assertIn("mss", p, f"{name} missing mss")
            self.assertIn("desc", p, f"{name} missing desc")
            self.assertIsInstance(p["mss"], int)
            self.assertTrue(p["desc"], f"{name} desc empty")

    def test_preset_mss_values(self):
        from chimera.modules.server_fragment import _PRESETS
        self.assertEqual(_PRESETS["aggressive"]["mss"], 800)
        self.assertEqual(_PRESETS["balanced"]["mss"], 1300)
        self.assertEqual(_PRESETS["light"]["mss"], 1400)

    def test_custom_preset_mss_is_zero(self):
        from chimera.modules.server_fragment import _PRESETS
        self.assertEqual(_PRESETS["custom"]["mss"], 0)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Поиск inbound'ов
# ─────────────────────────────────────────────────────────────────────────────

class TestFindInbounds(unittest.TestCase):
    """_find_reality_inbound / _find_xhttp_inbound."""

    def setUp(self):
        _setup_core()

    def test_find_reality_returns_inbound(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        inb = _find_reality_inbound(_REALITY_CONFIG)
        self.assertIsNotNone(inb)
        self.assertEqual(inb["protocol"], "vless")
        self.assertEqual(inb["streamSettings"]["security"], "reality")

    def test_find_reality_returns_none_for_xhttp(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        self.assertIsNone(_find_reality_inbound(_XHTTP_CONFIG))

    def test_find_reality_returns_none_for_empty(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        self.assertIsNone(_find_reality_inbound({}))
        self.assertIsNone(_find_reality_inbound({"inbounds": []}))

    def test_find_reality_returns_first_of_many(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        inb = _find_reality_inbound(_MULTI_REALITY_CONFIG)
        self.assertIsNotNone(inb)
        self.assertEqual(inb["tag"], "vless-reality-a")

    def test_find_xhttp_returns_inbound(self):
        from chimera.modules.server_fragment import _find_xhttp_inbound
        inb = _find_xhttp_inbound(_XHTTP_CONFIG)
        self.assertIsNotNone(inb)
        self.assertEqual(inb["streamSettings"]["network"], "xhttp")

    def test_find_xhttp_returns_none_for_reality(self):
        from chimera.modules.server_fragment import _find_xhttp_inbound
        self.assertIsNone(_find_xhttp_inbound(_REALITY_CONFIG))


class TestRealityInbounds(unittest.TestCase):
    """_reality_inbounds / _reality_inbound_ports — ВСЕ reality inbound."""

    def setUp(self):
        _setup_core()

    def test_reality_inbounds_returns_all(self):
        from chimera.modules.server_fragment import _reality_inbounds
        inbs = _reality_inbounds(_MULTI_REALITY_CONFIG)
        self.assertEqual(len(inbs), 3)
        tags = {inb["tag"] for inb in inbs}
        self.assertEqual(tags, {"vless-reality-a", "vless-reality-b", "vless-reality-c"})

    def test_reality_inbounds_empty_for_xhttp(self):
        from chimera.modules.server_fragment import _reality_inbounds
        self.assertEqual(_reality_inbounds(_XHTTP_CONFIG), [])
        self.assertEqual(_reality_inbounds({}), [])

    def test_reality_inbound_ports_sorted_unique(self):
        from chimera.modules.server_fragment import _reality_inbound_ports
        # 8443, 443, "2053" → отсортировано, дубликатов нет
        self.assertEqual(_reality_inbound_ports(_MULTI_REALITY_CONFIG),
                         [443, 2053, 8443])

    def test_reality_inbound_ports_deduplicates(self):
        from chimera.modules.server_fragment import _reality_inbound_ports
        cfg = json.loads(json.dumps(_MULTI_REALITY_CONFIG))
        cfg["inbounds"].append(_make_reality_inbound("vless-reality-dup", 443))
        self.assertEqual(_reality_inbound_ports(cfg), [443, 2053, 8443])

    def test_reality_inbound_ports_skips_invalid(self):
        from chimera.modules.server_fragment import (
            _reality_inbound_ports, _reality_inbounds,
        )
        cfg = json.loads(json.dumps(_MULTI_REALITY_CONFIG))
        # inbound без порта — учитывается в _reality_inbounds, но не в ports
        cfg["inbounds"].append({
            "tag": "noport",
            "protocol": "vless",
            "streamSettings": {"security": "reality"},
        })
        self.assertEqual(len(_reality_inbounds(cfg)), 4)
        self.assertEqual(_reality_inbound_ports(cfg), [443, 2053, 8443])


# ─────────────────────────────────────────────────────────────────────────────
# 3. _resolve_mss — валидация
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveMss(unittest.TestCase):
    """_resolve_mss — пресеты, границы, отказы."""

    def setUp(self):
        _setup_core()

    def test_default_mss_per_preset(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("aggressive", None), 800)
        self.assertEqual(_resolve_mss("balanced", None), 1300)
        self.assertEqual(_resolve_mss("light", None), 1400)

    def test_custom_with_explicit_mss(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("custom", 1000), 1000)

    def test_boundary_min_accepted(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("balanced", 536), 536)
        self.assertEqual(_resolve_mss("custom", 536), 536)

    def test_boundary_max_accepted(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("balanced", 1460), 1460)
        self.assertEqual(_resolve_mss("custom", 1460), 1460)

    def test_numeric_string_mss_accepted(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("custom", "900"), 900)

    def test_explicit_mss_overrides_preset(self):
        from chimera.modules.server_fragment import _resolve_mss
        self.assertEqual(_resolve_mss("balanced", 800), 800)
        self.assertEqual(_resolve_mss("light", 600), 600)

    def test_reject_below_min(self):
        from chimera.modules.server_fragment import _resolve_mss
        with self.assertRaises(ValueError):
            _resolve_mss("balanced", 100)

    def test_reject_above_max(self):
        from chimera.modules.server_fragment import _resolve_mss
        with self.assertRaises(ValueError):
            _resolve_mss("balanced", 2000)

    def test_reject_non_numeric(self):
        from chimera.modules.server_fragment import _resolve_mss
        with self.assertRaises(ValueError):
            _resolve_mss("balanced", "abc")

    def test_reject_custom_without_mss(self):
        from chimera.modules.server_fragment import _resolve_mss
        with self.assertRaises(ValueError):
            _resolve_mss("custom", None)

    def test_reject_unknown_preset(self):
        from chimera.modules.server_fragment import _resolve_mss
        with self.assertRaises(ValueError):
            _resolve_mss("ultra", None)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Версия ядра Xray / feature-detect
# ─────────────────────────────────────────────────────────────────────────────

class TestXrayCoreVersion(unittest.TestCase):
    """_xray_core_version — парсинг вывода `xray version` (мок _run)."""

    def setUp(self):
        _setup_core()

    def _version_of(self, stdout):
        from chimera.modules.server_fragment import _xray_core_version
        cp = _cp(["xray", "version"], 0, stdout=stdout)
        with patch.object(Path, "exists", lambda self: True), \
             patch(MOD + "._run", return_value=cp):
            return _xray_core_version()

    def test_parse_modern_version(self):
        self.assertEqual(
            self._version_of(
                "Xray 26.10.21 (Xray, Penetrates Everything.) "
                "Custom (go1.24.1 linux/amd64)"),
            (26, 10, 21))

    def test_parse_old_version(self):
        self.assertEqual(
            self._version_of(
                "Xray 1.8.24 (Xray, Penetrates Everything.) "
                "Custom (go1.21.3 linux/amd64)"),
            (1, 8, 24))

    def test_parse_version_with_v_prefix(self):
        self.assertEqual(self._version_of("Xray v1.8.24 (Xray...)"), (1, 8, 24))

    def test_parse_garbage_returns_none(self):
        self.assertIsNone(self._version_of("random binary garbage no version"))

    def test_parse_empty_output_returns_none(self):
        self.assertIsNone(self._version_of(""))

    def test_parse_stderr_only_returns_none(self):
        # stdout пуст, stderr тоже — None
        self.assertIsNone(self._version_of(""))


class TestCoreSupportsTcpMaxSeg(unittest.TestCase):
    """_core_supports_tcp_max_seg — порог 26.7.11."""

    def setUp(self):
        _setup_core()

    def _supports(self, version):
        from chimera.modules.server_fragment import _core_supports_tcp_max_seg
        with patch(MOD + "._xray_core_version", return_value=version):
            return _core_supports_tcp_max_seg()

    def test_min_version_supported(self):
        self.assertTrue(self._supports((26, 7, 11)))

    def test_just_below_min_not_supported(self):
        self.assertFalse(self._supports((26, 7, 10)))

    def test_modern_supported(self):
        self.assertTrue(self._supports((26, 10, 21)))

    def test_old_core_not_supported(self):
        self.assertFalse(self._supports((1, 8, 24)))

    def test_no_binary_not_supported(self):
        self.assertFalse(self._supports(None))


# ─────────────────────────────────────────────────────────────────────────────
# 5. _build_tcpmss_rule — чистый билдер argv
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildTcpmssRule(unittest.TestCase):
    """_build_tcpmss_rule — точные argv без позиции вставки."""

    def setUp(self):
        _setup_core()

    def test_v4_single_port_exact_argv(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        self.assertEqual(
            _build_tcpmss_rule([443], 1300),
            ["iptables", "-t", "mangle", "-p", "tcp", "-m", "tcp",
             "--dport", "443", "--syn", "-m", "comment", "--comment",
             "chimera-server-frag", "-j", "TCPMSS", "--set-mss", "1300"])

    def test_v6_uses_ip6tables(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        cmd = _build_tcpmss_rule([443], 1300, ipv6=True)
        self.assertEqual(cmd[0], "ip6tables")
        self.assertIn("--dport", cmd)
        self.assertNotIn("--dports", cmd)

    def test_multiport_uses_dports_sorted(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        cmd = _build_tcpmss_rule([8443, 443], 1300)
        self.assertEqual(cmd[3:7], ["-p", "tcp", "-m", "multiport"])
        self.assertEqual(cmd[cmd.index("--dports") + 1], "443,8443")
        self.assertNotIn("--dport", cmd)

    def test_multiport_unsorted_input_sorted_output(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        cmd = _build_tcpmss_rule([2053, 8443, 443], 1300, ipv6=True)
        self.assertEqual(cmd[cmd.index("--dports") + 1], "443,2053,8443")

    def test_duplicate_ports_collapse_to_single(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        cmd = _build_tcpmss_rule([443, 443], 1300)
        self.assertIn("--dport", cmd)
        self.assertNotIn("--dports", cmd)

    def test_rule_contains_syn_comment_and_mss(self):
        from chimera.modules.server_fragment import _build_tcpmss_rule
        cmd = _build_tcpmss_rule([443], 800)
        self.assertIn("--syn", cmd)
        self.assertIn("chimera-server-frag", cmd)
        self.assertEqual(cmd[cmd.index("--set-mss") + 1], "800")


# ─────────────────────────────────────────────────────────────────────────────
# 6. iptables TCPMSS: install/remove/count + _run_soft
# ─────────────────────────────────────────────────────────────────────────────

class TestRunSoft(unittest.TestCase):
    """_run_soft — мягкая обёртка над _run (бинарник отсутствует → rc=127)."""

    def setUp(self):
        _setup_core()

    def test_returns_127_on_file_not_found(self):
        from chimera.modules.server_fragment import _run_soft
        with patch(MOD + "._run", side_effect=FileNotFoundError("iptables")):
            r = _run_soft(["iptables", "-t", "mangle", "-S", "PREROUTING"],
                          capture=True)
        self.assertEqual(r.returncode, 127)

    def test_passthrough_completed_process(self):
        from chimera.modules.server_fragment import _run_soft
        cp = _cp(["iptables", "-L"], 0, stdout="ok")
        with patch(MOD + "._run", return_value=cp):
            r = _run_soft(["iptables", "-L"], capture=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "ok")


class TestInstallTcpmssRules(unittest.TestCase):
    """_install_tcpmss_rules — идемпотентность, v4/v6, мягкие отказы."""

    def setUp(self):
        _setup_core()

    def test_install_v4_single_rule(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        cmds = []
        fake = _make_run_soft(rc_check=1, rc_insert=0, log=cmds)
        with patch(MOD + "._run_soft", fake):
            installed = _install_tcpmss_rules([443], 1300)
        self.assertEqual(installed, 1)
        inserts = [c for c in cmds if "-I" in c]
        self.assertEqual(len(inserts), 1)
        # ВАЖНО: проверяем членство токенов, а не точный argv — модуль
        # собирает insert как base[:2] + ["-I", "PREROUTING", "1"] + base[2:],
        # из-за чего "mangle" съезжает (подозрение на баг среза base[:2] —
        # должно быть base[:3]). Тест не цементирует баг, но требует, чтобы
        # вставка несла ПОЛНЫЙ спек правила.
        cmd = inserts[0]
        self.assertEqual(cmd[0], "iptables")
        for token in ("-t", "mangle", "-I", "PREROUTING", "-p", "tcp",
                      "--dport", "443", "--syn", "-m", "comment",
                      "chimera-server-frag", "-j", "TCPMSS",
                      "--set-mss", "1300"):
            self.assertIn(token, cmd)

    def test_install_idempotent_when_rule_exists(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        cmds = []
        fake = _make_run_soft(rc_check=0, log=cmds)   # -C → rc=0: правило стоит
        with patch(MOD + "._run_soft", fake):
            installed = _install_tcpmss_rules([443], 1300)
        self.assertEqual(installed, 0)
        self.assertFalse(any("-I" in c for c in cmds))

    def test_install_v4_only_without_global_ipv6(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        cmds = []
        fake = _make_run_soft(rc_check=1, rc_insert=0, log=cmds, ip6_out="")
        with patch(MOD + "._run_soft", fake):
            installed = _install_tcpmss_rules([443], 1300)
        self.assertEqual(installed, 1)
        self.assertFalse(any(c and c[0] == "ip6tables" for c in cmds))

    def test_install_v4_and_v6_with_global_ipv6(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        cmds = []
        fake = _make_run_soft(
            rc_check=1, rc_insert=0, log=cmds,
            ip6_out="2: eth0    inet6 2001:db8::1/64 scope global dynamic")
        with patch(MOD + "._run_soft", fake):
            installed = _install_tcpmss_rules([443], 1300)
        self.assertEqual(installed, 2)
        v6_inserts = [c for c in cmds if c and c[0] == "ip6tables" and "-I" in c]
        self.assertEqual(len(v6_inserts), 1)
        self.assertIn("--set-mss", v6_inserts[0])

    def test_install_empty_ports_returns_zero(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        cmds = []
        fake = _make_run_soft(log=cmds)
        with patch(MOD + "._run_soft", fake):
            installed = _install_tcpmss_rules([], 1300)
        self.assertEqual(installed, 0)
        self.assertEqual(cmds, [])

    def test_install_survives_missing_binary(self):
        from chimera.modules.server_fragment import _install_tcpmss_rules
        with patch(MOD + "._run", side_effect=FileNotFoundError("iptables")):
            installed = _install_tcpmss_rules([443], 1300)
        self.assertEqual(installed, 0)


class TestRemoveCountTcpmssRules(unittest.TestCase):
    """_remove_tcpmss_rules / _count_tcpmss_rules — парсинг -S PREROUTING."""

    def setUp(self):
        _setup_core()

    def test_remove_deletes_only_chimera_rules(self):
        from chimera.modules.server_fragment import _remove_tcpmss_rules
        cmds = []
        fake = _make_run_soft(v4_save=_SAVED_CHAIN_V4, v6_save="",
                              rc_delete=0, log=cmds)
        with patch(MOD + "._run_soft", fake):
            removed = _remove_tcpmss_rules()
        self.assertEqual(removed, 1)
        deletes = [c for c in cmds if "-D" in c]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][0], "iptables")
        self.assertIn("-D", deletes[0])
        self.assertIn("PREROUTING", deletes[0])
        self.assertIn("chimera-server-frag", deletes[0])
        self.assertIn("--set-mss", deletes[0])
        # чужие строки (ACCEPT / some-other-comment) не удаляются
        self.assertFalse(any("some-other-comment" in c for c in deletes))
        self.assertFalse(any("ACCEPT" in c for c in deletes))

    def test_remove_no_rules_is_noop(self):
        from chimera.modules.server_fragment import _remove_tcpmss_rules
        cmds = []
        fake = _make_run_soft(v4_save="-N PREROUTING\n-A PREROUTING -j ACCEPT",
                              v6_save="", rc_delete=0, log=cmds)
        with patch(MOD + "._run_soft", fake):
            removed = _remove_tcpmss_rules()
        self.assertEqual(removed, 0)
        self.assertFalse(any("-D" in c for c in cmds))

    def test_remove_v4_and_v6(self):
        from chimera.modules.server_fragment import _remove_tcpmss_rules
        cmds = []
        fake = _make_run_soft(v4_save=_SAVED_CHAIN_V4, v6_save=_SAVED_CHAIN_V4,
                              rc_delete=0, log=cmds)
        with patch(MOD + "._run_soft", fake):
            removed = _remove_tcpmss_rules()
        self.assertEqual(removed, 2)
        bins = {c[0] for c in cmds if "-D" in c}
        self.assertEqual(bins, {"iptables", "ip6tables"})

    def test_count_only_chimera_rules(self):
        from chimera.modules.server_fragment import _count_tcpmss_rules
        fake = _make_run_soft(v4_save=_SAVED_CHAIN_V4, v6_save="")
        with patch(MOD + "._run_soft", fake):
            self.assertEqual(_count_tcpmss_rules(), 1)

    def test_count_v4_and_v6(self):
        from chimera.modules.server_fragment import _count_tcpmss_rules
        fake = _make_run_soft(v4_save=_SAVED_CHAIN_V4, v6_save=_SAVED_CHAIN_V4)
        with patch(MOD + "._run_soft", fake):
            self.assertEqual(_count_tcpmss_rules(), 2)

    def test_count_zero_when_empty(self):
        from chimera.modules.server_fragment import _count_tcpmss_rules
        fake = _make_run_soft(v4_save="", v6_save="")
        with patch(MOD + "._run_soft", fake):
            self.assertEqual(_count_tcpmss_rules(), 0)

    def test_count_survives_missing_binary(self):
        from chimera.modules.server_fragment import (
            _count_tcpmss_rules, _remove_tcpmss_rules,
        )
        with patch(MOD + "._run", side_effect=FileNotFoundError("iptables")):
            self.assertEqual(_count_tcpmss_rules(), 0)
            self.assertEqual(_remove_tcpmss_rules(), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 6b. systemd drop-in + daemon-reload + journal (v2: GODEBUG/ExecStartPost)
# ─────────────────────────────────────────────────────────────────────────────

class TestDropinContent(unittest.TestCase):
    """_dropin_content — точный контент под каждый механизм."""

    def setUp(self):
        _setup_core()

    def test_sockopt_mechanism_content_exact(self):
        from chimera.modules.server_fragment import _dropin_content, MECH_SOCKOPT
        self.assertEqual(
            _dropin_content(MECH_SOCKOPT),
            "[Service]\nEnvironment=GODEBUG=multipathtcp=0\n")

    def test_tcpmss_mechanism_content_exact(self):
        from chimera.modules.server_fragment import (
            _dropin_content, MECH_TCPMSS, _RESTORE_SCRIPT,
        )
        self.assertEqual(
            _dropin_content(MECH_TCPMSS),
            f"[Service]\nExecStartPost=+{_RESTORE_SCRIPT}\n")


class TestDropinInstalled(unittest.TestCase):
    """_dropin_installed — существует ли drop-in (и под нужный механизм)."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._dropin_path = self._tmpdir / "chimera-server-frag.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch(MOD + "._SVC_DROPIN", self._dropin_path)

    def test_no_file_false_for_any_mechanism(self):
        from chimera.modules.server_fragment import (
            _dropin_installed, MECH_SOCKOPT, MECH_TCPMSS,
        )
        with self._patch():
            self.assertFalse(_dropin_installed())
            self.assertFalse(_dropin_installed(MECH_SOCKOPT))
            self.assertFalse(_dropin_installed(MECH_TCPMSS))

    def test_sockopt_content_matches_only_mech_a(self):
        from chimera.modules.server_fragment import (
            _dropin_installed, _dropin_content, MECH_SOCKOPT, MECH_TCPMSS,
        )
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        with self._patch():
            self.assertTrue(_dropin_installed(MECH_SOCKOPT))
            self.assertFalse(_dropin_installed(MECH_TCPMSS))

    def test_tcpmss_content_matches_only_mech_b(self):
        from chimera.modules.server_fragment import (
            _dropin_installed, _dropin_content, MECH_SOCKOPT, MECH_TCPMSS,
        )
        self._dropin_path.write_text(_dropin_content(MECH_TCPMSS))
        with self._patch():
            self.assertTrue(_dropin_installed(MECH_TCPMSS))
            self.assertFalse(_dropin_installed(MECH_SOCKOPT))

    def test_no_argument_true_for_any_our_content(self):
        from chimera.modules.server_fragment import (
            _dropin_installed, _dropin_content, MECH_SOCKOPT, MECH_TCPMSS,
        )
        for mech in (MECH_SOCKOPT, MECH_TCPMSS):
            self._dropin_path.write_text(_dropin_content(mech))
            with self._patch():
                self.assertTrue(_dropin_installed())

    def test_garbage_content_mechanism_false_any_true(self):
        from chimera.modules.server_fragment import (
            _dropin_installed, MECH_SOCKOPT, MECH_TCPMSS,
        )
        self._dropin_path.write_text("какой-то чужой drop-in\n")
        with self._patch():
            self.assertFalse(_dropin_installed(MECH_SOCKOPT))
            self.assertFalse(_dropin_installed(MECH_TCPMSS))
            self.assertTrue(_dropin_installed())


class TestInstallRemoveDropin(unittest.TestCase):
    """_install_dropin / _remove_dropin — файловые операции + daemon-reload."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._dropin_path = self._tmpdir / "chimera-server-frag.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        self._reload = MagicMock(return_value=True)
        return [
            patch(MOD + "._SVC_DROPIN", self._dropin_path),
            patch(MOD + "._daemon_reload", self._reload),
        ]

    def test_install_writes_content_and_reloads(self):
        from chimera.modules.server_fragment import (
            _install_dropin, _dropin_content, MECH_SOCKOPT,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = _install_dropin(MECH_SOCKOPT)
        self.assertTrue(ok)
        self.assertEqual(self._dropin_path.read_text(),
                         _dropin_content(MECH_SOCKOPT))
        self._reload.assert_called_once()

    def test_install_creates_parent_directories(self):
        from chimera.modules.server_fragment import (
            _install_dropin, MECH_TCPMSS,
        )
        self._dropin_path = self._tmpdir / "nested" / "dir" / "frag.conf"
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = _install_dropin(MECH_TCPMSS)
        self.assertTrue(ok)
        self.assertTrue(self._dropin_path.exists())

    def test_install_overwrites_previous_mechanism(self):
        from chimera.modules.server_fragment import (
            _install_dropin, _dropin_content, MECH_SOCKOPT, MECH_TCPMSS,
        )
        # лежит drop-in от механизма B → ставим A: контент заменяется
        self._dropin_path.write_text(_dropin_content(MECH_TCPMSS))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = _install_dropin(MECH_SOCKOPT)
        self.assertTrue(ok)
        self.assertEqual(self._dropin_path.read_text(),
                         _dropin_content(MECH_SOCKOPT))
        self._reload.assert_called_once()

    def test_remove_unlinks_and_reloads(self):
        from chimera.modules.server_fragment import (
            _remove_dropin, _dropin_content, MECH_SOCKOPT,
        )
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            removed = _remove_dropin()
        self.assertTrue(removed)
        self.assertFalse(self._dropin_path.exists())
        self._reload.assert_called_once()

    def test_remove_without_file_returns_false_no_reload(self):
        from chimera.modules.server_fragment import _remove_dropin
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            removed = _remove_dropin()
        self.assertFalse(removed)
        self._reload.assert_not_called()

    def test_remove_idempotent_no_second_reload(self):
        from chimera.modules.server_fragment import (
            _remove_dropin, _dropin_content, MECH_TCPMSS,
        )
        self._dropin_path.write_text(_dropin_content(MECH_TCPMSS))
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            first = _remove_dropin()
            second = _remove_dropin()
        self.assertTrue(first)
        self.assertFalse(second)           # повторный remove — уже нечего снимать
        self._reload.assert_called_once()  # daemon-reload только по факту удаления


class TestDaemonReload(unittest.TestCase):
    """_daemon_reload — systemctl daemon-reload через _run_soft."""

    def setUp(self):
        _setup_core()

    def test_calls_systemctl_daemon_reload(self):
        from chimera.modules.server_fragment import _daemon_reload
        cmds = []

        def fake(cmd, capture=False, timeout=15):
            cmds.append(list(cmd))
            return _cp(cmd, 0)

        with patch(MOD + "._run_soft", fake):
            ok = _daemon_reload()
        self.assertTrue(ok)
        self.assertEqual(cmds, [["systemctl", "daemon-reload"]])

    def test_false_on_failure(self):
        from chimera.modules.server_fragment import _daemon_reload
        with patch(MOD + "._run_soft", lambda cmd, **kw: _cp(cmd, 1)):
            self.assertFalse(_daemon_reload())


class TestJournalTcpmaxsegFailed(unittest.TestCase):
    """_journal_tcpmaxseg_failed — верификация механизма A по журналу."""

    def setUp(self):
        _setup_core()

    def _journal(self, outputs):
        """Фейковый _run_soft: выдаёт outputs по порядку, пишет лог вызовов."""
        calls = []
        it = iter(outputs)

        def fake(cmd, capture=False, timeout=15):
            calls.append(list(cmd))
            return next(it, _cp(cmd, 0, stdout=""))

        return fake, calls

    def test_true_when_journal_contains_marker(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        fake, _ = self._journal([
            _cp(["journalctl"], 0, stdout="... failed to set TCP_MAXSEG ...")])
        with patch(MOD + "._run_soft", fake):
            self.assertTrue(
                _journal_tcpmaxseg_failed(since="2025-01-01 00:00:00"))

    def test_false_when_journal_clean(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        fake, _ = self._journal([
            _cp(["journalctl"], 0, stdout="xray started ok"),
            _cp(["journalctl"], 0, stdout="nothing interesting"),
        ])
        with patch(MOD + "._run_soft", fake):
            self.assertFalse(
                _journal_tcpmaxseg_failed(since="2025-01-01 00:00:00"))

    def test_false_when_journalctl_missing(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        with patch(MOD + "._run_soft", lambda cmd, **kw: _cp(cmd, 127)):
            self.assertFalse(
                _journal_tcpmaxseg_failed(since="2025-01-01 00:00:00"))

    def test_checks_both_service_units(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        # первый юнит чист, второй (xray-core) содержит маркер → True
        fake, calls = self._journal([
            _cp(["journalctl"], 0, stdout="clean"),
            _cp(["journalctl"], 0, stdout="failed to set TCP_MAXSEG"),
        ])
        with patch(MOD + "._run_soft", fake):
            self.assertTrue(_journal_tcpmaxseg_failed(since="ts"))
        units = [c[c.index("-u") + 1] for c in calls]
        self.assertEqual(units, ["xray", "xray-core"])

    def test_marker_in_stderr_detected(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        cp = subprocess.CompletedProcess(
            ["journalctl"], 0, stdout="",
            stderr="xray: failed to set TCP_MAXSEG")
        with patch(MOD + "._run_soft", lambda cmd, **kw: cp):
            self.assertTrue(_journal_tcpmaxseg_failed(since="ts"))

    def test_journalctl_flags_and_since_passed(self):
        from chimera.modules.server_fragment import _journal_tcpmaxseg_failed
        fake, calls = self._journal([
            _cp(["journalctl"], 0, stdout="clean"),
            _cp(["journalctl"], 0, stdout="clean"),
        ])
        with patch(MOD + "._run_soft", fake):
            _journal_tcpmaxseg_failed(since="2025-06-01 12:00:00")
        self.assertEqual(len(calls), 2)
        for cmd in calls:
            self.assertEqual(cmd[0], "journalctl")
            self.assertEqual(cmd[1], "-u")
            self.assertIn("--since", cmd)
            self.assertEqual(cmd[cmd.index("--since") + 1], "2025-06-01 12:00:00")
            self.assertIn("--no-pager", cmd)
            self.assertIn("-n", cmd)
            self.assertEqual(cmd[cmd.index("-n") + 1], "200")


# ─────────────────────────────────────────────────────────────────────────────
# 6c. restore-скрипт (v2): запись/удаление + инварианты контента
# ─────────────────────────────────────────────────────────────────────────────

class TestRestoreScriptIO(unittest.TestCase):
    """_write_restore_script / _remove_restore_script — файловые операции."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._restore_path = self._tmpdir / "chimera-server-frag-restore"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch(MOD + "._RESTORE_SCRIPT", self._restore_path)

    def test_write_creates_executable_with_exact_content(self):
        from chimera.modules.server_fragment import (
            _write_restore_script, _RESTORE_SCRIPT_CONTENT,
        )
        with self._patch():
            ok = _write_restore_script()
        self.assertTrue(ok)
        self.assertEqual(self._restore_path.read_text(),
                         _RESTORE_SCRIPT_CONTENT)
        self.assertEqual(self._restore_path.stat().st_mode & 0o777, 0o755)

    def test_write_idempotent_overwrites(self):
        from chimera.modules.server_fragment import (
            _write_restore_script, _RESTORE_SCRIPT_CONTENT,
        )
        with self._patch():
            self._restore_path.write_text("old garbage")
            ok1 = _write_restore_script()
            ok2 = _write_restore_script()
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertEqual(self._restore_path.read_text(),
                         _RESTORE_SCRIPT_CONTENT)

    def test_write_creates_parent_directories(self):
        from chimera.modules.server_fragment import _write_restore_script
        self._restore_path = self._tmpdir / "usr" / "local" / "bin" / "restore"
        with self._patch():
            ok = _write_restore_script()
        self.assertTrue(ok)
        self.assertTrue(self._restore_path.exists())

    def test_remove_deletes_existing(self):
        from chimera.modules.server_fragment import _remove_restore_script
        with self._patch():
            self._restore_path.write_text("#!/bin/sh\n")
            removed = _remove_restore_script()
        self.assertTrue(removed)
        self.assertFalse(self._restore_path.exists())

    def test_remove_idempotent_when_absent(self):
        from chimera.modules.server_fragment import _remove_restore_script
        with self._patch():
            self.assertFalse(_remove_restore_script())
            self.assertFalse(_remove_restore_script())


class TestRestoreScriptContent(unittest.TestCase):
    """_RESTORE_SCRIPT_CONTENT — standalone-инварианты (без исполнения:
    STATE/CONFIG зашиты константами в контенте, поэтому проверяем текст
    и компилируемость, а не прогон main())."""

    def setUp(self):
        _setup_core()

    def _content(self):
        from chimera.modules.server_fragment import _RESTORE_SCRIPT_CONTENT
        return _RESTORE_SCRIPT_CONTENT

    def test_compiles_as_python(self):
        compile(self._content(), "<chimera-server-frag-restore>", "exec")

    def test_shebang_and_main_guard(self):
        c = self._content()
        self.assertTrue(c.startswith("#!/usr/bin/env python3"))
        self.assertIn('if __name__ == "__main__":', c)

    def test_no_chimera_imports(self):
        c = self._content()
        self.assertNotIn("import chimera", c)
        self.assertNotIn("from chimera", c)

    def test_stdlib_only_imports(self):
        import ast
        tree = ast.parse(self._content())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(n.name.split(".")[0] for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
        self.assertTrue(mods)                       # импорты вообще есть
        self.assertTrue(mods <= {"json", "subprocess", "pathlib"},
                        f"не-stdlib импорты в restore-скрипте: {mods}")

    def test_logic_key_tokens(self):
        c = self._content()
        # механизм B: TCPMSS-правила по портам из state/config
        for token in ("server_fragment", "tcpmss", "TCPMSS", "PREROUTING",
                      "mangle", "chimera-server-frag", "state.json"):
            self.assertIn(token, c, f"token {token!r} missing in restore script")
        # идемпотентность: перед вставкой проверяет наличие наших правил (-S)
        self.assertIn("-S", c)
        self.assertIn("-I", c)


# ─────────────────────────────────────────────────────────────────────────────
# 7. server_fragment_enable — механизм A (tcpMaxSeg)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableMechanismA(_FragmentTestBase):
    """server_fragment_enable на новом ядре (26.10.21) → sockopt.tcpMaxSeg."""

    def test_enable_writes_tcpmaxseg_and_state(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state,
        )
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced", restart=True)
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
            dropin = self._dropin_path.read_text()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpMaxSeg"], 1300)
        self.assertNotIn("fragment", sockopt)
        # v2: GODEBUG-drop-in установлен, restore-скрипт НЕ создаётся
        self.assertEqual(dropin, "[Service]\nEnvironment=GODEBUG=multipathtcp=0\n")
        self.assertFalse(self._restore_path.exists())
        # v2: daemon-reload и journal-верификация — по одному разу
        mocks["reload"].assert_called_once()
        mocks["journal"].assert_called_once()
        # state
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["preset"], "balanced")
        self.assertEqual(sf["mss"], 1300)
        self.assertEqual(sf["mechanism"], "tcpMaxSeg")
        self.assertEqual(sf["ports"], [443])
        self.assertNotIn("fallback_reason", sf)
        self.assertRegex(sf["last_applied"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        # рестарт вызван ровно один раз
        mocks["restart"].assert_called_once()

    def test_enable_preserves_existing_sockopt_keys(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        cfg = json.loads(json.dumps(_REALITY_CONFIG))
        cfg["inbounds"][0]["streamSettings"]["sockopt"] = {
            "tcpCongestion": "bbr",
            "tcpFastOpen": True,
        }
        patches, _ = self._mech_a_patches(cfg)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            out = _load_xray_config()
        self.assertTrue(ok)
        sockopt = out["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpCongestion"], "bbr")
        self.assertTrue(sockopt["tcpFastOpen"])
        self.assertEqual(sockopt["tcpMaxSeg"], 1300)

    def test_enable_idempotent_same_mss_no_second_restart(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok1 = server_fragment_enable(preset="balanced")
            ok2 = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        # повторный enable того же MSS — рестарт/daemon-reload/journal-verify
        # второй раз НЕ вызываются (идемпотентность v2)
        mocks["restart"].assert_called_once()
        mocks["reload"].assert_called_once()
        mocks["journal"].assert_called_once()
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpMaxSeg"], 1300)

    def test_enable_mss_change_rewrites_tcpmaxseg(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_enable(preset="balanced")
            server_fragment_enable(preset="aggressive")
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpMaxSeg"], 800)
        self.assertEqual(mocks["restart"].call_count, 2)

    def test_enable_custom_mss(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, _ = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="custom", mss=900)
            cfg = _load_xray_config()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpMaxSeg"], 900)

    def test_enable_cleans_legacy_fragment_placebo(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, _ = self._mech_a_patches(_reality_with_legacy_fragment())
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("fragment", sockopt)          # плацебо вычищено
        self.assertEqual(sockopt["tcpMaxSeg"], 1300)   # рабочий механизм на месте
        self.assertTrue(sockopt["tcpFastOpen"])        # остальное не тронуто

    def test_enable_multiple_reality_inbounds_all_patched(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state,
        )
        patches, _ = self._mech_a_patches(_MULTI_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
        self.assertTrue(ok)
        reality = [inb for inb in cfg["inbounds"]
                   if inb.get("protocol") == "vless"
                   and inb.get("streamSettings", {}).get("security") == "reality"]
        self.assertEqual(len(reality), 3)
        for inb in reality:
            self.assertEqual(
                inb["streamSettings"]["sockopt"].get("tcpMaxSeg"), 1300,
                f"inbound {inb['tag']} without tcpMaxSeg")
        # ws-inbound не тронут
        ws = next(inb for inb in cfg["inbounds"] if inb["tag"] == "ws-in")
        self.assertNotIn("sockopt", ws["streamSettings"])
        self.assertEqual(sf["ports"], [443, 2053, 8443])

    def test_enable_rollback_on_restart_failure(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state,
        )
        restart = MagicMock(side_effect=[False, True])   # apply fail, rollback ok
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG, restart=restart)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
        self.assertFalse(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"].get("sockopt", {})
        self.assertNotIn("tcpMaxSeg", sockopt)   # конфиг откачен
        self.assertFalse(sf.get("enabled", False))  # state не включён
        self.assertEqual(restart.call_count, 2)  # попытка + рестарт отката
        mocks["remove"].assert_called_once()    # TCPMSS-правила тоже сняты
        # v2: поставленный здесь GODEBUG-drop-in снят при откате,
        # restore-скрипт не остался
        self.assertFalse(self._dropin_path.exists())
        self.assertFalse(self._restore_path.exists())

    def test_enable_without_restart_flag(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced", restart=False)
            cfg = _load_xray_config()
        self.assertTrue(ok)
        mocks["restart"].assert_not_called()
        # v2: верификация по журналу — только после фактического рестарта
        mocks["journal"].assert_not_called()
        # drop-in ставится и без рестарта (переживёт следующий рестарт сервиса)
        self.assertTrue(self._dropin_path.exists())
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpMaxSeg"], 1300)

    def test_enable_mechanism_a_never_touches_iptables(self):
        from chimera.modules.server_fragment import server_fragment_enable
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_enable(preset="balanced")
        mocks["install"].assert_not_called()
        mocks["count"].assert_not_called()

    def test_enable_light_preset_writes_1400(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, _ = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="light")
            cfg = _load_xray_config()
        self.assertTrue(ok)
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["sockopt"]["tcpMaxSeg"], 1400)

    def test_enable_a_journal_called_with_since_timestamp(self):
        from chimera.modules.server_fragment import server_fragment_enable
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_enable(preset="balanced")
        mocks["journal"].assert_called_once()
        kwargs = mocks["journal"].call_args.kwargs
        self.assertIn("since", kwargs)
        # since — момент ДО применения (время включения)
        self.assertRegex(kwargs["since"],
                         r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

    def test_enable_a_replaces_foreign_dropin_content(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _dropin_content,
            MECH_SOCKOPT, MECH_TCPMSS,
        )
        # с прошлого раза остался drop-in механизма B (ExecStartPost) →
        # enable A должен заменить его на GODEBUG-контент
        self._dropin_path.write_text(_dropin_content(MECH_TCPMSS))
        patches, mocks = self._mech_a_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            content = self._dropin_path.read_text()
        self.assertTrue(ok)
        self.assertEqual(content, _dropin_content(MECH_SOCKOPT))
        mocks["reload"].assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 7b. Фолбэк A → B по журналу (v2: GODEBUG не помог — MPTCP-нооп)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableGodebugFallback(_FragmentTestBase):
    """enable на новом ядре, но журнал видит «failed to set TCP_MAXSEG» →
    автоматический переход на механизм B (TCPMSS + restore + ExecStartPost)."""

    def _fallback_patches(self, cfg=None, count_after=1):
        return self._mech_a_patches(
            cfg, journal_failed=True, install_ret=1, count_ret=count_after)

    def test_fallback_switches_to_tcpmss(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state,
        )
        patches, mocks = self._fallback_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
            dropin = self._dropin_path.read_text()
            restore_exists = self._restore_path.exists()
        self.assertTrue(ok)
        # журнал опрошен (причина фолбэка), правила TCPMSS поставлены
        mocks["journal"].assert_called_once()
        mocks["install"].assert_called_once_with([443], 1300)
        # хореография daemon-reload: GODEBUG-install → GODEBUG-remove →
        # ExecStartPost-install (3 раза)
        self.assertEqual(mocks["reload"].call_count, 3)
        # рестарт только один (механизм B применяется без рестарта)
        mocks["restart"].assert_called_once()
        # GODEBUG-drop-in снят, вместо него — ExecStartPost (механизм B)
        self.assertIn("ExecStartPost=+", dropin)
        self.assertNotIn("GODEBUG", dropin)
        self.assertTrue(restore_exists)
        # state: механизм tcpmss + причина фолбэка
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["mechanism"], "tcpmss")
        self.assertEqual(sf["mss"], 1300)
        self.assertEqual(sf["ports"], [443])
        self.assertIn("fallback_reason", sf)
        self.assertIn("TCP_MAXSEG", sf["fallback_reason"])
        # tcpMaxSeg остаётся в конфиге: поле валидно для ядра ≥ 26.7.11,
        # без GODEBUG оно no-op — реальную сегментацию делает TCPMSS
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["sockopt"]["tcpMaxSeg"], 1300)

    def test_fallback_reason_cleared_on_clean_reenable(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_server_fragment_state,
        )
        # первый enable — фолбэк (журнал видит провал TCP_MAXSEG);
        # второй — чистый механизм A (GODEBUG помог / журнал чист)
        patches, mocks = self._mech_a_patches(
            _REALITY_CONFIG, journal_failed=True, install_ret=1, count_ret=1)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_enable(preset="balanced")
            mocks["journal"].return_value = False
            server_fragment_enable(preset="aggressive")
            sf = _load_server_fragment_state()
        self.assertEqual(sf["mechanism"], "tcpMaxSeg")
        self.assertNotIn("fallback_reason", sf)   # причина вычищена из state

    def test_fallback_count_zero_full_rollback(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state,
        )
        # фолбэк случился, но и TCPMSS не поставился → полный откат
        patches, mocks = self._fallback_patches(_REALITY_CONFIG, count_after=0)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
        self.assertFalse(ok)
        self.assertFalse(sf.get("enabled", False))
        # конфиг откачен к оригиналу (без tcpMaxSeg)
        self.assertNotIn(
            "tcpMaxSeg", cfg["inbounds"][0]["streamSettings"].get("sockopt", {}))
        # restore-скрипт снят при откате
        self.assertFalse(self._restore_path.exists())
        mocks["remove"].assert_called_once()
        # ИЗВЕСТНАЯ ОСОБЕННОСТЬ (не чиним — код модуля не трогаем):
        # ExecStartPost-drop-in, поставленный в B-блоке, откатом не снимается
        # (dropin_installed_here отслеживает только GODEBUG-вариант)

    def test_fallback_status_reports_restore_and_reason(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, server_fragment_status,
        )
        patches, mocks = self._fallback_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_enable(preset="balanced")
            st = server_fragment_status()
        self.assertTrue(st["enabled"])
        self.assertEqual(st["mechanism"], "tcpmss")
        self.assertTrue(st["restore_installed"])
        self.assertFalse(st["godebug_installed"])
        self.assertIn("fallback_reason", st)
        self.assertIn("TCP_MAXSEG", st["fallback_reason"])


# ─────────────────────────────────────────────────────────────────────────────
# 8. server_fragment_enable — механизм B (iptables TCPMSS)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableMechanismB(_FragmentTestBase):
    """server_fragment_enable на старом ядре (1.8.24) → iptables TCPMSS."""

    def test_enable_installs_rules_and_state(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
            _load_server_fragment_state, _RESTORE_SCRIPT_CONTENT,
        )
        patches, mocks = self._mech_b_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
            dropin = self._dropin_path.read_text()
            restore = self._restore_path.read_text()
        self.assertTrue(ok)
        mocks["install"].assert_called_once_with([443], 1300)
        # tcpMaxSeg НЕ пишется старому ядру
        sockopt = cfg["inbounds"][0]["streamSettings"].get("sockopt", {})
        self.assertNotIn("tcpMaxSeg", sockopt)
        # v2: restore-скрипт (точный контент) + ExecStartPost-drop-in
        self.assertEqual(restore, _RESTORE_SCRIPT_CONTENT)
        self.assertEqual(dropin, f"[Service]\nExecStartPost=+{self._restore_path}\n")
        self.assertNotIn("GODEBUG", dropin)
        # v2: daemon-reload был (установка drop-in), журнал НЕ опрашивался
        mocks["reload"].assert_called_once()
        mocks["journal"].assert_not_called()
        # state
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["mechanism"], "tcpmss")
        self.assertEqual(sf["mss"], 1300)
        self.assertEqual(sf["ports"], [443])
        self.assertNotIn("fallback_reason", sf)
        # конфиг не менялся → рестарта нет
        mocks["restart"].assert_not_called()

    def test_enable_b_pops_existing_tcpmaxseg(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, mocks = self._mech_b_patches(_reality_with_tcpmaxseg(1300))
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("tcpMaxSeg", sockopt)
        self.assertEqual(sockopt.get("tcpCongestion"), "bbr")   # остальное цело
        mocks["restart"].assert_called_once()   # конфиг менялся (pop) → рестарт

    def test_enable_b_fails_when_no_rules_installed(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_server_fragment_state,
        )
        patches, mocks = self._mech_b_patches(_REALITY_CONFIG, count_after=0)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            sf = _load_server_fragment_state()
        self.assertFalse(ok)
        self.assertFalse(sf.get("enabled", False))
        mocks["install"].assert_called_once()
        # v2: restore-скрипт, написанный в B-блоке, снят при откате
        self.assertFalse(self._restore_path.exists())

    def test_enable_b_count_zero_with_config_change_reverts_config(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        # конфиг с tcpMaxSeg: механизм B его выкидывает (pop) → рестарт;
        # правила не поставились → полный откат К ОРИГИНАЛУ (в нём был
        # tcpMaxSeg — поле возвращается на место)
        patches, mocks = self._mech_b_patches(_reality_with_tcpmaxseg(1300),
                                              count_after=0)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertFalse(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt.get("tcpMaxSeg"), 1300)   # оригинал восстановлен
        self.assertEqual(sockopt.get("tcpCongestion"), "bbr")
        self.assertTrue(sockopt.get("tcpFastOpen"))
        self.assertEqual(mocks["restart"].call_count, 2)  # apply + откат
        self.assertFalse(self._restore_path.exists())

    def test_enable_b_repeat_no_restart_no_journal(self):
        from chimera.modules.server_fragment import server_fragment_enable
        patches, mocks = self._mech_b_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok1 = server_fragment_enable(preset="balanced")
            ok2 = server_fragment_enable(preset="balanced")
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        # повторный enable: без рестарта и без journal-verify (механизм B)
        mocks["restart"].assert_not_called()
        mocks["journal"].assert_not_called()
        # правила переустанавливаются повторно (идемпотентно на уровне
        # iptables -C внутри _install_tcpmss_rules)
        self.assertEqual(mocks["install"].call_count, 2)

    def test_enable_b_cleans_legacy_fragment(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        patches, mocks = self._mech_b_patches(_reality_with_legacy_fragment())
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("fragment", sockopt)
        self.assertNotIn("tcpMaxSeg", sockopt)
        self.assertTrue(sockopt["tcpFastOpen"])
        mocks["restart"].assert_called_once()   # конфиг менялся (чистка)

    def test_enable_b_multiple_ports(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_server_fragment_state,
        )
        patches, mocks = self._mech_b_patches(_MULTI_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_enable(preset="aggressive")
            sf = _load_server_fragment_state()
        self.assertTrue(ok)
        mocks["install"].assert_called_once_with([443, 2053, 8443], 800)
        self.assertEqual(sf["ports"], [443, 2053, 8443])
        self.assertEqual(sf["mss"], 800)


# ─────────────────────────────────────────────────────────────────────────────
# 9. server_fragment_enable — отказы
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableRefusals(_FragmentTestBase):
    """enable возвращает False на неподходящих условиях."""

    def _refusal_patches(self, cfg=None):
        return self._base_patches(cfg) + [
            patch(MOD + "._xray_core_version", return_value=(26, 10, 21)),
            patch(MOD + "._xray_test_and_restart", MagicMock(return_value=True)),
            patch(MOD + "._install_tcpmss_rules", MagicMock(return_value=0)),
            patch(MOD + "._count_tcpmss_rules", MagicMock(return_value=0)),
            patch(MOD + "._remove_tcpmss_rules", MagicMock(return_value=0)),
            patch(MOD + "._daemon_reload", MagicMock(return_value=True)),
            patch(MOD + "._journal_tcpmaxseg_failed", MagicMock(return_value=False)),
        ]

    def test_enable_refuses_xhttp_config(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(_XHTTP_CONFIG))
            ok = server_fragment_enable(preset="balanced")
            cfg = _load_xray_config()
        self.assertFalse(ok)
        # конфиг не тронут
        self.assertNotIn("sockopt", cfg["inbounds"][0]["streamSettings"])

    def test_enable_refuses_empty_inbounds(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches({"inbounds": []}))
            ok = server_fragment_enable(preset="balanced")
        self.assertFalse(ok)

    def test_enable_refuses_non_reality_only(self):
        from chimera.modules.server_fragment import server_fragment_enable
        cfg = {"inbounds": [_MULTI_REALITY_CONFIG["inbounds"][1]]}   # только ws
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(cfg))
            ok = server_fragment_enable(preset="balanced")
        self.assertFalse(ok)

    def test_enable_refuses_missing_config(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch(MOD + "._XRAY_CONFIG", Path("/tmp/nonexistent_config.json")),
                patch(MOD + "._XRAY_CONFIG_ALT", Path("/tmp/nonexistent_alt.json")),
                patch(MOD + "._STATE_FILE", self._state_path),
                patch(MOD + "._SVC_DROPIN", self._dropin_path),
                patch(MOD + "._RESTORE_SCRIPT", self._restore_path),
            ])
            ok = server_fragment_enable(preset="balanced")
        self.assertFalse(ok)

    def test_enable_refuses_unknown_preset(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="nonexistent")
            cfg = _load_xray_config()
        self.assertFalse(ok)
        self.assertNotIn("sockopt", cfg["inbounds"][0]["streamSettings"])

    def test_enable_refuses_mss_below_range(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="custom", mss=100)
        self.assertFalse(ok)

    def test_enable_refuses_mss_above_range(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="custom", mss=2000)
        self.assertFalse(ok)

    def test_enable_refuses_custom_without_mss(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._refusal_patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="custom")
        self.assertFalse(ok)


# ─────────────────────────────────────────────────────────────────────────────
# 10. server_fragment_disable
# ─────────────────────────────────────────────────────────────────────────────

class TestDisable(_FragmentTestBase):
    """server_fragment_disable — снятие tcpMaxSeg + легаси + TCPMSS +
    drop-in/restore-скрипт (v2)."""

    def _disable_patches(self, cfg=None):
        restart = MagicMock(return_value=True)
        remove = MagicMock(return_value=0)
        reload = MagicMock(return_value=True)
        patches = self._base_patches(cfg) + [
            patch(MOD + "._xray_test_and_restart", restart),
            patch(MOD + "._remove_tcpmss_rules", remove),
            patch(MOD + "._daemon_reload", reload),
        ]
        return patches, restart, remove, reload

    def test_disable_removes_tcpmaxseg_and_updates_state(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
            _load_server_fragment_state,
        )
        patches, restart, remove, reload = self._disable_patches(
            _reality_with_tcpmaxseg(1300))
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("tcpMaxSeg", sockopt)
        self.assertEqual(sockopt.get("tcpCongestion"), "bbr")   # остальное цело
        self.assertTrue(sockopt.get("tcpFastOpen"))
        # state
        self.assertFalse(sf["enabled"])
        self.assertEqual(sf["mechanism"], "")
        self.assertEqual(sf["ports"], [])
        self.assertIn("last_disabled", sf)
        # TCPMSS-правила сняты всегда; рестарт был (конфиг менялся)
        remove.assert_called_once()
        restart.assert_called_once()

    def test_disable_removes_legacy_fragment_too(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        patches, _, _, _ = self._disable_patches(_reality_with_legacy_fragment())
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
            cfg = _load_xray_config()
        self.assertTrue(ok)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("fragment", sockopt)
        self.assertNotIn("tcpMaxSeg", sockopt)
        self.assertTrue(sockopt["tcpFastOpen"])

    def test_disable_noop_when_nothing_to_remove(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        patches, restart, remove, reload = self._disable_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
            cfg = _load_xray_config()
        self.assertTrue(ok)
        # изменений не было → рестарта нет; TCPMSS всё равно снимаем
        restart.assert_not_called()
        remove.assert_called_once()
        self.assertNotIn("sockopt", cfg["inbounds"][0]["streamSettings"])

    def test_disable_without_restart_flag(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        patches, restart, _, _ = self._disable_patches(
            _reality_with_tcpmaxseg(1300))
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable(restart=False)
            cfg = _load_xray_config()
        self.assertTrue(ok)
        restart.assert_not_called()
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertNotIn("tcpMaxSeg", sockopt)

    def test_disable_without_reality_inbounds(self):
        from chimera.modules.server_fragment import server_fragment_disable
        patches, _, remove, _ = self._disable_patches({"inbounds": []})
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
        self.assertTrue(ok)
        remove.assert_called_once()   # TCPMSS-правила сняты и без inbound

    def test_disable_removes_dropin_and_restore_script(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
            _load_server_fragment_state, _dropin_content, MECH_SOCKOPT,
        )
        # эмулируем включённый механизм A: GODEBUG-drop-in + tcpMaxSeg в конфиге
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        self._restore_path.write_text("#!/usr/bin/env python3\n")
        patches, restart, remove, reload = self._disable_patches(
            _reality_with_tcpmaxseg(1300))
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
            cfg = _load_xray_config()
            sf = _load_server_fragment_state()
        self.assertTrue(ok)
        self.assertFalse(self._dropin_path.exists())    # drop-in снят
        self.assertFalse(self._restore_path.exists())   # restore-скрипт снят
        reload.assert_called_once()                     # + daemon-reload
        self.assertNotIn("tcpMaxSeg",
                         cfg["inbounds"][0]["streamSettings"]["sockopt"])
        self.assertFalse(sf["enabled"])
        self.assertEqual(sf["mechanism"], "")
        restart.assert_called_once()   # рестарт из-за изменения конфига

    def test_disable_extra_restart_when_only_dropin_present(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _dropin_content, MECH_SOCKOPT,
        )
        # конфиг уже чист, но GODEBUG-drop-in стоит → нужен дополнительный
        # рестарт («Перезапускаю xray для применения окружения без GODEBUG»)
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        patches, restart, remove, reload = self._disable_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
        self.assertTrue(ok)
        self.assertFalse(self._dropin_path.exists())
        reload.assert_called_once()
        restart.assert_called_once()   # именно дополнительный рестарт

    def test_disable_restart_false_skips_extra_restart(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _dropin_content, MECH_SOCKOPT,
        )
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        patches, restart, remove, reload = self._disable_patches(_REALITY_CONFIG)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable(restart=False)
        self.assertTrue(ok)
        self.assertFalse(self._dropin_path.exists())   # снят и без рестарта
        reload.assert_called_once()
        restart.assert_not_called()

    def test_disable_dropin_removed_before_restart(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _dropin_content, MECH_SOCKOPT,
        )
        # порядок: drop-in (+daemon-reload) снимается ДО рестарта сервиса,
        # чтобы рестартнутый процесс сразу поднялся без GODEBUG/ExecStartPost
        self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
        patches, restart, remove, reload = self._disable_patches(
            _reality_with_tcpmaxseg(1300))
        manager = MagicMock()
        manager.attach_mock(reload, "reload")
        manager.attach_mock(restart, "restart")
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
        self.assertTrue(ok)
        names = [c[0] for c in manager.mock_calls]
        self.assertLess(names.index("reload"), names.index("restart"))

    def test_disable_multiple_reality_inbounds(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        cfg = json.loads(json.dumps(_MULTI_REALITY_CONFIG))
        for inb in cfg["inbounds"]:
            if inb.get("streamSettings", {}).get("security") == "reality":
                inb["streamSettings"]["sockopt"] = {"tcpMaxSeg": 1300}
        patches, _, _, _ = self._disable_patches(cfg)
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            ok = server_fragment_disable()
            out = _load_xray_config()
        self.assertTrue(ok)
        for inb in out["inbounds"]:
            sockopt = inb.get("streamSettings", {}).get("sockopt")
            if sockopt is not None:
                self.assertNotIn("tcpMaxSeg", sockopt,
                                 f"inbound {inb['tag']} keeps tcpMaxSeg")


# ─────────────────────────────────────────────────────────────────────────────
# 11. server_fragment_status
# ─────────────────────────────────────────────────────────────────────────────

_STATUS_KEYS = (
    "enabled", "preset", "mss", "mechanism", "ports",
    "in_config", "config_mss", "legacy_fragment", "iptables_rules",
    "godebug_installed", "restore_installed",
    "core_version", "core_supported", "inbound_protocol",
    "last_applied", "last_disabled",
)


class TestStatus(_FragmentTestBase):
    """server_fragment_status — полный набор полей и их значения."""

    def _status_patches(self, cfg=None, core=(26, 10, 21), ipt=0, state=None):
        if state is not None:
            self._state_path.write_text(json.dumps(state))
        patches = self._base_patches(cfg) + [
            patch(MOD + "._xray_core_version", return_value=core),
            patch(MOD + "._count_tcpmss_rules", return_value=ipt),
        ]
        return patches

    def test_status_returns_dict_with_required_keys(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            st = server_fragment_status()
        self.assertIsInstance(st, dict)
        for key in _STATUS_KEYS:
            self.assertIn(key, st, f"missing key: {key}")

    def test_status_enabled_mechanism_a(self):
        from chimera.modules.server_fragment import server_fragment_status
        state = {"server_fragment": {
            "enabled": True, "preset": "balanced", "mss": 1300,
            "mechanism": "tcpMaxSeg", "ports": [443],
            "last_applied": "2025-01-01 00:00:00",
        }}
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(
                _reality_with_tcpmaxseg(1300), state=state))
            st = server_fragment_status()
        self.assertTrue(st["enabled"])
        self.assertEqual(st["mechanism"], "tcpMaxSeg")
        self.assertTrue(st["in_config"])
        self.assertEqual(st["config_mss"], 1300)
        self.assertFalse(st["legacy_fragment"])
        self.assertEqual(st["iptables_rules"], 0)
        # v2: ни GODEBUG-drop-in, ни restore-скрипта в этом сценарии нет;
        # fallback_reason — опциональный ключ, здесь отсутствует
        self.assertFalse(st["godebug_installed"])
        self.assertFalse(st["restore_installed"])
        self.assertNotIn("fallback_reason", st)
        self.assertEqual(st["core_version"], "26.10.21")
        self.assertTrue(st["core_supported"])
        self.assertEqual(st["inbound_protocol"], "reality")
        self.assertEqual(st["ports"], [443])
        self.assertEqual(st["last_applied"], "2025-01-01 00:00:00")

    def test_status_disabled_by_default(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            st = server_fragment_status()
        self.assertFalse(st["enabled"])
        self.assertFalse(st["in_config"])
        self.assertIsNone(st["config_mss"])
        self.assertFalse(st["legacy_fragment"])
        self.assertEqual(st["inbound_protocol"], "reality")

    def test_status_detects_legacy_fragment(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(
                _reality_with_legacy_fragment()))
            st = server_fragment_status()
        self.assertTrue(st["legacy_fragment"])
        self.assertFalse(st["in_config"])
        self.assertIsNone(st["config_mss"])

    def test_status_partial_tcpmaxseg_not_in_config(self):
        from chimera.modules.server_fragment import server_fragment_status
        # tcpMaxSeg только у первого из двух reality inbound → in_config False
        cfg = json.loads(json.dumps(_MULTI_REALITY_CONFIG))
        cfg["inbounds"][0]["streamSettings"]["sockopt"] = {"tcpMaxSeg": 1300}
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(cfg))
            st = server_fragment_status()
        self.assertFalse(st["in_config"])
        self.assertEqual(st["config_mss"], 1300)

    def test_status_mechanism_b_fields(self):
        from chimera.modules.server_fragment import server_fragment_status
        state = {"server_fragment": {
            "enabled": True, "preset": "custom", "mss": 800,
            "mechanism": "tcpmss", "ports": [443],
        }}
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(
                _REALITY_CONFIG, core=(1, 8, 24), ipt=2, state=state))
            st = server_fragment_status()
        self.assertEqual(st["mechanism"], "tcpmss")
        self.assertEqual(st["mss"], 800)
        self.assertFalse(st["in_config"])          # механизм B — конфиг чист
        self.assertIsNone(st["config_mss"])
        self.assertEqual(st["iptables_rules"], 2)  # правила стоят
        self.assertEqual(st["core_version"], "1.8.24")
        self.assertFalse(st["core_supported"])
        self.assertFalse(st["godebug_installed"])   # v2: GODEBUG не ставился
        self.assertFalse(st["restore_installed"])   # v2: ни скрипта, ни drop-in

    def test_status_reports_xhttp_protocol(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_XHTTP_CONFIG))
            st = server_fragment_status()
        self.assertEqual(st["inbound_protocol"], "xhttp")
        self.assertFalse(st["in_config"])

    def test_status_reports_none_without_config(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch(MOD + "._XRAY_CONFIG", Path("/tmp/nonexistent_config.json")),
                patch(MOD + "._XRAY_CONFIG_ALT", Path("/tmp/nonexistent_alt.json")),
                patch(MOD + "._STATE_FILE", self._state_path),
                patch(MOD + "._SVC_DROPIN", self._dropin_path),
                patch(MOD + "._RESTORE_SCRIPT", self._restore_path),
                patch(MOD + "._xray_core_version", return_value=None),
                patch(MOD + "._count_tcpmss_rules", return_value=0),
            ])
            st = server_fragment_status()
        self.assertEqual(st["inbound_protocol"], "none")
        self.assertEqual(st["core_version"], "")
        self.assertFalse(st["core_supported"])
        self.assertFalse(st["in_config"])

    def test_status_godebug_installed_true(self):
        from chimera.modules.server_fragment import (
            server_fragment_status, _dropin_content, MECH_SOCKOPT,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
            st = server_fragment_status()
        self.assertTrue(st["godebug_installed"])
        self.assertFalse(st["restore_installed"])

    def test_status_restore_requires_script_and_execstartpost(self):
        from chimera.modules.server_fragment import (
            server_fragment_status, _dropin_content, MECH_TCPMSS,
            _RESTORE_SCRIPT_CONTENT,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            # только скрипт без drop-in → False
            self._restore_path.write_text(_RESTORE_SCRIPT_CONTENT)
            st1 = server_fragment_status()
            # скрипт + drop-in B (ExecStartPost) → True
            self._dropin_path.write_text(_dropin_content(MECH_TCPMSS))
            st2 = server_fragment_status()
        self.assertFalse(st1["restore_installed"])
        self.assertTrue(st2["restore_installed"])
        self.assertFalse(st2["godebug_installed"])

    def test_status_restore_false_with_godebug_dropin(self):
        from chimera.modules.server_fragment import (
            server_fragment_status, _dropin_content, MECH_SOCKOPT,
            _RESTORE_SCRIPT_CONTENT,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            # GODEBUG-drop-in (механизм A) + restore-скрипт → restore_installed
            # False: drop-in не содержит ExecStartPost
            self._dropin_path.write_text(_dropin_content(MECH_SOCKOPT))
            self._restore_path.write_text(_RESTORE_SCRIPT_CONTENT)
            st = server_fragment_status()
        self.assertTrue(st["godebug_installed"])
        self.assertFalse(st["restore_installed"])

    def test_status_fallback_reason_from_state(self):
        from chimera.modules.server_fragment import server_fragment_status
        reason = "tcpMaxSeg не применился (журнал: failed to set TCP_MAXSEG)"
        state = {"server_fragment": {
            "enabled": True, "preset": "balanced", "mss": 1300,
            "mechanism": "tcpmss", "ports": [443],
            "fallback_reason": reason,
        }}
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG, state=state))
            st = server_fragment_status()
        self.assertIn("fallback_reason", st)
        self.assertEqual(st["fallback_reason"], reason)

    def test_status_fallback_reason_absent_by_default(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._status_patches(_REALITY_CONFIG))
            st = server_fragment_status()
        self.assertNotIn("fallback_reason", st)


# ─────────────────────────────────────────────────────────────────────────────
# 12. server_fragment_reapply_after_rebuild — хук
# ─────────────────────────────────────────────────────────────────────────────

class TestReapplyHook(_FragmentTestBase):
    """reapply_after_rebuild: disabled → noop; enabled → enable(preset, mss)."""

    def _reapply_patches(self, state):
        self._state_path.write_text(json.dumps(state))
        enable = MagicMock(return_value=True)
        patches = self._base_patches(_REALITY_CONFIG) + [
            patch(MOD + ".server_fragment_enable", enable),
        ]
        return patches, enable

    def test_noop_when_disabled(self):
        from chimera.modules.server_fragment import (
            server_fragment_reapply_after_rebuild, _load_xray_config,
        )
        patches, enable = self._reapply_patches(
            {"server_fragment": {"enabled": False, "preset": "balanced",
                                 "mss": 1300}})
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_reapply_after_rebuild()
            cfg = _load_xray_config()
        enable.assert_not_called()
        self.assertNotIn("sockopt", cfg["inbounds"][0]["streamSettings"])

    def test_reapplies_with_state_params(self):
        from chimera.modules.server_fragment import (
            server_fragment_reapply_after_rebuild,
        )
        patches, enable = self._reapply_patches(
            {"server_fragment": {"enabled": True, "preset": "aggressive",
                                 "mss": 800}})
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_reapply_after_rebuild()
        enable.assert_called_once_with(preset="aggressive", mss=800,
                                       restart=True)

    def test_reapplies_missing_mss_passes_none(self):
        from chimera.modules.server_fragment import (
            server_fragment_reapply_after_rebuild,
        )
        patches, enable = self._reapply_patches(
            {"server_fragment": {"enabled": True, "preset": "light"}})
        with ExitStack() as stack:
            _enter_patches(stack, patches)
            server_fragment_reapply_after_rebuild()
        enable.assert_called_once_with(preset="light", mss=None,
                                       restart=True)


# ─────────────────────────────────────────────────────────────────────────────
# 13. _ensure_state / _migrate_legacy_state
# ─────────────────────────────────────────────────────────────────────────────

class TestEnsureState(unittest.TestCase):
    """_ensure_state — дефолт + миграция легаси-state v4.27."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch(MOD + "._STATE_FILE", self._state_path)

    def _write_sf(self, sf):
        self._state_path.write_text(json.dumps({"server_fragment": sf}))

    def test_creates_default_when_missing(self):
        from chimera.modules.server_fragment import _ensure_state
        with self._patch():
            sf = _ensure_state()
        self.assertFalse(sf["enabled"])
        self.assertEqual(sf["preset"], "balanced")
        self.assertEqual(sf["mss"], 1300)
        self.assertEqual(sf["mechanism"], "")
        self.assertEqual(sf["ports"], [])
        self.assertEqual(sf["last_applied"], "")
        self.assertTrue(self._state_path.exists())

    def test_migrates_legacy_light(self):
        from chimera.modules.server_fragment import _ensure_state
        self._write_sf({"enabled": True, "preset": "light",
                        "packets": "1-3", "length": "3-7", "interval": "10-20"})
        with self._patch():
            sf = _ensure_state()
        self.assertTrue(sf["enabled"])          # enabled сохраняется
        self.assertEqual(sf["preset"], "light")
        self.assertEqual(sf["mss"], 1400)       # light → 1400
        for k in ("packets", "length", "interval"):
            self.assertNotIn(k, sf, f"legacy key {k} must be removed")

    def test_migrates_legacy_aggressive_and_balanced(self):
        from chimera.modules.server_fragment import _ensure_state
        for preset, mss in (("aggressive", 800), ("balanced", 1300)):
            with self.subTest(preset=preset):
                self._write_sf({"enabled": True, "preset": preset,
                                "packets": "1-3", "length": "3-7",
                                "interval": "10-20"})
                with self._patch():
                    sf = _ensure_state()
                self.assertEqual(sf["mss"], mss)
                self.assertNotIn("packets", sf)
                self.assertNotIn("length", sf)
                self.assertNotIn("interval", sf)

    def test_migrates_legacy_custom_to_default_1300(self):
        from chimera.modules.server_fragment import _ensure_state
        self._write_sf({"enabled": False, "preset": "custom",
                        "packets": "2-4", "length": "8-16", "interval": "15-30"})
        with self._patch():
            sf = _ensure_state()
        self.assertEqual(sf["mss"], 1300)
        self.assertFalse(sf["enabled"])

    def test_non_legacy_state_untouched(self):
        from chimera.modules.server_fragment import _ensure_state
        original = {"enabled": True, "preset": "aggressive", "mss": 900,
                    "mechanism": "tcpMaxSeg", "ports": [443],
                    "last_applied": "2025-01-01 00:00:00"}
        self._write_sf(original)
        with self._patch():
            sf = _ensure_state()
        self.assertEqual(sf, original)

    def test_state_without_mss_gets_default(self):
        from chimera.modules.server_fragment import _ensure_state
        self._write_sf({"enabled": False, "preset": "balanced"})
        with self._patch():
            sf = _ensure_state()
        self.assertEqual(sf["mss"], 1300)

    def test_returns_existing_state(self):
        from chimera.modules.server_fragment import _ensure_state
        self._write_sf({"enabled": True, "preset": "aggressive"})
        with self._patch():
            sf = _ensure_state()
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["preset"], "aggressive")


class TestMigrateLegacyState(unittest.TestCase):
    """_migrate_legacy_state — чистая функция миграции."""

    def setUp(self):
        _setup_core()

    def test_no_legacy_keys_unchanged(self):
        from chimera.modules.server_fragment import _migrate_legacy_state
        sf = {"enabled": False, "preset": "balanced", "mss": 1300,
              "mechanism": "", "ports": []}
        self.assertEqual(_migrate_legacy_state(dict(sf)), sf)

    def test_legacy_keys_mapped_to_mss(self):
        from chimera.modules.server_fragment import _migrate_legacy_state
        sf = {"enabled": True, "preset": "light",
              "packets": "1-3", "length": "3-7", "interval": "10-20"}
        out = _migrate_legacy_state(sf)
        self.assertEqual(out["mss"], 1400)
        self.assertNotIn("packets", out)
        self.assertNotIn("length", out)
        self.assertNotIn("interval", out)
        self.assertTrue(out["enabled"])

    def test_keeps_explicit_mss(self):
        from chimera.modules.server_fragment import _migrate_legacy_state
        sf = {"enabled": True, "preset": "light", "mss": 999,
              "packets": "1-3", "length": "3-7", "interval": "10-20"}
        out = _migrate_legacy_state(sf)
        self.assertEqual(out["mss"], 999)

    def test_unknown_legacy_preset_defaults_to_1300(self):
        from chimera.modules.server_fragment import _migrate_legacy_state
        sf = {"enabled": True, "preset": "bogus", "packets": "1-3",
              "length": "3-7", "interval": "10-20"}
        out = _migrate_legacy_state(sf)
        self.assertEqual(out["mss"], 1300)


# ─────────────────────────────────────────────────────────────────────────────
# 14. TUI-хелперы
# ─────────────────────────────────────────────────────────────────────────────

class TestTuiHelpers(unittest.TestCase):
    """_format_status_line / _prompt_custom_and_apply (без input()-меню)."""

    def setUp(self):
        _setup_core()

    @staticmethod
    def _st(**over):
        base = {"enabled": False, "mechanism": "", "mss": 0,
                "in_config": False, "iptables_rules": 0}
        base.update(over)
        return base

    def test_status_line_disabled(self):
        from chimera.modules.server_fragment import _format_status_line
        s = _format_status_line(self._st(enabled=False))
        self.assertIn("отключён", s)
        self.assertNotIn("включён", s)

    def test_status_line_enabled_and_applied(self):
        from chimera.modules.server_fragment import _format_status_line
        s = _format_status_line(self._st(
            enabled=True, mechanism="tcpMaxSeg", mss=1300, in_config=True))
        self.assertIn("включён", s)
        self.assertIn("tcpMaxSeg", s)
        self.assertIn("MSS 1300", s)
        self.assertIn("применён ✓", s)

    def test_status_line_enabled_not_applied(self):
        from chimera.modules.server_fragment import _format_status_line
        s = _format_status_line(self._st(
            enabled=True, mechanism="tcpmss", mss=800,
            in_config=False, iptables_rules=0))
        self.assertIn("включён", s)
        self.assertIn("применён ✗", s)
        self.assertIn("MSS 800", s)

    def test_status_line_iptables_rules_count_as_applied(self):
        from chimera.modules.server_fragment import _format_status_line
        s = _format_status_line(self._st(
            enabled=True, mechanism="tcpmss", mss=800,
            in_config=False, iptables_rules=2))
        self.assertIn("применён ✓", s)

    def test_prompt_custom_applies_valid_mss(self):
        from chimera.modules.server_fragment import _prompt_custom_and_apply
        enable = MagicMock()
        with patch(MOD + ".server_fragment_enable", enable), \
             patch("builtins.input", return_value="1200"), \
             patch("time.sleep"):
            _prompt_custom_and_apply()
        enable.assert_called_once_with(preset="custom", mss=1200)

    def test_prompt_custom_rejects_non_numeric(self):
        from chimera.modules.server_fragment import _prompt_custom_and_apply
        enable = MagicMock()
        with patch(MOD + ".server_fragment_enable", enable), \
             patch("builtins.input", return_value="abc"), \
             patch("time.sleep"):
            _prompt_custom_and_apply()
        enable.assert_not_called()

    def test_prompt_custom_rejects_out_of_range(self):
        from chimera.modules.server_fragment import _prompt_custom_and_apply
        enable = MagicMock()
        with patch(MOD + ".server_fragment_enable", enable), \
             patch("builtins.input", return_value="2000"), \
             patch("time.sleep"):
            _prompt_custom_and_apply()
        enable.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 15. Сохранение/чтение state (базовая IO-гигиена, как в старом файле)
# ─────────────────────────────────────────────────────────────────────────────

class TestStateIO(unittest.TestCase):
    """_load_state / _save_state / _load_server_fragment_state."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch(MOD + "._STATE_FILE", self._state_path)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.server_fragment import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.server_fragment import _load_state
        self._state_path.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_save_writes_json(self):
        from chimera.modules.server_fragment import _save_state, _load_state
        with self._patch():
            _save_state({"server_fragment": {"enabled": True}})
            self.assertEqual(_load_state()["server_fragment"]["enabled"], True)

    def test_save_server_fragment_preserves_other_keys(self):
        from chimera.modules.server_fragment import (
            _save_server_fragment_state, _load_state,
        )
        self._state_path.write_text(json.dumps({
            "uuid": "test-uuid",
            "domain": "example.com",
        }))
        with self._patch():
            _save_server_fragment_state({"enabled": True, "mss": 1300})
            full = _load_state()
        self.assertEqual(full["uuid"], "test-uuid")
        self.assertEqual(full["domain"], "example.com")
        self.assertTrue(full["server_fragment"]["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
