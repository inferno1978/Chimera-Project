#!/usr/bin/env python3
"""
tests/test_v58_identity_guard.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для v58 (Anti-Empty Identity Guard):

  A. _identity_params_recover (ядро):
     • все параметры на месте → ничего не меняется, [] возвращён;
     • глобалы пустые + живой config.json → восстановление uuid/short_id/
       private_key/public_key/domain/spiderx ИЗ ЖИВОГО КОНФИГА (источник
       истины для выданных ссылок);
     • глобалы пустые + только state.json → восстановление из state;
     • state пустой, config пустой, users.json есть → uuid из users.json;
     • public_key пустой, private_key есть → деривация через xray x25519 -i;
     • полный vacuum (fresh install) → генерация новых значений (непустых!);
     • self-heal: восстановленные значения дописываются в state.json, если
       там пусто (генераторы ссылок читают state напрямую).

  B. _reality_transport_params_from_state (ссылочные генераторы):
     • state с ключами → как есть;
     • state без public_key/short_id + живой конфиг → добор из конфига;
     • ничего нет → пустые строки (но не исключение).

  C. Генераторы конфига вызывают guard:
     • generate_xray_config / generate_xray_config_xhttp /
       generate_xray_config_chain_entry / generate_xray_config_chain_entry_multi
       содержат вызов _identity_params_recover до чтения параметров.

  D. Мини-фиксы v58:
     • awg_peer_rebuild_conf: пустой server_privkey → False, конфиг не пишется;
     • singbox _build_vless_ws_cdn_inbound: пустой uuid → ValueError
       (и генерация не пишет users: []);
     • credential_rotation cron-скрипт патчит users.json + reset-failed;
     • csqtt main-ссылка: пустой main_password → guard (нет битой ссылки);
     • trusttunnel_install: нет предсказуемого placeholder-пароля.

Контекст: регенерация конфига при частично повреждённом state.json
оставляла UUID/ShortID/REALITY-ключи пустыми — xray стартовал с битым
REALITY, а генераторы ссылок выдавали vless://...?pbk=&sid=. Все выданные
пользователям ссылки умирали. v58 — гарантия непустых параметров во всех
точках генерации/регенерации.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec в __dict__ фейкового модуля."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    fake_core = types.ModuleType("chimera._core")
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


# Живой конфиг с реальными (валидными по формату) значениями
_LIVE_CONFIG = {
    "inbounds": [{
        "tag": "inbound-vless",
        "port": 443,
        "protocol": "vless",
        "settings": {"clients": [
            {"id": "11111111-2222-3333-4444-555555555555",
             "email": "user@example.com"},
        ]},
        "streamSettings": {
            "security": "reality",
            "realitySettings": {
                "privateKey": "privKEY_livE_0123456789abcdef",
                "publicKey":  "pubKEY_livE_0123456789abcdef",
                "shortIds":   ["abcd1234"],
                "spiderX":    "/spider",
                "serverNames": ["live.example.com"],
            },
        },
    }],
}


def _make_core_with(state_json=None, live_config=None, users_json=None,
                    xray_x25519_out="", xray_bin_exists=True):
    """Собирает фейковый _core с изолированной ФС (tmp_path)."""
    fake_core = _setup_core_in_sysmodules()
    import tempfile
    tmp = tempfile.mkdtemp(prefix="v58_test_")
    tmp_path = Path(tmp)

    state_file = tmp_path / "state.json"
    if state_json is not None:
        state_file.write_text(json.dumps(state_json))
    # подменяем пути в fake_core
    fake_core.STATE_FILE = state_file
    fake_core.USERS_FILE = tmp_path / "users.json"
    if users_json is not None:
        fake_core.USERS_FILE.write_text(json.dumps(users_json))
    cfg = tmp_path / "config.json"
    if live_config is not None:
        cfg.write_text(json.dumps(live_config))
    fake_core.CONFIG_DIR = tmp_path
    fake_core.XRAY_BIN = tmp_path / ("xray" if xray_bin_exists else "nope")

    def fake_run(cmd, capture=False, check=False, quiet=False, **kw):
        cmd = list(cmd)
        if cmd[:1] == [str(fake_core.XRAY_BIN)] and "x25519" in cmd:
            return _completed(stdout=xray_x25519_out)
        return _completed()

    fake_core._run = fake_run
    # info/warn уже определены в _core; лог в файл отключаем (no-op)
    return fake_core


# ═════════════════════════════════════════════════════════════════════════════
#  A. _identity_params_recover
# ═════════════════════════════════════════════════════════════════════════════
class TestIdentityParamsRecover(unittest.TestCase):

    def test_all_filled_noop(self):
        """Все параметры на месте → guard не меняет ничего, возвращает []."""
        core = _make_core_with(
            state_json={"uuid": "u", "short_id": "s", "domain": "d.com",
                        "public_key": "pbk", "private_key": "prk",
                        "spiderx": "/sx", "socket": "/run/x.sock"},
            live_config=_LIVE_CONFIG)
        core.PARAM_UUID = "u-uuid"
        core.PARAM_SHORTID = "sid"
        core.PARAM_PRIVATE_KEY = "prk"
        core.PARAM_PUBLIC_KEY = "pbk"
        core.PARAM_DOMAIN = "d.com"
        core.PARAM_SPIDERX = "/sx"
        core.PARAM_SOCKET_PATH = "/run/x.sock"
        recovered = core._identity_params_recover()
        self.assertEqual(recovered, [])
        self.assertEqual(core.PARAM_UUID, "u-uuid")

    def test_recover_from_live_config(self):
        """Глобалы пустые + живой config.json → восстановление из конфига."""
        core = _make_core_with(
            state_json={"domain": "live.example.com"},
            live_config=_LIVE_CONFIG)
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = ""
        core.PARAM_PRIVATE_KEY = ""
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_DOMAIN = ""
        core.PARAM_SPIDERX = ""
        recovered = core._identity_params_recover()
        self.assertEqual(core.PARAM_UUID,
                         "11111111-2222-3333-4444-555555555555")
        self.assertEqual(core.PARAM_SHORTID, "abcd1234")
        self.assertEqual(core.PARAM_PRIVATE_KEY, "privKEY_livE_0123456789abcdef")
        self.assertEqual(core.PARAM_PUBLIC_KEY, "pubKEY_livE_0123456789abcdef")
        self.assertEqual(core.PARAM_DOMAIN, "live.example.com")
        self.assertEqual(core.PARAM_SPIDERX, "/spider")
        for f in ("uuid", "short_id", "private_key", "public_key"):
            self.assertIn(f, recovered)

    def test_recover_from_state(self):
        """Глобалы пустые + только state.json (конфига нет) → из state."""
        core = _make_core_with(
            state_json={"uuid": "state-uuid", "short_id": "state-sid",
                        "public_key": "state-pbk",
                        "private_key": "state-prk",
                        "spiderx": "/st", "domain": "state.example.com"},
            live_config=None)
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = ""
        core.PARAM_PRIVATE_KEY = ""
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_SPIDERX = ""
        core.PARAM_DOMAIN = ""
        core._identity_params_recover()
        self.assertEqual(core.PARAM_UUID, "state-uuid")
        self.assertEqual(core.PARAM_SHORTID, "state-sid")
        self.assertEqual(core.PARAM_PRIVATE_KEY, "state-prk")
        self.assertEqual(core.PARAM_PUBLIC_KEY, "state-pbk")

    def test_uuid_from_users_json(self):
        """state без uuid, конфига нет, users.json есть → uuid юзера."""
        core = _make_core_with(
            state_json={"domain": "x.com", "short_id": "s",
                        "public_key": "p", "private_key": "k"},
            live_config=None,
            users_json=[{"uuid": "users-uuid", "email": "a@b.c"}])
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = "s"
        core.PARAM_PRIVATE_KEY = "k"
        core.PARAM_PUBLIC_KEY = "p"
        core.PARAM_SPIDERX = "/"
        core._identity_params_recover()
        self.assertEqual(core.PARAM_UUID, "users-uuid")

    def test_pubkey_derived_from_privkey(self):
        """public_key пустой, private_key есть → деривация xray x25519 -i."""
        core = _make_core_with(
            state_json={"uuid": "u", "short_id": "s", "domain": "d.com",
                        "private_key": "PRIV-KEY"},
            live_config=None,
            xray_x25519_out="Private key: PRIV-KEY\nPublic key: DERIVED-PUB-KEY\n")
        core.PARAM_UUID = "u"
        core.PARAM_SHORTID = "s"
        core.PARAM_PRIVATE_KEY = "PRIV-KEY"
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_SPIDERX = "/"
        core._identity_params_recover()
        self.assertEqual(core.PARAM_PUBLIC_KEY, "DERIVED-PUB-KEY")

    def test_fresh_install_generates_nonempty(self):
        """Полный vacuum → генерация НОВЫХ непустых значений."""
        core = _make_core_with(state_json=None, live_config=None,
                               users_json=None,
                               xray_x25519_out="Private key: NEWPRIV\nPublic key: NEWPUB\n")
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = ""
        core.PARAM_PRIVATE_KEY = ""
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_SPIDERX = ""
        core.PARAM_DOMAIN = "fresh.example.com"
        core._identity_params_recover()
        self.assertTrue(core.PARAM_UUID)
        self.assertTrue(core.PARAM_SHORTID)
        self.assertTrue(core.PARAM_SPIDERX)
        # private из x25519-вывода, public — тоже
        self.assertEqual(core.PARAM_PRIVATE_KEY, "NEWPRIV")
        self.assertEqual(core.PARAM_PUBLIC_KEY, "NEWPUB")

    def test_selfheal_state_json(self):
        """Восстановленные из конфига значения дописываются в state.json."""
        core = _make_core_with(
            state_json={"domain": "live.example.com", "installed": True},
            live_config=_LIVE_CONFIG)
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = ""
        core.PARAM_PRIVATE_KEY = ""
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_SPIDERX = ""
        core.PARAM_DOMAIN = ""
        core._identity_params_recover()
        healed = json.loads(core.STATE_FILE.read_text())
        self.assertEqual(healed.get("uuid"),
                         "11111111-2222-3333-4444-555555555555")
        self.assertEqual(healed.get("short_id"), "abcd1234")
        self.assertEqual(healed.get("public_key"), "pubKEY_livE_0123456789abcdef")
        self.assertEqual(healed.get("private_key"), "privKEY_livE_0123456789abcdef")
        # существующее поле не тронуто
        self.assertEqual(healed.get("domain"), "live.example.com")
        self.assertTrue(healed.get("installed"))


# ═════════════════════════════════════════════════════════════════════════════
#  B. _reality_transport_params_from_state
# ═════════════════════════════════════════════════════════════════════════════
class TestRealityTransportParams(unittest.TestCase):

    def test_state_complete(self):
        """State содержит ключи → возвращаются как есть (без чтения конфига)."""
        core = _make_core_with(
            state_json={"public_key": "PBK", "short_id": "SID",
                        "spiderx": "/sx"},
            live_config=None)
        pub, sid, spx = core._reality_transport_params_from_state(
            {"public_key": "PBK", "short_id": "SID", "spiderx": "/sx"})
        self.assertEqual((pub, sid, spx), ("PBK", "SID", "/sx"))

    def test_state_partial_fallback_to_live_config(self):
        """State без public_key/short_id → добор из живого config.json."""
        core = _make_core_with(
            state_json={"domain": "live.example.com"},
            live_config=_LIVE_CONFIG)
        pub, sid, spx = core._reality_transport_params_from_state(
            {"domain": "live.example.com"})
        self.assertEqual(pub, "pubKEY_livE_0123456789abcdef")
        self.assertEqual(sid, "abcd1234")
        self.assertEqual(spx, "/spider")

    def test_nothing_available_empty_not_exception(self):
        """Ни state, ни конфига → пустые строки, БЕЗ исключения."""
        core = _make_core_with(state_json=None, live_config=None)
        pub, sid, spx = core._reality_transport_params_from_state({})
        self.assertEqual((pub, sid, spx), ("", "", ""))


# ═════════════════════════════════════════════════════════════════════════════
#  C. Генераторы конфига вызывают guard
# ═════════════════════════════════════════════════════════════════════════════
class TestGeneratorsCallGuard(unittest.TestCase):

    def test_generate_xray_config_calls_guard(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "xray_install.py").read_text()
        for func in ("def generate_xray_config(", "def generate_xray_config_xhttp("):
            start = src.index(func)
            body = src[start:start + 3000]
            self.assertIn("_identity_params_recover", body,
                          f"{func} должен звать _identity_params_recover")

    def test_chain_generators_call_guard(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "chain_nodes.py").read_text()
        for func in ("def generate_xray_config_chain_entry(",
                     "def generate_xray_config_chain_entry_multi("):
            start = src.index(func)
            body = src[start:start + 3000]
            self.assertIn("_identity_params_recover", body,
                          f"{func} должен звать _identity_params_recover")

    def test_guard_callable_through_module(self):
        """Guard доступен как атрибут _core (генераторы зовут core.<name>)."""
        core = _setup_core_in_sysmodules()
        self.assertTrue(callable(getattr(core, "_identity_params_recover", None)))
        self.assertTrue(callable(getattr(core, "_reality_transport_params_from_state", None)))


# ═════════════════════════════════════════════════════════════════════════════
#  D. Мини-фиксы v58
# ═════════════════════════════════════════════════════════════════════════════
class TestMiniFixes(unittest.TestCase):

    def test_awg_rebuild_conf_guards_empty_privkey(self):
        """awg_peer_rebuild_conf: пустой server_privkey → False (конфиг цел)."""
        awg_state = types.ModuleType("chimera.modules.awg_state")
        awg_state.awgs_state_load = lambda: {"peers": [], "port": 51820}
        awg_state.awgs_state_save = lambda s: None
        awg_state.awgs_state_peer_add = lambda *a, **kw: None
        awg_state.awgs_state_peer_remove = lambda *a, **kw: None
        awg_state.awgs_state_peer_find = lambda *a, **kw: None
        awg_state.awgs_state_peer_update = lambda *a, **kw: None
        awg_state.awgs_state_next_ip = lambda *a, **kw: ""
        awg_state.awgs_state_next_ipv6 = lambda *a, **kw: ""
        awg_state.awgs_state_get_params = lambda *a, **kw: {}
        awg_state.awgs_state_get_server_pubkey = lambda *a, **kw: ""
        awg_state.awgs_state_get_port = lambda *a, **kw: 51820
        awg_state.awgs_state_get_endpoint = lambda *a, **kw: ""

        awg_const = types.ModuleType("chimera.modules.awg_constants")
        awg_const.AWGS_KEYS_DIR = Path("/tmp/keys")
        awg_const.AWGS_BIN = "awg"
        awg_const.AWGS_DEFAULT_PARAMS = {}

        wrote = []

        standalone = types.ModuleType("chimera.modules.awg_standalone")
        def _build(**kw):
            wrote.append(kw)
            return "[Interface]\n"
        standalone.awgs_build_server_conf = _build
        standalone.awgs_write_server_conf = lambda c: wrote.append("write") or True
        standalone.awgs_generate_keys = lambda: ("", "")
        standalone.awgs_generate_preshared_key = lambda: ""

        apply_mod = types.ModuleType("chimera.modules.awg_apply")
        apply_mod.awgs_apply = lambda: True

        qr_mod = types.ModuleType("chimera.modules.awg_qr")
        qr_mod.awgs_qr_export_peer = lambda *a, **kw: None

        expires_mod = types.ModuleType("chimera.modules.awg_expires")
        expires_mod.awgs_expires_parse = lambda *a, **kw: None
        expires_mod.awgs_expires_compute_iso = lambda *a, **kw: ""
        expires_mod.awgs_expires_humanize = lambda *a, **kw: ""

        fake_core = _setup_core_in_sysmodules()
        fake_core.warn = lambda *a, **kw: None

        import importlib
        with patch.dict(sys.modules, {
                "chimera.modules.awg_state": awg_state,
                "chimera.modules.awg_constants": awg_const,
                "chimera.modules.awg_standalone": standalone,
                "chimera.modules.awg_apply": apply_mod,
                "chimera.modules.awg_qr": qr_mod,
                "chimera.modules.awg_expires": expires_mod,
                "chimera._core": fake_core}):
            # перезагружаем модуль с чистыми зависимостями
            for m in list(sys.modules):
                if m == "chimera.modules.awg_peers":
                    del sys.modules[m]
            import chimera.modules.awg_peers as awg_peers
            ok = awg_peers.awg_peer_rebuild_conf(apply=False)
        self.assertFalse(ok, "пустой server_privkey должен давать False")
        self.assertNotIn("write", wrote,
                         "awg0.conf НЕ должен перезаписываться при пустом ключе")

    def test_singbox_empty_uuid_raises(self):
        """_build_vless_ws_cdn_inbound: пустой uuid → ValueError (не users: [])."""
        _setup_core_in_sysmodules()
        import chimera.modules.singbox_config as sb
        with self.assertRaises(ValueError):
            sb._build_vless_ws_cdn_inbound({"uuid": "", "ws_path": "/x"})

    def test_cron_rotation_patches_users_json(self):
        """Cron-скрипт ротации UUID патчит users.json (анти-рассинхрон)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "credential_rotation.py").read_text()
        start = src.index("def _uuid_install_cron(")
        body = src[start:start + 8000]
        self.assertIn("users.json", body,
                      "cron-скрипт должен патчить /etc/xray/users.json")
        self.assertIn("reset-failed", body,
                      "cron-скрипт должен содержать reset-failed перед restart")

    def test_trusttunnel_no_placeholder_password(self):
        """Программный install: нет предсказуемого derive_password(000...)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "trusttunnel.py").read_text()
        start = src.index("def trusttunnel_install(")
        end = src.index("def ", start + 10)
        body = src[start:end]
        self.assertNotIn("00000000-0000-0000-0000-000000000000", body,
                         "placeholder-uuid пароля не должен использоваться")
        self.assertIn("token_urlsafe", body,
                      "пароль должен генерироваться случайно")
        self.assertIn("admin_password", body,
                      "пароль должен сохраняться в state")

    def test_csqtt_main_link_guard(self):
        """Меню csqtt: пустой main_password → guard вместо битой ссылки."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "csqtt.py").read_text()
        idx = src.index('main_pass = state.get("main_password", "")')
        window = src[idx:idx + 1200]
        self.assertIn("if not main_pass", window,
                      "после чтения main_pass должен быть guard на пустоту")


# ═════════════════════════════════════════════════════════════════════════════
#  E. Интеграционный сценарий: регенерация не меняет параметры ссылок
# ═════════════════════════════════════════════════════════════════════════════
class TestEndToEndIdentityPreservation(unittest.TestCase):
    """Симуляция: битый state (ключи потеряны) + рабочий конфиг →
    регенерация сохраняет РОВНО те параметры, из которых построены ссылки."""

    def test_regeneration_preserves_link_params(self):
        core = _make_core_with(
            state_json={"domain": "live.example.com",
                        "server_port": 443,
                        "protocol_mode": "reality",
                        "fingerprint": "chrome"},
            live_config=_LIVE_CONFIG)
        # глобалы пустые (как после сбоя загрузки state)
        core.PARAM_UUID = ""
        core.PARAM_SHORTID = ""
        core.PARAM_PRIVATE_KEY = ""
        core.PARAM_PUBLIC_KEY = ""
        core.PARAM_DOMAIN = ""
        core.PARAM_SPIDERX = ""

        core._identity_params_recover()

        # параметры совпадают с живым конфигом → ссылки продолжат работать
        self.assertEqual(core.PARAM_PRIVATE_KEY,
                         _LIVE_CONFIG["inbounds"][0]["streamSettings"]
                         ["realitySettings"]["privateKey"])
        self.assertEqual(core.PARAM_PUBLIC_KEY,
                         _LIVE_CONFIG["inbounds"][0]["streamSettings"]
                         ["realitySettings"]["publicKey"])
        self.assertEqual(core.PARAM_SHORTID,
                         _LIVE_CONFIG["inbounds"][0]["streamSettings"]
                         ["realitySettings"]["shortIds"][0])
        self.assertEqual(core.PARAM_UUID,
                         _LIVE_CONFIG["inbounds"][0]["settings"]
                         ["clients"][0]["id"])

        # и генератор ссылок (fallback-хелпер) выдаёт те же pbk/sid
        pub, sid, _ = core._reality_transport_params_from_state(
            {"domain": "live.example.com"})
        self.assertEqual(pub, "pubKEY_livE_0123456789abcdef")
        self.assertEqual(sid, "abcd1234")


if __name__ == "__main__":
    unittest.main(verbosity=2)
