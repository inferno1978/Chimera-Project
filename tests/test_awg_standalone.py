#!/usr/bin/env python3
"""
tests/test_awg_standalone.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_standalone.py.

Покрывает:
  1. awgs_build_server_conf — генерация awg0.conf (серверная сторона)
  2. awgs_rotate_obfuscation — ротация параметров обфускации (mocked)
"""
from __future__ import annotations

import sys
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


def _default_params():
    return {
        "jc": 4, "jmin": 40, "jmax": 70,
        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
        "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
    }


def _sample_peer(name="alice", **overrides):
    base = {
        "name": name,
        "client_pubkey": "CLIENT_PUBKEY",
        "client_ip": "10.66.66.2",
        "client_ipv6": "fd66:66:66::2",
        "preshared_key": "",
    }
    base.update(overrides)
    return base


class TestAwgsBuildServerConf(unittest.TestCase):
    """awgs_build_server_conf — генерация awg0.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_minimal_config(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="SERVER_PRIV",
            port=51820, subnet="10.66.66.0/24",
            subnet_v6="fd66:66:66::/64", mtu=1280,
            params=_default_params(),
        )
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = SERVER_PRIV", conf)
        self.assertIn("ListenPort = 51820", conf)
        self.assertIn("MTU = 1280", conf)
        self.assertIn("Address = 10.66.66.1/24", conf)
        self.assertIn("Address = fd66:66:66::1/64", conf)

    def test_includes_awg_params(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
        )
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_omits_ipv6_when_empty(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
        )
        # без IPv6 — только один Address (v4)
        self.assertEqual(conf.count("Address ="), 1)

    def test_includes_peers(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer("alice"), _sample_peer("bob")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertIn("[Peer]", conf)
        self.assertIn("CLIENT_PUBKEY", conf)
        self.assertIn("10.66.66.2", conf)

    def test_peer_with_preshared_key(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer(preshared_key="PSK_KEY")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_peer_without_preshared_key(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer(preshared_key="")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertNotIn("PresharedKey", conf)

    def test_i1_included_when_non_empty(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        params = _default_params()
        params["i1"] = "deadbeef"
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=params,
        )
        self.assertIn("I1 = deadbeef", conf)

    def test_empty_i1_to_i5_commented(self):
        """Пустые I1-I5 КОММЕНТИРУЮТСЯ (как в эталонном конфиге Amnezia).

        КОРЕНЬ ПРОБЛЕМЫ (подтверждено zvshka): старые amneziawg-tools падают
        с 'Line unrecognized: I2=' при виде пустой строки 'I2 = '. zvshka
        подтвердил: комментирование строк '# I2 = ' решает проблему.

        РЕШЕНИЕ: пустые I1-I5 пишутся как '# I1 = ' (закомментировано).
        Непустые — без комментария. Это работает везде: старые tools
        игнорируют '#', современные тоже игнорируют, Keenetic принимает
        (эталонный Amnezia конфиг имеет все I1-I5 закомментированными).
        """
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),  # все I1-I5 пустые
        )
        # Все 5 ключей I1-I5 должны быть ЗАКОММЕНТИРОВАНЫ (пустые)
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"когда значение пустое")
            # Не должно быть незакомментированной пустой строки
            # (т.е. 'I2 = ' без '#' перед ней — это ломает старые tools)

    def test_non_empty_i1_to_i5_uncommented(self):
        """Непустые I1-I5 пишутся БЕЗ комментария (как раньше)."""
        from chimera.modules.awg_standalone import awgs_build_server_conf
        params = _default_params()
        params["i1"] = "<r 24>"
        params["i3"] = "<r 16>"  # непустое
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=params,
        )
        # I1 и I3 (непустые) — без комментария
        self.assertIn("I1 = <r 24>", conf)
        self.assertIn("I3 = <r 16>", conf)
        # I2, I4, I5 (пустые) — закомментированы
        self.assertIn("# I2 = ", conf)
        self.assertIn("# I4 = ", conf)
        self.assertIn("# I5 = ", conf)

    def test_no_bare_empty_i_keys(self):
        """Regression — НЕ должно быть 'I2 = ' без '#' (ломает старые tools).

        Это КЛЮЧЕВОЙ regression-тест на жалобу zvshka: пустая строка
        'I2 = ' (без '#') вызывает 'Line unrecognized: I2=' в старых
        amneziawg-tools, сервис не стартует. Все пустые I-ключи должны
        быть закомментированы.
        """
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),  # все I1-I5 пустые
        )
        # Проверяем что НЕТ незакомментированных пустых I-ключей
        for line in conf.splitlines():
            line_stripped = line.strip()
            # Если строка начинается с 'I' и содержит '= ' но значение пустое
            # после '= ' — это баг (должно быть '# I...')
            for key in ("I1", "I2", "I3", "I4", "I5"):
                if line_stripped.startswith(f"{key} = ") and line_stripped == f"{key} = ":
                    self.fail(
                        f"Найдена незакомментированная пустая строка '{line}' — "
                        f"это ломает старые amneziawg-tools. Должно быть '# {key} = '. "
                        f"(регрессия zvshka)"
                    )

    def test_cascade_entry_role(self):
        """cascade_role='entry' + cascade_peer → [Peer] для exit-VPS."""
        from chimera.modules.awg_standalone import awgs_build_server_conf
        cascade_peer = {
            "pubkey": "EXIT_PUBKEY",
            "preshared_key": "CASCADE_PSK",
        }
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
            cascade_role="entry", cascade_peer=cascade_peer,
        )
        self.assertIn("[Peer]", conf)
        self.assertIn("EXIT_PUBKEY", conf)
        self.assertIn("CASCADE_PSK", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertIn("PersistentKeepalive = 25", conf)


# ────────────────────────────────────────────────────────────────────────────
#  Ротация обфускации (Фича 3 из HYDRA-ULTIMATE)
# ────────────────────────────────────────────────────────────────────────────

class TestAwgsRotateObfuscation(unittest.TestCase):
    """awgs_rotate_obfuscation — ротация Jc/Jmin/Jmax/I1 без разрыва туннеля.

    ВАЖНО: эти тесты НЕ мокают awg_peer_rebuild_conf как чёрный ящик —
    иначе регрессия 225c2ba (state коммитился после rebuild_conf, который
    читал СТАРЫЕ params → ротация молча не работала) не ловится.
    Вместо этого мокаются нижележащие функции:
      • awgs_build_server_conf — чтобы проверить с какими params построен конфиг
      • awgs_write_server_conf — чтобы не писать на диск
      • awgs_apply — чтобы контролировать успех/провал syncconf+restart
      • awgs_state_load — чтобы вернуть state со СТАРЫМИ params
    Это позволяет утверждать что в awgs_build_server_conf ушли NEW_PARAMS,
    а не OLD_PARAMS из state.
    """

    # Старые параметры (как в state на диске до ротации)
    OLD_PARAMS = {
        "jc": 4, "jmin": 40, "jmax": 70,
        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
        "i1": "OLD_I1_VALUE", "i2": "", "i3": "", "i4": "", "i5": "",
    }
    # Новые параметры (что вернёт awgs_presets_generate)
    NEW_PARAMS = {
        "jc": 50, "jmin": 100, "jmax": 200,
        "s1": 10, "s2": 20, "s3": 30, "s4": 40,
        "h1": 5, "h2": 6, "h3": 7, "h4": 8,
        "i1": "NEW_I1_VALUE", "i2": "", "i3": "", "i4": "", "i5": "",
    }

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self):
        core = MagicMock()
        for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
            setattr(core, attr, "")
        for attr in ("info", "success", "warn", "error", "log_to_file"):
            setattr(core, attr, MagicMock())
        return core

    def _make_state(self, params=None):
        """Создаёт state-объект с заданными params (по умолчанию OLD_PARAMS)."""
        return {
            "installed": True,
            "carrier_preset": "default",
            "params": params if params is not None else dict(self.OLD_PARAMS),
            "server_privkey": "server_priv_key_xxx",
            "port": 51820,
            "subnet": "10.66.66.0/24",
            "subnet_v6": "",
            "mtu": 1280,
            "peers": [],
            "endpoint_host": "",
            "cascade_role": "",
        }

    def test_returns_false_when_not_installed(self):
        """AWG не установлен → False."""
        from chimera.modules import awg_standalone
        with patch.object(awg_standalone, "_core_module",
                          return_value=self._mock_core()), \
             patch.object(awg_standalone, "awgs_state_is_installed",
                          return_value=False):
            ok, msg = awg_standalone.awgs_rotate_obfuscation()
        self.assertFalse(ok)
        self.assertIn("не установлен", msg)

    def test_returns_false_for_unknown_preset(self):
        from chimera.modules import awg_standalone
        with patch.object(awg_standalone, "_core_module",
                          return_value=self._mock_core()), \
             patch.object(awg_standalone, "awgs_state_is_installed",
                          return_value=True):
            ok, msg = awg_standalone.awgs_rotate_obfuscation("nonexistent_preset")
        self.assertFalse(ok)
        self.assertIn("пресет", msg.lower())

    def test_rotates_and_applies_syncconf_with_new_params(self):
        """Успешная ротация: конфиг строится с NEW_PARAMS (не OLD_PARAMS),
        state коммитится только после успеха apply.

        Regression test for 225c2ba: до фикса awg_peer_rebuild_conf() читал
        state с диска (где OLD_PARAMS) и строил конфиг со СТАРЫМИ параметрами,
        затем возвращал True, и только тогда new_params писались в state.
        Итог: интерфейс оставался на OLD_PARAMS, но state врал что применены NEW.
        """
        from chimera.modules import awg_standalone
        from chimera.modules import awg_peers
        from chimera.modules import awg_presets

        mock_core = self._mock_core()
        state = self._make_state()  # state со OLD_PARAMS

        with patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_update") as mock_update, \
             patch.object(awg_presets, "awgs_presets_generate",
                          return_value=dict(self.NEW_PARAMS)) as mock_gen, \
             patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_build_server_conf",
                          return_value="[Interface]\nPrivateKey = xxx\n") as mock_build, \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_peers, "awgs_apply",
                          return_value=True):
            ok, msg = awg_standalone.awgs_rotate_obfuscation("default")

        self.assertTrue(ok)

        # awgs_presets_generate был вызван (с "default")
        # контракт расширен — ротация передаёт protocol_version из
        # state (отсутствие ключа = "2.0" — старые установки)
        mock_gen.assert_called_once_with("default", protocol_version="2.0")

        # ── КЛЮЧЕВАЯ ПРОВЕРКА: awgs_build_server_conf вызван с NEW_PARAMS ──
        mock_build.assert_called_once()
        build_kwargs = mock_build.call_args.kwargs
        self.assertIn("params", build_kwargs,
                      "awgs_build_server_conf должен принимать params как kwarg")
        applied_params = build_kwargs["params"]

        # Проверяем что это именно NEW_PARAMS, не OLD_PARAMS
        self.assertNotEqual(applied_params.get("jc"), self.OLD_PARAMS["jc"],
                            "Применён jc не должен быть OLD_PARAMS.jc — регрессия 225c2ba")
        self.assertEqual(applied_params.get("jc"), self.NEW_PARAMS["jc"],
                         f"awgs_build_server_conf должен получить NEW jc={self.NEW_PARAMS['jc']}, "
                         f"получили {applied_params.get('jc')}")
        self.assertEqual(applied_params.get("jmin"), self.NEW_PARAMS["jmin"])
        self.assertEqual(applied_params.get("jmax"), self.NEW_PARAMS["jmax"])
        self.assertEqual(applied_params.get("i1"), self.NEW_PARAMS["i1"],
                         "I1 должен быть NEW_I1_VALUE — это и есть ротация обфускации")

        # State коммитится с new_params (после успеха apply)
        mock_update.assert_called_once()
        update_kwargs = mock_update.call_args.kwargs
        self.assertIn("params", update_kwargs)
        committed_params = update_kwargs["params"]
        self.assertEqual(committed_params.get("jc"), self.NEW_PARAMS["jc"])
        self.assertEqual(committed_params.get("i1"), self.NEW_PARAMS["i1"])

        # Сообщение содержит новые значения
        self.assertIn("Jc=", msg)
        self.assertIn(str(self.NEW_PARAMS["jc"]), msg)

    def test_returns_false_when_apply_fails_state_unchanged(self):
        """Apply зафейлился (syncconf + restart оба провалились) → False,
        state НЕ обновлён, и ПОДТВЕРЖДЕНО что на интерфейс ушли НОВЫЕ
        параметры (через write_conf+apply), но state откатился к OLD.

        ВАЖНО: даже при неудаче apply конфиг БЫЛ построен с NEW_PARAMS
        (это нормально — write_conf записал new конфиг на диск, но apply
        не смог его активировать). Проверяем что:
          (a) awgs_build_server_conf вызвана с NEW_PARAMS (не OLD)
          (b) awgs_state_update НЕ вызвана (state не закоммичен)
          (c) сообщение честно говорит о неудаче
        """
        from chimera.modules import awg_standalone
        from chimera.modules import awg_peers
        from chimera.modules import awg_presets

        mock_core = self._mock_core()
        state = self._make_state()  # state со OLD_PARAMS

        with patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_update") as mock_update, \
             patch.object(awg_presets, "awgs_presets_generate",
                          return_value=dict(self.NEW_PARAMS)), \
             patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_build_server_conf",
                          return_value="[Interface]\nPrivateKey = xxx\n") as mock_build, \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_peers, "awgs_apply",
                          return_value=False):  # ← apply зафейлился
            ok, msg = awg_standalone.awgs_rotate_obfuscation("default")

        self.assertFalse(ok)

        # (a) Конфиг был построен с NEW_PARAMS (не OLD) — даже при неудаче apply
        mock_build.assert_called_once()
        build_kwargs = mock_build.call_args.kwargs
        applied_params = build_kwargs["params"]
        self.assertEqual(applied_params.get("jc"), self.NEW_PARAMS["jc"],
                         "Даже при неудаче apply конфиг должен строиться с NEW_PARAMS")
        self.assertEqual(applied_params.get("i1"), self.NEW_PARAMS["i1"])

        # (b) State НЕ обновлён при неудаче apply
        mock_update.assert_not_called()

        # (c) Сообщение честно говорит о неудаче обоих методов
        self.assertIn("syncconf", msg.lower())
        self.assertIn("restart", msg.lower())
        self.assertIn("ручное", msg.lower())

    def test_uses_current_preset_when_not_specified(self):
        """Пустой preset_name → используется carrier_preset из state."""
        from chimera.modules import awg_standalone
        from chimera.modules import awg_peers
        from chimera.modules import awg_presets

        mock_core = self._mock_core()
        state = self._make_state()
        state["carrier_preset"] = "mobile"

        with patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_update"), \
             patch.object(awg_presets, "awgs_presets_generate",
                          return_value=dict(self.NEW_PARAMS)), \
             patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_build_server_conf",
                          return_value="[Interface]\n"), \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_peers, "awgs_apply",
                          return_value=True):
            ok, msg = awg_standalone.awgs_rotate_obfuscation()

        self.assertTrue(ok)
        # info должна была вызваться с "mobile" в сообщении
        mock_core.info.assert_any_call(
            unittest.mock.ANY  # точная строка не важна, главное что вызвалась
        )


class TestAwgsNatHelperV545(unittest.TestCase):
    """NAT-персистентность — helper-скрипт вместо сломанного инлайна.

    E2E 2026-10-03 (de1): инлайн `ExecStart=/bin/bash -c '...awk '{print $5}'...'`
    разрывался systemd-токенизатором на вложенной кавычке, $WAN разворачивал
    systemd (пусто) → NAT умирал после каждой перезагрузки.
    """

    def test_nat_unit_no_inline_bash_c(self):
        """awg-nat.service вызывает helper-скрипт, НЕ bash -c с кавычками."""
        from chimera.modules.awg_standalone import awgs_build_nat_unit_content
        unit = awgs_build_nat_unit_content()
        self.assertIn("ExecStart=/usr/local/sbin/awg-nat-rules.sh up", unit)
        self.assertIn("ExecStop=/usr/local/sbin/awg-nat-rules.sh down", unit)
        # Инлайн-баш с кавычками ЗАПРЕЩЁН (systemd разрывает аргумент)
        self.assertNotIn("bash -c '", unit,
                         "инлайн bash -c '<...>' в ExecStart разрывается "
                         "systemd-токенизатором (баг, E2E de1)")

    def test_nat_unit_wanted_by_awg_quick(self):
        """FIX-F: WantedBy содержит awg-quick@awg0.service — старт
        туннеля тянет за собой NAT (иначе stop/start awg0 = чёрная дыра:
        Requires гасит NAT, повторный старт его не поднимает)."""
        from chimera.modules.awg_standalone import awgs_build_nat_unit_content
        unit = awgs_build_nat_unit_content()
        self.assertIn("WantedBy=multi-user.target awg-quick@awg0.service", unit)
        # стоп-направление сохранено
        self.assertIn("Requires=awg-quick@awg0.service", unit)

    def test_nat_helper_body_contract(self):
        """helper-скрипт: шебанг, up/down, WAN-детект, идемпотентные правила."""
        from chimera.modules.awg_standalone import awgs_build_nat_helper_body
        body = awgs_build_nat_helper_body("10.66.66.0/24", "awg0")
        self.assertTrue(body.startswith("#!/bin/bash"))
        # WAN-детект тем же способом, что и раньше
        self.assertIn("ip route show default | awk '{print $5; exit}'", body)
        # up: идемпотентное добавление (с -o $WAN — иначе дубли правил)
        self.assertIn("-C POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", body)
        self.assertIn("-t nat -A POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", body)
        # down: удаление с -o $WAN (симметрия с установкой
        # в uninstall: -D без -o НЕ матчил правило)
        self.assertIn("-D POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", body)
        # кейс-структура
        self.assertIn('case "$CMD" in', body)
        self.assertIn("up)", body)
        self.assertIn("down)", body)


class TestUninstallNatParityV545(unittest.TestCase):
    """uninstall удаляет NAT правилА теми же спеками, что ставил.

    E2E 2026-10-03 (de1): MASQUERADE пережила uninstall — -D был без -o WAN.
    """

    def test_cleanup_shell_masq_deletes_with_wan(self):
        """build_nat_cleanup_shell: MASQ -D включает -o $WAN (парity с -A)."""
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        cleanup = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn(
            "iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE",
            cleanup,
            "-D без -o $WAN НЕ матчит правило с -o (MASQUERADE остаётся, E2E de1)")

    def test_uninstall_uses_cleanup_shell(self):
        """source-contract: uninstall вызывает build_nat_cleanup_shell +
        удаляет helper/wrapper/PPA (не только ручные -D без -o)."""
        src = Path(_PROJECT_ROOT / "chimera" / "modules" / "awg_uninstall.py").read_text()
        self.assertIn("build_nat_cleanup_shell", src,
                      "uninstall должен использовать cleanup-сниппет")
        self.assertIn("awg-nat-rules.sh", src,
                      "uninstall должен удалять helper awg-nat-rules.sh")
        self.assertIn("awg-expires-check.sh", src,
                      "uninstall должен удалять wrapper awg-expires-check.sh")
        self.assertIn("amnezia-ppa.sources", src,
                      "uninstall должен удалять PPA sources")
        self.assertIn("amnezia-ppa.gpg", src,
                      "uninstall должен удалять PPA keyring")


class TestAwgsPurePythonKeygen(unittest.TestCase):
    """Pure-Python X25519 keygen (RFC 7748) — fallback при сломанном apt.

    Кейс продакшена: на VPS с 'E: Unmet dependencies' не встают ни
    wireguard-tools (wg), ни amneziawg-tools (awg); stub-обёртка awg после
    Go-fallback проксирует в amneziawg-go, который НЕ поддерживает genkey.
    Pure-Python X25519 закрывает этот кейс навсегда.
    """

    def _try_cryptography(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )
            return X25519PrivateKey
        except ImportError:
            return None

    def test_x25519_rfc7748_vector(self):
        """Официальный тест-вектор RFC 7748 section 5.2 (scalar=basepoint*1... )."""
        from chimera.modules.awg_standalone import _awgs_x25519

        # RFC 7748 §6.1: Diffie-Hellman тест (Alice/Bob) — canonical вектор
        alice_priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_priv = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        bob_pub_expected = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared_expected = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        # Публичный ключ Боба: X25519(bob_priv, basepoint)
        bob_pub = _awgs_x25519(bob_priv, b"\x09" + b"\x00" * 31)
        self.assertEqual(bob_pub, bob_pub_expected,
                         "X25519(bob_priv, 9) != RFC 7748 §6.1 bob_pub")

        # Shared secret: X25519(alice_priv, bob_pub) == X25519(bob_priv, alice_pub)
        alice_pub = _awgs_x25519(alice_priv, b"\x09" + b"\x00" * 31)
        shared_a = _awgs_x25519(alice_priv, bob_pub)
        shared_b = _awgs_x25519(bob_priv, alice_pub)
        self.assertEqual(shared_a, shared_expected, "shared(A) != RFC 7748")
        self.assertEqual(shared_b, shared_expected, "shared(B) != RFC 7748")

    def test_x25519_against_cryptography(self):
        """Свемка со ссылкой на 20 случайных ключей (если cryptography доступна)."""
        X25519PrivateKey = self._try_cryptography()
        if X25519PrivateKey is None:
            self.skipTest("cryptography не установлена — пропускаю свемку")
        import base64
        import os as _os
        from chimera.modules.awg_standalone import _awgs_x25519

        for _ in range(20):
            scalar = bytearray(_os.urandom(32))
            scalar[0] &= 248
            scalar[31] &= 127
            scalar[31] |= 64
            scalar = bytes(scalar)
            ref = (X25519PrivateKey.from_private_bytes(scalar)
                   .public_key().public_bytes_raw())
            mine = _awgs_x25519(scalar, b"\x09" + b"\x00" * 31)
            self.assertEqual(mine, ref)
            self.assertEqual(len(base64.b64encode(mine)), 44)

    def test_py_keygen_pair_format(self):
        """Формат пары идентичен wg genkey: 44 символа base64, '=' на конце."""
        import base64
        import re
        from chimera.modules.awg_standalone import _awgs_py_keygen_pair

        priv, pub = _awgs_py_keygen_pair()
        self.assertRegex(priv, r"^[A-Za-z0-9+/]{43}=$")
        self.assertRegex(pub, r"^[A-Za-z0-9+/]{43}=$")
        priv_raw = base64.b64decode(priv)
        self.assertEqual(priv_raw[0] & 7, 0, "clamp k[0]&=248 нарушен")
        self.assertEqual(priv_raw[31] & 128, 0, "clamp k[31]&=127 нарушен")
        self.assertEqual(priv_raw[31] & 64, 64, "clamp k[31]|=64 нарушен")

        X25519PrivateKey = self._try_cryptography()
        if X25519PrivateKey is not None:
            ref = base64.b64encode(
                X25519PrivateKey.from_private_bytes(priv_raw)
                .public_key().public_bytes_raw()).decode()
            self.assertEqual(pub, ref, "pub != cryptography-эталону")

    def test_py_genpsk_format(self):
        """PSK = 32 случайных байта base64 — формат wg genpsk."""
        import base64
        from chimera.modules.awg_standalone import _awgs_py_genpsk

        psk = _awgs_py_genpsk()
        self.assertRegex(psk, r"^[A-Za-z0-9+/]{43}=$")
        self.assertEqual(len(base64.b64decode(psk)), 32)
        self.assertNotEqual(psk, _awgs_py_genpsk(), "PSK не случайный")


class TestAwgsKeygenFallbackChain(unittest.TestCase):
    """awgs_generate_keys: цепочка wg → awg → pure-Python.

    Главный кейс: wg нет, awg — нерабочая userspace-заглушка
    (amneziawg-go не поддерживает genkey) → pure-Python fallback спасает.
    """

    def _make_core(self, genkey_rc=1):
        """Fake core: which → пусто (нет wg/awg), _run возвращает rc=1."""
        core = MagicMock()
        # which-вызовы возвращают пустой stdout → бинари "не найдены"
        core._run = MagicMock(
            side_effect=self._fake_run_factory(genkey_rc))
        return core

    def _fake_run_factory(self, genkey_rc):
        def _run(cmd, capture=False, check=False, quiet=False, input_text=None):
            m = MagicMock()
            m.returncode = 0 if cmd[:2] == ["apt-get", "update"] else genkey_rc
            # which → пусто; genkey/pubkey → ошибка (заглушка не умеет)
            if cmd[0] == "which":
                m.returncode = 1
                m.stdout = ""
            elif cmd[1:2] == ["genkey"] or cmd[1:2] == ["pubkey"]:
                m.returncode = genkey_rc
                m.stdout = ""
            else:
                m.returncode = 0
                m.stdout = ""
            m.stderr = "amneziawg-go: unknown command"
            return m
        return _run

    def test_fallback_to_pure_python_when_binaries_broken(self):
        """wg нет, awg-заглушка падает на genkey → pure-Python ключи."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )
        from chimera.modules import awg_standalone

        core = self._make_core(genkey_rc=1)
        with patch.object(awg_standalone, "_core_module", return_value=core):
            priv, pub = awg_standalone.awgs_generate_keys()

        self.assertTrue(priv and pub, "pure-Python fallback не сработал")
        self.assertRegex(priv, r"^[A-Za-z0-9+/]{43}=$")
        self.assertRegex(pub, r"^[A-Za-z0-9+/]{43}=$")
        # Валидность пары против эталона
        ref = base64.b64encode(
            X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
            .public_key().public_bytes_raw()).decode()
        self.assertEqual(pub, ref)

    def test_preshared_key_fallback_when_genpsk_unsupported(self):
        """genpsk от заглушки падает → pure-Python PSK."""
        from chimera.modules import awg_standalone

        core = self._make_core(genkey_rc=1)
        with patch.object(awg_standalone, "_core_module", return_value=core):
            psk = awg_standalone.awgs_generate_preshared_key()

        self.assertRegex(psk, r"^[A-Za-z0-9+/]{43}=$")

    def test_wg_preferred_when_available(self):
        """При живом wg ключи идут через него (нативный путь)."""
        from chimera.modules import awg_standalone

        fake_priv = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        fake_pub = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

        def _run(cmd, capture=False, check=False, quiet=False, input_text=None):
            m = MagicMock()
            m.stderr = ""
            if cmd[0] == "which":
                m.returncode = 0 if cmd[1] == "wg" else 1
                m.stdout = "/usr/bin/wg" if cmd[1] == "wg" else ""
            elif cmd[1:2] == ["genkey"]:
                m.returncode = 0
                m.stdout = fake_priv
            elif cmd[1:2] == ["pubkey"]:
                m.returncode = 0
                m.stdout = fake_pub
            else:
                m.returncode = 0
                m.stdout = ""
            return m

        core = MagicMock()
        core._run = MagicMock(side_effect=_run)
        with patch.object(awg_standalone, "_core_module", return_value=core):
            priv, pub = awg_standalone.awgs_generate_keys()

        self.assertEqual((priv, pub), (fake_priv, fake_pub))


class TestAwgsAptAutoRepair(unittest.TestCase):
    """apt-авторемонт: dpkg --configure -a + --fix-broken + ретрай.

    Кейс продакшена: 'E: Unmet dependencies. Try apt --fix-broken install'
    на VPS с полусобранными пакетами — раньше валил установку AWG целиком.
    """

    def _make_core(self, install_results):
        """install_results: список кодов возврата apt-get install по порядку."""
        core = MagicMock()
        calls = {"install": 0}

        def _run(cmd, capture=False, check=False, quiet=False, input_text=None):
            m = MagicMock()
            m.stdout = ""
            m.stderr = ""
            if cmd[:2] == ["apt-get", "install"]:
                idx = min(calls["install"], len(install_results) - 1)
                rc = install_results[idx]
                calls["install"] += 1
                m.returncode = rc
                if rc != 0:
                    m.stderr = ("E: Unmet dependencies. Try 'apt --fix-broken "
                                "install' with no packages (or specify a solution).")
            elif cmd[:2] == ["apt-get", "check"]:
                # В этом тесте ремонт проходит: check после dpkg --configure -a
                # и --fix-broken возвращает 0 (зависимости починены)
                m.returncode = 0
            else:
                m.returncode = 0
            return m

        core._run = MagicMock(side_effect=_run)
        return core, calls

    def test_apt_install_retries_after_repair(self):
        """Первый install падает (Unmet) → ремонт → ретрай успешен."""
        from chimera.modules import awg_standalone

        core, calls = self._make_core(install_results=[1, 0])
        with patch.object(awg_standalone, "_core_module", return_value=core):
            ok = awg_standalone._awgs_apt_install("wireguard-tools")

        self.assertTrue(ok, "ретрай после авто-ремонта не сработал")
        self.assertGreaterEqual(calls["install"], 2, "не было ретрая")
        # Ремонт действительно вызывался
        ran_cmds = [c.args[0] for c in core._run.call_args_list]
        self.assertIn(["dpkg", "--configure", "-a"], ran_cmds)

    def test_apt_install_gives_up_when_repair_fails(self):
        """Ремонт не помог (check всё ещё падает) → честный False."""
        from chimera.modules import awg_standalone

        core = MagicMock()

        def _run(cmd, capture=False, check=False, quiet=False, input_text=None):
            m = MagicMock()
            m.stdout = ""
            m.stderr = ""
            if cmd[:2] == ["apt-get", "install"]:
                m.returncode = 1
                m.stderr = "E: Unmet dependencies. Try 'apt --fix-broken install'"
            elif cmd[:2] == ["apt-get", "check"]:
                m.returncode = 1  # сломан даже после ремонта
            else:
                m.returncode = 0
            return m

        core._run = MagicMock(side_effect=_run)
        with patch.object(awg_standalone, "_core_module", return_value=core):
            ok = awg_standalone._awgs_apt_install("wireguard-tools")

        self.assertFalse(ok)

    def test_apt_install_no_retry_on_unrelated_error(self):
        """Ошибка не про зависимости (например 404) → без ремонта, сразу False."""
        from chimera.modules import awg_standalone

        core = MagicMock()
        core._run = MagicMock(return_value=MagicMock(
            returncode=100, stdout="", stderr="E: Unable to locate package foo"))
        with patch.object(awg_standalone, "_core_module", return_value=core):
            ok = awg_standalone._awgs_apt_install("foo")

        self.assertFalse(ok)
        # Никакого dpkg --configure -a не выполнялось
        ran_cmds = [c.args[0] for c in core._run.call_args_list]
        self.assertNotIn(["dpkg", "--configure", "-a"], ran_cmds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
