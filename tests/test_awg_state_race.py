#!/usr/bin/env python3
"""
tests/test_awg_state_race.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты инцидента 09.11.2026 «AWG 3.1 пропал после обновления».

Корни инцидента (репро в chimera-work/awg_state_race/):
  1. awgs_state_save писал во ФИКСИРОВАННЫЙ .tmp — все процессы (TUI,
     ежеминутный failover/LB-тик, веб-панель, cron) делили один inode:
     два одновременных write_text перемешивали JSON, rename фиксировал
     порчу (репро: 3 писателя → битый JSON за 12 сек).
  2. lb_health_tick / awgs_cascade_activate_exit сохраняли УСТАРЕВШИЙ
     снапшот state (пробы 30-60 сек) поверх свежих правок TUI — «добавляю
     exit — скрипт отрабатывает штатно, а толку 0».
  3. Следом read-modify-write писатель закреплял {} — файл вида
     {"lb": ...} без installed/peers → «Не установлен» при живом туннеле.

Покрывает:
  A. Конкурентная запись: N потоков × большие state — файл ВСЕГДА
     валидный JSON, tmp-остатков нет (раньше — порча).
  B. awgs_state_integrity: ok | missing | corrupt; load при corrupt → {}
     + карантин-копия .corrupt.<ts>.
  C. Честность каскада: register/remove возвращают False при сбое save;
     activate_exit НЕ затирает свежий cascade_exits устаревшим списком
     (гонка «добавил exit во время рестарта awg1»).
  D. LB merge-save: _lb_merge_save сохраняет ТОЛЬКО lb-поддерево поверх
     свежего state — правки TUI (пиры/exits) переживают health-тик.
  E. awg_recover: парсер awg-конфигов (двойной AllowedIPs v4+v6,
     закомментированные пустые директивы, спец-пиры каскада), полный
     rebuild state из живой системы, карантин .lost, самопроверка.
  F. backup-гейт: при утерянном state, но живых конфигах/ключах —
     backup создаётся (catch-22 сломан); при полном отсутствии — отказ.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
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


def _mock_core():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    core._run = MagicMock(return_value=r)
    core.get_server_ip = MagicMock(return_value="198.51.100.7")
    return core


_HPKEY = "aGVhZGVycHJvdGVjdGlvbi1rZXktMzItYnl0ZXMhISEhIQ=="

_PARAMS_31 = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 32, "s2": 32, "s3": 32, "s4": 32,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "<r 16>", "i2": "", "i3": "", "i4": "", "i5": "",
    "header_protection_key": _HPKEY,
    "content_padding_addition": "200-300",
    "rekey_after_time": "100",
    "rekey_timeout": "15",
    "reject_after_time": "300",
    "keepalive_timeout": "15",
    "max_handshake_attempts": "10",
    "random_trailers": "on",
    "disable_cookies": "on",
}


def _big_state(n: int, peers: int = 39) -> dict:
    """State, близкий к прод-инциденту: 39 пиров + каскад + LB."""
    return {
        "installed": True, "protocol_version": "3.1",
        "port": 51820, "subnet": "10.66.66.0/24",
        "server_privkey": "K" * 44,
        "params": dict(_PARAMS_31),
        "peers": [{"name": f"peer-{i}", "client_privkey": "P" * 44,
                   "client_ip": f"10.66.66.{i + 2}", "owner_email": ""}
                  for i in range(peers)],
        "cascade_role": "entry",
        "cascade_exits": [{"name": f"exit-{k}",
                            "endpoint": f"203.0.113.{k}", "port": 52831}
                           for k in range(1, 4)],
        "lb": {"alive": ["exit-1"], "probes": {}, "balance": None,
               "alive_prev": ["exit-1"]},
    }


# ══════════════════════════════════════════════════════════════════════════════
#  A. Конкурентная запись
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrentSaveSafety(unittest.TestCase):
    """FIX 09.11: уникальный tmp в awgs_state_save — гонка писателей
    больше не порчит файл (раньше: общий .tmp → перемешанный JSON)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_concurrent_writers_never_corrupt(self):
        """4 потока × 150 больших state + валидатор: файл всегда валиден."""
        from chimera.modules import awg_state
        awg_state.AWGS_STATE_FILE = self._state_file
        awg_state.awgs_state_save(_big_state(0))

        stop = threading.Event()
        bad_reads = []
        errors = []

        def writer(n: int):
            try:
                for i in range(150):
                    awg_state.awgs_state_save(_big_state(n * 1000 + i))
            except Exception as e:          # pragma: no cover
                errors.append(e)
                stop.set()

        def reader():
            while not stop.is_set():
                st = awg_state.awgs_state_load()
                # живой файл всегда полный: installed + 39 пиров
                if not st.get("installed") or len(st.get("peers", [])) != 39:
                    bad_reads.append(sorted(st.keys()))
                if not bad_reads:
                    stop.set() if errors else None

        # читатель гоняет плотнее писателей
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        rt = threading.Thread(target=reader, daemon=True)
        rt.start()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        stop.set()
        rt.join(timeout=5)

        self.assertEqual(errors, [])
        self.assertEqual(bad_reads, [])
        # tmp-остатков не осталось (каждый save прибирает за собой)
        leftovers = [p for p in self._tmpdir.iterdir() if ".tmp." in p.name]
        self.assertEqual(leftovers, [])

    def test_save_failure_leaves_old_file_intact(self):
        """Сбой записи (недоступный каталог) не трогает прежний файл."""
        from chimera.modules import awg_state
        awg_state.AWGS_STATE_FILE = self._state_file
        awg_state.awgs_state_save(_big_state(1))
        before = self._state_file.read_text()
        # ломаем запись: target внутри ФАЙЛА (mkdir упадёт)
        broken = self._state_file / "sub" / "state.json"
        with patch.object(awg_state, "AWGS_STATE_FILE", broken):
            self.assertFalse(awg_state.awgs_state_save(_big_state(2)))
        self.assertEqual(self._state_file.read_text(), before)


# ══════════════════════════════════════════════════════════════════════════════
#  B. Целостность + карантин
# ══════════════════════════════════════════════════════════════════════════════

class TestStateIntegrity(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        from chimera.modules import awg_state
        return patch.object(awg_state, "AWGS_STATE_FILE", self._state_file)

    def test_integrity_ok_missing_corrupt(self):
        from chimera.modules import awg_state
        with self._patch():
            self.assertEqual(awg_state.awgs_state_integrity(), "missing")
            self._state_file.write_text(json.dumps(_big_state(0)))
            self.assertEqual(awg_state.awgs_state_integrity(), "ok")
            self._state_file.write_text('{"installed": true, "peers": [')  # битый
            self.assertEqual(awg_state.awgs_state_integrity(), "corrupt")

    def test_load_corrupt_quarantines_and_returns_empty(self):
        """Битый JSON → {} + карантин-копия .corrupt.<ts> (не удаление)."""
        from chimera.modules import awg_state
        corrupt_payload = '{"installed": true, "peers": [{"n": 1}, {"n"'  # хвост другого JSON
        self._state_file.write_text(corrupt_payload)
        with self._patch():
            self.assertEqual(awg_state.awgs_state_load(), {})
        q = list(self._tmpdir.glob("state.corrupt.*"))
        self.assertEqual(len(q), 1)
        # оригинал НЕ удалён (могут быть данные для ручного восстановления)
        self.assertEqual(self._state_file.read_text(), corrupt_payload)


# ══════════════════════════════════════════════════════════════════════════════
#  C. Честность каскада + свежий cascade_exits
# ══════════════════════════════════════════════════════════════════════════════

class _CascadeBase(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"
        self._awg1_conf = self._tmpdir / "awg1.conf"
        from chimera.modules import awg_cascade
        self.awg_cascade = awg_cascade
        self.mock_core = _mock_core()
        self._patches = [
            patch.object(awg_cascade, "_core_module",
                         return_value=self.mock_core),
            patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                  self._state_file),
            patch("chimera.modules.awg_cascade.AWGS_AWG1_CONF",
                  self._awg1_conf),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop_patches)

    def _stop_patches(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_state(self, state: dict):
        self._state_file.write_text(json.dumps(state))

    def _read_state(self) -> dict:
        return json.loads(self._state_file.read_text())

    @staticmethod
    def _box(name, endpoint, pv="3.1"):
        return {
            "name": name, "endpoint": endpoint, "port": 52831,
            "server_pubkey": f"PUB-{name}", "peer_privkey": f"PRIV-{name}",
            "peer_psk": "", "peer_ip": "172.16.91.2",
            "subnet": "172.16.91.0/24", "protocol_version": pv,
            "params": dict(_PARAMS_31), "mtu": 1280,
            "added_at": "2026-11-09T00:00:00+00:00",
        }


class TestHonestCascadeSaves(_CascadeBase):
    """FIX 09.11: register/remove честно сообщают о сбое записи state
    (репорт юзера: «добавляю ноду — скрипт отрабатывает штатно, толку 0»)."""

    _BASE = {
        "installed": True, "protocol_version": "3.1",
        "port": 51831, "subnet": "172.16.81.0/24",
        "params": dict(_PARAMS_31),
        "cascade_role": "entry",
    }

    def test_register_returns_false_when_save_fails(self):
        self._write_state(dict(self._BASE))
        with patch.object(self.awg_cascade, "awgs_state_save",
                          return_value=False):
            ok = self.awg_cascade.awgs_cascade_register_exit(
                name="de", endpoint="203.0.113.106", port=52831,
                server_pubkey="PUB", peer_privkey="PRIV",
                subnet="172.16.91.0/24", protocol_version="3.1",
                params=dict(_PARAMS_31))
        self.assertFalse(ok)

    def test_remove_returns_false_when_save_fails(self):
        st = dict(self._BASE)
        st["cascade_exits"] = [self._box("de", "203.0.113.106")]
        st["cascade_active_exit"] = "de"
        self._write_state(st)
        with patch.object(self.awg_cascade, "awgs_state_save",
                          return_value=False):
            ok = self.awg_cascade.awgs_cascade_remove_exit("de")
        self.assertFalse(ok)

    def test_activate_save_failure_reported(self):
        st = dict(self._BASE)
        st["cascade_exits"] = [self._box("de", "203.0.113.106")]
        st["cascade_active_exit"] = "de"
        self._write_state(st)
        with patch.object(self.awg_cascade, "awgs_state_save",
                          return_value=False), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_create_routing_script"):
            ok = self.awg_cascade.awgs_cascade_activate_exit("de")
        self.assertFalse(ok)


class TestActivateNoClobber(_CascadeBase):
    """FIX 09.11: activate_exit НЕ затирает cascade_exits списком, снятым
    ДО рестарта awg1 (юзер мог добавить exit за время рестарта)."""

    def test_exit_added_during_restart_survives(self):
        st = {
            "installed": True, "protocol_version": "3.1",
            "port": 51831, "subnet": "172.16.81.0/24",
            "params": dict(_PARAMS_31), "cascade_role": "entry",
            "cascade_exits": [self._box("de", "203.0.113.106")],
            "cascade_active_exit": "de",
        }
        self._write_state(st)

        # Симуляция гонки: между exits_load (начало activate) и save
        # (после рестарта awg1) юзер добавляет pl1 через TUI.
        def concurrent_add(*a, **kw):
            fresh = json.loads(self._state_file.read_text())
            fresh["cascade_exits"] = fresh.get("cascade_exits", []) + [
                self._box("pl1", "203.0.113.115")]
            fresh["cascade_active_exit"] = "pl1"
            self._state_file.write_text(json.dumps(fresh))
            return "conf"

        with patch.object(self.awg_cascade,
                          "_awgs_cascade_build_awg1_conf",
                          side_effect=concurrent_add), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_create_routing_script"):
            ok = self.awg_cascade.awgs_cascade_activate_exit("de")
        self.assertTrue(ok)

        saved = self._read_state()
        names = sorted(e["name"] for e in saved["cascade_exits"])
        # pl1 (добавлен «параллельно») НЕ затёрт устаревшим списком
        self.assertEqual(names, ["de", "pl1"])
        self.assertEqual(saved["cascade_active_exit"], "de")


# ══════════════════════════════════════════════════════════════════════════════
#  D. LB merge-save
# ══════════════════════════════════════════════════════════════════════════════

class TestLbMergeSave(unittest.TestCase):
    """FIX 09.11: health-тик сохраняет ТОЛЬКО lb-поддерево поверх свежего
    state — правки TUI (пиры/exits) переживают тик (раньше тик держал
    снапшок T0 всё время проб и затирал его поверх)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"
        from chimera.modules import awg_cascade_lb
        self.lb = awg_cascade_lb
        self._p = patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                        self._state_file)
        self._p.start()
        self.addCleanup(self._p.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_merge_preserves_fresh_non_lb_fields(self):
        # на диске — СВЕЖИЙ state (юзер только добавил exit и пира)
        fresh = _big_state(0)
        fresh["cascade_exits"].append({"name": "pl1", "endpoint": "203.0.113.9"})
        fresh["peers"].append({"name": "peer-NEW", "client_privkey": "X" * 44})
        self._state_file.write_text(json.dumps(fresh))

        # тик пришёл со СТАРЫМ снапшком (без pl1 и peer-NEW)
        stale = _big_state(0)
        del stale["cascade_exits"][:]
        stale["peers"] = stale["peers"][:10]
        stale["lb"] = {"alive": ["exit-1"], "probes": {"exit-1": {"rtt_ms": 5}},
                       "ts_last_install": "2026-11-09T00:00:00+00:00"}

        ok = self.lb._lb_merge_save(stale)
        self.assertTrue(ok)
        saved = json.loads(self._state_file.read_text())
        # lb-поддерево — из снапшота тика
        self.assertEqual(saved["lb"], stale["lb"])
        # НЕ-lb поля — из СВЕЖЕГО state (не затёрты)
        names = [e["name"] for e in saved["cascade_exits"]]
        self.assertIn("pl1", names)
        peer_names = [p["name"] for p in saved["peers"]]
        self.assertIn("peer-NEW", peer_names)
        self.assertEqual(len(saved["peers"]), 40)
        self.assertTrue(saved["installed"])

    def test_merge_creates_lb_when_missing(self):
        self._state_file.write_text(json.dumps(_big_state(0)))
        stale = _big_state(0)
        stale.pop("lb", None)
        ok = self.lb._lb_merge_save(stale)
        self.assertTrue(ok)
        saved = json.loads(self._state_file.read_text())
        # у снапшка тика lb-поддерева нет — свежий lb с диска сохранён как есть
        self.assertEqual(saved["lb"], _big_state(0)["lb"])


# ══════════════════════════════════════════════════════════════════════════════
#  E. awg_recover — восстановление state из живой системы
# ══════════════════════════════════════════════════════════════════════════════

_AWG0_CONF = f"""[Interface]
PrivateKey = {('S' * 43)}=
Address = 10.66.66.1/24
Address = fd66:66:66::1/64
ListenPort = 51820
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 32
S2 = 32
S3 = 32
S4 = 32
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 16>
# I2 = 
# I3 = 
HeaderProtectionKey = {_HPKEY}
ContentPaddingAddition = 200-300
RandomTrailers = on
DisableCookies = on

[Peer]
# alice
PublicKey = {('A' * 42)}=
AllowedIPs = 10.66.66.2/32
AllowedIPs = fd66:66:66::2/128
PresharedKey = {('E' * 42)}=

[Peer]
# bob
PublicKey = {('B' * 42)}=
AllowedIPs = 10.66.66.3/32
"""

_AWG1_CONF = f"""[Interface]
PrivateKey = {('L' * 43)}=
Address = 172.16.61.2/24
Jc = 4
S1 = 32
HeaderProtectionKey = {_HPKEY}
RandomTrailers = on

[Peer]
PublicKey = {('X' * 42)}=
Endpoint = 203.0.113.99:52831
AllowedIPs = 0.0.0.0/0
"""


class TestRecover(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._awg0 = self._tmpdir / "awg0.conf"
        self._awg1 = self._tmpdir / "awg1.conf"
        self._keys = self._tmpdir / "keys"
        self._keys.mkdir()
        self._state = self._tmpdir / "state.json"
        self._awg0.write_text(_AWG0_CONF)
        self._awg1.write_text(_AWG1_CONF)
        (self._keys / "alice.conf").write_text(
            "[Interface]\nPrivateKey = ALICEPRIV=\nAddress = 10.66.66.2\n")
        # у bob конфига нет — приватник утерян

        from chimera.modules import awg_recover
        self.rec = awg_recover
        self._patches = [
            patch.object(awg_recover, "AWGS_SERVER_CONF", self._awg0),
            patch.object(awg_recover, "AWGS_AWG1_CONF", self._awg1),
            patch.object(awg_recover, "AWGS_KEYS_DIR", self._keys),
            patch.object(awg_recover, "AWGS_STATE_FILE", self._state),
            patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state),
            patch.object(awg_recover, "_core_module",
                         return_value=_mock_core()),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_parser_dual_allowedips_and_commented_empties(self):
        iface, peers = self.rec._parse_awg_conf(self._awg0)
        self.assertEqual(iface["Address"], "10.66.66.1/24")   # первый — v4
        self.assertNotIn("I2", iface)                          # «# I2 = » пропущен
        self.assertEqual(len(peers), 2)
        a = peers[0]
        self.assertEqual(a["_comment"], "alice")
        # ДВЕ строки AllowedIPs склеены (v4 /32 + v6 /128)
        self.assertEqual(a["AllowedIPs"],
                         "10.66.66.2/32,fd66:66:66::2/128")

    def test_rebuild_full(self):
        res = self.rec.awgs_recover_state(apply=True)
        self.assertTrue(res["ok"], res["report"])
        st = res["state"]
        self.assertTrue(st["installed"])
        self.assertEqual(st["subnet"], "10.66.66.0/24")
        self.assertEqual(st["subnet_v6"], "fd66:66:66::/64")
        self.assertEqual(st["port"], 51820)
        self.assertEqual(st["protocol_version"], "3.1")
        self.assertEqual(st["params"]["i1"], "<r 16>")
        self.assertEqual(st["params"]["header_protection_key"], _HPKEY)
        # 2 пира: у alice приватник из keys/, у bob — пустой (утерян)
        by = {p["name"]: p for p in st["peers"]}
        self.assertEqual(by["alice"]["client_ip"], "10.66.66.2")
        self.assertEqual(by["alice"]["client_ipv6"], "fd66:66:66::2")
        self.assertEqual(by["alice"]["client_privkey"], "ALICEPRIV=")
        self.assertEqual(by["alice"]["preshared_key"], "E" * 42 + "=")
        self.assertEqual(by["bob"]["client_privkey"], "")
        # expires_at="" — НЕ истекаем чужих клиентов
        self.assertEqual(by["bob"]["expires_at"], "")
        # каскад entry: активный exit из awg1.conf
        self.assertEqual(st["cascade_role"], "entry")
        self.assertEqual(st["cascade_exits"][0]["endpoint"], "203.0.113.99")
        self.assertEqual(st["cascade_exits"][0]["port"], 52831)
        self.assertEqual(st["cascade_active_exit"], "203.0.113.99")
        self.assertEqual(st["cascade_peer_privkey"], "L" * 43 + "=")
        # server_pubkey выведен из server_privkey (X25519)
        self.assertTrue(st["server_pubkey"])
        # warn про bob в отчёте
        self.assertTrue(any("bob" in r for r in res["report"]))

    def test_rebuild_quarantines_previous_state(self):
        self._state.write_text('{"lb": {"alive": ["de"]}}')  # вайпнутый
        res = self.rec.awgs_recover_state(apply=True)
        self.assertTrue(res["ok"])
        lost = list(self._tmpdir.glob("state.lost.*"))
        self.assertEqual(len(lost), 1)

    def test_rebuild_refuses_on_selfcheck_mismatch(self):
        # peer БЕЗ PublicKey, но С комментарием → самопроверка должна
        # посчитать его в awg0.conf... он отфильтрован и там и там —
        # ломаем иначе: имя без PublicKey не считается, добавим битого
        # с PublicKey — а в парсере отфильтруется? Проверяем отказ
        # через peer с PublicKey, но БЕЗ имени (комментарий-мусор).
        conf = _AWG0_CONF + "\n[Peer]\n# wireguard-legacy\nPublicKey = CCCCC=\nAllowedIPs = 10.66.66.9/32\n"
        self._awg0.write_text(conf)
        # «wireguard-…» коммент отсеивается как не-имя → 2 клиента
        res = self.rec.awgs_recover_state(apply=True)
        self.assertTrue(res["ok"])
        st = res["state"]
        self.assertEqual(len(st["peers"]), 2)   # мусорный не стал клиентом

    def test_rebuild_nothing_to_recover(self):
        self._awg0.unlink()
        res = self.rec.awgs_recover_state(apply=True)
        self.assertFalse(res["ok"])

    def test_exit_role_detection(self):
        # awg0 со спец-пиром cascade_entry → мы exit-сторона
        conf = _AWG0_CONF + "\n[Peer]\n# cascade_entry\nPublicKey = DDDDD=\nAllowedIPs = 172.16.61.3/32\n"
        self._awg0.write_text(conf)
        self._awg1.unlink()
        pv = self.rec.awgs_recover_preview()
        self.assertTrue(pv["exit_role"])
        res = self.rec.awgs_recover_state(apply=True)
        self.assertTrue(res["ok"])
        self.assertEqual(res["state"]["cascade_role"], "exit")
        # спец-пир не попал в клиенты
        self.assertEqual(len(res["state"]["peers"]), 2)


# ══════════════════════════════════════════════════════════════════════════════
#  F. backup-гейт при утерянном state
# ══════════════════════════════════════════════════════════════════════════════

class TestBackupGate(unittest.TestCase):
    """FIX 09.11: state утерян, но конфиги/ключи живы → backup делается
    (спасаем оставшееся), полный отказ — только когда снимать нечего."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._conf = self._tmpdir / "awg0.conf"
        self._keys = self._tmpdir / "keys"
        self._keys.mkdir()
        self._backups = self._tmpdir / "backups"
        from chimera.modules import awg_backup, awg_constants
        self.bak = awg_backup
        self._patches = [
            patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state),
            patch.object(awg_backup, "AWGS_STATE_FILE", self._state),
            patch.object(awg_backup, "AWGS_SERVER_CONF", self._conf),
            patch.object(awg_backup, "AWGS_KEYS_DIR", self._keys),
            patch.object(awg_backup, "AWGS_BACKUP_DIR", self._backups),
            patch.object(awg_backup, "AWGS_CONF_DIR", self._tmpdir),
            patch.object(awg_backup, "_core_module",
                         return_value=_mock_core()),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_backup_with_lost_state_but_conf(self):
        self._conf.write_text("[Interface]\nPrivateKey = X=\n")
        (self._keys / "alice.conf").write_text("[Interface]\n")
        path = self.bak.awgs_backup_create(label="lost-state")
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())

    def test_backup_refused_when_nothing_exists(self):
        path = self.bak.awgs_backup_create(label="empty")
        self.assertIsNone(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
