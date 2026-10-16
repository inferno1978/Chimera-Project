#!/usr/bin/env python3
"""
tests/test_xray_downgrade.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для даунгрейда ядра Xray-core — пункт меню 5c
(chimera/modules/xray_downgrade.py).

Покрывает:
  1. Чистые хелперы: parse_version / era_for_version /
     required_min_client_ver / era_label / era_client_rows
     (эпохи: до-гейт ≤26.6.27 / гейт 26.7.11–26.7.28 / MLKEM 26.9.8+)
  2. DOWNGRADE_TARGETS: ровно три цели, значения согласованы с эпохами
  3. state.json: read_min_client_ver_from_state / save_min_client_ver
     (flock read-modify-write, чужие ключи, синк глобали _core)
  4. apply_min_client_ver_to_live_configs: патч REALITY-инбаундов,
     не-REALITY не трогаем, идемпотентность, провал теста → откат
     файла + дамп .downgrade-failed, битый JSON → error
  5. sync_min_client_ver_for_core: эпоха-управляемые значения мигрируют
     ("1.8.0"↔""), кастомное значение не трогается
  6. Гард автапдейта: autoupdate_timer_enabled / disable
  7. Полный флоу меню 5c: выбор цели, подтверждение, отмена, провал
     установки, гард автапдейта, итоговая матрица
  8. Хук в do_xray_update_interactive: после апгрейда на 26.9.9 гейт
     сбрасывается в "" автоматически
  9. Врезка 5c в _menu_install_system (_core.py)

Механика эпох: docs/faq/VLESS_FAQ.md §18.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import chimera.modules.xray_downgrade as xdg  # noqa: E402


def _fake_core() -> types.ModuleType:
    """Фейковый chimera._core (паттерн соседних сьютов): цвета пустые,
    info/warn/success/dim — print, _run всегда rc=0, box-хелперы — print."""
    m = types.ModuleType("chimera._core")
    for c in ("NC", "CYAN", "BOLD", "DIM", "GREEN", "RED", "YELLOW", "BLUE"):
        setattr(m, c, "")
    m.info    = lambda s: print(f"[i] {s}")
    m.warn    = lambda s: print(f"[!] {s}")
    m.success = lambda s: print(f"[+] {s}")
    m.dim     = lambda s: print(f"    {s}")
    m._run = lambda cmd, capture=True, check=False, quiet=False: SimpleNamespace(
        returncode=0, stdout="", stderr="")
    m._box_top    = lambda t="": print(f"\n=== {t} ===")
    m._box_row    = lambda s="": print(s)
    m._box_sep    = lambda: print("-" * 64)
    m._box_item   = lambda k="", s="": print(f"  [{k}] {s}")
    m._box_back   = lambda: print("  [Q] Назад")
    m._box_bottom = lambda: print("=" * 64)
    m.PARAM_MIN_CLIENT_VER = ""
    m.STATE_FILE = Path("/nonexistent/state.json")
    return m


def _fake_xray_install(current="26.9.9", final=None, upgrade_result=True,
                       restart_result=True) -> types.ModuleType:
    """Фейковый chimera.modules.xray_install с записью вызовов."""
    m = types.ModuleType("chimera.modules.xray_install")
    m._versions = [current, final if final is not None else current]

    def _cur():
        if len(m._versions) > 1:
            return m._versions.pop(0)
        return m._versions[0]

    m._xray_current_version = _cur
    m._upgrade_calls = []

    def _upg(tag, is_prerelease=False):
        m._upgrade_calls.append((tag, is_prerelease))
        # после установки «версия» становится целевой
        if len(m._versions) == 1:
            m._versions[0] = tag.lstrip("v")
        return upgrade_result

    m._xray_do_upgrade = _upg
    m._restart_calls = []

    def _restart():
        m._restart_calls.append(1)
        return restart_result

    m._xray_restart_all_services = _restart
    return m


def _install_fake_xray_install(fake_xi):
    """Ставит фейковый xray_install в sys.modules И в атрибут пакета.

    Форма «from chimera.modules import xray_install» (ею пользуется
    do_xray_downgrade_interactive) берёт АТРИБУТ пакета, если реальный
    модуль уже импортирован в процессе: без подмены атрибута групповой
    прогон test_runner'а (группа «1 VLESS Core»: xray_install идёт
    раньше xray_downgrade, один процесс) ловил бы реальный модуль —
    и _xray_do_upgrade выходил бы в сеть. Возвращает restore-функцию
    (вызвать обязательно, лучше в finally).
    """
    import chimera.modules as pkg
    had_attr = hasattr(pkg, "xray_install")
    saved_attr = getattr(pkg, "xray_install", None)
    sys.modules["chimera.modules.xray_install"] = fake_xi
    pkg.xray_install = fake_xi

    def _restore():
        if had_attr:
            pkg.xray_install = saved_attr
        else:
            try:
                del pkg.xray_install
            except AttributeError:
                pass

    return _restore


def _reality_cfg(mcv="") -> dict:
    return {
        "inbounds": [
            {
                "tag": "vless-in",
                "protocol": "vless",
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "K",
                        "shortIds": ["aa"],
                        "minClientVer": mcv,
                        "maxClientVer": "",
                    },
                },
            },
            {
                "tag": "pq-in",
                "protocol": "vless",
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {"dest": "x:443", "minClientVer": mcv},
                },
            },
            {
                "tag": "tcp-in",
                "protocol": "vless",
                "streamSettings": {"security": "none", "tcpSettings": {}},
            },
            {"tag": "bare-in", "protocol": "vless"},
        ],
        "outbounds": [],
    }


class _TmpBase(unittest.TestCase):
    """Общий базис: tmp-пути + фейковый _core в sys.modules (с восстановлением)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.state_file = Path(self._tmp) / "state.json"
        self.cfg_a = Path(self._tmp) / "config.json"
        self.cfg_b = Path(self._tmp) / "mirror.json"

        self._saved_core = sys.modules.get("chimera._core")
        self._fake_core = _fake_core()
        self._fake_core.STATE_FILE = self.state_file
        sys.modules["chimera._core"] = self._fake_core
        self._saved_xi = sys.modules.get("chimera.modules.xray_install")

        patcher = patch.object(xdg, "STATE_FILE", self.state_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(xdg, "XRAY_CONFIG_PATHS", [self.cfg_a, self.cfg_b])
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        if self._saved_core is None:
            sys.modules.pop("chimera._core", None)
        else:
            sys.modules["chimera._core"] = self._saved_core
        if self._saved_xi is None:
            sys.modules.pop("chimera.modules.xray_install", None)
        else:
            sys.modules["chimera.modules.xray_install"] = self._saved_xi
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_state(self, d: dict):
        self.state_file.write_text(json.dumps(d, ensure_ascii=False))


class TestPureHelpers(unittest.TestCase):
    """parse_version / эпохи / требуемые значения / матрица клиентов."""

    def test_parse_version(self):
        self.assertEqual(xdg.parse_version("v26.7.28"), (26, 7, 28))
        self.assertEqual(xdg.parse_version("26.9.9"), (26, 9, 9))
        self.assertEqual(xdg.parse_version([26, 7, 28]), (26, 7, 28))
        self.assertIsNone(xdg.parse_version("абракадабра"))
        self.assertIsNone(xdg.parse_version(""))
        self.assertIsNone(xdg.parse_version(None))

    def test_eras(self):
        self.assertEqual(xdg.era_for_version("26.9.9"), "mlkim")
        self.assertEqual(xdg.era_for_version("26.9.8"), "mlkim")
        self.assertEqual(xdg.era_for_version("27.0.0"), "mlkim")
        self.assertEqual(xdg.era_for_version("26.7.11"), "gate")
        self.assertEqual(xdg.era_for_version("26.7.28"), "gate")
        self.assertEqual(xdg.era_for_version("26.7.15"), "gate")
        self.assertEqual(xdg.era_for_version("26.6.27"), "pre-gate")
        self.assertEqual(xdg.era_for_version("26.3.27"), "pre-gate")
        self.assertEqual(xdg.era_for_version("25.12.1"), "pre-gate")
        self.assertIsNone(xdg.era_for_version("хх.хх.хх"))

    def test_required_values(self):
        self.assertEqual(xdg.required_min_client_ver("26.7.28"), "1.8.0")
        self.assertEqual(xdg.required_min_client_ver("26.7.11"), "1.8.0")
        self.assertEqual(xdg.required_min_client_ver("26.9.9"), "")
        self.assertEqual(xdg.required_min_client_ver("26.3.27"), "")
        self.assertEqual(xdg.required_min_client_ver("26.6.27"), "")
        self.assertIsNone(xdg.required_min_client_ver("oops"))

    def test_era_label(self):
        self.assertEqual(xdg.era_label("mlkim"), "MLKEM-эпоха")
        self.assertEqual(xdg.era_label("gate"), "гейт-эпоха")
        self.assertEqual(xdg.era_label("pre-gate"), "до-гейт")
        self.assertEqual(xdg.era_label(None), "эпоха не определена")

    def test_client_rows_mlkim(self):
        rows = xdg.era_client_rows("mlkim")
        self.assertEqual(len(rows), 3)
        self.assertIn("✗", dict(rows)["sing-box (Nyamebox, Karing, Hiddify, SFM)"])

    def test_client_rows_pre_gate(self):
        rows = xdg.era_client_rows("pre-gate")
        self.assertEqual(len(rows), 3)
        self.assertTrue(all("✓" in st for _, st in rows))

    def test_client_rows_gate_empty_mcv(self):
        rows = xdg.era_client_rows("gate", "")
        d = {n: st for n, st in rows}
        self.assertIn("дефолт-гейт 26.3.27", "".join(d.keys()))
        self.assertIn("✗ ниже порога", d["sing-box (Nyamebox, Karing, Hiddify, SFM)"])
        self.assertIn("✗ ниже порога", d["mihomo (Clash Verge, FlClash, роутеры)"])

    def test_client_rows_gate_180(self):
        rows = xdg.era_client_rows("gate", "1.8.0")
        d = {n: st for n, st in rows}
        self.assertIn("✓ проходит порог", d["sing-box (Nyamebox, Karing, Hiddify, SFM)"])
        self.assertIn("✓ проходит порог", d["mihomo (Clash Verge, FlClash, роутеры)"])

    def test_client_rows_gate_high_threshold(self):
        rows = xdg.era_client_rows("gate", "2.0.0")
        d = {n: st for n, st in rows}
        self.assertIn("✗ ниже порога", d["sing-box (Nyamebox, Karing, Hiddify, SFM)"])

    def test_client_rows_unknown_era(self):
        self.assertEqual(xdg.era_client_rows(None), [])


class TestTargets(unittest.TestCase):
    """Целей даунгрейда ровно три, значения согласованы с эпохами."""

    def test_exactly_three_targets(self):
        self.assertEqual(len(xdg.DOWNGRADE_TARGETS), 3)
        self.assertEqual({t["tag"] for t in xdg.DOWNGRADE_TARGETS},
                         {"v26.7.28", "v26.6.27", "v26.3.27"})
        # порядок в меню — от новейшей к старейшей
        self.assertEqual([t["tag"] for t in xdg.DOWNGRADE_TARGETS],
                         ["v26.7.28", "v26.6.27", "v26.3.27"])

    def test_values_match_eras(self):
        for t in xdg.DOWNGRADE_TARGETS:
            self.assertIsNotNone(xdg.parse_version(t["version"]))
            self.assertEqual(t["min_client_ver"],
                             xdg.required_min_client_ver(t["version"]))
            self.assertEqual(t["era"], xdg.era_for_version(t["version"]))
            self.assertEqual(len(t["clients"]), 3)

    def test_prerelease_flags(self):
        flags = {t["tag"]: t["is_prerelease"] for t in xdg.DOWNGRADE_TARGETS}
        self.assertTrue(flags["v26.7.28"])   # теги с 26.4.x помечены Pre-release
        self.assertTrue(flags["v26.6.27"])   # июньский пререлиз (GitHub API)
        self.assertFalse(flags["v26.3.27"])  # GitHub stable-latest

    def test_no_mlkim_target(self):
        # 26.9.8 в списке быть не должно: та же MLKIM-эпоха, конфиг не меняется
        for t in xdg.DOWNGRADE_TARGETS:
            self.assertNotEqual(xdg.era_for_version(t["version"]), "mlkim")


class TestStateIO(_TmpBase):
    """read_min_client_ver_from_state / save_min_client_ver."""

    def test_read_default_when_no_file(self):
        self.assertEqual(xdg.read_min_client_ver_from_state(), "")

    def test_read_value(self):
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.assertEqual(xdg.read_min_client_ver_from_state(), "1.8.0")

    def test_read_non_string_falls_back(self):
        self._write_state({"min_client_ver": 42})
        self.assertEqual(xdg.read_min_client_ver_from_state(), "")

    def test_read_corrupt_state(self):
        self.state_file.write_text("{not json")
        self.assertEqual(xdg.read_min_client_ver_from_state(), "")

    def test_save_roundtrip_preserves_other_keys(self):
        self._write_state({"domain": "x.com", "uuid": "u-1", "min_client_ver": "old"})
        self.assertTrue(xdg.save_min_client_ver("1.8.0"))
        st = json.loads(self.state_file.read_text())
        self.assertEqual(st["min_client_ver"], "1.8.0")
        self.assertEqual(st["domain"], "x.com")
        self.assertEqual(st["uuid"], "u-1")

    def test_save_missing_file(self):
        self.assertFalse(xdg.save_min_client_ver("1.8.0"))

    def test_save_syncs_core_global(self):
        self._write_state({"domain": "x.com"})
        self._fake_core.PARAM_MIN_CLIENT_VER = ""
        xdg.save_min_client_ver("1.8.0")
        self.assertEqual(self._fake_core.PARAM_MIN_CLIENT_VER, "1.8.0")

    def test_save_no_core_loaded_is_fine(self):
        # _core не в sys.modules (симуляция cron-контекста) — сохранение живёт
        sys.modules.pop("chimera._core", None)
        try:
            self._write_state({"domain": "x.com"})
            self.assertTrue(xdg.save_min_client_ver(""))
            self.assertEqual(
                json.loads(self.state_file.read_text())["min_client_ver"], "")
        finally:
            sys.modules["chimera._core"] = self._fake_core


class TestApplyLiveConfigs(_TmpBase):
    """apply_min_client_ver_to_live_configs — патчер живых конфигов."""

    def setUp(self):
        super().setUp()
        patcher = patch.object(xdg, "_find_xray_bin", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_patches_all_reality_inbounds_only(self):
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        report = xdg.apply_min_client_ver_to_live_configs("1.8.0")
        self.assertEqual(report["changed_files"], 1)
        self.assertTrue(report["test_ok"])
        entry = report["files"][0]
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["patched_inbounds"], 2)
        cfg = json.loads(self.cfg_a.read_text())
        rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["minClientVer"], "1.8.0")
        self.assertEqual(rs["maxClientVer"], "")
        rs2 = cfg["inbounds"][1]["streamSettings"]["realitySettings"]
        self.assertEqual(rs2["minClientVer"], "1.8.0")
        self.assertEqual(rs2["maxClientVer"], "")
        # не-REALITY инбаунды не тронуты
        self.assertNotIn("realitySettings",
                         cfg["inbounds"][2]["streamSettings"])
        self.assertNotIn("streamSettings", cfg["inbounds"][3])

    def test_missing_file_skipped(self):
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        report = xdg.apply_min_client_ver_to_live_configs("1.8.0")
        self.assertEqual(report["files"][1]["status"], "skipped")

    def test_idempotent_second_call(self):
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        xdg.apply_min_client_ver_to_live_configs("1.8.0")
        report = xdg.apply_min_client_ver_to_live_configs("1.8.0")
        self.assertEqual(report["changed_files"], 0)
        self.assertEqual(report["files"][0]["status"], "unchanged")

    def test_reset_to_empty(self):
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))
        report = xdg.apply_min_client_ver_to_live_configs("")
        self.assertEqual(report["changed_files"], 1)
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "")

    def test_broken_json_reports_error(self):
        self.cfg_a.write_text("{broken")
        report = xdg.apply_min_client_ver_to_live_configs("1.8.0")
        self.assertEqual(report["files"][0]["status"], "error")
        self.assertFalse(report["test_ok"])

    def test_config_test_failure_restores_file(self):
        original = json.dumps(_reality_cfg(""), indent=2, ensure_ascii=False)
        self.cfg_a.write_text(original)
        # фейковый xray-бинарник + _run с rc=1 → тест конфига «провален»
        self._fake_core._run = lambda cmd, capture=True, check=False, quiet=False: \
            SimpleNamespace(returncode=1, stdout="", stderr="mock: config rejected")
        with patch.object(xdg, "_find_xray_bin", return_value="/fake/xray"):
            report = xdg.apply_min_client_ver_to_live_configs("1.8.0")
        entry = report["files"][0]
        self.assertEqual(entry["status"], "test_failed")
        self.assertIn("mock: config rejected", entry["error"])
        self.assertFalse(report["test_ok"])
        # файл откачен байт-в-байт
        self.assertEqual(self.cfg_a.read_text(), original)
        # провалившийся вариант сохранён рядом (паттерн pq_vless)
        self.assertTrue(
            (Path(str(self.cfg_a) + ".downgrade-failed")).exists())


class TestSync(_TmpBase):
    """sync_min_client_ver_for_core — значение следует за эпохой ядра."""

    def test_gate_era_sets_180(self):
        self._write_state({"domain": "x.com"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed = xdg.sync_min_client_ver_for_core("26.7.28", verbose=True)
        self.assertTrue(changed)
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "1.8.0")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "1.8.0")

    def test_mlkim_era_resets_to_empty(self):
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed = xdg.sync_min_client_ver_for_core("v26.9.9", verbose=True)
        self.assertTrue(changed)
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "")

    def test_custom_value_untouched(self):
        self._write_state({"domain": "x.com", "min_client_ver": "1.0.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.0.0")))
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed = xdg.sync_min_client_ver_for_core("26.9.9", verbose=True)
        self.assertFalse(changed)
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "1.0.0")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "1.0.0")

    def test_already_matching_noop(self):
        self._write_state({"min_client_ver": "1.8.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed = xdg.sync_min_client_ver_for_core("26.7.28", verbose=True)
        self.assertFalse(changed)
        # файл не перезаписывался
        self.assertEqual(
            json.loads(self.cfg_a.read_text())
            ["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "1.8.0")

    def test_unparseable_version_noop(self):
        self._write_state({"domain": "x.com"})
        changed = xdg.sync_min_client_ver_for_core("oops", verbose=False)
        self.assertFalse(changed)
        self.assertNotIn("min_client_ver",
                         json.loads(self.state_file.read_text()))

    def test_no_live_configs_still_saves_state(self):
        self._write_state({"domain": "x.com"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed = xdg.sync_min_client_ver_for_core("26.7.28", verbose=True)
        self.assertTrue(changed)
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "1.8.0")
        self.assertIn("перегенерации", buf.getvalue())


class TestAutoupdateGuard(unittest.TestCase):
    """autoupdate_timer_enabled / disable (скрипт таймера обновляет ядро
    только «вверх» — сравнение «старше»; гард 5c страхует смену stable)."""

    def test_enabled(self):
        with patch("subprocess.run",
                   return_value=SimpleNamespace(returncode=0,
                                                stdout="enabled\n", stderr="")):
            self.assertTrue(xdg.autoupdate_timer_enabled())

    def test_disabled(self):
        with patch("subprocess.run",
                   return_value=SimpleNamespace(returncode=1,
                                                stdout="disabled\n", stderr="")):
            self.assertFalse(xdg.autoupdate_timer_enabled())

    def test_exception(self):
        with patch("subprocess.run", side_effect=OSError("no systemctl")):
            self.assertFalse(xdg.autoupdate_timer_enabled())

    def test_disable_ok(self):
        with patch("subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            self.assertTrue(xdg.disable_autoupdate_timer())


class TestMenuFlow(_TmpBase):
    """do_xray_downgrade_interactive — полный флоу пункта 5c."""

    def _run_menu(self, inputs, fake_xi):
        restore_xi = _install_fake_xray_install(fake_xi)
        try:
            patcher = patch.object(xdg, "autoupdate_timer_enabled",
                                   return_value=False)
            patcher.start()
            self.addCleanup(patcher.stop)
            buf = io.StringIO()
            with patch("builtins.input", side_effect=inputs), \
                 redirect_stdout(buf):
                xdg.do_xray_downgrade_interactive()
        finally:
            restore_xi()
        return buf.getvalue()

    def test_happy_path_26728(self):
        self._write_state({"domain": "x.com"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        fake_xi = _fake_xray_install(current="26.9.9", final="26.7.28")
        out = self._run_menu(["1", "y"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [("v26.7.28", True)])
        self.assertEqual(len(fake_xi._restart_calls), 1)
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "1.8.0")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "1.8.0")
        self.assertIn("ДАУНГРЕЙД ВЫПОЛНЕН", out)
        self.assertIn("sing-box", out)
        self.assertIn("26.7.28", out)

    def test_happy_path_26327(self):
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))
        fake_xi = _fake_xray_install(current="26.9.9", final="26.3.27")
        out = self._run_menu(["3", "y"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [("v26.3.27", False)])
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "")
        self.assertIn("ДАУНГРЕЙД ВЫПОЛНЕН", out)

    def test_happy_path_26627(self):
        # [2] — июньская до-гейт-цель: эпоха-управляемый "1.8.0"
        # сбрасывается в "" (до-гейт — гейт не нужен)
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))
        fake_xi = _fake_xray_install(current="26.9.9", final="26.6.27")
        out = self._run_menu(["2", "y"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [("v26.6.27", True)])
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "")
        self.assertIn("ДАУНГРЕЙД ВЫПОЛНЕН", out)
        self.assertIn("26.6.27", out)

    def test_cancel_at_confirm(self):
        self._write_state({"domain": "x.com"})
        fake_xi = _fake_xray_install(current="26.9.9")
        out = self._run_menu(["1", "n"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [])
        self.assertNotIn("min_client_ver",
                         json.loads(self.state_file.read_text()))

    def test_quit(self):
        fake_xi = _fake_xray_install(current="26.9.9")
        self._run_menu(["q"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [])

    def test_invalid_choice(self):
        fake_xi = _fake_xray_install(current="26.9.9")
        self._run_menu(["9"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [])

    def test_target_already_installed(self):
        self._write_state({"domain": "x.com"})
        fake_xi = _fake_xray_install(current="26.7.28")
        out = self._run_menu(["1"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [])
        self.assertIn("уже установлено", out)

    def test_upgrade_failure_no_config_touch(self):
        self._write_state({"domain": "x.com"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("")))
        fake_xi = _fake_xray_install(current="26.9.9", upgrade_result=False)
        out = self._run_menu(["1", "y"], fake_xi)
        self.assertEqual(fake_xi._upgrade_calls, [("v26.7.28", True)])
        self.assertEqual(fake_xi._restart_calls, [])
        self.assertNotIn("min_client_ver",
                         json.loads(self.state_file.read_text()))
        self.assertIn("не выполнен", out)

    def test_autoupdate_guard_disable(self):
        self._write_state({"domain": "x.com"})
        fake_xi = _fake_xray_install(current="26.9.9", final="26.7.28")
        restore_xi = _install_fake_xray_install(fake_xi)
        disabled = []
        try:
            with patch.object(xdg, "autoupdate_timer_enabled", return_value=True), \
                 patch.object(xdg, "disable_autoupdate_timer",
                              side_effect=lambda: disabled.append(True) or True):
                buf = io.StringIO()
                with patch("builtins.input", side_effect=["1", "y", "y"]), \
                     redirect_stdout(buf):
                    xdg.do_xray_downgrade_interactive()
        finally:
            restore_xi()
        self.assertEqual(disabled, [True])
        self.assertEqual(fake_xi._upgrade_calls, [("v26.7.28", True)])

    def test_autoupdate_guard_keep_timer(self):
        self._write_state({"domain": "x.com"})
        fake_xi = _fake_xray_install(current="26.9.9", final="26.7.28")
        restore_xi = _install_fake_xray_install(fake_xi)
        disabled = []
        try:
            with patch.object(xdg, "autoupdate_timer_enabled", return_value=True), \
                 patch.object(xdg, "disable_autoupdate_timer",
                              side_effect=lambda: disabled.append(True) or True):
                buf = io.StringIO()
                with patch("builtins.input", side_effect=["1", "y", "n"]), \
                     redirect_stdout(buf):
                    xdg.do_xray_downgrade_interactive()
        finally:
            restore_xi()
        self.assertEqual(disabled, [])
        self.assertIn("поднимет ядро", buf.getvalue())

    def test_restart_failure_shows_rollback_hints(self):
        self._write_state({"domain": "x.com"})
        fake_xi = _fake_xray_install(current="26.9.9", final="26.7.28",
                                     restart_result=False)
        out = self._run_menu(["1", "y"], fake_xi)
        self.assertIn("НЕ ЗАПУСТИЛСЯ", out)
        self.assertIn("journalctl", out)


class TestUpdateHookEraSync(_TmpBase):
    """do_xray_update_interactive (пункт [5]): после апгрейда на 26.9.9
    эпоха-управляемый "1.8.0" сбрасывается в "" автоматически."""

    def test_upgrade_to_mlkim_resets_gate(self):
        from chimera.modules import xray_install as xi
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.cfg_a.write_text(json.dumps(_reality_cfg("1.8.0")))

        upg_calls = []
        with patch.object(xi, "_xray_current_version",
                          side_effect=["26.7.28", "26.9.9"]), \
             patch.object(xi, "_xray_get_release_info",
                          side_effect=[{"tag_name": "v26.3.27",
                                        "prerelease": False},
                                       {"tag_name": "v26.9.9",
                                        "prerelease": True}]), \
             patch.object(xi, "_xray_do_upgrade",
                          side_effect=lambda tag, is_prerelease=False:
                          upg_calls.append((tag, is_prerelease)) or True), \
             patch.object(xi, "_xray_restart_all_services", return_value=True):
            buf = io.StringIO()
            with patch("builtins.input", side_effect=["1", "y"]), \
                 redirect_stdout(buf):
                xi.do_xray_update_interactive()

        self.assertEqual(upg_calls, [("v26.9.9", True)])
        self.assertEqual(
            json.loads(self.state_file.read_text())["min_client_ver"], "")
        cfg = json.loads(self.cfg_a.read_text())
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["minClientVer"],
            "")
        self.assertIn("26.9.9", buf.getvalue())


class TestMenuWiring(unittest.TestCase):
    """Пункт 5c в _menu_install_system (_core.py) — рендер и диспетчер."""

    def _exec_core(self):
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        src = core_path.read_text()
        fake_core = types.ModuleType("chimera._core")
        sys.modules["chimera._core"] = fake_core
        with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'touch', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch('os.chown', lambda *a, **kw: None), \
             patch('os.geteuid', return_value=0):
            exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
        return fake_core

    def setUp(self):
        self._saved_core = sys.modules.get("chimera._core")
        self._saved_xdg = sys.modules.get("chimera.modules.xray_downgrade")
        fake_xdg = types.ModuleType("chimera.modules.xray_downgrade")
        self._calls = []
        fake_xdg.do_xray_downgrade_interactive = \
            lambda: self._calls.append("5c")
        sys.modules["chimera.modules.xray_downgrade"] = fake_xdg
        self.core = self._exec_core()

    def tearDown(self):
        if self._saved_core is None:
            sys.modules.pop("chimera._core", None)
        else:
            sys.modules["chimera._core"] = self._saved_core
        if self._saved_xdg is None:
            sys.modules.pop("chimera.modules.xray_downgrade", None)
        else:
            sys.modules["chimera.modules.xray_downgrade"] = self._saved_xdg

    def test_menu_renders_5c_item(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("5c"', src)

    def test_menu_dispatches_5c(self):
        buf = io.StringIO()
        with patch("builtins.input", side_effect=["5c", "", "q"]), \
             redirect_stdout(buf):
            self.core._menu_install_system()
        self.assertEqual(self._calls, ["5c"])
        self.assertIn("Даунгрейд ядра Xray", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
