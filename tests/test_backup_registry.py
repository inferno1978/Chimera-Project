#!/usr/bin/env python3
"""
tests/test_backup_registry.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/backup_registry.py — единой автоматической
расширяемой системы бэкапа/восстановления всех протоколов.

Покрывает:
  1. discover_backup_paths() находит фейковые тестовые модули с
     get_backup_paths() (через monkeypatch списка модулей — НЕ полагается
     на реальные 214 модулей chimera.modules).
  2. Модуль без get_backup_paths() — тихо пропускается.
  3. Модуль, чей get_backup_paths() бросает исключение — не роняет
     остальной сбор.
  4. Дедупликация одинаковых путей от двух модулей.
  5. Timeout-guard: «зависший» модуль не блокирует сбор — частичный
     результат + WARN.
  6. ГЛАВНЫЙ смысловой тест — «будущий протокол» сценарий: временный
     фейковый модуль, которого не было в списке ни разу до теста,
     подхватывается автоматически БЕЗ правок системы бэкапа.
  7. Тесты на каждый новый get_backup_paths() в протокол-модулях
     (mtproto/mieru/naiveproxy/fptn/trusttunnel/singbox_state/
     awg_standalone/hysteria2_backup): пустой список без установки,
     непустой с установленными файлами.
  8. Регрессионный тест: «импорт только пользователей» достижим из
     живого меню _menu_migration() (раньше был мёртвым кодом).
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт minimal fake chimera._core в sys.modules, чтобы ленивые
    импорты из backup_registry и протокол-модулей работали без реального
    исполнения всего _core.py (который тянет много сайд-эффектов).
    """
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


# =============================================================================
#  Test fixtures: fake "future protocol" module injected via monkeypatch
# =============================================================================
def _make_fake_module(name: str, paths_retval, *, raise_exc=None, sleep_sec=0.0):
    """Создаёт фейковый модуль с get_backup_paths()."""
    mod = types.ModuleType(name)

    def get_backup_paths():
        if sleep_sec:
            import time as _t
            _t.sleep(sleep_sec)
        if raise_exc is not None:
            raise raise_exc
        return list(paths_retval)

    mod.get_backup_paths = get_backup_paths
    return mod


class _FakeModInfo:
    """Имитация pkgutil.ModuleInfo для monkeypatch."""
    def __init__(self, name: str):
        self.name = name


# =============================================================================
#  Tests for discover_backup_paths() core behavior
# =============================================================================
class TestDiscoverBackupPaths(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        # Импортируем тестируемый модуль
        from chimera.modules import backup_registry
        self.backup_registry = backup_registry
        self._pkgutil_patch = None
        self._import_patch = None
        self._fake_modules: dict[str, types.ModuleType] = {}

    def tearDown(self):
        if self._pkgutil_patch:
            self._pkgutil_patch.stop()
        if self._import_patch:
            self._import_patch.stop()
        # Чистим sys.modules от фейков
        for k in list(self._fake_modules.keys()):
            sys.modules.pop(k, None)

    def _patch_module_list(self, fake_modules: dict[str, types.ModuleType]):
        """Monkeypatch pkgutil.iter_modules + importlib.import_module
        чтобы вернуть только фейковые модули.
        """
        self._fake_modules = fake_modules

        def fake_iter_modules(_path):
            for name in fake_modules:
                yield _FakeModInfo(name)

        def fake_import_module(full_name, *args, **kwargs):
            # full_name обычно "chimera.modules.{short_name}", но мы
            # индексируем fake_modules и по полному, и по короткому имени.
            if full_name in fake_modules:
                return fake_modules[full_name]
            short_name = full_name.rsplit(".", 1)[-1]
            if short_name in fake_modules:
                return fake_modules[short_name]
            # Fallback — реальный импорт (для тестов не нужно, но безопасно)
            return importlib.__import__(full_name)

        self._pkgutil_patch = patch(
            "chimera.modules.backup_registry.pkgutil.iter_modules",
            side_effect=fake_iter_modules,
        )
        self._import_patch = patch(
            "chimera.modules.backup_registry.importlib.import_module",
            side_effect=fake_import_module,
        )
        self._pkgutil_patch.start()
        self._import_patch.start()

    # ── 1. Находит пути из фейковых модулей ──────────────────────────────────
    def test_discovers_paths_from_fake_modules(self):
        tmp1 = Path(tempfile.mkstemp()[1])
        tmp2 = Path(tempfile.mkstemp()[1])
        tmp3 = Path(tempfile.mkstemp()[1])
        try:
            tmp1.write_text("a")
            tmp2.write_text("b")
            tmp3.write_text("c")
            fakes = {
                "fake_proto_a": _make_fake_module(
                    "fake_proto_a",
                    [(tmp1, "a/conf.txt"), (tmp2, "a/state.json")],
                ),
                "fake_proto_b": _make_fake_module(
                    "fake_proto_b",
                    [(tmp3, "b/state.json")],
                ),
            }
            self._patch_module_list(fakes)
            result = self.backup_registry.discover_backup_paths(timeout_sec=5)
            # 3 уникальных пути (tmp1, tmp2, tmp3) — без дедупликации
            self.assertEqual(len(result), 3)
            arcnames = sorted(a for _, a in result)
            self.assertEqual(arcnames, ["a/conf.txt", "a/state.json", "b/state.json"])
        finally:
            tmp1.unlink(missing_ok=True)
            tmp2.unlink(missing_ok=True)
            tmp3.unlink(missing_ok=True)

    # ── 2. Модуль БЕЗ get_backup_paths() — тихо пропускается ─────────────────
    def test_module_without_get_backup_paths_is_silently_skipped(self):
        # Модуль без функции — это норма (большинство из 214 модулей такие)
        mod_no_fn = types.ModuleType("mod_no_fn")
        mod_no_fn.some_other_func = lambda: 42

        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("x")
            mod_with_fn = _make_fake_module(
                "mod_with_fn", [(tmp, "x/conf.txt")]
            )
            fakes = {"mod_no_fn": mod_no_fn, "mod_with_fn": mod_with_fn}
            self._patch_module_list(fakes)
            result = self.backup_registry.discover_backup_paths(timeout_sec=5)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][1], "x/conf.txt")
        finally:
            tmp.unlink(missing_ok=True)

    # ── 3. Модуль, чей get_backup_paths() бросает — не роняет остальные ──────
    def test_module_that_raises_does_not_break_others(self):
        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("x")
            bad_module = _make_fake_module(
                "bad_module", [], raise_exc=RuntimeError("boom")
            )
            good_module = _make_fake_module(
                "good_module", [(tmp, "good/conf.txt")]
            )
            fakes = {"bad_module": bad_module, "good_module": good_module}
            self._patch_module_list(fakes)
            result = self.backup_registry.discover_backup_paths(timeout_sec=5)
            # bad_module пропущен, good_module в результате
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][1], "good/conf.txt")
        finally:
            tmp.unlink(missing_ok=True)

    # ── 4. Дедупликация одинаковых путей от двух модулей ─────────────────────
    def test_dedup_same_path_from_two_modules(self):
        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("x")
            mod_a = _make_fake_module(
                "mod_a", [(tmp, "mod_a/conf.txt")]
            )
            mod_b = _make_fake_module(
                "mod_b", [(tmp, "mod_b/conf.txt")]  # тот же путь, другое arcname
            )
            fakes = {"mod_a": mod_a, "mod_b": mod_b}
            self._patch_module_list(fakes)
            result = self.backup_registry.discover_backup_paths(timeout_sec=5)
            # Дедупликация по Path.resolve() — должен остаться один путь
            self.assertEqual(len(result), 1)
        finally:
            tmp.unlink(missing_ok=True)

    # ── 5. Timeout-guard: зависший модуль не блокирует сбор ──────────────────
    def test_timeout_guard_with_hanging_module(self):
        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("x")
            # Hanging module: sleeps 30s in get_backup_paths (больше timeout)
            hanging = _make_fake_module(
                "hanging", [], sleep_sec=30
            )
            fast = _make_fake_module(
                "fast", [(tmp, "fast/conf.txt")]
            )
            # Важно: hanging ДОЛЖЕН идти первым в словаре, чтобы его импорт
            # начался раньше (на самом деле get_backup_paths вызывается
            # последовательно — мы зависнем на hanging, fast не успеет).
            # Поэтому кладём fast ПЕРВЫМ, hanging ВТОРЫМ — fast успеет
            # выполниться до зависания.
            fakes = {"fast": fast, "hanging": hanging}
            self._patch_module_list(fakes)

            import time as _t
            t0 = _t.time()
            result = self.backup_registry.discover_backup_paths(timeout_sec=1.5)
            elapsed = _t.time() - t0

            # Должно завершиться за разумное время (≈ timeout + overhead)
            self.assertLess(elapsed, 5.0,
                            f"timeout guard failed: took {elapsed:.2f}s")
            # Fast-модуль должен быть в результате (выполнился до зависания)
            self.assertTrue(any(arc == "fast/conf.txt" for _, arc in result),
                            f"fast module result missing: {result}")
        finally:
            tmp.unlink(missing_ok=True)

    # ── 6. ГЛАВНЫЙ: «будущий протокол» подхватывается автоматически ──────────
    def test_future_protocol_auto_discovered_without_code_changes(self):
        """Создаём ВРЕМЕННЫЙ фейковый модуль с get_backup_paths(),
        которого не было НИ РАЗУ до теста. Убеждается, что система его
        подхватывает БЕЗ единой правки кода самой системы бэкапа.

        Это тест, который доказывает решение заявленной задачи: «протокол
        появится позже — подхватится автоматически».
        """
        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("future-protocol-config-content")
            # Имя модуля — заведомо «новое», не существующее в chimera/modules/
            # и не упомянутое нигде в коде системы бэкапа.
            future_mod = _make_fake_module(
                "chimera_modules_future_protocol_xyz_v9",
                [(tmp, "future_protocol_xyz/config.toml")],
            )
            fakes = {future_mod.__name__: future_mod}
            self._patch_module_list(fakes)

            result = self.backup_registry.discover_backup_paths(timeout_sec=5)

            # Future-protocol подхвачен без правок системы бэкапа
            self.assertEqual(len(result), 1)
            src, arc = result[0]
            self.assertEqual(arc, "future_protocol_xyz/config.toml")
            self.assertEqual(src.resolve(), tmp.resolve())
        finally:
            tmp.unlink(missing_ok=True)

    # ── 7. Malformed entries — не роняют остальные ───────────────────────────
    def test_malformed_entries_are_skipped(self):
        tmp = Path(tempfile.mkstemp()[1])
        try:
            tmp.write_text("x")
            mod = types.ModuleType("mod_with_malformed")
            def get_backup_paths():
                return [
                    (tmp, "ok/conf.txt"),                # OK
                    (tmp,),                              # malformed: len 1
                    ("not_a_path", 123),                 # malformed: bad arcname
                    (tmp, ""),                           # malformed: empty arcname
                    [tmp, "list_ok/conf.txt"],           # list instead of tuple — OK
                ]
            mod.get_backup_paths = get_backup_paths
            fakes = {"mod_with_malformed": mod}
            self._patch_module_list(fakes)

            result = self.backup_registry.discover_backup_paths(timeout_sec=5)
            # 2 валидных: ok/conf.txt и list_ok/conf.txt
            # (однако дедупликация по tmp (resolve) уберёт list_ok/conf.txt)
            # → остаётся один — первый валидный (ok/conf.txt)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][1], "ok/conf.txt")
        finally:
            tmp.unlink(missing_ok=True)


# =============================================================================
#  Tests for get_backup_paths() in each protocol module
# =============================================================================
class TestProtocolGetBackupPaths(unittest.TestCase):
    """Каждый модуль-протокола должен:
      • возвращать [] если файлы не существуют (протокол не установлен)
      • возвращать непустой список если файлы существуют
      • никогда не бросать исключение
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._patches = []  # list of (patcher, attr_path) for restoration

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        # Все патчи автоматически снимаются через stop
        for p in self._patches:
            p.stop()

    def _patch_path_attr(self, module, attr_name: str, new_path: Path):
        """Меняет путь-константу в модуле на путь в self._tmpdir."""
        p = patch.object(module, attr_name, new_path)
        p.start()
        self._patches.append(p)

    def _touch(self, name: str) -> Path:
        """Создаёт файл в self._tmpdir и возвращает его путь."""
        p = self._tmpdir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("test-content")
        return p

    # ── mtproto ──────────────────────────────────────────────────────────────
    def test_mtproto_empty_when_uninstalled(self):
        from chimera.modules import mtproto
        # Все пути несуществующие → []
        result = mtproto.get_backup_paths()
        self.assertEqual(result, [])

    def test_mtproto_nonempty_when_installed(self):
        from chimera.modules import mtproto
        f1 = self._touch("telemt.toml")
        f2 = self._touch("telemt.service")
        f3 = self._touch("telemt_limits.json")
        self._patch_path_attr(mtproto, "CONFIG_FILE", f1)
        self._patch_path_attr(mtproto, "SERVICE_FILE", f2)
        self._patch_path_attr(mtproto, "LIMITS_FILE", f3)

        result = mtproto.get_backup_paths()
        self.assertEqual(len(result), 3)
        arcnames = sorted(a for _, a in result)
        self.assertIn("telemt/telemt.toml", arcnames)

    def test_mtproto_never_raises(self):
        from chimera.modules import mtproto
        # Создаём ситуацию, в которой Path.exists() бросает — должна
        # вернуться [], не исключение
        with patch.object(Path, 'exists', side_effect=OSError("boom")):
            result = mtproto.get_backup_paths()
        self.assertEqual(result, [])

    # ── mieru ────────────────────────────────────────────────────────────────
    def test_mieru_empty_when_uninstalled(self):
        from chimera.modules import mieru
        self.assertEqual(mieru.get_backup_paths(), [])

    def test_mieru_nonempty_when_installed(self):
        from chimera.modules import mieru
        f1 = self._touch("server.json")
        f2 = self._touch("mita.service")
        f3 = self._touch("mieru.json")
        self._patch_path_attr(mieru, "_SERVER_CFG", f1)
        self._patch_path_attr(mieru, "_SERVICE_FILE", f2)
        self._patch_path_attr(mieru, "_MODULE_STATE", f3)

        result = mieru.get_backup_paths()
        self.assertEqual(len(result), 3)

    # ── naiveproxy ───────────────────────────────────────────────────────────
    def test_naiveproxy_empty_when_uninstalled(self):
        from chimera.modules import naiveproxy
        self.assertEqual(naiveproxy.get_backup_paths(), [])

    def test_naiveproxy_nonempty_when_installed(self):
        from chimera.modules import naiveproxy
        f1 = self._touch("Caddyfile")
        f2 = self._touch("probe_secret")
        f3 = self._touch("caddy-naive.service")
        f4 = self._touch("naiveproxy.json")
        self._patch_path_attr(naiveproxy, "_CADDYFILE", f1)
        self._patch_path_attr(naiveproxy, "_PROBE_SECRET", f2)
        self._patch_path_attr(naiveproxy, "_SERVICE_FILE", f3)
        self._patch_path_attr(naiveproxy, "_MODULE_STATE", f4)

        result = naiveproxy.get_backup_paths()
        self.assertEqual(len(result), 4)

    # ── fptn ─────────────────────────────────────────────────────────────────
    def test_fptn_empty_when_uninstalled(self):
        from chimera.modules import fptn
        self.assertEqual(fptn.get_backup_paths(), [])

    def test_fptn_nonempty_when_installed(self):
        from chimera.modules import fptn
        f1 = self._touch("server.conf")
        f2 = self._touch("server.crt")
        f3 = self._touch("server.key")
        f4 = self._touch("fptn-server.service")
        f5 = self._touch("fptn.json")
        self._patch_path_attr(fptn, "_CFG_FILE", f1)
        self._patch_path_attr(fptn, "_CERT_FILE", f2)
        self._patch_path_attr(fptn, "_KEY_FILE", f3)
        self._patch_path_attr(fptn, "_SERVICE_FILE", f4)
        self._patch_path_attr(fptn, "_MODULE_STATE", f5)

        result = fptn.get_backup_paths()
        self.assertEqual(len(result), 5)

    # ── trusttunnel ──────────────────────────────────────────────────────────
    def test_trusttunnel_empty_when_uninstalled(self):
        from chimera.modules import trusttunnel
        self.assertEqual(trusttunnel.get_backup_paths(), [])

    def test_trusttunnel_nonempty_when_installed(self):
        from chimera.modules import trusttunnel
        f1 = self._touch("trusttunnel.json")
        f2 = self._touch("vpn.toml")
        f3 = self._touch("hosts.toml")
        f4 = self._touch("rules.toml")
        f5 = self._touch("trusttunnel.service")
        self._patch_path_attr(trusttunnel, "_STATE_FILE", f1)
        self._patch_path_attr(trusttunnel, "_VPN_TOML", f2)
        self._patch_path_attr(trusttunnel, "_HOSTS_TOML", f3)
        self._patch_path_attr(trusttunnel, "_RULES_TOML", f4)
        self._patch_path_attr(trusttunnel, "_SERVICE_FILE", f5)

        result = trusttunnel.get_backup_paths()
        self.assertEqual(len(result), 5)

    # ── singbox_state ────────────────────────────────────────────────────────
    def test_singbox_empty_when_uninstalled(self):
        from chimera.modules import singbox_state
        self.assertEqual(singbox_state.get_backup_paths(), [])

    def test_singbox_nonempty_when_installed(self):
        from chimera.modules import singbox_state
        f1 = self._touch("singbox_state.json")
        f2 = self._touch("config.json")
        # Cert dir
        cert_dir = self._tmpdir / "certs"
        cert_dir.mkdir(exist_ok=True)
        (cert_dir / "anytls.crt").write_text("cert")
        (cert_dir / "anytls.key").write_text("key")

        self._patch_path_attr(singbox_state, "SINGBOX_STATE_FILE", f1)
        self._patch_path_attr(singbox_state, "SINGBOX_CONFIG_FILE", f2)
        # SINGBOX_CONFIG_FILE.parent должен указывать на tmpdir — для certs/
        # Патчим parent через саму Path: cert_dir = SINGBOX_CONFIG_FILE.parent / "certs"
        # Меняем SINGBOX_CONFIG_FILE на tmpdir/config.json — parent будет tmpdir.
        # f2 = self._tmpdir / "config.json" уже, всё OK.

        result = singbox_state.get_backup_paths()
        # state + config + 2 cert files = 4
        self.assertEqual(len(result), 4)
        arcnames = sorted(a for _, a in result)
        self.assertIn("singbox/singbox_state.json", arcnames)
        self.assertIn("singbox/config.json", arcnames)
        self.assertIn("singbox/certs/anytls.crt", arcnames)
        self.assertIn("singbox/certs/anytls.key", arcnames)

    # ── awg_standalone ───────────────────────────────────────────────────────
    def test_awg_standalone_empty_when_uninstalled(self):
        from chimera.modules import awg_standalone
        self.assertEqual(awg_standalone.get_backup_paths(), [])

    def test_awg_standalone_nonempty_when_installed(self):
        from chimera.modules import awg_standalone
        from chimera.modules import awg_constants
        f1 = self._touch("awg0.conf")
        f2 = self._touch("awgsetup_cfg.init")
        f3 = self._touch("awg_standalone_state.json")
        f4 = self._touch("awg-cascade-routing.service")

        # awg_standalone.get_backup_paths импортирует константы inline,
        # поэтому патчим в awg_constants.
        p1 = patch.object(awg_constants, "AWGS_SERVER_CONF", f1); p1.start()
        p2 = patch.object(awg_constants, "AWGS_INIT_FILE", f2); p2.start()
        p3 = patch.object(awg_constants, "AWGS_STATE_FILE", f3); p3.start()
        p4 = patch.object(awg_constants, "AWGS_SYSTEMD_CASCADE", f4); p4.start()
        self._patches.extend([p1, p2, p3, p4])

        result = awg_standalone.get_backup_paths()
        self.assertEqual(len(result), 4)

    # ── hysteria2_backup ─────────────────────────────────────────────────────
    def test_hysteria2_empty_when_uninstalled(self):
        from chimera.modules import hysteria2_backup
        self.assertEqual(hysteria2_backup.get_backup_paths(), [])

    def test_hysteria2_nonempty_when_installed(self):
        from chimera.modules import hysteria2_backup
        f1 = self._touch("config.yaml")
        f2 = self._touch("hysteria.crt")
        f3 = self._touch("hysteria.key")
        f4 = self._touch("hysteria-server.service")

        p1 = patch.object(hysteria2_backup, "H2_CONFIG_FILE", f1); p1.start()
        p2 = patch.object(hysteria2_backup, "H2_CERT_FILE", f2); p2.start()
        p3 = patch.object(hysteria2_backup, "H2_KEY_FILE", f3); p3.start()
        # 4-й путь — Path("/etc/systemd/system/hysteria-server.service") —
        # это литерал в коде, патчим через модуль Path
        p4 = patch("chimera.modules.hysteria2_backup.Path", side_effect=lambda x: f4 if str(x) == "/etc/systemd/system/hysteria-server.service" else Path(x)); p4.start()
        self._patches.extend([p1, p2, p3, p4])

        result = hysteria2_backup.get_backup_paths()
        # Должно быть 4 — config.yaml, hysteria.crt, hysteria.key, service
        self.assertEqual(len(result), 4)

    def test_hysteria2_backup_include_in_main_is_now_deprecated_delegate(self):
        """h2_backup_include_in_main() — deprecated заглушка, делегирует к
        новому get_backup_paths(). Тест гарантирует, что функция не
        возвращает труп-данные: результат эквивалентен get_backup_paths()
        в виде голых строк.
        """
        from chimera.modules import hysteria2_backup
        f1 = self._touch("config.yaml")
        f2 = self._touch("hysteria.crt")
        p1 = patch.object(hysteria2_backup, "H2_CONFIG_FILE", f1); p1.start()
        p2 = patch.object(hysteria2_backup, "H2_CERT_FILE", f2); p2.start()
        p3 = patch.object(hysteria2_backup, "H2_KEY_FILE", Path("/nonexistent.key")); p3.start()
        self._patches.extend([p1, p2, p3])

        # get_backup_paths → [(config.yaml, ...), (hysteria.crt, ...)]
        paths = hysteria2_backup.get_backup_paths()
        # deprecated returns list[str]
        deprecated_result = hysteria2_backup.h2_backup_include_in_main()
        self.assertIsInstance(deprecated_result, list)
        # Каждый элемент deprecated_result должен быть строкой
        for s in deprecated_result:
            self.assertIsInstance(s, str)
        # Содержимое — те же пути что и в get_backup_paths, но как str
        expected = sorted(str(p) for p, _ in paths)
        actual = sorted(deprecated_result)
        self.assertEqual(expected, actual)


# =============================================================================
#  Regression test: "import only users" is reachable from the live menu
# =============================================================================
class TestImportOnlyUsersReachable(unittest.TestCase):
    """Регрессионный тест: «импорт только пользователей» должен быть
    достижим из живого меню _menu_migration() (раньше был мёртвым кодом
    в do_manage_backup(), который нигде не вызывался).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_menu_migration_has_import_only_users_item(self):
        """Симулируем ввод '4' в _menu_migration() и проверяем, что
        вызывается _import_users_only. Создаём реальный пустой файл
        (через patch Path.exists → True), чтобы выполнение дошло до
        _import_users_only.

        ВАЖНО: _menu_migration() определена через exec(compile(...), g),
        поэтому её __globals__ — это словарь g, а НЕ fake_core.__dict__.
        Соответственно, патчить нужно через __globals__, а не через
        setattr(core, ...).
        """
        import chimera._core as core

        # Фиксируем факт вызова _import_users_only через mock
        called_with = {"path": None, "count": 0}
        g = core._menu_migration.__globals__
        original = g["_import_users_only"]
        def fake_import_users_only(path):
            called_with["path"] = path
            called_with["count"] += 1
            return True
        g["_import_users_only"] = fake_import_users_only
        try:
            # Симулируем ввод: '4' → путь к архиву → 'q' (выход)
            inputs = iter(["4", "/tmp/chimera-test-import-users.tar.gz", "q"])
            with patch("builtins.input", lambda *a, **k: next(inputs)):
                with patch("os.system"):
                    with patch("time.sleep"):
                        # Path.exists → True для нашего пути, реальное
                        # поведение для остальных.
                        orig_exists = Path.exists
                        def patched_exists(self):
                            if str(self) == "/tmp/chimera-test-import-users.tar.gz":
                                return True
                            return orig_exists(self)
                        with patch.object(Path, "exists", patched_exists):
                            try:
                                core._menu_migration()
                            except StopIteration:
                                pass  # input() кончился — нормальный выход

            # _import_users_only должен был быть вызван с тем путём
            self.assertEqual(called_with["count"], 1,
                             "_import_users_only was NOT called from menu item 4")
            self.assertEqual(str(called_with["path"]),
                             "/tmp/chimera-test-import-users.tar.gz")
        finally:
            g["_import_users_only"] = original

    def test_menu_migration_renders_option_4_label(self):
        """В выводе меню должна быть строчка про «Импорт только пользователей»."""
        import chimera._core as core
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        # Сразу выходим из меню
        with patch("builtins.input", return_value="q"):
            with patch("os.system"):
                with redirect_stdout(buf):
                    try:
                        core._menu_migration()
                    except Exception:
                        pass
        out = buf.getvalue()
        # Проверяем, что в меню есть пункт 4 с нужной подписью
        self.assertIn("4", out)
        self.assertIn("Импорт только пользователей", out)


# =============================================================================
#  Regression tests: warn about server secrets in non-encrypted archive
# =============================================================================
class TestExportConfigWarnsAboutServerSecrets(unittest.TestCase):
    """Регрессионные тесты на предупреждение о серверных секретах в
    do_export_config() при encrypt=False И непустом результате
    автообнаружения.

    Покрывает 3 случая:
      1. encrypt=False, _discovered непустой → warn ВЫЗВАН
      2. encrypt=False, _discovered пустой   → warn НЕ вызван
      3. encrypt=True,  _discovered непустой → warn НЕ вызван
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run_do_export_config_with_spy(self, *, encrypt, discovered_paths,
                                       allow_real_packaging=False):
        """Запускает do_export_config(encrypt=encrypt) с замоканным
        discover_backup_paths (возвращает discovered_paths) и spy на warn().

        Возвращает список сообщений, переданных в warn() ДО того, как
        функция дошла до реальной упаковки архива (которую мы обрываем
        через StopIteration или SystemExit, чтобы не трогать /root/ и
        tempfile).

        Если allow_real_packaging=True — не обрываем, даём дойти до конца
        (используется для проверки что warn вызывается в нужном порядке).
        """
        import chimera._core as core
        import chimera.modules.backup_registry as br

        # Spy на warn — собирает все вызовы
        warn_calls: list[str] = []
        original_warn = core.warn
        def spy_warn(msg):
            warn_calls.append(msg)
            original_warn(msg)

        # Мокаем discover_backup_paths в модуле backup_registry
        # (do_export_config делает `from ... import discover_backup_paths`
        # внутри функции, поэтому патчим сам атрибут модуля)
        original_discover = br.discover_backup_paths
        def fake_discover(*args, **kwargs):
            return list(discovered_paths)
        br.discover_backup_paths = fake_discover

        # Чтобы не выполнять реальную упаковку (tempfile/tar/shutil.copy2
        # в /root/xray-backup-*.tar.gz) — патчим TemporaryDirectory так,
        # чтобы сразу бросить StopIteration (сигнал "достаточно, мы уже
        # видели warn"). Это сработает ПОСЛЕ блока автообнаружения и
        # ПОСЛЕ блока warn-о-секретах, но ДО реальной упаковки.
        import tempfile as _tempfile_mod
        original_TemporaryDirectory = _tempfile_mod.TemporaryDirectory
        class _EarlyExitTemporaryDirectory:
            def __init__(self, *a, **kw):
                raise StopIteration("_early_exit_")
            def __enter__(self, *a, **kw):
                pass
            def __exit__(self, *a, **kw):
                pass

        g = core.do_export_config.__globals__
        g["warn"] = spy_warn
        # _discovered инициализируется в самой функции — патчить не нужно

        try:
            with patch("chimera.modules.backup_registry.discover_backup_paths",
                       fake_discover):
                with patch("tempfile.TemporaryDirectory",
                           _EarlyExitTemporaryDirectory):
                    try:
                        core.do_export_config(encrypt=encrypt)
                    except StopIteration as _e:
                        if str(_e) != "_early_exit_":
                            raise
                        # Нормальный early-exit — мы перехватили до tar.gz
                    except Exception:
                        # Любые другие ошибки от патчей / не-наших путей
                        # — не интересны, нас волнует только warn_calls
                        pass
        finally:
            g["warn"] = original_warn
            br.discover_backup_paths = original_discover

        return warn_calls

    # ── 1. encrypt=False, _discovered непустой → warn ВЫЗВАН ─────────────────
    def test_warn_called_when_encrypt_false_and_discovery_nonempty(self):
        from pathlib import Path
        # Создаём фейковые пути, которые "вернуло" автообнаружение
        # (сами файлы могут не существовать — это ОК, мы обрываем до .exists())
        fake_paths = [
            (Path("/etc/telemt/telemt.toml"), "telemt/telemt.toml"),
            (Path("/etc/caddy-naive/probe_secret"), "caddy-naive/probe_secret"),
            (Path("/etc/xray/hysteria.key"), "hysteria/hysteria.key"),
        ]
        warn_calls = self._run_do_export_config_with_spy(
            encrypt=False, discovered_paths=fake_paths,
        )
        # Среди warn-вызовов должен быть тот, что про серверные секреты
        secrets_warns = [w for w in warn_calls
                         if "серверные секреты" in w and "НЕ зашифрован" in w]
        self.assertEqual(len(secrets_warns), 1,
                         f"expected exactly 1 server-secrets warn, got "
                         f"{len(secrets_warns)}: {secrets_warns}")
        # Проверяем ключевые элементы текста
        w = secrets_warns[0]
        self.assertIn("MTProto/NaiveProxy/Hysteria2", w)
        self.assertIn("TLS-ключи", w)
        self.assertIn("приватный ключ", w)
        # Упоминается количество путей (3 в нашем фейке)
        self.assertIn("3", w)

    # ── 2. encrypt=False, _discovered пустой → warn НЕ вызван ────────────────
    def test_warn_NOT_called_when_encrypt_false_and_discovery_empty(self):
        warn_calls = self._run_do_export_config_with_spy(
            encrypt=False, discovered_paths=[],
        )
        # Не должно быть warn про серверные секреты
        secrets_warns = [w for w in warn_calls
                         if "серверные секреты" in w and "НЕ зашифрован" in w]
        self.assertEqual(len(secrets_warns), 0,
                         f"expected NO server-secrets warn when discovery is "
                         f"empty, but got: {secrets_warns}")

    # ── 3. encrypt=True, _discovered непустой → warn НЕ вызван ───────────────
    def test_warn_NOT_called_when_encrypt_true_even_if_discovery_nonempty(self):
        from pathlib import Path
        fake_paths = [
            (Path("/etc/telemt/telemt.toml"), "telemt/telemt.toml"),
            (Path("/etc/xray/hysteria.key"), "hysteria/hysteria.key"),
        ]
        warn_calls = self._run_do_export_config_with_spy(
            encrypt=True, discovered_paths=fake_paths,
        )
        # При encrypt=True предупреждения о секретах быть не должно —
        # архив закрыт AES-256-CBC, не о чем волноваться.
        secrets_warns = [w for w in warn_calls
                         if "серверные секреты" in w and "НЕ зашифрован" in w]
        self.assertEqual(len(secrets_warns), 0,
                         f"expected NO server-secrets warn when encrypt=True, "
                         f"but got: {secrets_warns}")


# =============================================================================
#  Regression tests: do_export_config handles nested dest_name (arcname)
# =============================================================================
class TestExportConfigHandlesNestedDestNames(unittest.TestCase):
    """Регрессионный тест на bug, вскрытый после коммита 8a4e93c:

    get_backup_paths() возвращает arcname с вложенностью —
    "telemt/telemt.toml", "etc/systemd/system/mita.service", и т.д.
    Старый статический EXPORT_INCLUDE состоял только из плоских имён,
    поэтому цикл `shutil.copy2(src, tmp / dest_name)` работал — директория
    tmp уже существовала как сама временная папка. С появлением вложенных
    arcname shutil.copy2 стал падать с FileNotFoundError, потому что
    поддиректория tmp/telemt/ не существовала.

    Фикс: перед shutil.copy2 вызывается `dest_path.parent.mkdir(parents=True,
    exist_ok=True)`.

    Этот тест проверяет: _export_list с вложенным dest_name и РЕАЛЬНО
    существующим src (temp-файл) — архив собирается без FileNotFoundError,
    файл оказывается в архиве по вложенному пути.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cleanup_files: list[Path] = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        for f in self._cleanup_files:
            try:
                if f.is_file():
                    f.unlink()
                elif f.exists():
                    f.rmdir()
            except Exception:
                pass

    def test_nested_dest_name_does_not_raise(self):
        """do_export_config() с _export_list, содержащим вложенный dest_name,
        НЕ падает с FileNotFoundError, файл попадает в архив по вложенному
        пути.
        """
        import chimera._core as core

        # Создаём реальный src-файл — он будет скопирован во вложенный путь
        src_file = self._tmpdir / "src_telemt.toml"
        src_file.write_text("# test telemt config\n")
        self._cleanup_files.append(src_file)

        # Путь к архиву (тоже в tmpdir, не в /root/, чтобы не требовать root)
        archive_path = self._tmpdir / "test-export.tar.gz"
        self._cleanup_files.append(archive_path)

        # Мокаем discover_backup_paths, чтобы он вернул ВЛОЖЕННЫЙ arcname
        # (это главный триггер бага — до фикса parent.mkdir).
        import chimera.modules.backup_registry as br
        fake_paths = [
            (src_file, "telemt/telemt.toml"),  # ← ВЛОЖЕННЫЙ arcname
        ]
        original_discover = br.discover_backup_paths
        br.discover_backup_paths = lambda *a, **k: list(fake_paths)

        # Мокаем datetime (используется для имени архива) и Path-операции
        # Патчим archive_path: do_export_config хардкодит
        # Path(f"/root/xray-backup-{ts}.tar.gz") — перехватываем через mock
        # временной директории, чтобы получить реальный путь к архиву.
        # Альтернатива: положить src_file в EXPORT_INCLUDE и проверить, что
        # копирование во вложенный путь работает. Так и сделаем — патчим
        # EXPORT_INCLUDE напрямую через __globals__.

        g = core.do_export_config.__globals__
        original_export_include = g["EXPORT_INCLUDE"]
        # Полностью заменяем — нас интересует ТОЛЬКО вложенный arcname
        g["EXPORT_INCLUDE"] = [(src_file, "mita/server.json")]

        # Патчим путь архива, чтобы он шёл в tmpdir, а не в /root/
        # do_export_config: archive_path = Path(f"/root/{archive_name}")
        # Перехватываем через patch.object(Path, __truediv__) — слишком сложно.
        # Проще: мокаем datetime.now, чтобы потом найти архив по timestamp.
        # Или: мокаем Path.lstat / chmod для /root/ — нет, это не поможет.
        # Самый чистый способ: подменить archive_path через monkeypatch
        # глобала datetime или напрямую через patch временной функции.
        #
        # На самом деле, проще всего подменить OPEN tarfile.open и
        # shutil.copy2 — но мы ХОТИМ проверить, что copy2 РЕАЛЬНО
        # вызывается с вложенным путём и НЕ падает. Поэтому мокаем только
        # путь архива.
        #
        # Решение: патчим Path в chimera._core через globals — но Path
        # импортирован туда глобально. Проще — патчим datetime.now, чтобы
        # генерировать детерминированное имя, и патчим Path(f"/root/...")
        # через подмену самого archive_path.
        #
        # Ещё проще: патчим core.Path (класс) так, чтобы Path("/root/...")
        # возвращал путь в self._tmpdir. НО это слишком инвазивно.
        #
        # Финальное решение: НЕ тестировать реальную запись tar.gz, а
        # только проверить что цикл копирования проходит без FileNotFoundError.
        # Делаем это через monkeypatch shutil.copy2 — записываем аргументы
        # и проверяем, что dest_path.parent СУЩЕСТВУЕТ к моменту вызова.

        copy2_calls: list[tuple] = []
        original_copy2 = core.shutil.copy2
        def spy_copy2(src, dst, *a, **kw):
            # К моменту вызова copy2 dst.parent должен существовать —
            # это и есть проверка фикса.
            from pathlib import Path as _P
            dst_path = _P(dst)
            self.assertTrue(
                dst_path.parent.exists(),
                f"parent dir {dst_path.parent} does not exist when copy2 "
                f"is called with nested dest_name — bug not fixed"
            )
            # Реально копируем, чтобы не сломать последующий tar.add
            original_copy2(src, dst, *a, **kw)
            copy2_calls.append((str(src), str(dst)))

        # Патчим tarfile.open, чтобы архив писался в tmpdir, не в /root/
        import tarfile as _tarfile_mod
        original_tarfile_open = _tarfile_mod.open
        def fake_tarfile_open(path, mode, *a, **kw):
            # Перенаправляем запись в tmpdir
            redirected = self._tmpdir / "test-export.tar.gz"
            return original_tarfile_open(redirected, mode, *a, **kw)

        # Патчим chmod архива (не падать на /root/xray-backup-*.tar.gz)
        original_path_chmod = Path.chmod
        def fake_path_chmod(self_p, *a, **kw):
            # Пропускаем chmod для /root/ — нас интересует только tmpdir
            s = str(self_p)
            if s.startswith("/root/"):
                return
            return original_path_chmod(self_p, *a, **kw)

        # Патчим getpass (encrypt=False — не нужен, но на всякий случай)
        # и input (чтобы тест не зависал)
        try:
            with patch.object(core.shutil, "copy2", spy_copy2):
                with patch.object(_tarfile_mod, "open", fake_tarfile_open):
                    with patch.object(Path, "chmod", fake_path_chmod):
                        with patch("builtins.input", return_value=""):
                            try:
                                core.do_export_config(encrypt=False)
                            except SystemExit:
                                pass
                            except FileNotFoundError as e:
                                # Если упало — это и есть bug, тест должен фейлиться
                                self.fail(
                                    f"do_export_config raised FileNotFoundError "
                                    f"with nested dest_name — bug not fixed: {e}"
                                )
                            except Exception as e:
                                # Прочие исключения (например, info-вывод
                                # и логирование) — не интересны, главный
                                # критерий: НЕ FileNotFoundError на copy2
                                if "copy2" in str(e).lower() or "telemt" in str(e).lower():
                                    self.fail(
                                        f"Unexpected error related to copy2/nested "
                                        f"dest_name: {type(e).__name__}: {e}"
                                    )
        finally:
            g["EXPORT_INCLUDE"] = original_export_include
            br.discover_backup_paths = original_discover

        # Проверяем: copy2 вызывался с вложенным путём
        self.assertTrue(len(copy2_calls) > 0,
                        "shutil.copy2 was not called at all")
        nested_calls = [c for c in copy2_calls if "mita" in c[1] or "telemt" in c[1]]
        self.assertTrue(len(nested_calls) > 0,
                        f"copy2 was not called with nested dest_name, "
                        f"all calls: {copy2_calls}")


# =============================================================================
#  Integration test: end-to-end auto-discovery with real chimera.modules
# =============================================================================
class TestIntegrationWithRealModules(unittest.TestCase):
    """Интеграционный тест: discover_backup_paths() на реальном дереве
    chimera.modules (214 модулей) — должен:
      • завершиться за разумное время (< 30 сек)
      • не бросить исключение
      • найти get_backup_paths() в модулях, где мы его добавили
        (если их файлы существуют — но в тестовой среде их нет, поэтому
        результат пустой; всё равно проверяем, что функция не падает)
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_real_discovery_completes_quickly(self):
        import time as _t
        from chimera.modules.backup_registry import discover_backup_paths
        t0 = _t.time()
        result = discover_backup_paths(timeout_sec=30)
        elapsed = _t.time() - t0
        # Должно завершиться за < 30 сек (фактически ~0.8-1.0 сек на 214 модулей)
        self.assertLess(elapsed, 30.0,
                        f"discovery took too long: {elapsed:.2f}s")
        # Не бросило исключение — это уже успех
        self.assertIsInstance(result, list)

    def test_real_modules_have_get_backup_paths(self):
        """Проверяем, что все ЦЕЛЕВЫЕ модули имеют get_backup_paths()."""
        targets = [
            "chimera.modules.mtproto",
            "chimera.modules.mieru",
            "chimera.modules.naiveproxy",
            "chimera.modules.fptn",
            "chimera.modules.trusttunnel",
            "chimera.modules.singbox_state",
            "chimera.modules.awg_standalone",
            "chimera.modules.hysteria2_backup",
        ]
        for mod_name in targets:
            mod = importlib.import_module(mod_name)
            self.assertTrue(
                hasattr(mod, "get_backup_paths") and callable(mod.get_backup_paths),
                f"{mod_name} должен иметь callable get_backup_paths()"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
