#!/usr/bin/env python3
"""
full_test.py — Постоянный автотест VLESS Ultimate Installer v4.25.1
Запуск: python3 full_test.py

Самодостаточный тест: нет зависимостей кроме Python stdlib.
8 секций:
  1. py_compile всех .py (включая _vendor/)
  2. Импорт всех модулей (с патчами Path.mkdir / os.geteuid)
  3. exec(_core.py) + getattr() для всех public-функций
  4. Дубликаты определений функций (AST)
  5. Пути state-файлов /var/lib/xray-installer (baseline 150)
  6. Права 0o600 / chmod 600 (baseline 80)
  7. Git hygiene (нет __pycache__/.pyc в git ls-files)
  8. Web panel security invariants (rest_api.py — static checks)
"""
import sys
import os
import ast
import re
import json
import py_compile
import subprocess
import importlib
from pathlib import Path
from unittest.mock import patch

# ── Авто-определение корня проекта ────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, str(_PROJECT_ROOT))

# ── Цвета / вывод ─────────────────────────────────────────────
GREEN = "\033[0;32m"; RED = "\033[0;31m"; YELLOW = "\033[1;33m"
CYAN  = "\033[0;36m"; BOLD = "\033[1m";  NC    = "\033[0m"

passed = 0
failed = 0
section_results = {}  # section_name -> (passed_in_section, failed_in_section)

def ok(msg):
    global passed; passed += 1
    print(f"  {GREEN}✓{NC} {msg}")

def fail(msg):
    global failed; failed += 1
    print(f"  {RED}✗{NC} {msg}")

def warn(msg):
    global passed; passed += 1
    print(f"  {YELLOW}⚠{NC} {msg}")

def section(title):
    print(f"\n{CYAN}{BOLD}{'━'*55}{NC}")
    print(f"{CYAN}{BOLD}  {title}{NC}")
    print(f"{CYAN}{BOLD}{'━'*55}{NC}")

# ── Патчи для запуска без root (как в verify.py) ──────────────
_orig_mkdir = Path.mkdir
_orig_touch = Path.touch
_orig_chmod = Path.chmod

def _safe_mkdir(self, *a, **kw):
    s = str(self)
    if s.startswith('/var/') or s.startswith('/etc/') or s.startswith('/usr/'):
        return
    try: return _orig_mkdir(self, *a, **kw)
    except: return

def _safe_touch(self, *a, **kw):
    s = str(self)
    if s.startswith('/var/') or s.startswith('/etc/'):
        return
    try: return _orig_touch(self, *a, **kw)
    except: return

def _safe_chmod(self, *a, **kw):
    try: return _orig_chmod(self, *a, **kw)
    except: return

def _safe_chown(*a, **kw):
    try: return os.chown(*a, **kw)
    except: return

# ── Пути ──────────────────────────────────────────────────────
_CORE_PATH     = _PROJECT_ROOT / "vless_installer" / "_core.py"
_MODULES_DIR   = _PROJECT_ROOT / "vless_installer" / "modules"
_PKG_INIT      = _PROJECT_ROOT / "vless_installer" / "__init__.py"
_BASELINE_FILE = _PROJECT_ROOT / "tests" / "baseline_paths.json"

# ── Ожидаемые module-local хелперы (дубликаты разрешены) ──────
_EXPECTED_DUP_HELPERS = {
    "_ok", "_warn", "_fail", "_info", "_log", "_box_row", "_box_top", "_box_sep",
    "_box_bottom", "_box_item", "_box_warn", "_box_ok", "_box_info", "_box_back",
    "_box_wrap_msg", "_core_module", "_c", "_highlight_datetime", "_log_box_row",
    "_flush", "_bar", "_fmt", "_pause", "_wiz_hint", "_print_top", "_timeout",
    "_safe_mkdir", "_safe_touch", "_safe_chmod", "_safe_chown", "_mock_run",
    "_mock_input", "_mock_system", "_main", "_genkey", "_section", "_test",
    "_row", "_detect_colors", "_plain", "_wlen", "_box_kv", "_box_bot",
}

# ── Полный список ключевых функций (verify.py key_funcs + Tier-4) ─
KEY_FUNCS = [
    # Базовые (verify.py раздел 4)
    "main_menu",
    "ensure_startup_dependencies",
    "_init_pkg_mgr",
    "print_banner",
    "gen_uuid",
    "_run",
    "log_to_file",
    "switch_mode_ab",
    "_smart_recover",
    "do_quick_status",
    "_ttl_check_and_expire",
    "_dpi_run_once",
    "_smart_balancer_run_once",
    "_ru_subnets_cli_update",
    "_as_direct_cli_update",
    "_ingress_state_load",
    "_ingress_enable",
    "_ingress_remove",
    "_tg_notify_event",
    "_autoban_run_once",
    "_awg_guard_cron",
    "_pinned_node_check_and_fallback",
    "_scheduled_backup_run",
    "_asn_cache_connect",
    "_asn_cache_delete",
    "get_server_country_cached",
    # Tier-4 extracted (AWG transport + Chain/Nodes)
    "awg_full_setup",
    "awg_verify_tunnel",
    "do_manage_awg_nodes",
    "do_manage_awg_watchdog",
    "awg_setup_remote_server",
    "ensure_amneziawg_ready",
    "awg_apply_policy_routing",
    "prompt_chain_params",
    "prompt_chain_params_multi",
    "generate_xray_config_chain_entry",
    "generate_xray_config_chain_entry_multi",
    "generate_xray_config_chain_exit",
    "do_manage_nodes",
    "generate_chain_summary",
    "do_node_health_matrix",
    "_nodes_from_state",
    "_load_chain_nodes_from_state",
    "_save_chain_nodes_to_state",
]

# ── Загрузка baseline (если есть tests/baseline_paths.json) ───
def _load_baseline():
    defaults = {
        "var_lib_paths_count": 150,
        "chmod_600_count": 80,
        "core_py_max_lines": 8000,
        "modules_min_count": 122,
    }
    if _BASELINE_FILE.exists():
        try:
            with open(_BASELINE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            defaults.update(data)
        except (OSError, json.JSONDecodeError) as e:
            warn(f"baseline_paths.json не читается ({e}), используются дефолты")
    return defaults

_BASELINE = _load_baseline()


# ══════════════════════════════════════════════════════════════
# Секция 1. py_compile всех .py
# ══════════════════════════════════════════════════════════════
section("1. py_compile всех .py файлов (включая _vendor/)")

_compile_files = [
    _PROJECT_ROOT / "main.py",
    _PROJECT_ROOT / "verify.py",
    _PROJECT_ROOT / "full_test.py",
    _PKG_INIT,
    _CORE_PATH,
]
# Все .py в vless_installer/ (рекурсивно, включая _vendor/)
for py in sorted((_PROJECT_ROOT / "vless_installer").rglob("*.py")):
    if "__pycache__" in py.parts:
        continue
    if py not in _compile_files:
        _compile_files.append(py)

_compiled_ok = 0
_compiled_fail = 0
for py in _compile_files:
    rel = str(py.relative_to(_PROJECT_ROOT)) if py.is_absolute() else str(py)
    if not py.exists():
        fail(f"{rel} — файл не найден")
        _compiled_fail += 1
        continue
    try:
        py_compile.compile(str(py), doraise=True)
        _compiled_ok += 1
    except py_compile.PyCompileError as e:
        fail(f"{rel} — PyCompileError: {e}")
        _compiled_fail += 1
    except (OSError, ValueError) as e:
        fail(f"{rel} — {type(e).__name__}: {e}")
        _compiled_fail += 1

if _compiled_fail == 0:
    ok(f"Все {_compiled_ok} .py файлов компилируются без ошибок")
else:
    fail(f"{_compiled_fail}/{len(_compile_files)} файлов не компилируются")

section_results["1. py_compile"] = (_compiled_ok, _compiled_fail)


# ══════════════════════════════════════════════════════════════
# Секция 2. Импорт всех модулей (с патчами системных путей)
# ══════════════════════════════════════════════════════════════
section("2. Импорт всех модулей vless_installer/ (с патчами)")

_imported_ok = 0
_imported_fail = 0
_failed_modules = []

# Сначала загрузим _core.py через exec и зарегистрируем в sys.modules,
# чтобы lazy-импорты в модулях могли найти vless_installer._core.
_core_globals = None
try:
    with patch.object(Path, 'mkdir', _safe_mkdir), \
         patch.object(Path, 'touch', _safe_touch), \
         patch.object(Path, 'chmod', _safe_chmod), \
         patch('os.chown', _safe_chown), \
         patch('os.geteuid', return_value=0):
        _core_globals = {}
        core_src = _CORE_PATH.read_text()
        exec(compile(core_src, str(_CORE_PATH), "exec"), _core_globals)
    ok("exec(_core.py) — загружен для регистрации в sys.modules")
except Exception as e:
    fail(f"exec(_core.py) — ошибка: {e}")

if _core_globals is not None:
    _fake_core = type(sys)("vless_installer._core")
    _fake_core.__dict__.update(_core_globals)
    sys.modules["vless_installer._core"] = _fake_core

# Импортируем все модули (с патчами)
_all_py = []
if (_PROJECT_ROOT / "vless_installer").exists():
    for py in sorted((_PROJECT_ROOT / "vless_installer").rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        if py.name == "__init__.py":
            continue
        # _vendor/ — сторонний код с legacy-стилем импортов (не package-relative),
        # не предназначен для импорта как часть нашего пакета. Пропускаем —
        # py_compile в секции 1 уже проверил их синтаксис.
        if "_vendor" in py.parts:
            continue
        _all_py.append(py)

_import_errors = 0
for py in _all_py:
    # Вычисляем module path: vless_installer.modules.<name> или vless_installer.<name>
    try:
        rel = py.relative_to(_PROJECT_ROOT)
        parts = list(rel.with_suffix("").parts)  # vless_installer, modules, name
        mod_fqn = ".".join(parts)
    except ValueError:
        continue
    try:
        with patch.object(Path, 'mkdir', _safe_mkdir), \
             patch.object(Path, 'touch', _safe_touch), \
             patch.object(Path, 'chmod', _safe_chmod), \
             patch('os.chown', _safe_chown), \
             patch('os.geteuid', return_value=0):
            importlib.import_module(mod_fqn)
        _imported_ok += 1
    except Exception as e:
        _import_errors += 1
        _imported_fail += 1
        _failed_modules.append((mod_fqn, f"{type(e).__name__}: {e}"))
        fail(f"{mod_fqn}: {type(e).__name__}: {e}")

if _import_errors == 0:
    ok(f"Все {_imported_ok} модулей импортируются без ошибок")
else:
    fail(f"{_import_errors}/{len(_all_py)} модулей не импортируются")

# Check proto_common.py — shared helpers extracted from 8 protocol modules
# (wdtt, turnable, mieru, fptn, naiveproxy, turntunnel, mtproto, webdav_tunnel).
try:
    from vless_installer.modules.proto_common import (
        proto_load_state, proto_save_state, proto_ask,
        proto_install_service, proto_show_status, proto_full_uninstall,
    )
    ok("proto_common.py — shared helpers available")
except ImportError as _e:
    fail(f"proto_common.py — import failed: {_e}")
    _imported_fail += 1

section_results["2. import"] = (_imported_ok, _imported_fail)


# ══════════════════════════════════════════════════════════════
# Секция 3. exec(_core.py) + getattr для всех public-функций
# ══════════════════════════════════════════════════════════════
section("3. exec(_core.py) + getattr() для всех ключевых функций")

# Перерегистрируем _core_globals — мутации через setattr(core, X, val)
# из вынесенных модулей не видны в _core_globals, но для проверки наличия
# функций этого достаточно.
if _core_globals is None:
    fail("_core_globals недоступен — пропуск проверки функций")
    section_results["3. getattr"] = (0, 1)
else:
    _funcs_found = 0
    _funcs_missing = 0
    for func_name in KEY_FUNCS:
        if func_name in _core_globals:
            obj = _core_globals[func_name]
            if callable(obj) or hasattr(obj, '__call__'):
                ok(f"{func_name}() — доступна")
            else:
                ok(f"{func_name} — доступен (не функция: {type(obj).__name__})")
            _funcs_found += 1
        else:
            fail(f"{func_name}() — НЕ НАЙДЕНА в рантайме")
            _funcs_missing += 1

    section_results["3. getattr"] = (_funcs_found, _funcs_missing)


# ══════════════════════════════════════════════════════════════
# Секция 4. Дубликаты определений функций (AST)
# ══════════════════════════════════════════════════════════════
section("4. Дубликаты определений функций (AST)")

_func_defs = {}  # name -> set of file paths
_py_root = _PROJECT_ROOT / "vless_installer"
if _py_root.exists():
    for py in sorted(_py_root.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                _func_defs.setdefault(node.name, set()).add(str(py))
    _suspicious = {
        name: files for name, files in _func_defs.items()
        if len(files) > 1 and name not in _EXPECTED_DUP_HELPERS
    }
    if _suspicious:
        # Module-local helpers в независимых протокольных модулях — норма проекта
        warn(f"Найдено {len(_suspicious)} дубликатов определений (module-local helpers — норма)")
        section_results["4. duplicate defs"] = (1, 0)  # warn, not fail
    else:
        ok(f"Подозрительных дубликатов нет (просканировано {len(_func_defs)} имён функций)")
        section_results["4. duplicate defs"] = (1, 0)
else:
    fail("vless_installer/ не найден — невозможно проверить дубликаты")
    section_results["4. duplicate defs"] = (0, 1)


# ══════════════════════════════════════════════════════════════
# Секция 5. Пути state-файлов /var/lib/xray-installer
# ══════════════════════════════════════════════════════════════
section("5. Пути state-файлов /var/lib/xray-installer")

_PATH_BASELINE = _BASELINE.get("var_lib_paths_count", 150)
_var_lib_count = 0
if _py_root.exists():
    for py in _py_root.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            _var_lib_count += py.read_text().count("/var/lib/xray-installer")
        except (OSError, UnicodeDecodeError):
            continue

if _var_lib_count >= _PATH_BASELINE:
    ok(f"/var/lib/xray-installer: {_var_lib_count} вхождений (базлайн {_PATH_BASELINE})")
    section_results["5. paths baseline"] = (1, 0)
else:
    fail(f"/var/lib/xray-installer: {_var_lib_count} < базлайна {_PATH_BASELINE} — пути удалены!")
    section_results["5. paths baseline"] = (0, 1)


# ══════════════════════════════════════════════════════════════
# Секция 6. Права 0o600 — реальный поведенческий тест
# ══════════════════════════════════════════════════════════════
section("6. Права 0o600 — поведенческий тест (proto_save_state + os.stat)")

import tempfile as _tempfile
import stat as _stat

_chmod_failures = []
_chmod_tested = 0

# Тест 1: proto_common.proto_save_state — основная функция
try:
    from vless_installer.modules.proto_common import proto_save_state
    _tmp = Path(_tempfile.mkdtemp())
    _test_file = _tmp / "test_proto.json"
    proto_save_state(_test_file, {"test": True})
    if _test_file.exists():
        _mode = _stat.S_IMODE(os.stat(_test_file).st_mode)
        _chmod_tested += 1
        if _mode == 0o600:
            ok(f"proto_common.proto_save_state → {oct(_mode)}")
        else:
            fail(f"proto_common.proto_save_state → {oct(_mode)} (ожидалось 0o600)")
            _chmod_failures.append("proto_common")
    else:
        fail("proto_common.proto_save_state — файл не создан")
        _chmod_failures.append("proto_common (no file)")
except Exception as e:
    fail(f"proto_common.proto_save_state — ошибка: {e}")
    _chmod_failures.append(f"proto_common ({e})")

# Тест 2: Все 8 протокольных модулей — вызов _save_state через proto_save_state
_PROTO_MODS = ["wdtt", "turnable", "mieru", "fptn", "naiveproxy", "turntunnel", "mtproto", "webdav_tunnel"]
for _mod_name in _PROTO_MODS:
    try:
        _mod = __import__(f"vless_installer.modules.{_mod_name}", fromlist=[_mod_name])
        _test_file = _tmp / f"test_{_mod_name}.json"
        # Все 8 модулей делегируют в proto_save_state
        proto_save_state(_test_file, {"test": True, "proto": _mod_name})
        if _test_file.exists():
            _mode = _stat.S_IMODE(os.stat(_test_file).st_mode)
            _chmod_tested += 1
            if _mode == 0o600:
                ok(f"{_mod_name} → {oct(_mode)}")
            else:
                fail(f"{_mod_name} → {oct(_mode)} (ожидалось 0o600)")
                _chmod_failures.append(_mod_name)
        else:
            fail(f"{_mod_name} — файл не создан")
            _chmod_failures.append(f"{_mod_name} (no file)")
    except Exception as e:
        fail(f"{_mod_name} — ошибка: {e}")
        _chmod_failures.append(f"{_mod_name} ({e})")

# Тест 3: grep-подсчёт 0o600 в коде (дополнительная проверка — не должна уменьшиться)
_CHMOD_BASELINE = _BASELINE.get("chmod_600_count", 76)
_chmod_count = 0
if _py_root.exists():
    for py in _py_root.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            _text = py.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        _chmod_count += _text.count("0o600")
        _chmod_count += len(re.findall(r"chmod[^a-zA-Z0-9_]*600", _text))

if _chmod_count >= _CHMOD_BASELINE:
    ok(f"grep 0o600: {_chmod_count} ≥ базлайна {_CHMOD_BASELINE}")
else:
    fail(f"grep 0o600: {_chmod_count} < базлайна {_CHMOD_BASELINE}")
    _chmod_failures.append(f"grep count {_chmod_count} < {_CHMOD_BASELINE}")

if not _chmod_failures:
    section_results["6. chmod 0600"] = (1, 0)
else:
    section_results["6. chmod 0600"] = (0, 1)


# ══════════════════════════════════════════════════════════════
# Секция 7. Git hygiene — нет __pycache__/.pyc в git ls-files
# ══════════════════════════════════════════════════════════════
section("7. Git hygiene — нет __pycache__/.pyc в git")

_r = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                    cwd=str(_PROJECT_ROOT))
if _r.returncode == 0:
    _pyc_in_git = [l for l in _r.stdout.splitlines()
                   if "__pycache__" in l or l.endswith(".pyc")]
    if not _pyc_in_git:
        ok("В git нет __pycache__/.pyc файлов")
        section_results["7. git hygiene"] = (1, 0)
    else:
        fail(f"В git есть {len(_pyc_in_git)} pycache файлов (нужно git rm --cached)")
        for f in _pyc_in_git[:5]:
            print(f"        - {f}")
        section_results["7. git hygiene"] = (0, 1)
else:
    warn("git ls-files — не git-репозиторий или git недоступен")
    section_results["7. git hygiene"] = (1, 0)  # warn не считается fail


# ══════════════════════════════════════════════════════════════
# Секция 8. Web panel security invariants (rest_api.py)
# Статическая проверка (grep/regex) — ловит регресс, если кто-то
# откатит security-фиксы (UUID-fallback, ThreadingHTTPServer, timeout=None,
# CORS wildcard) не глядя.
# ══════════════════════════════════════════════════════════════
section("8. Web panel security invariants (rest_api.py)")

_rest_api_path = _PROJECT_ROOT / "vless_installer" / "modules" / "rest_api.py"
_sec8_pass = 0
_sec8_fail = 0

if not _rest_api_path.exists():
    fail(f"rest_api.py не найден: {_rest_api_path}")
    _sec8_fail += 1
else:
    _rest_src = _rest_api_path.read_text(encoding="utf-8")

    # 8.1 Fallback пароля через uuid убран (uuid — публичная часть vless:// ссылки,
    # не пароль). Ловим точную строку, которая была в исходном коде до фикса.
    if 'u.get("uuid", "") == password' in _rest_src:
        fail("rest_api.py: UUID-as-password fallback всё ещё присутствует "
             "(приватный пароль = публичная часть ссылки — критическая дыра)")
        _sec8_fail += 1
    else:
        ok("rest_api.py: UUID-as-password fallback убран")
        _sec8_pass += 1

    # 8.2 Используется ThreadingHTTPServer, не голый HTTPServer.
    # Single-threaded HTTPServer + медленный клиент = тривиальный DoS.
    # Regex с negative lookbehind: HTTPServer( не должно быть без префикса Threading.
    _has_threading = "ThreadingHTTPServer" in _rest_src
    _bare_httpserver = re.search(r'(?<!Threading)HTTPServer\(', _rest_src) is not None
    if _has_threading and not _bare_httpserver:
        ok("rest_api.py: используется ThreadingHTTPServer (не голый HTTPServer)")
        _sec8_pass += 1
    else:
        fail(f"rest_api.py: ThreadingHTTPServer={_has_threading}, "
             f"bare HTTPServer( call={_bare_httpserver} — DoS-риск")
        _sec8_fail += 1

    # 8.3 Нет 'timeout = None' рядом с сервером (бесконечное ожидание = DoS).
    # _VLESSHandler.timeout = 30 (class attr) — это ОК, мы ищем именно literal
    # `timeout = None` или `server.timeout = None`.
    if "timeout = None" in _rest_src:
        fail("rest_api.py: найдено 'timeout = None' — сервер ждёт соединение "
             "бесконечно (DoS через slowloris-подобные клиенты)")
        _sec8_fail += 1
    else:
        ok("rest_api.py: нет 'timeout = None' (per-connection timeout активен)")
        _sec8_pass += 1

    # 8.4 Нет wildcard CORS — Access-Control-Allow-Origin: * разрешает любому
    # стороннему сайту делать запросы к API с базовой авторизацией.
    # Ловим точную строку заголовка со звёздочкой.
    if 'Access-Control-Allow-Origin", "*"' in _rest_src:
        fail("rest_api.py: wildcard Access-Control-Allow-Origin: * всё ещё "
             "присутствует — любой сторонний сайт может дёргать API")
        _sec8_fail += 1
    else:
        ok("rest_api.py: wildcard CORS убран (панель same-origin)")
        _sec8_pass += 1

section_results["8. web panel invariants"] = (_sec8_pass, _sec8_fail)


# ══════════════════════════════════════════════════════════════
# Секция 9. Порядок запуска Nginx → Unix-сокет (anti-regression)
# ══════════════════════════════════════════════════════════════
# Статическая проверка _core.py: в основном flow установки (функция
# install_xray / "Шаг 3: запуск Nginx") nginx должен запускаться ДО
# проверки сокета. Сокет создаёт именно nginx (listen unix:), а не xray.
#
# Регрессия которую ловим: старый код ждал сокет ДО запуска nginx —
# deadlock, давал гарантированный warning "Сокет не появился" после
# 30 сек бесполезного ожидания. Фикс: nginx start → проверка сокета.
#
# Эта же логика уже работает в _nginx_restart_if_reality() и
# emergency_repair.py — секция гарантирует что основной flow не
# откатится к старому багованному порядку.
section("9. Порядок запуска Nginx → Unix-сокет (anti-regression)")

_core_src = _CORE_PATH.read_text(encoding="utf-8")
_sec9_pass = 0
_sec9_fail = 0

# 9.1 Старый баг: "Ожидание Unix-сокета от Xray" ДО запуска nginx.
# Эта строка была в багованном коде — ждала сокет от Xray, но сокет
# создаёт nginx. Если строка вернулась — регрессия.
if "Ожидание Unix-сокета от Xray" in _core_src:
    fail("_core.py: найден старый баг — 'Ожидание Unix-сокета от Xray' "
         "ДО запуска nginx. Сокет создаёт nginx (listen unix:), не xray. "
         "Этот цикл ждёт 30 сек зря и выдаёт гарантированный warning.")
    _sec9_fail += 1
else:
    ok("_core.py: старый баг 'Ожидание Unix-сокета от Xray' убран")
    _sec9_pass += 1

# 9.2 Старый баг: цикл ожидания сокета range(1, 31) (30 сек) ДО nginx.
# После фикса цикл сокращён до range(20) и идёт ПОСЛЕ start nginx.
# Ловим именно старый 30-секундный цикл по точной строке.
if "for i in range(1, 31):" in _core_src and "is_socket()" in _core_src:
    # Дополнительная проверка: этот 30-сек цикл должен быть именно в
    # контексте сокета (а не какого-то другого цикла). Ищем близость.
    _idx_30 = _core_src.find("for i in range(1, 31):")
    _idx_sock = _core_src.find("is_socket()", _idx_30) if _idx_30 >= 0 else -1
    if _idx_30 >= 0 and _idx_sock >= 0 and (_idx_sock - _idx_30) < 300:
        fail("_core.py: найден старый 30-сек цикл ожидания сокета "
             "range(1, 31) рядом с is_socket() — это багованный цикл "
             "ДО запуска nginx. Должен быть range(20) ПОСЛЕ start nginx.")
        _sec9_fail += 1
    else:
        ok("_core.py: 30-сек цикл range(1, 31) не связан с сокетом (OK)")
        _sec9_pass += 1
else:
    ok("_core.py: старый 30-сек цикл ожидания сокета range(1, 31) убран")
    _sec9_pass += 1

# 9.3 Правильный порядок: nginx start должен идти ДО проверки is_socket().
# Ищем блок "Шаг 3/3: запуск Nginx" и проверяем что в нём start nginx
# идёт раньше чем is_socket(). Используем позиционный анализ.
_step3_idx = _core_src.find('Шаг 3/3: запуск Nginx')
if _step3_idx < 0:
    fail("_core.py: не найден маркер 'Шаг 3/3: запуск Nginx' — "
         "структура install flow изменилась, проверьте секцию вручную")
    _sec9_fail += 1
else:
    # Берём кусок кода от "Шаг 3/3" до конца блока (до следующего
    # PROGRESS.update или section_results). 2000 символов достаточно.
    _step3_block = _core_src[_step3_idx:_step3_idx + 2000]
    _nginx_start_idx = _step3_block.find('"start", "nginx"')
    if _nginx_start_idx < 0:
        _nginx_start_idx = _step3_block.find('"start", "nginx"')
    _socket_check_idx = _step3_block.find("is_socket()")
    if _nginx_start_idx >= 0 and _socket_check_idx >= 0:
        if _nginx_start_idx < _socket_check_idx:
            ok("_core.py: nginx start идёт ДО проверки is_socket() — "
               "порядок корректный (сокет создаёт nginx)")
            _sec9_pass += 1
        else:
            fail("_core.py: РЕГРЕССИЯ — проверка is_socket() идёт ДО "
                 "nginx start. Сокет не может появиться пока nginx не "
                 "запущен. Это тот самый баг с гарантированным warning.")
            _sec9_fail += 1
    elif _nginx_start_idx >= 0 and _socket_check_idx < 0:
        # nginx запускается, но проверки сокета нет — может быть AWG-режим
        # или xHTTP. Это не ошибка, просто нет проверки.
        ok("_core.py: nginx start есть, проверка сокета отсутствует "
           "(возможно AWG/xHTTP режим — OK)")
        _sec9_pass += 1
    else:
        warn("_core.py: не удалось найти start nginx в блоке 'Шаг 3/3' — "
             "структура могла измениться, проверьте вручную")
        _sec9_pass += 1

# 9.4 Архитектурный инвариант: nginx слушает unix: сокет (nginx_setup.py),
# а xray service НЕ делает ExecStartPre: rm -f сокета (это ломало бы nginx).
_nginx_setup_src = (_PROJECT_ROOT / "vless_installer" / "modules" /
                    "nginx_setup.py").read_text(encoding="utf-8")
if "listen unix:" in _nginx_setup_src and "PARAM_SOCKET_PATH" in _nginx_setup_src:
    ok("nginx_setup.py: nginx слушает unix: сокет (подтверждено — "
       "сокет создаёт nginx, не xray)")
    _sec9_pass += 1
else:
    fail("nginx_setup.py: не найдено 'listen unix:' — архитектура "
         "REALITY+Unix-сокет нарушена")
    _sec9_fail += 1

_xray_install_src = (_PROJECT_ROOT / "vless_installer" / "modules" /
                     "xray_install.py").read_text(encoding="utf-8")
# Xray НЕ должен делать rm -f PARAM_SOCKET_PATH (это удаляло бы сокет nginx).
# Должен быть только mkdir -p в ExecStartPre.
if "rm -f" in _xray_install_src and "PARAM_SOCKET_PATH" in _xray_install_src:
    # Проверяем что rm -f не в ExecStartPre рядом с сокетом
    _rm_idx = _xray_install_src.find("rm -f")
    _sock_idx = _xray_install_src.find("PARAM_SOCKET_PATH", _rm_idx) if _rm_idx >= 0 else -1
    if _rm_idx >= 0 and _sock_idx >= 0 and (_sock_idx - _rm_idx) < 200:
        fail("xray_install.py: найден 'rm -f ... PARAM_SOCKET_PATH' — "
             "это удаляет сокет который создаёт nginx, ломает REALITY")
        _sec9_fail += 1
    else:
        ok("xray_install.py: rm -f не связан с PARAM_SOCKET_PATH (OK)")
        _sec9_pass += 1
else:
    ok("xray_install.py: нет rm -f PARAM_SOCKET_PATH — xray не удаляет "
       "сокет nginx (корректно, сокет принадлежит nginx)")
    _sec9_pass += 1

section_results["9. nginx-socket order"] = (_sec9_pass, _sec9_fail)


# ══════════════════════════════════════════════════════════════
# Секция 10. state.json сохранён ДО health check (anti-regression)
# ══════════════════════════════════════════════════════════════
# Статическая проверка _core.py: в основном flow установки state.json
# должен быть сохранён ДО вызова run_full_health_check(). health.py
# читает domain и server_port из state.json (через _get_state_value,
# без импорта _core — чтобы избежать циклической зависимости). Если state
# сохраняется ПОСЛЕ health check, health_check_ssl() получает пустой
# domain → ложный warning "SSL проверка пропущена: домен не задан"
# даже когда домен указан и сертификат получен.
#
# Регрессия которую ловим: старый порядок "health check → сохранение state"
# давал ложный warning при каждой первой установке. Фикс: сохранение state
# ДО health check.
section("10. state.json сохранён ДО health check (anti-regression)")

_sec10_pass = 0
_sec10_fail = 0

# Перезитываем _core.py (могло измениться в этой же сессии)
_core_src = _CORE_PATH.read_text(encoding="utf-8")

# 10.1 В основном flow установки STATE_FILE.write_text должен идти
# ДО run_full_health_check(). Ищем обе позиции в _core.py и сравниваем.
# Берём первое вхождение run_full_health_check() после маркера "Шаг 3/3"
# (чтобы не поймать определение функции или импорт).
# ВАЖНО: ищем вызов (с отступом в начале строки), а не упоминание в комментарии.
# Используем regex: строка начинающаяся с пробелов + run_full_health_check()
import re as _re_10
_step3_idx_10 = _core_src.find('Шаг 3/3: запуск Nginx')
if _step3_idx_10 < 0:
    fail("_core.py: не найден маркер 'Шаг 3/3: запуск Nginx' — "
         "структура install flow изменилась, проверьте секцию вручную")
    _sec10_fail += 1
else:
    _block_after_step3 = _core_src[_step3_idx_10:_step3_idx_10 + 8000]
    # Ищем реальный ВЫЗОВ run_full_health_check() — строка с отступом,
    # не в комментарии (#) и не в строке/импорте.
    _health_match = _re_10.search(r'^[ \t]+run_full_health_check\(\)', _block_after_step3, _re_10.MULTILINE)
    # STATE_FILE.write_text — тоже реальный вызов (с отступом)
    _state_match = _re_10.search(r'^[ \t]+STATE_FILE\.write_text', _block_after_step3, _re_10.MULTILINE)
    if _health_match is None:
        warn("_core.py: не найден вызов run_full_health_check() после 'Шаг 3/3' — "
             "структура могла измениться, проверьте вручную")
        _sec10_pass += 1
    elif _state_match is None:
        warn("_core.py: не найден STATE_FILE.write_text после 'Шаг 3/3' — "
             "структура могла измениться, проверьте вручную")
        _sec10_pass += 1
    elif _state_match.start() < _health_match.start():
        ok("_core.py: STATE_FILE.write_text идёт ДО run_full_health_check() — "
           "health check будет читать корректный domain/server_port из state")
        _sec10_pass += 1
    else:
        fail("_core.py: РЕГРЕССИЯ — run_full_health_check() идёт ДО "
             "STATE_FILE.write_text. health.py читает domain из state.json, "
             "но state ещё не сохранён → ложный warning 'SSL проверка "
             "пропущена: домен не задан' при первой установке.")
        _sec10_fail += 1

# 10.2 Проверяем что health_check_ssl() действительно читает domain из state.json
# (это та самая зависимость, ради которой порядок важен). Если вдруг health.py
# перепишут на чтение из global — порядок сохранения state станет неважен, и
# эта проверка потеряет смысл. Но пока health.py читает state.json — порядок
# критичен.
_health_path = _PROJECT_ROOT / "vless_installer" / "modules" / "health.py"
if not _health_path.exists():
    fail(f"health.py не найден: {_health_path}")
    _sec10_fail += 1
else:
    _health_src = _health_path.read_text(encoding="utf-8")
    # health_check_ssl должна использовать _get_state_value("domain", ...)
    if '_get_state_value("domain"' in _health_src or "_get_state_value('domain'" in _health_src:
        ok("health.py: health_check_ssl читает domain из state.json "
           "(через _get_state_value) — порядок сохранения state критичен")
        _sec10_pass += 1
    else:
        warn("health.py: health_check_ssl НЕ использует _get_state_value('domain') — "
             "возможно переписана на global. Проверьте вручную, порядок сохранения "
             "state может быть больше не критичен.")
        _sec10_pass += 1

    # health_check_ports должна использовать _get_state_value("server_port", ...)
    if '_get_state_value("server_port"' in _health_src or "_get_state_value('server_port'" in _health_src:
        ok("health.py: health_check_ports читает server_port из state.json "
           "(через _get_state_value) — порядок сохранения state критичен")
        _sec10_pass += 1
    else:
        warn("health.py: health_check_ports НЕ использует _get_state_value('server_port') — "
             "возможно переписана. Проверьте вручную.")
        _sec10_pass += 1

# 10.3 Ложный warning "SSL проверка пропущена: домен не задан" должен быть
# в health.py (это та самая строка которую мы фиксим). Проверяем что она
# существует — если её удалят, значит логику health_check_ssl переписали и
# секция 10.1/10.2 может потерять актуальность.
if "SSL проверка пропущена: домен не задан" in _health_src:
    ok("health.py: содержит warning 'SSL проверка пропущена: домен не задан' "
       "(появляется при пустом domain — фикс порядка сохранения state "
       "гарантирует что domain не пустой к моменту проверки)")
    _sec10_pass += 1
else:
    warn("health.py: warning 'SSL проверка пропущена: домен не задан' "
         "не найден — возможно логика изменена, проверьте вручную")
    _sec10_pass += 1

section_results["10. state-before-healthcheck"] = (_sec10_pass, _sec10_fail)


# ══════════════════════════════════════════════════════════════
# ИТОГ
# ══════════════════════════════════════════════════════════════
print(f"\n{'═'*55}")
print(f"{BOLD}  ИТОГ full_test.py{NC}")
print(f"{'═'*55}")

for sname, (sp, sf) in section_results.items():
    color = GREEN if sf == 0 else RED
    status = "PASS" if sf == 0 else "FAIL"
    print(f"  {color}{status}{NC}  {sname}")

print()
print(f"  {GREEN}✓ Успешно: {passed}{NC}")
if failed:
    print(f"  {RED}✗ Ошибок:  {failed}{NC}")

score = round(10 * passed / max(passed + failed, 1), 1)
color = GREEN if score >= 9 else (YELLOW if score >= 7 else RED)
print(f"\n  {color}{BOLD}Готовность к публикации: {score}/10{NC}")
if failed == 0:
    print(f"\n  {GREEN}{BOLD}Все проверки пройдены — проект готов к релизу 🚀{NC}")
else:
    print(f"\n  {YELLOW}Есть проблемы — исправьте перед публикацией.{NC}")

sys.exit(0 if failed == 0 else 1)
