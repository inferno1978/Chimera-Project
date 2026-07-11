"""
vless_installer/modules/test_runner.py
───────────────────────────────────────────────────────────────────────────────
TUI-интерфейс для запуска unit-тестов из главного меню установщика.

Группирует 122 тестовых файла в 10 логических категорий, соответствующих
разделам главного меню. Запускает тесты в ИЗОЛИРОВАННОМ САБПРОЦЕССЕ через
`python -m unittest`, парсит вывод и формирует отчёт в
/var/log/vless-test-report.log.

Безопасность: тесты используют mock/tempfile, НЕ меняют систему.
ДОПОЛНИТЕЛЬНО: запуск в сабпроцессе гарантирует что даже если какой-то
тест случайно тронет sys.modules или другой module-level state
родительского процесса, это не повлияет на живую TUI-сессию администратора.

ВАЖНО (регрессия исправлена): до этого фикса тесты запускались in-process
через unittest.TestLoader. Каждый test-файл в setUp() делал
    sys.modules["vless_installer._core"] = types.ModuleType(...)
БЕЗ tearDown. В pytest-процессе это безопасно (процесс завершается),
но при запуске из живого TUI (тот же процесс что main_menu()) подмена
оставалась навсегда — module-level state (PROGRESS, INSTALL_START_TIME,
TOTAL_RAM, BANNER) пересоздавался, и весь последующий код получал другой
объект модуля через importlib.import_module("vless_installer._core").
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_TESTS_DIR = _PROJECT_ROOT / "tests"
_REPORT_FILE = Path("/var/log/vless-test-report.log")


# ══════════════════════════════════════════════════════════════════════════════
#  ГРУППЫ ТЕСТОВ
# ══════════════════════════════════════════════════════════════════════════════

TEST_GROUPS: dict[str, dict] = {
    "1": {
        "label": "VLESS Core",
        "description": "Установка, пользователи, ссылки, REST API",
        "tests": [
            "health", "proto_common", "users_manager",
            "client_config_export", "xray_install", "chain_nodes",
            "rest_api", "rest_api_auth",
        ],
    },
    "2": {
        "label": "AWG / Каскад",
        "description": "Standalone AWG, каскад, пиры, ротация обфускации",
        "tests": [
            "awg_constants", "awg_presets", "awg_state", "awg_qr",
            "awg_expires", "awg_apply", "awg_transport", "awg_diagnose",
            "awg_cascade", "awg_peers", "awg_standalone", "awg_backup",
            "awg_hw_tuning", "awg_net_common", "awg_rest_api",
        ],
    },
    "3": {
        "label": "Hysteria2",
        "description": "H2 транспорт, балансировка, сертификаты, DPI",
        "tests": [
            "hysteria2_common", "hysteria2_transport", "hysteria2_balancer",
            "hysteria2_cert_mgr", "hysteria2_cluster", "hysteria2_dpi",
            "hysteria2_quality", "hysteria2_smoke_test", "hysteria2_traffic",
            "hysteria2_watchdog", "hysteria2_exit_mgr", "hysteria2_backup",
        ],
    },
    "4": {
        "label": "Mieru",
        "description": "Mieru, обфускация (traffic pattern), статистика",
        "tests": [
            "mieru", "mieru_stats", "mieru_traffic_presets",
        ],
    },
    "5": {
        "label": "Fragment",
        "description": "Фрагментация, ссылки, статистика, watchdog",
        "tests": [
            "fragment_config", "fragment_presets", "fragment_noise",
            "fragment_mux", "fragment_stats", "fragment_link",
            "fragment_log_viewer", "fragment_share", "fragment_watchdog",
            "fragment_guide",
        ],
    },
    "6": {
        "label": "Протоколы",
        "description": "MTProto, NaiveProxy, WDTT, Turnable, TurnTunnel,\nSlipGate, WebDAV, FPTN, olcRTC",
        "tests": [
            "mtproto", "mtproto_stats", "naiveproxy", "naiveproxy_stats",
            "wdtt", "turnable", "turntunnel", "turntunnel_links",
            "slipgate", "webdav_tunnel", "fptn", "olcrtc",
        ],
    },
    "7": {
        "label": "Сеть и Безопасность",
        "description": "DNS, баны, GeoIP, firewall, SSH, сертификаты",
        "tests": [
            "dns_rules", "dnscrypt_selector", "dnscrypt_setup",
            "ipban", "autoban", "fail2ban_manager",
            "geoip_block", "ingress_geoip", "ru_subnets",
            "port_hopping", "honeypot", "ssl_certbot",
            "asn_cache", "ripe_file_age",
        ],
    },
    "8": {
        "label": "Инфраструктура",
        "description": "Диагностика, бэкапы, мониторинг, статус, failover",
        "tests": [
            "diagnostics", "status_panel", "node_health_monitor",
            "failover", "cold_boot_restore", "config_backup",
            "logrotate", "nginx_watchdog",
            "traffic_tracking", "health_report",
            "scheduler", "traffic_history", "connection_audit",
            "ipset_persist", "system_deps", "xray_safe_apply",
            "network_bench", "mtu_tuning", "geo_files",
        ],
    },
    "9": {
        "label": "Telegram / Боты / DPI",
        "description": "TG-бот, DPI-детектор, ротация ключей, fingerprint",
        "tests": [
            "tg_bot", "tg_nets", "dpi_detector", "dpi_censor_check",
            "credential_rotation", "user_fp_manager", "fingerprint_manager",
            "subscription", "entry_mirrors",
        ],
    },
    "A": {
        "label": "Утилиты и UI",
        "description": "Box renderer, TUI, admin panel, user portal, ресурсы",
        "tests": [
            "box_renderer", "tui", "admin_panel", "user_portal",
            "resources", "warp", "warp_curated_lists", "hybrid_addon",
            "smart_balancer", "cluster_ops", "as_direct",
            "telemt_fallback", "telemt_ios_fix", "telemt_mss_selector",
            "telemt_panel", "telemt_syn_limiter", "migration",
            "pq_vless", "smoke_test",
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  ЗАПУСК ТЕСТОВ
# ══════════════════════════════════════════════════════════════════════════════

def _run_py_compile() -> tuple[int, int, list[str]]:
    """Проверка синтаксиса всех .py файлов проекта.
    Возвращает (ok_count, fail_count, errors)."""
    ok = 0
    fail = 0
    errors = []
    for py_file in sorted(_PROJECT_ROOT.rglob("*.py")):
        # Пропускаем __pycache__, .git, _vendor (не наш код)
        rel = str(py_file.relative_to(_PROJECT_ROOT))
        if "__pycache__" in rel or ".git" in rel:
            continue
        try:
            import py_compile
            py_compile.compile(str(py_file), doraise=True)
            ok += 1
        except py_compile.PyCompileError as e:
            fail += 1
            errors.append(f"  {rel}: {e}")
    return ok, fail, errors


def _run_test_modules(test_names: list[str]) -> dict:
    """Запускает список тестовых модулей в ИЗОЛИРОВАННОМ САБПРОЦЕССЕ.

    Возвращает dict с результатами (тот же формат что и раньше, чтобы
    _format_report / _run_and_display не менять):
        found: list[str]         — найденные модули
        not_found: list[str]     — ненайденные модули
        tests_run: int           — кол-во запущенных тестов
        failures: int            — кол-во проваленных
        errors: int              — кол-во ошибок
        skipped: int             — кол-во пропущенных
        expected_failures: int   — кол-во ожидаемых провалов
        output: str              — текстовый вывод unittest (для _run_and_display)
        result_obj: object       — pseudo-result с .failures и .errors (list of
                                   (test_name_str, traceback_str) tuples) для
                                   _format_report
        returncode: int          — exit code сабпроцесса

    ИЗОЛЯЦИЯ (фикс регрессии):
      Раньше тесты запускались in-process через unittest.TestLoader.
      Каждый test-файл в setUp() делал sys.modules["vless_installer._core"]
      = types.ModuleType(...) БЕЗ tearDown. В pytest-процессе это безопасно
      (процесс завершается), но при запуске из живого TUI подмена оставалась
      навсегда — module-level state (PROGRESS, INSTALL_START_TIME, TOTAL_RAM,
      BANNER) пересоздавался.

      Теперь тесты запускаются в отдельном процессе через
      `sys.executable -m unittest tests.test_xxx tests.test_yyy ...`.
      Сабпроцесс имеет свой собственный sys.modules — любые подмены
      остаются в нём и не влияют на родительский процесс TUI.
    """
    not_found = []
    found = []
    test_paths = []

    for name in test_names:
        test_file = _TESTS_DIR / f"test_{name}.py"
        if not test_file.exists():
            not_found.append(name)
            continue
        test_paths.append(f"tests.test_{name}")
        found.append(name)

    if not test_paths:
        # Нет найденных тестов — возвращаем пустой результат
        return {
            "found": found,
            "not_found": not_found,
            "tests_run": 0,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "output": "",
            "result_obj": _PseudoResult([]),
            "returncode": 0,
        }

    # Запускаем в сабпроцессе.
    # -u: unbuffered (чтобы вывод шёл в реальном времени, но мы всё равно
    #   ждём завершения процесса — это для будущего streaming-режима).
    # -m unittest: запускает unittest как модуль.
    # verbosity 2: показывает каждый тест по имени + результат.
    cmd = [sys.executable, "-u", "-m", "unittest", "-v"] + test_paths

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(_PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=600,  # 10 минут максимум на группу
        )
        output = proc.stdout + proc.stderr
        returncode = proc.returncode
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or "") + (e.stderr or "") if isinstance(e.stdout, str) else ""
        output += "\n\nTIMEOUT: тесты превысили 10-минутный лимит\n"
        returncode = 124
    except Exception as e:
        output = f"Не удалось запустить сабпроцесс: {e}\n"
        returncode = 1

    # Парсим вывод unittest чтобы извлечь статистику и список проваленных тестов.
    stats, failures_list, errors_list = _parse_unittest_output(output, found)

    return {
        "found": found,
        "not_found": not_found,
        "tests_run": stats["tests_run"],
        "failures": stats["failures"],
        "errors": stats["errors"],
        "skipped": stats["skipped"],
        "expected_failures": stats["expected_failures"],
        "output": output,
        "result_obj": _PseudoResult(failures_list + errors_list,
                                    failures_list, errors_list),
        "returncode": returncode,
    }


class _PseudoResult:
    """Pseudo-result объект, имитирующий unittest.TestResult интерфейс.

    Нужен чтобы _format_report и _run_and_display (которые обращаются к
    result.failures и result.errors как к list of (test, traceback) tuples)
    продолжали работать без изменений.

    Атрибуты:
      failures: list[tuple[str, str]]  — (test_name, traceback)
      errors:   list[tuple[str, str]]  — (test_name, traceback)
    """

    def __init__(self, combined: list, failures: list = None, errors: list = None):
        # Для обратной совместимости: если передан только combined, используем
        # его для обоих (старый код использовал result.failures + result.errors)
        self._combined = combined
        self.failures = failures if failures is not None else combined
        self.errors = errors if errors is not None else []


# Regex для парсинга итоговой строки unittest:
#   Ran 42 tests in 0.123s
_RE_RAN = re.compile(r'^Ran\s+(\d+)\s+tests?\s+in\s+([\d.]+)s', re.MULTILINE)
# Regex для парсинга строки результата:
#   OK
#   FAILED (failures=2, errors=1, skipped=3, expected failures=1)
_RE_RESULT = re.compile(
    r'^(OK|FAILED)\s*(?:\(([^)]*)\))?',
    re.MULTILINE
)


def _parse_unittest_output(output: str, found_modules: list[str]) -> tuple[dict, list, list]:
    """Парсит вывод unittest -v.

    Возвращает (stats_dict, failures_list, errors_list) где:
      stats_dict: {tests_run, failures, errors, skipped, expected_failures}
      failures_list: list[tuple[str, str]] — (test_name, traceback) для FAILED
      errors_list:   list[tuple[str, str]] — (test_name, traceback) для ERRORS
    """
    stats = {
        "tests_run": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
    }

    # 1) "Ran N tests in X.Ys"
    m = _RE_RAN.search(output)
    if m:
        stats["tests_run"] = int(m.group(1))

    # 2) "OK" или "FAILED (failures=X, errors=Y, skipped=Z, expected failures=W)"
    m = _RE_RESULT.search(output)
    if m:
        status = m.group(1)
        details = m.group(2) or ""
        if status == "FAILED":
            # Парсим "failures=2, errors=1, skipped=3, expected failures=1"
            for kv in details.split(","):
                kv = kv.strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    try:
                        v_int = int(v)
                    except ValueError:
                        continue
                    if k == "failures":
                        stats["failures"] = v_int
                    elif k == "errors":
                        stats["errors"] = v_int
                    elif k == "skipped":
                        stats["skipped"] = v_int
                    elif k == "expected failures":
                        stats["expected_failures"] = v_int
        # OK — все нули (уже инициализированы)

    # 3) Извлекаем список проваленных тестов и ошибок.
    # unittest -v выводит для каждого теста строку вида:
    #   test_method (tests.test_xxx.TestClass) ... ok
    #   test_method (tests.test_xxx.TestClass) ... FAIL
    #   test_method (tests.test_xxx.TestClass) ... ERROR
    # А затем блоки:
    #   ======================================================================
    #   FAIL: test_method (tests.test_xxx.TestClass)
    #   ----------------------------------------------------------------------
    #   Traceback (most recent call last):
    #     ...
    #
    #   ======================================================================
    #   ERROR: test_method (tests.test_xxx.TestClass)
    #   ...
    failures_list = _extract_failures_or_errors(output, "FAIL")
    errors_list = _extract_failures_or_errors(output, "ERROR")

    # Подстраховка: если парсинг деталей не сработал, используем длины списков
    if stats["failures"] == 0 and failures_list:
        stats["failures"] = len(failures_list)
    if stats["errors"] == 0 and errors_list:
        stats["errors"] = len(errors_list)

    return stats, failures_list, errors_list


def _extract_failures_or_errors(output: str, kind: str) -> list[tuple[str, str]]:
    """Извлекает из вывода unittest блоки FAIL: или ERROR:.

    Возвращает list of (test_name, traceback) tuples.

    Формат вывода unittest -v:
        ======================================================================
        FAIL: test_name (tests.test_xxx.TestClass.test_method)
        ----------------------------------------------------------------------
        Traceback (most recent call last):
          File "...", line N, in test_method
            ...
        AssertionError: ...

        ======================================================================
        ERROR: test_name (tests.test_xxx.TestClass.test_method)
        ----------------------------------------------------------------------
        Traceback (most recent call last):
          ...

        ----------------------------------------------------------------------
        Ran N tests in X.Ys

    Блок заканчивается либо следующим `====*` (начало следующего FAIL/ERROR),
    либо `----*` (разделитель перед итоговой строкой "Ran N tests").
    """
    result = []
    # Pattern: "====*\nKIND: test_name\n----*\n<traceback>\n(?====*|----*)"
    # Используем lookahead чтобы не "съедать" разделитель следующего блока.
    pattern = re.compile(
        r'={70,}\n' + kind + r': (.+?)\n' + r'-{70,}\n(.*?)\n(?=={70,}|-{70,})',
        re.DOTALL
    )
    for m in pattern.finditer(output):
        test_name = m.group(1).strip()
        traceback = m.group(2).strip()
        result.append((test_name, traceback))
    return result


def _format_report(group_label: str, stats: dict, duration: float) -> str:
    """Форматирует отчёт для лог-файла."""
    lines = [
        f"{'=' * 70}",
        f"VLESS Test Report — {group_label}",
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Duration: {duration:.1f}s",
        f"{'=' * 70}",
        "",
        f"Modules found:     {len(stats['found'])}",
        f"Modules not found: {len(stats['not_found'])}",
        f"Tests run:         {stats['tests_run']}",
        f"Failures:          {stats['failures']}",
        f"Errors:            {stats['errors']}",
        f"Skipped:           {stats['skipped']}",
        f"Expected failures: {stats['expected_failures']}",
        "",
    ]

    if stats["not_found"]:
        lines.append("Not found:")
        for name in stats["not_found"]:
            lines.append(f"  - test_{name}.py")
        lines.append("")

    if stats["failures"] > 0 or stats["errors"] > 0:
        lines.append("FAILED TESTS:")
        result = stats["result_obj"]
        for test, traceback in result.failures + result.errors:
            lines.append(f"  ✗ {test}")
            # Первые 5 строк traceback для контекста
            for tb_line in traceback.strip().splitlines()[:5]:
                lines.append(f"    {tb_line}")
            lines.append("")
    else:
        lines.append("All tests passed ✅")
        lines.append("")

    lines.append(f"{'=' * 70}")
    lines.append("")
    return "\n".join(lines)


def _save_report(report_text: str) -> Path:
    """Дописывает отчёт в лог-файл."""
    try:
        _REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _REPORT_FILE.open("a") as f:
            f.write(report_text)
    except Exception:
        pass
    return _REPORT_FILE


# ══════════════════════════════════════════════════════════════════════════════
#  TUI
# ══════════════════════════════════════════════════════════════════════════════

def _get_colors():
    """Получает цвета из _core, с fallback на пустые строки."""
    try:
        import importlib
        core = importlib.import_module("vless_installer._core")
        return {
            "RED": core.RED, "GREEN": core.GREEN, "YELLOW": core.YELLOW,
            "CYAN": core.CYAN, "BLUE": core.BLUE, "DIM": core.DIM,
            "BOLD": core.BOLD, "NC": core.NC,
        }
    except Exception:
        return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD", "NC")}


def do_test_runner_menu() -> None:
    """TUI-меню запуска диагностических тестов."""
    c = _get_colors()
    RED, GREEN, YELLOW, CYAN, DIM, BOLD, NC = (
        c["RED"], c["GREEN"], c["YELLOW"], c["CYAN"], c["DIM"], c["BOLD"], c["NC"]
    )

    _BOX_W = 66

    def _box_top(title: str = "") -> None:
        print(f"  {CYAN}╔{'═' * _BOX_W}╗{NC}")
        if title:
            pad = _BOX_W - len(title)
            lpad = pad // 2
            rpad = pad - lpad
            print(f"  {CYAN}║{NC}{' ' * lpad}{BOLD}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
            print(f"  {CYAN}╠{'═' * _BOX_W}║{NC}")

    def _box_sep() -> None:
        print(f"  {CYAN}╠{'═' * _BOX_W}║{NC}")

    def _box_bot() -> None:
        print(f"  {CYAN}╚{'═' * _BOX_W}╝{NC}")

    def _box_row(text: str = "") -> None:
        # Обрезаем длинный текст
        plain = text
        # Убираем ANSI для расчёта ширины
        import re as _re
        clean = _re.sub(r'\033\[[0-9;]*m', '', plain)
        w = len(clean)
        if w > _BOX_W:
            clean = clean[:_BOX_W - 1] + "…"
            w = len(clean)
        pad = max(0, _BOX_W - w)
        print(f"  {CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

    def _box_item(key: str, label: str) -> None:
        col = RED + BOLD if key.strip().upper() in ("Q", "0") else CYAN + BOLD
        _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

    while True:
        os.system("clear")
        print()
        _box_top("🧪  ДИАГНОСТИЧЕСКИЕ ТЕСТЫ")
        _box_row()
        _box_row(f"  {DIM}Запуск unit-тестов проекта. Тесты используют mock/tempfile{NC}")
        _box_row(f"  {DIM}и НЕ меняют систему. Результаты сохраняются в лог.{NC}")
        _box_sep()

        # Группы тестов
        for key, group in TEST_GROUPS.items():
            count = len(group["tests"])
            label = group["label"]
            desc = group["description"]
            _box_item(key, f"{BOLD}{label}{NC} ({count} модулей)")
            # description может содержать \n для длинных списков —
            # каждая строка выводится как отдельная _box_row
            for desc_line in desc.split("\n"):
                _box_row(f"       {DIM}{desc_line}{NC}")

        _box_sep()
        # Все тесты — используем [T] (не [A], т.к. [A] занят группой "Утилиты и UI")
        total = sum(len(g["tests"]) for g in TEST_GROUPS.values())
        _box_item("T", f"{BOLD}Все тесты{NC} ({total} модулей)")
        _box_row(f"       {DIM}Полный прогон всех групп{NC}")
        _box_item("0", f"py_compile — проверка синтаксиса всех .py")
        _box_row(f"       {DIM}Быстрая проверка без запуска тестов{NC}")
        _box_row()
        _box_item("Q", "← Назад")
        _box_bot()
        print()

        try:
            choice = input(f"  {CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if choice in ("q", ""):
            return

        if choice == "0":
            _run_py_compile_menu(c)
            continue

        if choice == "t":
            # Все тесты
            all_tests = []
            for group in TEST_GROUPS.values():
                all_tests.extend(group["tests"])
            _run_and_display("Все тесты", all_tests, c)
            continue

        if choice in TEST_GROUPS:
            group = TEST_GROUPS[choice]
            _run_and_display(group["label"], group["tests"], c)
            continue

        print(f"\n  {YELLOW}Неверный выбор.{NC}")
        time.sleep(1)


def _run_py_compile_menu(c: dict) -> None:
    """Запуск py_compile и отображение результатов."""
    GREEN, RED, YELLOW, DIM, NC = c["GREEN"], c["RED"], c["YELLOW"], c["DIM"], c["NC"]

    print(f"\n  {DIM}Проверка синтаксиса всех .py файлов...{NC}\n")
    ok, fail, errors = _run_py_compile()

    if fail == 0:
        print(f"  {GREEN}✅ Все {ok} файлов прошли проверку синтаксиса.{NC}")
    else:
        print(f"  {RED}❌ {fail} файлов с ошибками синтаксиса:{NC}")
        for err in errors:
            print(f"  {RED}{err}{NC}")

    report = (f"{'=' * 70}\n"
              f"py_compile Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"{'=' * 70}\n"
              f"Files checked: {ok + fail}\n"
              f"OK: {ok}\n"
              f"Failed: {fail}\n")
    if errors:
        report += "\nErrors:\n" + "\n".join(errors) + "\n"
    report += f"{'=' * 70}\n\n"
    _save_report(report)

    print(f"\n  {DIM}Отчёт: {_REPORT_FILE}{NC}")
    input(f"\n  {CYAN}Нажмите Enter...{NC}")


def _run_and_display(group_label: str, test_names: list[str], c: dict) -> None:
    """Запускает тесты, показывает результаты, сохраняет отчёт."""
    GREEN, RED, YELLOW, CYAN, DIM, BOLD, NC = (
        c["GREEN"], c["RED"], c["YELLOW"], c["CYAN"], c["DIM"], c["BOLD"], c["NC"]
    )

    print(f"\n  {DIM}Запуск тестов: {group_label}...{NC}\n")
    print(f"  {'─' * 60}")

    start_time = time.time()
    stats = _run_test_modules(test_names)
    duration = time.time() - start_time

    # Выводим результаты по каждому модулю
    output = stats["output"]
    # Парсим output для краткого отображения
    for line in output.splitlines():
        if "..." in line and ("ok" in line or "FAIL" in line or "ERROR" in line
                               or "expected failure" in line or "skipped" in line):
            # Краткая строка результата
            if "ok" in line.lower():
                print(f"  {GREEN}{line.strip()}{NC}")
            elif "FAIL" in line:
                print(f"  {RED}{line.strip()}{NC}")
            elif "ERROR" in line:
                print(f"  {RED}{line.strip()}{NC}")
            elif "expected failure" in line:
                print(f"  {YELLOW}{line.strip()}{NC}")
            elif "skipped" in line:
                print(f"  {DIM}{line.strip()}{NC}")
            else:
                print(f"  {line.strip()}")

    print(f"  {'─' * 60}")

    # Итоговая строка
    total = stats["tests_run"]
    failures = stats["failures"]
    errors = stats["errors"]
    skipped = stats["skipped"]
    exp_fail = stats["expected_failures"]
    not_found = stats["not_found"]

    if failures == 0 and errors == 0:
        print(f"\n  {GREEN}✅ {group_label}: {total} тестов, все прошли"
              f" ({duration:.1f}s){NC}")
    else:
        print(f"\n  {RED}❌ {group_label}: {total} тестов, "
              f"{failures} провалено, {errors} ошибок ({duration:.1f}s){NC}")

        # Показываем проваленные тесты
        result = stats["result_obj"]
        if result.failures:
            print(f"\n  {RED}FAILED:{NC}")
            for test, _ in result.failures:
                print(f"    {RED}✗ {test}{NC}")
        if result.errors:
            print(f"\n  {RED}ERRORS:{NC}")
            for test, _ in result.errors:
                print(f"    {RED}✗ {test}{NC}")

    if not_found:
        print(f"\n  {YELLOW}⚠ Файлы не найдены:{NC}")
        for name in not_found:
            print(f"    {YELLOW}test_{name}.py{NC}")

    if skipped > 0:
        print(f"  {DIM}Пропущено: {skipped}{NC}")
    if exp_fail > 0:
        print(f"  {DIM}Ожидаемых провалов: {exp_fail}{NC}")

    # Сохраняем отчёт
    report = _format_report(group_label, stats, duration)
    _save_report(report)
    print(f"\n  {DIM}Отчёт: {_REPORT_FILE}{NC}")

    input(f"\n  {CYAN}Нажмите Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API (для вызова из _core.py)
# ══════════════════════════════════════════════════════════════════════════════

def run_tests_cli(group: str = "all") -> int:
    """CLI-запуск тестов (для cron/скриптов).
    group: 'all' или ключ из TEST_GROUPS ('1'-'9') или 'compile'.
    Возвращает 0 при успехе, 1 при провале."""
    if group == "compile":
        ok, fail, _ = _run_py_compile()
        return 0 if fail == 0 else 1

    if group == "all":
        all_tests = []
        for g in TEST_GROUPS.values():
            all_tests.extend(g["tests"])
        test_names = all_tests
        label = "Все тесты"
    elif group in TEST_GROUPS:
        test_names = TEST_GROUPS[group]["tests"]
        label = TEST_GROUPS[group]["label"]
    else:
        print(f"Unknown group: {group}")
        return 1

    start = time.time()
    stats = _run_test_modules(test_names)
    duration = time.time() - start

    report = _format_report(label, stats, duration)
    print(report)
    _save_report(report)

    return 0 if stats["failures"] == 0 and stats["errors"] == 0 else 1


if __name__ == "__main__":
    import sys
    group = sys.argv[1] if len(sys.argv) > 1 else "all"
    sys.exit(run_tests_cli(group))
