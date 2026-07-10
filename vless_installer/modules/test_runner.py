"""
vless_installer/modules/test_runner.py
───────────────────────────────────────────────────────────────────────────────
TUI-интерфейс для запуска unit-тестов из главного меню установщика.

Группирует 122 тестовых файла в 10 логических категорий, соответствующих
разделам главного меню. Запускает тесты через unittest.TextTestRunner,
формирует отчёт в /var/log/vless-test-report.log.

Безопасность: тесты используют mock/tempfile, НЕ меняют систему.
"""
from __future__ import annotations

import io
import os
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
        "description": "MTProto, NaiveProxy, WDTT, Turnable, TurnTunnel, SlipGate, WebDAV, FPTN, olcRTC",
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
    """Запускает список тестовых модулей через unittest.
    Возвращает dict с результатами."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    not_found = []
    found = []

    for name in test_names:
        module_path = f"tests.test_{name}"
        try:
            # Проверяем что модуль существует
            test_file = _TESTS_DIR / f"test_{name}.py"
            if not test_file.exists():
                not_found.append(name)
                continue
            module_tests = loader.loadTestsFromName(module_path)
            suite.addTest(module_tests)
            found.append(name)
        except Exception:
            not_found.append(name)

    # Запускаем
    buf = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=2, descriptions=True)
    result = runner.run(suite)

    return {
        "found": found,
        "not_found": not_found,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(getattr(result, "expectedFailures", [])),
        "output": buf.getvalue(),
        "result_obj": result,
    }


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

    while True:
        os.system("clear")
        print()
        print(f"  {BOLD}{CYAN}🧪  ДИАГНОСТИЧЕСКИЕ ТЕСТЫ{NC}")
        print()
        print(f"  {DIM}Запуск unit-тестов проекта. Тесты используют mock/tempfile{NC}")
        print(f"  {DIM}и НЕ меняют систему. Результаты сохраняются в лог.{NC}")
        print()

        # Подсчитываем тесты в каждой группе
        for key, group in TEST_GROUPS.items():
            count = len(group["tests"])
            label = group["label"]
            desc = group["description"]
            print(f"  {CYAN}[{key}]{NC}  {BOLD}{label}{NC} ({count} модулей)")
            print(f"       {DIM}{desc}{NC}")
            print()

        print(f"  {CYAN}[A]{NC}  {BOLD}Все тесты{NC} ({sum(len(g['tests']) for g in TEST_GROUPS.values())} модулей)")
        print(f"       {DIM}Полный прогон всех групп{NC}")
        print()
        print(f"  {CYAN}[0]{NC}  py_compile — проверка синтаксиса всех .py")
        print(f"       {DIM}Быстрая проверка без запуска тестов{NC}")
        print()
        print(f"  {DIM}[Q]{NC}  ← Назад")
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

        if choice == "a":
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
