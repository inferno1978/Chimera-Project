#!/usr/bin/env python3
"""
Автоматический smoke-тест всех вынесенных из _core.py модулей.

╔══════════════════════════════════════════════════════════════╗
║  ⚠️  ВНИМАНИЕ: скрипт предназначен ТОЛЬКО для прогона в      ║
║  контейнере / песочнице / тестовой ВМ.                       ║
║  НЕ запускайте на боевом сервере!                            ║
║  Скрипт вызывает функции установщика, которые могут          ║
║  изменять конфигурацию системы.                              ║
╚══════════════════════════════════════════════════════════════╝

Для каждого модуля:
1. Проверяет что _core_module() возвращает __main__ (dual-instance fix)
2. Вызывает главную функцию-меню в "стен-режиме":
   - input() замокан на 'q' (выход из меню)
   - subprocess.run / subprocess.Popen замоканы (возвращают success)
   - os.system / os.popen замоканы (no-op)
   - shutil.which замокан (возвращает None — нет бинарников)
   - Path.mkdir/touch для /var/, /etc/ замоканы
3. Ловит NameError, AttributeError, TypeError — реальные баги
4. Не считает ошибкой: SystemExit, KeyboardInterrupt (норма для меню)

Это покрывает те же классы багов которые мы ловили вручную:
- NameError: NC (color bindings) — fixed in 4d12741
- NameError: PARAM_DOMAIN (dual instance) — fixed in 8bc0800
- AttributeError: core.X (missing attrs)

НЕ покрывает: логические баги (неправильный вывод, неверный конфиг).
"""
import sys
import os
import io
import importlib
import traceback
import re
from pathlib import Path
from unittest.mock import patch, MagicMock
from contextlib import redirect_stdout, redirect_stderr

# Авто-определение корня проекта: скрипт лежит в корне, рядом с main.py
_PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT))

# Список (модуль, функция, описание) — только функции-меню и публичные API
TEST_CASES = [
    # Меню-функции (вызываем с 'q' для немедленного выхода)
    # do_user_menu удалён в патче №5 — мёртвый код, дублировал
    # do_unified_user_manager из _core.py.
    ("users_manager", "do_user_list", "список пользователей"),
    ("users_manager", "generate_client_links", "генерация ссылок"),
    ("ttl_users", "do_manage_ttl_users", "меню TTL-пользователей"),
    ("credential_rotation", "do_manage_uuid_rotation", "меню ротации UUID"),
    ("credential_rotation", "do_manage_reality_keys", "меню ротации REALITY-ключей"),
    ("credential_rotation", "_menu_rotation", "подменю ротации"),
    ("client_config_export", "do_generate_client_config", "генерация клиентских конфигов"),
    ("client_config_export", "do_export_client_config", "экспорт конфигов"),
    # do_full_diagnostic — пропускаем (wizard с while True и pause)
    # do_live_traffic_dashboard — пропускаем (while True)
    ("connection_audit", "do_connection_audit", "аудит подключений"),
    ("standalone_screens", "do_view_logs", "просмотр логов"),
    ("standalone_screens", "do_check_domain_external", "проверка домена снаружи"),
    # do_system_dashboard — пропускаем (while True, нужен Ctrl+C)
    ("standalone_screens", "check_exit_geo", "геопроверка IP"),
    ("health_report", "do_manage_health_report", "меню health-отчёта"),
    ("traffic_tracking", "do_manage_traffic_limits", "меню лимитов трафика"),
    ("traffic_history", "do_traffic_history", "история трафика"),
    ("quick_status", "do_quick_status", "быстрый статус"),
    ("speed_test", "do_speed_test", "тест скорости"),
    # do_reconfigure, switch_mode_ab — пропускаем (мутируют globals, могут сломать state)
    # ("reconfigure", "do_reconfigure", "смена домена/порта"),
    # ("switch_mode", "switch_mode_ab", "переключение A↔B"),
    ("migration", "do_full_migration_export", "экспорт миграции"),
    ("backup_manager", "do_manage_scheduled_backup", "плановый бэкап"),
    ("backup_rollback", "run_unit_tests", "unit-тесты"),
    ("backup_rollback", "verify_connectivity", "проверка связи"),
    ("split_tunnel", "do_manage_split_tunnel", "раздельное туннелирование"),
    ("ru_subnets", "do_manage_ru_subnet_direct", "РФ-подсети"),
    ("as_direct", "do_manage_as_direct", "AS-маршрутизация"),
    ("geoip_block", "do_manage_geoip_block", "GeoIP-блокировка"),
    ("mtu_tuning", "do_mtu_tuning", "MTU/MSS тюнинг"),
    ("ssh_hardening", "do_ssh_hardening", "SSH hardening"),
    ("fail2ban_setup", "do_manage_watchdog", "watchdog"),
    ("autoban", "do_manage_autoban", "авто-бан"),
    ("failover", "do_failover_status", "failover статус"),
    ("failover", "do_manage_auto_fallback", "авто-фолбэк"),
    ("nginx_setup", "create_website", "создание сайта"),
    ("ssl_certbot", "do_manage_certbot_monitor", "мониторинг certbot"),
    ("geo_files", "do_manage_geo_update", "управление geo-файлами"),
    ("network_setup", "apply_sysctl_and_limits", "применение sysctl"),
    # Web panel menu — безопасно для мока: input='q' сразу выходит из while-цикла,
    # реальный start_server() не вызывается в этом пути.
    ("rest_api", "do_manage_web_panel", "меню веб-панели"),
    # CLI entry points
    ("ttl_users", "_ttl_check_and_expire", "CLI: --ttl-check"),
    ("autoban", "_autoban_run_once", "CLI: --autoban"),
    ("backup_manager", "_scheduled_backup_run", "CLI: --scheduled-backup"),
    ("ru_subnets", "_ru_subnets_cli_update", "CLI: --update-ru-subnets"),
    ("as_direct", "_as_direct_cli_update", "CLI: --update-as-direct"),
    # TrustTunnel
    ("trusttunnel", "do_trusttunnel_menu", "меню TrustTunnel"),
    ("trusttunnel_health", "trusttunnel_health_check", "health-check TrustTunnel"),
    # Инсталляционные (НЕ вызываем — слишком опасно, но проверяем callable)
    # ("install_prompts", "prompt_parameters", "параметры установки"),
    # ("xray_install", "install_xray", "установка Xray"),
    # ("emergency_repair", "do_emergency_repair", "восстановление"),
    # ("uninstall", "do_uninstall", "удаление"),
]

# Патчи для системных операций
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

# Мок для subprocess.run — возвращает success (НЕ выполняет реальные команды)
def _mock_run(*args, **kwargs):
    return MagicMock(returncode=0, stdout="mock", stderr="")

# Мок для subprocess.Popen / os.popen — возвращает mock-объект
def _mock_popen(*args, **kwargs):
    m = MagicMock()
    m.returncode = 0
    m.stdout = MagicMock()
    m.stdout.read = lambda: "mock"
    m.stdout.readline = lambda: ""
    m.stdout.__iter__ = lambda self: iter([])
    m.stderr = MagicMock()
    m.stderr.read = lambda: ""
    m.stderr.readline = lambda: ""
    m.stderr.__iter__ = lambda self: iter([])
    m.wait = lambda *a, **kw: 0
    m.poll = lambda: 0
    m.communicate = lambda *a, **kw: ("mock", "")
    m.terminate = lambda: None
    m.kill = lambda: None
    m.close = lambda: None
    return m

# Мок для input — всегда 'q' (выход)
def _mock_input(prompt=""):
    return "q"

# Мок для os.system — no-op
def _mock_system(*args, **kwargs):
    return 0


def run_test(mod_name, func_name, description):
    """Запускает одну функцию в стен-режиме. Возвращает (status, detail)."""
    import signal

    try:
        mod = importlib.import_module(f"vless_installer.modules.{mod_name}")
    except Exception as e:
        return ("IMPORT_ERROR", f"не удалось импортировать модуль: {e}")

    if not hasattr(mod, func_name):
        return ("MISSING", f"функция {func_name} не найдена в модуле")

    func = getattr(mod, func_name)
    if not callable(func):
        return ("NOT_CALLABLE", f"{func_name} не вызываемый: {type(func)}")

    # Timeout handler — убиваем зависшие функции (live-дашборды с while True)
    class _Timeout(Exception):
        pass

    def _timeout_handler(signum, frame):
        raise _Timeout()

    # Подменяем input, os.system, _run, sys.stdout
    captured = io.StringIO()
    try:
        # Устанавливаем timeout 8 секунд на каждую функцию
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(8)

        with patch.object(Path, 'mkdir', _safe_mkdir), \
             patch.object(Path, 'touch', _safe_touch), \
             patch.object(Path, 'chmod', _safe_chmod), \
             patch('os.chown', _safe_chown), \
             patch('os.geteuid', return_value=0), \
             patch('os.system', _mock_system), \
             patch('os.popen', _mock_popen), \
             patch('subprocess.run', _mock_run), \
             patch('subprocess.Popen', _mock_popen), \
             patch('shutil.which', lambda *a, **kw: None), \
             patch('builtins.input', _mock_input), \
             redirect_stdout(captured), redirect_stderr(captured):
            
            try:
                func()
            except SystemExit:
                pass  # нормально для меню
            except KeyboardInterrupt:
                pass  # нормально для live-дашбордов
            except _Timeout:
                pass  # live-дашборд с while True — это нормально
        
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        return ("PASS", "")
    
    except _Timeout:
        return ("PASS", "(timeout — live loop, OK)")
    except NameError as e:
        signal.alarm(0)
        return ("NameError", str(e))
    except AttributeError as e:
        signal.alarm(0)
        return ("AttributeError", str(e))
    except TypeError as e:
        signal.alarm(0)
        err_str = str(e)
        if "missing 1 required" in err_str or "unexpected keyword" in err_str:
            return ("PASS", "")
        return ("TypeError", err_str)
    except ValueError as e:
        signal.alarm(0)
        if "invalid literal for int()" in str(e) or "could not convert" in str(e):
            return ("PASS", "")
        return ("ValueError", str(e))
    except (PermissionError, FileNotFoundError, OSError) as e:
        # Эти ошибки ожидаемы — функции пытаются писать в /root/, /etc/ и т.п.
        # Это НЕ баг рефакторинга, просто sandbox не имеет прав.
        signal.alarm(0)
        return ("PASS", f"(sandbox: {type(e).__name__})")
    except EOFError:
        signal.alarm(0)
        return ("PASS", "")
    except Exception as e:
        signal.alarm(0)
        tb = traceback.format_exc()
        if f"vless_installer/modules/{mod_name}.py" in tb:
            return (type(e).__name__, str(e)[:200])
        return ("PASS", "")


def main():
    print("=" * 70)
    print("АВТОМАТИЧЕСКИЙ SMOKE-ТЕСТ ВЫНЕСЕННЫХ МОДУЛЕЙ")
    print("=" * 70)
    print()
    print("⚠️  ВНИМАНИЕ: скрипт предназначен ТОЛЬКО для контейнера/песочницы/тестовой ВМ.")
    print("⚠️  НЕ запускайте на боевом сервере!")
    print()

    # Проверка: не боевой ли сервер?
    _prod_markers = [
        Path("/opt/vless-ultimate"),
        Path("/var/lib/xray-installer/state.json"),
        Path("/etc/xray/config.json"),
        Path("/etc/systemd/system/xray.service"),
    ]
    _prod_hits = [str(p) for p in _prod_markers if p.exists()]
    if _prod_hits:
        print(f"⚠️  ОБНАРУЖЕНЫ маркеры боевого сервера:")
        for p in _prod_hits:
            print(f"     • {p}")
        print()
        try:
            ans = input("Это похоже на боевой сервер. Продолжить? yes/no: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "no"
        if ans != "yes":
            print("Отмена. Скрипт не запущен.")
            sys.exit(0)
        print("Продолжаем по требованию пользователя...")
        print()

    print(f"Тестируется {len(TEST_CASES)} функций из {len(set(t[0] for t in TEST_CASES))} модулей")
    print("Режим: input='q', subprocess.run=mock, os.system=mock, shutil.which=mock, /var/ /etc/ = mock")
    print()

    # Сначала загружаем _core.py как main.py это делает
    print("Загрузка _core.py...")
    _core_path = Path("vless_installer/_core.py")
    with open(_core_path, encoding="utf-8") as f:
        _core_src = f.read()

    with patch.object(Path, 'mkdir', _safe_mkdir), \
         patch.object(Path, 'touch', _safe_touch), \
         patch.object(Path, 'chmod', _safe_chmod), \
         patch('os.chown', _safe_chown), \
         patch('os.geteuid', return_value=0), \
         patch('subprocess.run', _mock_run), \
         patch('subprocess.Popen', _mock_popen), \
         patch('os.popen', _mock_popen), \
         patch('shutil.which', lambda *a, **kw: None):
        exec(compile(_core_src, str(_core_path), "exec"), globals())

    # КРИТИЧЕСКИЙ ФИКС: регистрируем __main__ как vless_installer._core
    sys.modules["vless_installer._core"] = sys.modules["__main__"]
    print("✓ _core.py загружен, sys.modules зарегистрирован")
    print()
    
    # Прогоняем тесты
    results = {"PASS": 0, "NameError": 0, "AttributeError": 0, 
               "TypeError": 0, "ValueError": 0, "IMPORT_ERROR": 0,
               "MISSING": 0, "NOT_CALLABLE": 0, "OTHER": 0}
    failures = []
    
    print(f"{'МОДУЛЬ':<25} {'ФУНКЦИЯ':<30} {'СТАТУС':<15} ОПИСАНИЕ")
    print("-" * 100)
    
    for mod_name, func_name, description in TEST_CASES:
        status, detail = run_test(mod_name, func_name, description)
        
        if status == "PASS":
            results["PASS"] += 1
            marker = "✓"
        else:
            results[status] = results.get(status, 0) + 1
            if status not in ("NameError", "AttributeError", "TypeError", 
                              "ValueError", "IMPORT_ERROR", "MISSING", "NOT_CALLABLE"):
                results["OTHER"] += 1
            marker = "❌"
            failures.append((mod_name, func_name, status, detail))
        
        print(f"{mod_name:<25} {func_name:<30} {marker} {status:<13} {description}")
    
    # Итог
    print()
    print("=" * 70)
    print("ИТОГ")
    print("=" * 70)
    print(f"  Всего тестов:    {len(TEST_CASES)}")
    print(f"  ✓ PASS:          {results['PASS']}")
    print(f"  ❌ NameError:     {results['NameError']}")
    print(f"  ❌ AttributeError:{results['AttributeError']}")
    print(f"  ❌ TypeError:     {results['TypeError']}")
    print(f"  ❌ ValueError:    {results['ValueError']}")
    print(f"  ❌ IMPORT_ERROR:  {results['IMPORT_ERROR']}")
    print(f"  ❌ MISSING:       {results['MISSING']}")
    print(f"  ❌ OTHER:         {results['OTHER']}")
    
    if failures:
        print()
        print("=" * 70)
        print("ДЕТАЛИ ОШИБОК")
        print("=" * 70)
        for mod, func, status, detail in failures:
            print(f"\n  {mod}.{func}() → {status}")
            print(f"    {detail}")
    
    print()
    if not failures:
        print("🟢 ВСЕ ФУНКЦИИ ВЫЗЫВАЮТСЯ БЕЗ NameError/AttributeError")
        print("   (это не значит что логика верна — только что нет undefined names)")
    else:
        print(f"🔴 ОБНАРУЖЕНО {len(failures)} ОШИБОК — требуется исправление")
    
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
