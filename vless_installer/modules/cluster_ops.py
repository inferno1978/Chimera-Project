"""
vless_installer/modules/cluster_ops.py
───────────────────────────────────────────────────────────────────────────────
Мультисерверное управление Exit Nodes из Entry Node по SSH.

Зачем: Режим B поддерживает до 10 exit-нод, но для управления каждой нодой
нужно заходить по SSH отдельно. Этот модуль позволяет с Entry Node применять
изменения на всех Exit Nodes одной командой.

Операции:
  • Диагностика  — systemctl status xray + xray -test
  • Перезапуск   — systemctl restart xray
  • Обновление   — скачать latest Xray-core с GitHub + atomically заменить
  • Ротация UUID — новый UUID → конфиг на Exit Node → restart
  • Произвольная команда

SSH-доступ: сначала пробуется ключ, при неудаче — запрос пароля (sshpass).
Ноды читаются из /var/lib/xray-installer/state.json → chain_nodes.

Точка входа из _core.py:
    from vless_installer.modules.cluster_ops import do_cluster_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import json
import shutil
import subprocess
import sys
import time
import uuid as _uuid_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE  = Path('/var/lib/xray-installer/state.json')
_SSH_TIMEOUT = 30
_CONN_TIMEOUT = 10


# ── Типы данных ───────────────────────────────────────────────────────────────
@dataclass
class NodeResult:
    host: str
    ok: bool
    output: str = ''
    error: str = ''
    duration: float = 0.0


# ── SSH-аутентификация ────────────────────────────────────────────────────────
def _find_ssh_key() -> Optional[str]:
    for cand in ('~/.ssh/id_ed25519', '~/.ssh/id_rsa', '~/.ssh/id_ecdsa'):
        p = Path(cand).expanduser()
        if p.exists():
            return str(p)
    return None


def _has_sshpass() -> bool:
    return shutil.which('sshpass') is not None


def _ssh_base_opts() -> list[str]:
    """Базовые SSH-опции без ключа и без BatchMode."""
    return [
        'ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', f'ConnectTimeout={_CONN_TIMEOUT}',
        '-o', 'LogLevel=ERROR',
        '-o', 'UserKnownHostsFile=/dev/null',
    ]


def _ssh_opts_key(ssh_key: Optional[str] = None) -> list[str]:
    """SSH-опции для ключевой аутентификации (BatchMode=yes)."""
    opts = _ssh_base_opts() + ['-o', 'BatchMode=yes']
    key = ssh_key or _find_ssh_key()
    if key:
        opts += ['-i', key]
    return opts


def _ssh_opts_pass() -> list[str]:
    """SSH-опции для парольной аутентификации (без BatchMode)."""
    opts = _ssh_base_opts() + [
        '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no',
    ]
    return opts


def _ssh(host: str, cmd: str, ssh_key: Optional[str] = None,
         password: Optional[str] = None,
         timeout: int = _SSH_TIMEOUT) -> tuple[bool, str, str]:
    """
    Выполняет команду на хосте. Возвращает (ok, stdout, stderr).

    Порядок аутентификации:
      1. Если передан password — sshpass с парольной аутентификацией.
      2. Иначе — ключевая аутентификация (BatchMode=yes).
    """
    if password:
        if not _has_sshpass():
            return False, '', 'sshpass не установлен (apt install sshpass)'
        full = ['sshpass', '-p', password, *_ssh_opts_pass(), f'root@{host}', cmd]
    else:
        full = [*_ssh_opts_key(ssh_key), f'root@{host}', cmd]

    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, '', f'timeout {timeout}s'
    except FileNotFoundError as e:
        return False, '', f'{e.filename} не найден в PATH'
    except Exception as e:
        return False, '', str(e)


def _probe_auth(host: str, ssh_key: Optional[str] = None,
                password: Optional[str] = None) -> tuple[bool, str]:
    """
    Проверяет подключение к ноде. Возвращает (ok, reason).
    Пробует ключ (если есть), потом пароль (если задан).
    """
    # Сначала ключ
    key = ssh_key or _find_ssh_key()
    if key:
        ok, out, err = _ssh(host, 'echo ok', ssh_key=key, timeout=15)
        if ok and 'ok' in out:
            return True, ''

    # Потом пароль
    if password:
        ok, out, err = _ssh(host, 'echo ok', password=password, timeout=15)
        if ok and 'ok' in out:
            return True, ''
        return False, err or 'неверный пароль'

    return False, 'нет ключа и пароль не задан'


# ── Управление паролем в сессии ───────────────────────────────────────────────
_session_password: Optional[str] = None


def _ensure_sshpass_installed() -> bool:
    """Устанавливает sshpass если отсутствует. Возвращает True при успехе."""
    if _has_sshpass():
        return True
    from vless_installer._core import _box_row
    _box_row(f"  {YELLOW}Установка sshpass...{NC}")
    r = subprocess.run(['apt-get', 'install', '-y', 'sshpass'],
                       capture_output=True, text=True)
    if r.returncode == 0:
        _box_row(f"  {GREEN}sshpass установлен.{NC}")
        return True
    _box_row(f"  {RED}Не удалось установить sshpass: {r.stderr[:80]}{NC}")
    return False


def _ask_password(nodes: list[dict]) -> Optional[str]:
    """
    Запрашивает пароль root у пользователя (один раз на сессию).
    Проверяет пароль на первой ноде. Возвращает пароль или None при отмене.
    """
    global _session_password
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom,
    )

    if _session_password is not None:
        return _session_password

    # Проверяем, работает ли ключевая аутентификация хотя бы на одной ноде
    key = _find_ssh_key()
    if key and nodes:
        h = nodes[0].get('host', '')
        if h:
            ok, _, _ = _ssh(h, 'echo ok', ssh_key=key, timeout=10)
            if ok:
                # Ключ работает — пароль не нужен
                return None

    # Ключ не работает — запрашиваем пароль
    _box_top("🔑  SSH — АУТЕНТИФИКАЦИЯ ПО ПАРОЛЮ")
    _box_row(f"  {YELLOW}Ключевая аутентификация недоступна.{NC}")
    _box_row(f"  Введите пароль root для нод.")
    _box_row(f"  {DIM}(пароль запрашивается один раз за сессию){NC}")
    if not _has_sshpass():
        _box_row(f"  {CYAN}Потребуется установить sshpass.{NC}")
    _box_sep()
    _box_row(f"  {DIM}Оставьте пустым для отмены.{NC}")
    _box_bottom()

    try:
        pwd = getpass.getpass(f'{CYAN}Пароль root:{NC} ')
    except (EOFError, KeyboardInterrupt):
        return None

    if not pwd:
        return None

    if not _ensure_sshpass_installed():
        return None

    # Проверяем пароль на первой ноде
    if nodes:
        h = nodes[0].get('host', '')
        if h:
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top("🔍  ПРОВЕРКА ПАРОЛЯ")
            _box_row(f"  {CYAN}Проверка на {h}...{NC}")
            _box_bottom()
            ok, out, err = _ssh(h, 'echo ok', password=pwd, timeout=15)
            if not ok:
                from vless_installer._core import _box_top, _box_row, _box_bottom
                _box_top("❌  ОШИБКА ПАРОЛЯ")
                _box_row(f"  {RED}Не удалось подключиться:{NC}")
                _box_row(f"  {RED}{err[:60]}{NC}")
                _box_bottom()
                try:
                    input(f'{CYAN}Нажмите Enter...{NC}')
                except (EOFError, KeyboardInterrupt):
                    pass
                return None

    _session_password = pwd
    return pwd


def _get_ssh_creds(nodes: list[dict]) -> tuple[Optional[str], Optional[str]]:
    """
    Возвращает (ssh_key, password) для использования в операциях.
    Ключ имеет приоритет. Если ключ не работает — запрашивает пароль.
    """
    key = _find_ssh_key()
    if key and nodes:
        h = nodes[0].get('host', '')
        if h:
            ok, _, _ = _ssh(h, 'echo ok', ssh_key=key, timeout=10)
            if ok:
                return key, None

    pwd = _ask_password(nodes)
    return None, pwd


# ── Операции ──────────────────────────────────────────────────────────────────
def op_diagnostics(host: str, ssh_key: Optional[str] = None,
                   password: Optional[str] = None) -> NodeResult:
    """Статус Xray + xray -test на удалённой ноде."""
    t0 = time.monotonic()
    lines = []
    ok_overall = True
    for cmd in (
        'systemctl is-active xray',
        'xray version 2>/dev/null | head -1',
        '/usr/local/bin/xray run -test -config /etc/xray/config.json 2>&1 | tail -2',
        'journalctl -u xray -n 3 --no-pager 2>/dev/null',
    ):
        ok, out, err = _ssh(host, cmd, ssh_key=ssh_key, password=password, timeout=90)
        if out:
            lines.append(out)
        if cmd.startswith('systemctl') and out != 'active':
            ok_overall = False
    return NodeResult(host=host, ok=ok_overall,
                      output='\n'.join(lines), duration=time.monotonic() - t0)


def op_restart(host: str, ssh_key: Optional[str] = None,
               password: Optional[str] = None) -> NodeResult:
    """Перезапускает Xray и ждёт active."""
    t0 = time.monotonic()
    ok, out, err = _ssh(
        host,
        'systemctl restart xray && sleep 5 && systemctl is-active xray',
        ssh_key=ssh_key, password=password, timeout=60,
    )
    return NodeResult(host=host, ok=ok and 'active' in (out or ''),
                      output=out, error=err, duration=time.monotonic() - t0)


def op_update_xray(host: str, ssh_key: Optional[str] = None,
                   password: Optional[str] = None) -> NodeResult:
    """Скачивает и устанавливает latest Xray-core, откатывает при неудаче."""
    t0 = time.monotonic()
    script = (
        "bash -c '"
        "set -e; "
        "BIN=/usr/local/bin/xray; "
        "ARCH=$(uname -m); "
        "case $ARCH in x86_64) A=64;; aarch64) A=arm64-v8a;; armv7l) A=arm32-v7a;; "
        "  *) echo unsupported arch $ARCH; exit 1;; esac; "
        "LATEST=$(curl -sf https://api.github.com/repos/XTLS/Xray-core/releases/latest "
        "  | python3 -c \"import sys,json; print(json.load(sys.stdin)[\\\"tag_name\\\"])\"); "
        "[[ -z $LATEST ]] && { echo cannot fetch latest version; exit 1; }; "
        "CURRENT=$($BIN version 2>/dev/null | awk \"{print \\$2}\" | head -1); "
        "echo current=$CURRENT latest=$LATEST; "
        "[[ \"v$CURRENT\" == \"$LATEST\" ]] && { echo already up to date; exit 0; }; "
        "TMP=$(mktemp -d); "
        "URL=https://github.com/XTLS/Xray-core/releases/download/$LATEST/Xray-linux-$A.zip; "
        "curl -sL $URL -o $TMP/xray.zip; "
        "cd $TMP && unzip -q xray.zip; "
        "cp $BIN ${BIN}.bak; "
        "cp xray $BIN && chmod +x $BIN; "
        "systemctl restart xray && sleep 5; "
        "systemctl is-active xray || { cp ${BIN}.bak $BIN; systemctl restart xray; "
        "  echo ROLLBACK; exit 1; }; "
        "echo updated to $LATEST; "
        "rm -rf $TMP; "
        "'"
    )
    ok, out, err = _ssh(host, script, ssh_key=ssh_key, password=password, timeout=180)
    return NodeResult(host=host, ok=ok, output=out, error=err,
                      duration=time.monotonic() - t0)


def op_rotate_uuid(host: str, ssh_key: Optional[str] = None,
                   password: Optional[str] = None) -> NodeResult:
    """
    Ротирует UUID клиентов в конфиге на Exit Node.
    Возвращает новый UUID в output для обновления Entry Node.
    """
    t0 = time.monotonic()
    new_uuid = str(_uuid_mod.uuid4())
    py = (
        f"python3 -c \""
        f"import json; p='/etc/xray/config.json'; c=json.load(open(p)); "
        f"[s.update({{'id':'{new_uuid}'}}) "
        f" for ib in c.get('inbounds',[]) "
        f" for s in ib.get('settings',{{}}).get('clients',[])]; "
        f"open(p,'w').write(json.dumps(c,indent=2)); "
        f"print('uuid_updated:{new_uuid}')"
        f"\""
    )
    ok1, out1, err1 = _ssh(host, py, ssh_key=ssh_key, password=password, timeout=30)
    if not ok1 or 'uuid_updated' not in out1:
        return NodeResult(host=host, ok=False, output=out1,
                          error=f'UUID замена не удалась: {err1[:200]}',
                          duration=time.monotonic() - t0)
    ok2, out2, err2 = _ssh(
        host,
        'systemctl restart xray && sleep 5 && systemctl is-active xray',
        ssh_key=ssh_key, password=password, timeout=60,
    )
    return NodeResult(host=host, ok=ok2 and 'active' in (out2 or ''),
                      output=f'new_uuid={new_uuid}\n{out2}',
                      error=err2, duration=time.monotonic() - t0)


def op_custom(host: str, cmd: str,
              ssh_key: Optional[str] = None,
              password: Optional[str] = None) -> NodeResult:
    """Произвольная команда на ноде."""
    t0 = time.monotonic()
    ok, out, err = _ssh(host, cmd, ssh_key=ssh_key, password=password, timeout=120)
    return NodeResult(host=host, ok=ok, output=out, error=err,
                      duration=time.monotonic() - t0)


# ── Параллельное применение ───────────────────────────────────────────────────
def cluster_run(
    nodes: list[dict],
    op_fn: Callable,
    parallel: bool = True,
    password: Optional[str] = None,
    **kwargs,
) -> dict[str, NodeResult]:
    """
    Применяет op_fn(host, ssh_key, password, **kwargs) ко всем нодам.
    parallel=True — ThreadPoolExecutor (макс 5 воркеров).
    Возвращает {host: NodeResult}.
    """
    results: dict[str, NodeResult] = {}
    if parallel:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        futures: dict = {}
        with ThreadPoolExecutor(max_workers=min(len(nodes), 5)) as pool:
            for nd in nodes:
                h = nd.get('host', '')
                if not h:
                    continue
                key = nd.get('ssh_key') or _find_ssh_key()
                futures[pool.submit(op_fn, h, key, password, **kwargs)] = h
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    results[h] = fut.result()
                except Exception as e:
                    results[h] = NodeResult(host=h, ok=False, error=str(e))
    else:
        for nd in nodes:
            h = nd.get('host', '')
            if not h:
                continue
            key = nd.get('ssh_key') or _find_ssh_key()
            try:
                results[h] = op_fn(h, key, password, **kwargs)
            except Exception as e:
                results[h] = NodeResult(host=h, ok=False, error=str(e))
    return results


# ── Загрузка нод из state.json ────────────────────────────────────────────────
def load_exit_nodes() -> list[dict]:
    """
    Читает Exit Nodes из state.json.
    Поддерживает chain_nodes (новый) и chain_exit_host (legacy).
    """
    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        print(f'  {RED}Не удалось прочитать state.json: {e}{NC}')
        return []
    if 'chain_nodes' in state and isinstance(state['chain_nodes'], list):
        return [n for n in state['chain_nodes'] if n.get('host')]
    host = state.get('chain_exit_host', '')
    if host:
        return [{'host': host, 'port': state.get('chain_exit_port', 443)}]
    return []


# ── Вывод результатов ─────────────────────────────────────────────────────────
def _print_results(results: dict[str, NodeResult], title: str = "РЕЗУЛЬТАТ") -> None:
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item,
    )
    ok_n  = sum(1 for r in results.values() if r.ok)
    all_n = len(results)
    color = GREEN if ok_n == all_n else (YELLOW if ok_n > 0 else RED)

    _box_top(f"📊  {title}")
    _box_row(f"  {color}Итог: {ok_n}/{all_n} нод ОК{NC}")
    _box_sep()
    for host, res in sorted(results.items()):
        icon = f'{GREEN}✓{NC}' if res.ok else f'{RED}✗{NC}'
        _box_row(f"  {icon} {BOLD}{host}{NC}  {DIM}({res.duration:.1f}s){NC}")
        for line in (res.output or '').splitlines()[:6]:
            _box_row(f"    {DIM}{line[:68]}{NC}")
        if res.error:
            _box_row(f"    {RED}{res.error[:70]}{NC}")
    _box_bottom()


# ── Проверка SSH-доступа ──────────────────────────────────────────────────────
def _check_ssh(host: str, ssh_key: Optional[str] = None,
               password: Optional[str] = None) -> tuple[bool, str]:
    ok, out, err = _ssh(host, 'echo ok', ssh_key=ssh_key,
                        password=password, timeout=15)
    if ok and 'ok' in out:
        return True, ''
    return False, err or 'нет ответа'


# ── Публичный API — интерактивное меню ───────────────────────────────────────
def do_cluster_menu() -> None:
    """Интерактивное меню мультисерверного управления Exit Nodes."""
    global _session_password
    import os
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    )
    while True:
        os.system('clear')
        nodes = load_exit_nodes()

        _box_top("🌐  КЛАСТЕР — управление Exit Nodes")
        if nodes:
            _box_row(f"  Exit Nodes ({len(nodes)}):")
            for i, nd in enumerate(nodes, 1):
                _box_row(f"    {i}. {nd.get('host','?')}:{nd.get('port',443)}")
            # Показываем режим аутентификации
            _box_sep()
            key = _find_ssh_key()
            if _session_password:
                _box_row(f"  🔑 {DIM}Авт-ция: пароль (сессия){NC}")
            elif key:
                _box_row(f"  🔑 {DIM}Авт-ция: SSH-ключ{NC}")
            else:
                _box_row(f"  {YELLOW}⚠  Нет ключа — потребуется пароль{NC}")
        else:
            _box_row(f"  {YELLOW}Нет Exit Nodes в state.json.{NC}")
            _box_row(f"  {DIM}Добавьте каскадный Режим B{NC}")
            _box_row(f"  {DIM}для появления нод.{NC}")
        _box_sep()
        _box_item("1", "Диагностика всех нод")
        _box_item("2", "Перезапуск Xray на всех нодах")
        _box_item("3", "Обновление Xray-core на всех нодах")
        _box_item("4", "Ротация UUID на всех нодах")
        _box_item("5", "Произвольная команда")
        _box_item("6", "Проверить SSH-доступ")
        _box_item("P", f"Сменить пароль сессии  {DIM}(сейчас: {'задан' if _session_password else 'не задан'}){NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f'{CYAN}Выбор:{NC} ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if not nodes and ch not in ('q', '', 'p'):
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top("⚠️   НЕТ НОД")
            _box_row(f"  {YELLOW}Нет Exit Nodes — нечего делать{NC}")
            _box_bottom()
            time.sleep(1)
            continue

        # Получаем реквизиты SSH перед любой операцией с нодами
        def _get_creds():
            """Возвращает (ssh_key, password). При неудаче — (None, None)."""
            key = _find_ssh_key()
            if _session_password:
                return None, _session_password
            if key:
                # Быстрая проверка ключа на первой ноде
                h = nodes[0].get('host', '') if nodes else ''
                if h:
                    ok, _, _ = _ssh(h, 'echo ok', ssh_key=key, timeout=10)
                    if ok:
                        return key, None
            # Ключ не работает или отсутствует — запрашиваем пароль
            pwd = _ask_password(nodes)
            return None, pwd

        if ch == '1':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            key, pwd = _get_creds()
            if key is None and pwd is None:
                continue
            _box_top(f"🔍  ДИАГНОСТИКА — {len(nodes)} нод")
            _box_row(f"  {CYAN}Выполняется...{NC}")
            _box_bottom()
            _print_results(
                cluster_run(nodes, op_diagnostics, password=pwd),
                "ДИАГНОСТИКА",
            )

        elif ch == '2':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"🔄  ПЕРЕЗАПУСК XRAY — {len(nodes)} нод")
            _box_row(f"  Перезапустить Xray на всех нодах?")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                key, pwd = _get_creds()
                if key is None and pwd is None:
                    continue
                _print_results(
                    cluster_run(nodes, op_restart, password=pwd),
                    "ПЕРЕЗАПУСК",
                )

        elif ch == '3':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"⬆️   ОБНОВЛЕНИЕ XRAY-CORE — {len(nodes)} нод")
            _box_row(f"  {YELLOW}Может занять 2–3 минуты на ноду.{NC}")
            _box_row(f"  Обновить Xray-core на всех нодах?")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                key, pwd = _get_creds()
                if key is None and pwd is None:
                    continue
                _print_results(
                    cluster_run(nodes, op_update_xray, password=pwd),
                    "ОБНОВЛЕНИЕ",
                )

        elif ch == '4':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"🔑  РОТАЦИЯ UUID — {len(nodes)} нод")
            _box_row(f"  {YELLOW}⚠  После ротации обновите{NC}")
            _box_row(f"  {YELLOW}конфиг Entry Node вручную!{NC}")
            _box_row(f"  Новые UUID будут выведены в результатах.")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                key, pwd = _get_creds()
                if key is None and pwd is None:
                    continue
                _print_results(
                    cluster_run(nodes, op_rotate_uuid, parallel=False, password=pwd),
                    "РОТАЦИЯ UUID",
                )
                from vless_installer._core import _box_top, _box_row, _box_bottom
                _box_top("ℹ️   ВАЖНО")
                _box_row(f"  {YELLOW}Скопируйте UUID выше и{NC}")
                _box_row(f"  {YELLOW}обновите конфиг Entry Node.{NC}")
                _box_bottom()

        elif ch == '5':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top("💬  ПРОИЗВОЛЬНАЯ КОМАНДА")
            _box_row(f"  Введите команду для")
            _box_row(f"  выполнения на всех нодах:")
            _box_bottom()
            try:
                cmd = input(f'{CYAN}Команда:{NC} ').strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if cmd:
                key, pwd = _get_creds()
                if key is None and pwd is None:
                    continue
                _print_results(
                    cluster_run(nodes, op_custom, password=pwd, cmd=cmd),
                    f"КОМАНДА: {cmd[:40]}",
                )

        elif ch == '6':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            key, pwd = _get_creds()
            if key is None and pwd is None:
                continue
            _box_top(f"🔐  ПРОВЕРКА SSH — {len(nodes)} нод")
            for nd in nodes:
                h = nd.get('host', '')
                ok, reason = _check_ssh(h, ssh_key=key, password=pwd)
                icon = f'{GREEN}✓{NC}' if ok else f'{RED}✗{NC}'
                if ok:
                    _box_row(f"  {icon} {BOLD}{h}{NC}  {GREEN}OK{NC}")
                else:
                    _box_row(f"  {icon} {BOLD}{h}{NC}")
                    _box_row(f"      {DIM}{reason}{NC}")
            _box_bottom()

        elif ch == 'p':
            # Сброс и повторный ввод пароля
            _session_password = None
            pwd = _ask_password(nodes)
            if pwd:
                from vless_installer._core import _box_top, _box_row, _box_bottom
                _box_top("✅  ПАРОЛЬ СОХРАНЁН")
                _box_row(f"  {GREEN}Пароль задан для текущей сессии.{NC}")
                _box_bottom()
                try:
                    input(f'{CYAN}Нажмите Enter...{NC}')
                except (EOFError, KeyboardInterrupt):
                    pass
            continue

        elif ch in ('q', ''):
            break

        if ch not in ('q', '', 'p'):
            try:
                input(f'{CYAN}Нажмите Enter...{NC}')
            except (EOFError, KeyboardInterrupt):
                pass
