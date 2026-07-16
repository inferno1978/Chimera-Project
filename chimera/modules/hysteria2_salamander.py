"""
chimera/modules/hysteria2_salamander.py
───────────────────────────────────────────────────────────────────────────────
Salamander obfuscation для Hysteria2 — XOR-обфускация QUIC-пакетов.

АРХИТЕКТУРА:
  Salamander — встроенный в Hysteria2 obfuscator типа XOR. Применяется
  на лету к каждому QUIC-пакету после TLS-расшифровки. ТСПУ, который
  классифицирует QUIC по длине initial-packet и по отсутствию/наличию
  ALPN, теряет сигнатуру: QUIC-пакеты перестают выглядеть как QUIC.

  Включается одной секцией `obfs:` в server.yaml и client.yaml:
      obfs:
        type: salamander
        salamander:
          password: <32-byte random hex>

  Клиент и сервер должны использовать ОДИНАКОВЫЙ пароль — иначе пакеты
  не деобфусцируются и QUIC handshake не доходит.

ИНТЕГРАЦИЯ:
  На Entry-ноде:
    - /etc/hysteria/client.yaml  ← добавляется секция obfs:
    - hysteria-client перезапусится
  На Exit-ноде (через SSH):
    - /etc/hysteria/config.yaml  ← добавляется секция obfs:
    - hysteria-server перезапускается
  Пароль хранится в state.json → hysteria2.salamander.password

ПОЧЕМУ ОТДЕЛЬНЫЙ МОДУЛЬ:
  Сейчас hysteria2_transport.py ставит только pinSHA256, не активируя
  obfs.salamander. Это значит, что QUIC-DPI по-прежнему видит
  классический QUIC-fingerprint. Salamander закрывает эту брешь.

ТОЧКИ ВЫЗОВА:
  • h2_salamander_menu()          — TUI-меню (вызывается из hysteria2_menu.py)
  • h2_salamander_enable()        — включает Salamander на клиенте + серверах
  • h2_salamander_disable()       — отключает Salamander
  • h2_salamander_status()        — dict {enabled, has_password, nodes[]}
  • h2_salamander_ensure_state()  — вызывается из h2_transport_apply()
                                    для автоматического добавления obfs в client.yaml
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from chimera.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state, _ensure_h2_state,
    _tg_h2_event,
    H2_CONFIG_FILE, H2_BINARY, H2_SERVICE,
)
from chimera.modules.hysteria2_transport import _H2_CLIENT_CONFIG
from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back, _box_desc, _box_info, _box_warn, _box_ok,
)


# ── Генерация пароля ──────────────────────────────────────────────────────────

def _generate_salamander_password() -> str:
    """
    Возвращает 32-байтный случайный пароль в hex (64 символа).
    Salamander принимает любую строку, но 32 байта (256 бит) — это
    криптографический стандарт, рекомендуемый apernet/hysteria.
    """
    return secrets.token_hex(32)


# ── Парсинг/патч YAML без сторонних зависимостей ──────────────────────────────
# Hysteria2 config.yaml — простой YAML без анкоров/алиасов, поэтому
# достаточно регекс-патчей. Это избегает зависимости от PyYAML, которая
# не везде установлена (минимальный install: apt-only).

_OBFS_BLOCK_RE = re.compile(
    r"^obfs:\s*\n(?:[ \t]+.*\n)*",
    re.MULTILINE,
)


def _has_obfs_block(yaml_text: str) -> bool:
    return bool(re.search(r"^obfs:\s*$", yaml_text, re.MULTILINE))


def _remove_obfs_block(yaml_text: str) -> str:
    """Удаляет существующую секцию `obfs:` (и её дочерние строки)."""
    return _OBFS_BLOCK_RE.sub("", yaml_text, count=1)


def _build_obfs_block(password: str, indent: str = "") -> str:
    """
    Возвращает YAML-блок obfs: с Salamander.
    Используется как для server.yaml, так и для client.yaml.
    """
    return (
        f"{indent}obfs:\n"
        f"{indent}  type: salamander\n"
        f"{indent}  salamander:\n"
        f"{indent}    password: {password}\n"
    )


def _inject_obfs(yaml_text: str, password: str) -> str:
    """
    Вставляет/заменяет секцию obfs: в YAML-конфиге Hysteria2.
    Возвращает новый текст.
    """
    # Удаляем существующий блок (если есть)
    if _has_obfs_block(yaml_text):
        yaml_text = _remove_obfs_block(yaml_text)
    # Добавляем в конец — это безопасно, Hysteria2 парсит секции в любом порядке
    if not yaml_text.endswith("\n"):
        yaml_text += "\n"
    yaml_text += _build_obfs_block(password)
    return yaml_text


def _strip_obfs(yaml_text: str) -> str:
    """Удаляет секцию obfs: из YAML-конфига."""
    if _has_obfs_block(yaml_text):
        return _remove_obfs_block(yaml_text)
    return yaml_text


# ── State helpers ─────────────────────────────────────────────────────────────

def _load_salamander_state() -> dict:
    """Возвращает подсекцию hysteria2.salamander из state.json."""
    h2 = _load_h2_state()
    return h2.get("salamander", {})


def _save_salamander_state(sal: dict) -> None:
    """Атомарно обновляет hysteria2.salamander в state.json."""
    h2 = _load_h2_state()
    h2["salamander"] = sal
    _save_h2_state(h2)


def _ensure_salamander_state() -> dict:
    h2 = _ensure_h2_state()
    if "salamander" not in h2:
        h2["salamander"] = {
            "enabled": False,
            "password": "",
            "applied_to_client": False,
            "applied_to_nodes": [],
        }
        _save_h2_state(h2)
    return h2["salamander"]


# ── Локальный клиент (Entry-нода, /etc/hysteria/client.yaml) ──────────────────

def _apply_obfs_to_client(password: str) -> bool:
    """Патчит /etc/hysteria/client.yaml, добавляя секцию obfs:."""
    if not _H2_CLIENT_CONFIG.exists():
        warn(f"Не найден {_H2_CLIENT_CONFIG} — клиентский конфиг Hysteria2 не создан")
        return False
    try:
        text = _H2_CLIENT_CONFIG.read_text()
        new_text = _inject_obfs(text, password)
        _H2_CLIENT_CONFIG.write_text(new_text)
        # chmod 0o600 — в файле теперь секретный пароль
        _H2_CLIENT_CONFIG.chmod(0o600)
        return True
    except Exception as e:
        error(f"Не удалось записать {_H2_CLIENT_CONFIG}: {e}")
        return False


def _strip_obfs_from_client() -> bool:
    if not _H2_CLIENT_CONFIG.exists():
        return True
    try:
        text = _H2_CLIENT_CONFIG.read_text()
        new_text = _strip_obfs(text)
        if new_text != text:
            _H2_CLIENT_CONFIG.write_text(new_text)
        return True
    except Exception as e:
        error(f"Не удалось очистить {_H2_CLIENT_CONFIG}: {e}")
        return False


def _restart_hysteria_client() -> bool:
    """Перезапускает systemd-юнит hysteria-client."""
    r = _run(["systemctl", "is-active", "--quiet", "hysteria-client"], quiet=True)
    if r.returncode != 0:
        # Клиент не запущен — это нормально, конфиг всё равно сохранён
        return True
    r = _run(["systemctl", "restart", "hysteria-client"], quiet=True)
    time.sleep(2)
    r2 = _run(["systemctl", "is-active", "--quiet", "hysteria-client"], quiet=True)
    return r2.returncode == 0


# ── Удалённые Exit-ноды (через SSH) ───────────────────────────────────────────

def _ssh_opts_for_node(node: dict) -> list:
    """Формирует опции ssh для подключения к Exit-ноде."""
    opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
    key = node.get("ssh_key") or node.get("key", "")
    if key:
        opts += ["-i", key]
    return opts


def _apply_obfs_to_remote_node(node: dict, password: str) -> tuple[bool, str]:
    """
    Патчит /etc/hysteria/config.yaml на удалённой Exit-ноде.
    Возвращает (success, message).
    """
    host = node.get("ip", "")
    if not host:
        return False, "Нет IP-адреса ноды"

    ssh_pass = node.get("ssh_pass") or node.get("password", "")
    ssh_opts = _ssh_opts_for_node(node)

    # 1. Читаем текущий server.yaml через SSH
    read_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                      "cat /etc/hysteria/config.yaml 2>/dev/null"]
    if ssh_pass:
        read_cmd = ["sshpass", "-p", ssh_pass] + read_cmd
    r = _run(read_cmd, capture=True, timeout=20, check=False)
    if r.returncode != 0:
        return False, f"Не удалось прочитать config.yaml на {host}: {r.stderr[:120]}"
    current = r.stdout

    # 2. Локально патчим
    new_text = _inject_obfs(current, password)

    # 3. Записываем обратно через heredoc
    write_cmd = (
        f"cat > /etc/hysteria/config.yaml << 'EOFSAL'\n{new_text}EOFSAL"
    )
    ssh_cmd = ["ssh"] + ssh_opts + [f"root@{host}", write_cmd]
    if ssh_pass:
        ssh_cmd = ["sshpass", "-p", ssh_pass] + ssh_cmd
    r2 = _run(ssh_cmd, capture=True, timeout=20, check=False)
    if r2.returncode != 0:
        return False, f"Не удалось записать config.yaml на {host}: {r2.stderr[:120]}"

    # 4. Перезапускаем hysteria-server
    restart_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                         f"systemctl restart {H2_SERVICE}"]
    if ssh_pass:
        restart_cmd = ["sshpass", "-p", ssh_pass] + restart_cmd
    r3 = _run(restart_cmd, capture=True, timeout=20, check=False)
    if r3.returncode != 0:
        return False, f"Не удалось перезапустить {H2_SERVICE} на {host}: {r3.stderr[:120]}"

    time.sleep(2)
    # 5. Проверяем, что сервис ожил
    status_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                        f"systemctl is-active {H2_SERVICE}"]
    if ssh_pass:
        status_cmd = ["sshpass", "-p", ssh_pass] + status_cmd
    r4 = _run(status_cmd, capture=True, timeout=15, check=False)
    if r4.stdout.strip() != "active":
        return False, f"{H2_SERVICE} упал после рестарта на {host}"

    return True, f"Salamander применён на {host}"


def _strip_obfs_from_remote_node(node: dict) -> tuple[bool, str]:
    host = node.get("ip", "")
    if not host:
        return False, "Нет IP-адреса ноды"

    ssh_pass = node.get("ssh_pass") or node.get("password", "")
    ssh_opts = _ssh_opts_for_node(node)

    read_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                      "cat /etc/hysteria/config.yaml 2>/dev/null"]
    if ssh_pass:
        read_cmd = ["sshpass", "-p", ssh_pass] + read_cmd
    r = _run(read_cmd, capture=True, timeout=20, check=False)
    if r.returncode != 0:
        return False, f"Не удалось прочитать config.yaml на {host}: {r.stderr[:120]}"
    current = r.stdout

    new_text = _strip_obfs(current)
    if new_text == current:
        # Уже без obfs
        return True, f"На {host} obfs уже отключён"

    write_cmd = (
        f"cat > /etc/hysteria/config.yaml << 'EOFSAL'\n{new_text}EOFSAL"
    )
    ssh_cmd = ["ssh"] + ssh_opts + [f"root@{host}", write_cmd]
    if ssh_pass:
        ssh_cmd = ["sshpass", "-p", ssh_pass] + ssh_cmd
    r2 = _run(ssh_cmd, capture=True, timeout=20, check=False)
    if r2.returncode != 0:
        return False, f"Не удалось записать config.yaml на {host}"

    restart_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                         f"systemctl restart {H2_SERVICE}"]
    if ssh_pass:
        restart_cmd = ["sshpass", "-p", ssh_pass] + restart_cmd
    _run(restart_cmd, capture=True, timeout=20, check=False)
    time.sleep(2)

    status_cmd = ["ssh"] + ssh_opts + [f"root@{host}",
                                        f"systemctl is-active {H2_SERVICE}"]
    if ssh_pass:
        status_cmd = ["sshpass", "-p", ssh_pass] + status_cmd
    r4 = _run(status_cmd, capture=True, timeout=15, check=False)
    if r4.stdout.strip() != "active":
        return False, f"{H2_SERVICE} упал после рестарта на {host}"
    return True, f"obfs снят на {host}"


# ── Публичный API ─────────────────────────────────────────────────────────────

def h2_salamander_enable(
    password: str = "",
    apply_to_remote: bool = True,
) -> bool:
    """
    Включает Salamander obfuscation:
      1. Генерирует пароль (если не задан)
      2. Патчит /etc/hysteria/client.yaml на Entry-ноде
      3. Перезапускает hysteria-client
      4. (опционально) Патчит /etc/hysteria/config.yaml на всех Exit-нодах
      5. Сохраняет пароль в state.json
    Возвращает True при успехе.
    """
    sal = _ensure_salamander_state()

    # 1. Пароль
    if not password:
        # Если уже есть сохранённый пароль — переиспользуем
        password = sal.get("password", "")
    if not password:
        password = _generate_salamander_password()
        info(f"Сгенерирован новый Salamander-пароль ({len(password)} hex chars)")

    # 2. Патчим клиент
    if not _apply_obfs_to_client(password):
        return False

    # 3. Перезапуск клиента
    if not _restart_hysteria_client():
        warn("hysteria-client не запущен после патча — проверьте journalctl")

    applied_nodes = []
    failed_nodes = []

    # 4. Патчим Exit-ноды
    if apply_to_remote:
        h2 = _load_h2_state()
        nodes = [n for n in h2.get("exit_nodes", [])
                 if n.get("status") == "active"]
        if not nodes:
            warn("Нет активных Exit-нод в state — Salamander применён только локально")
        else:
            info(f"Применяю Salamander на {len(nodes)} Exit-нодах через SSH...")
            for node in nodes:
                ok, msg = _apply_obfs_to_remote_node(node, password)
                if ok:
                    success(msg)
                    applied_nodes.append(node.get("ip"))
                else:
                    error(msg)
                    failed_nodes.append({"ip": node.get("ip"), "error": msg})

    # 5. Сохраняем в state
    sal["enabled"] = True
    sal["password"] = password
    sal["applied_to_client"] = True
    sal["applied_to_nodes"] = applied_nodes
    sal["last_applied"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _save_salamander_state(sal)

    success("Salamander obfuscation активирован")
    _tg_h2_event("h2_switch", f"Salamander obfs включён (nodes: {len(applied_nodes)})")
    log_to_file("INFO", f"Salamander enabled, password set, applied to {len(applied_nodes)} nodes")

    if failed_nodes:
        warn(f"На {len(failed_nodes)} нодах не удалось применить Salamander:")
        for fn in failed_nodes:
            warn(f"  {fn['ip']}: {fn['error']}")
        warn("Этим нодам нужен ручной патч /etc/hysteria/config.yaml")

    return True


def h2_salamander_disable(strip_from_remote: bool = True) -> bool:
    """
    Отключает Salamander:
      1. Удаляет секцию obfs: из client.yaml
      2. Перезапускает hysteria-client
      3. (опционально) Удаляет obfs: из server.yaml на всех Exit-нодах
      4. Обновляет state.json
    """
    sal = _ensure_salamander_state()

    # 1. Локальный клиент
    if not _strip_obfs_from_client():
        return False
    _restart_hysteria_client()

    # 2. Удалённые ноды
    if strip_from_remote:
        h2 = _load_h2_state()
        nodes = [n for n in h2.get("exit_nodes", [])
                 if n.get("status") == "active"]
        for node in nodes:
            ok, msg = _strip_obfs_from_remote_node(node)
            if ok:
                success(msg)
            else:
                warn(msg)

    # 3. State
    sal["enabled"] = False
    sal["applied_to_client"] = False
    sal["applied_to_nodes"] = []
    sal["last_disabled"] = time.strftime("%Y-%m-%d %H:%M:%S")
    # Пароль НЕ стираем — может понадобиться для повторного включения
    _save_salamander_state(sal)

    success("Salamander obfuscation отключён")
    _tg_h2_event("h2_switch", "Salamander obfs выключен")
    log_to_file("INFO", "Salamander disabled")
    return True


def h2_salamander_status() -> dict:
    """Возвращает dict с текущим статусом Salamander."""
    sal = _ensure_salamander_state()
    h2 = _load_h2_state()
    nodes = [n.get("ip") for n in h2.get("exit_nodes", [])
             if n.get("status") == "active"]

    # Проверяем реальное наличие obfs в client.yaml
    client_has_obfs = False
    if _H2_CLIENT_CONFIG.exists():
        try:
            client_has_obfs = _has_obfs_block(_H2_CLIENT_CONFIG.read_text())
        except Exception:
            pass

    return {
        "enabled":            sal.get("enabled", False),
        "has_password":       bool(sal.get("password")),
        "applied_to_client":  client_has_obfs,
        "applied_to_nodes":   sal.get("applied_to_nodes", []),
        "all_nodes":          nodes,
        "last_applied":       sal.get("last_applied", ""),
        "last_disabled":      sal.get("last_disabled", ""),
    }


def h2_salamander_ensure_state() -> None:
    """
    Вызывается из h2_transport_apply() после генерации нового client.yaml.
    Если в state включён Salamander — повторно применяет obfs к свежему
    client.yaml (иначе _write_h2_client_config затирает obfs-секцию).
    """
    sal = _load_salamander_state()
    if not sal.get("enabled"):
        return
    password = sal.get("password", "")
    if not password:
        return
    info("Salamander включён в state — пере-применяю obfs к свежему client.yaml")
    if _apply_obfs_to_client(password):
        _restart_hysteria_client()
        log_to_file("INFO", "Salamander re-applied to client.yaml after transport re-apply")


# ── TUI-меню ──────────────────────────────────────────────────────────────────

def _format_status_line(st: dict) -> str:
    """Возвращает однострочный статус Salamander для шапки меню."""
    if not st["enabled"]:
        return f"{YELLOW}отключён{NC}"
    parts = [f"{GREEN}включён{NC}"]
    if st["applied_to_client"]:
        parts.append(f"{GREEN}client ✓{NC}")
    else:
        parts.append(f"{RED}client ✗{NC}")
    n_ok = len(st["applied_to_nodes"])
    n_total = len(st["all_nodes"])
    if n_total > 0:
        col = GREEN if n_ok == n_total else YELLOW
        parts.append(f"{col}nodes {n_ok}/{n_total}{NC}")
    if st["has_password"]:
        parts.append(f"{DIM}pass ✓{NC}")
    else:
        parts.append(f"{RED}pass ✗{NC}")
    return "  │  ".join(parts)


def h2_salamander_menu() -> None:
    """
    TUI-меню управления Salamander obfuscation для Hysteria2.
    Вызывается из hysteria2_menu.py (пункт "S").
    """
    _ensure_salamander_state()

    while True:
        os.system("clear")
        print()
        st = h2_salamander_status()

        _box_top("🦎  HYSTERIA2 — SALAMANDER OBFUSCATION")
        _box_row(f"  Статус: {_format_status_line(st)}")
        _box_sep()
        _box_desc(
            "Salamander — XOR-обфускация QUIC-пакетов на лету. "
            "Ломает ТСПУ-классификацию QUIC по длине initial-packet и ALPN. "
            "Включается одновременно на клиенте (Entry) и сервере (Exit)."
        )
        _box_sep()
        _box_row()
        if st["enabled"]:
            _box_item("1", f"🔴 Выключить Salamander  {DIM}(снять obfs с client + exit-нод){NC}")
            _box_item("2", f"🔑 Сменить пароль        {DIM}(перегенерировать и применить){NC}")
            _box_item("3", f"🔁 Пере-применить        {DIM}(если client.yaml был перегенерирован){NC}")
        else:
            _box_item("1", f"🟢 Включить Salamander   {DIM}(сгенерировать пароль + применить){NC}")
            _box_item("2", f"🔑 Включить со своим паролем  {DIM}(ввести вручную){NC}")
        _box_sep()
        _box_item("S", f"📊 Подробный статус      {DIM}(список нод, проверка конфигов){NC}")
        _box_item("T", f"🧪 Тест соединения       {DIM}QUIC-пинг до exit-ноды{NC}")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", "Q", ""):
            break

        elif ch == "1":
            if st["enabled"]:
                # Выключить
                print()
                warn("Это снимет obfs с client.yaml и со всех Exit-нод.")
                warn("Трафик Hysteria2 снова станет видимым ТСПУ как QUIC.")
                try:
                    confirm = input(f"\n{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
                except KeyboardInterrupt:
                    confirm = ""
                if confirm == "y":
                    h2_salamander_disable()
                else:
                    info("Отменено")
            else:
                # Включить
                h2_salamander_enable()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if st["enabled"]:
                # Сменить пароль
                print()
                warn("Смена пароля разорвёт текущие соединения и потребует")
                warn("повторного применения на всех Exit-нодах через SSH.")
                try:
                    confirm = input(f"\n{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
                except KeyboardInterrupt:
                    confirm = ""
                if confirm == "y":
                    new_pass = _generate_salamander_password()
                    h2_salamander_enable(password=new_pass, apply_to_remote=True)
                else:
                    info("Отменено")
            else:
                # Включить со своим паролем
                print()
                try:
                    user_pass = input(
                        f"{CYAN}Введите Salamander-пароль {DIM}"
                        f"(пусто = сгенерировать):{NC} "
                    ).strip()
                except KeyboardInterrupt:
                    continue
                if not user_pass:
                    user_pass = _generate_salamander_password()
                    info("Сгенерирован новый пароль")
                elif len(user_pass) < 16:
                    warn("Пароль короче 16 символов — это небезопасно. Продолжить?")
                    try:
                        c = input(f"{YELLOW}(y/N):{NC} ").strip().lower()
                    except KeyboardInterrupt:
                        c = ""
                    if c != "y":
                        continue
                h2_salamander_enable(password=user_pass, apply_to_remote=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            # Пере-применить
            if not st["enabled"]:
                warn("Salamander не включён — нечего пере-применять")
                time.sleep(1.5)
                continue
            h2_salamander_ensure_state()
            success("Пере-применение завершено")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "S":
            _show_detailed_status(st)
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "T":
            _run_connection_test()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            warn("Неверный выбор")
            time.sleep(0.8)


def _show_detailed_status(st: dict) -> None:
    """Подробный статус Salamander — что где применено."""
    print()
    _box_top("📊  ПОДРОБНЫЙ СТАТУС SALAMANDER")

    _box_row(f"  Глобально:    "
             f"{GREEN}включён{NC}" if st["enabled"]
             else f"  Глобально:    {YELLOW}отключён{NC}")

    _box_row(f"  Пароль:       "
             f"{GREEN}установлен{NC}" if st["has_password"]
             else f"{RED}отсутствует{NC}")

    _box_row(f"  client.yaml:  "
             f"{GREEN}obfs: есть{NC}" if st["applied_to_client"]
             else f"{RED}obfs: нет{NC}")

    if st["last_applied"]:
        _box_row(f"  Посл. apply:  {DIM}{st['last_applied']}{NC}")
    if st["last_disabled"]:
        _box_row(f"  Посл. disable:{DIM}{st['last_disabled']}{NC}")

    _box_sep()
    _box_row(f"  {BOLD}Exit-ноды:{NC}")

    if not st["all_nodes"]:
        _box_row(f"    {DIM}нет активных нод{NC}")
    else:
        for ip in st["all_nodes"]:
            if ip in st["applied_to_nodes"]:
                _box_row(f"    {GREEN}✓{NC} {ip}")
            else:
                _box_row(f"    {RED}✗{NC} {ip}  {DIM}(требуется ручной патч){NC}")

    _box_row()
    _box_info("Если на ноде obfs отсутствует — пере-примените через пункт 1 меню.")
    _box_bottom()


def _run_connection_test() -> None:
    """
    Тест: пропинговать каждую Exit-ноду через QUIC и оценить, активен ли
    Salamander (т.е. отвечает ли Hysteria2-server на QUIC-запросы).
    """
    print()
    h2 = _load_h2_state()
    nodes = [n for n in h2.get("exit_nodes", [])
             if n.get("status") == "active"]
    if not nodes:
        warn("Нет активных Exit-нод для теста")
        return

    _box_top("🧪  ТЕСТ QUIC-СОЕДИНЕНИЯ")
    for node in nodes:
        ip = node.get("ip", "?")
        ports = node.get("ports", [443])
        port = ports[0] if ports else 443
        _box_row(f"  {CYAN}{ip}:{port}{NC}")
        # Простой UDP-пинг через nc (с таймаутом 3 сек)
        r = _run(["timeout", "3", "nc", "-u", "-z", "-w", "2", ip, str(port)],
                 capture=True, quiet=True, check=False)
        # nc -u -z всегда возвращает 0 даже если порт закрыт — проверяем
        # через hysteria ping (если бинарь есть)
        if H2_BINARY.exists():
            r2 = _run([str(H2_BINARY), "ping", "-c", "1",
                       f"{ip}:{port}"], capture=True, quiet=True, check=False,
                      timeout=5)
            if r2.returncode == 0:
                _box_row(f"    {GREEN}✓ QUIC-ответ получен{NC}")
            else:
                _box_row(f"    {RED}✗ QUIC не отвечает (Salamander пароль не совпадает?){NC}")
        else:
            _box_row(f"    {DIM}(hysteria binary не найден — пропускаю){NC}")
    _box_bottom()
