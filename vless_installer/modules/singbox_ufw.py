"""
vless_installer/modules/singbox_ufw.py
───────────────────────────────────────────────────────────────────────────────
Умное управление UFW-правилами для sing-box (v4.23.14).

Принципы:
  • Идемпотентность — повторный вызов не дублирует правила.
  • Не трогать чужое — если порт уже открыт БЕЗ нашего комментария,
    не добавлять и не удалять (warn).
  • Комментарии — каждое наше правило помечено 'sing-box-<proto>',
    чтобы точно знать, что наше.
  • При disable/uninstall — закрывать только наши правила, проверяя
    что порт не используется другим sing-box протоколом.

Команды UFW:
  ufw allow 9443/tcp comment 'sing-box-shadowtls'
  ufw delete allow 9443/tcp comment 'sing-box-shadowtls'
  ufw status numbered

───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
from typing import Optional

from vless_installer.modules.singbox_common import (
    info, success, warn, error, log_to_file,
    _run,
    SINGBOX_SERVICE,
)


SINGBOX_UFW_COMMENT_PREFIX = "sing-box-"


# ============================================================================
#  Базовые хелперы
# ============================================================================
def _ufw_active() -> bool:
    """True если UFW установлен и активен (Status: active)."""
    r = _run(["ufw", "status"], capture=True, quiet=True)
    if r.returncode != 0:
        return False  # ufw не установлен или нет root
    return "Status: active" in (r.stdout or "")


def _ufw_status_numbered() -> Optional[str]:
    """Возвращает вывод `ufw status numbered` или None."""
    r = _run(["ufw", "status", "numbered"], capture=True, quiet=True)
    if r.returncode != 0:
        return None
    return r.stdout or ""


def _ufw_parse_rules() -> list:
    """Парсит `ufw status numbered`, возвращает список dict-правил.

    Каждое правило:
      {"num": int, "to": "9443/tcp", "action": "ALLOW IN", "from": "Anywhere",
       "comment": "sing-box-shadowtls", "v6": False, "raw": "..."}
    """
    out = _ufw_status_numbered()
    if not out:
        return []
    rules = []
    for line in out.splitlines():
        # Формат: [ 1] 22/tcp                     ALLOW IN    Anywhere
        #         [ 2] 9443/tcp                   ALLOW IN    Anywhere                # sing-box-shadowtls
        #         [ 3] 9443/tcp (v6)              ALLOW IN    Anywhere (v6)           # sing-box-shadowtls
        m = re.match(
            r'^\[\s*(\d+)\]\s+(\S+)(?:\s+\(v6\))?\s+(ALLOW[^\s]*\s+[^\s]+)\s+(.+?)(?:\s+#\s*(.+))?\s*$',
            line,
        )
        if not m:
            continue
        num = int(m.group(1))
        to = m.group(2)
        action = m.group(3).strip()
        from_ = m.group(4).strip()
        comment = (m.group(5) or "").strip()
        v6 = "(v6)" in line
        rules.append({
            "num":     num,
            "to":      to,           # "9443/tcp"
            "action":  action,
            "from":    from_,
            "comment": comment,
            "v6":      v6,
            "raw":     line.strip(),
        })
    return rules


def _parse_to(to_str: str) -> tuple:
    """'9443/tcp' → (9443, 'tcp'). '443/udp (v6)' → (443, 'udp')."""
    m = re.match(r'^(\d+)/(tcp|udp)', to_str)
    if not m:
        return (0, "")
    return (int(m.group(1)), m.group(2))


def _is_loopback_listen(listen: str) -> bool:
    """True если listen — loopback (порт не нужно открывать в firewall)."""
    return listen in ("127.0.0.1", "::1", "localhost")


# ============================================================================
#  Публичные функции
# ============================================================================
def singbox_ufw_ensure_open(port: int, proto: str, protocol_tag: str,
                            listen: str = "0.0.0.0") -> bool:
    """Открывает порт в UFW для sing-box протокола, если нужно.

    Логика:
      • UFW не активен → return False (warn не делаем — это нормально).
      • listen loopback → return True (порт не нужен извне).
      • Порт уже открыт нашим правилом → return True (идемпотентно).
      • Порт открыт чужим правилом (без sing-box- комментария) →
        warn + return True (порт доступен, но мы его не трогаем).
      • Порт не открыт → добавляем ufw allow <port>/<proto> comment.

    Возвращает True если порт доступен извне (открыт нами или кем-то ещё),
    False если UFW не активен или не получилось.
    """
    if _is_loopback_listen(listen):
        return True  # loopback — firewall не нужен
    if not _ufw_active():
        return False  # UFW не активен — не наша забота, пользователь сам разрулит

    comment = f"{SINGBOX_UFW_COMMENT_PREFIX}{protocol_tag}"
    rules = _ufw_parse_rules()

    # Ищем существующие правила для этого port/proto
    ours = []
    foreign = []
    for r in rules:
        r_port, r_proto = _parse_to(r["to"])
        if r_port == port and r_proto == proto:
            if r["comment"].startswith(SINGBOX_UFW_COMMENT_PREFIX):
                ours.append(r)
            else:
                foreign.append(r)

    if ours:
        return True  # уже открыто нами — идемпотентно
    if foreign:
        # Порт открыт чужим правилом — НЕ дублируем, НЕ трогаем
        warn(f"Порт {port}/{proto} уже открыт в UFW другим правилом — не добавляем")
        return True

    # Добавляем наше правило
    r = _run(
        ["ufw", "allow", f"{port}/{proto}", "comment", comment],
        capture=True, quiet=True,
    )
    if r.returncode != 0:
        error(f"Не удалось открыть порт {port}/{proto} в UFW: {(r.stderr or '').strip()}")
        return False
    success(f"Порт {port}/{proto} открыт в UFW (правило: sing-box-{protocol_tag})")
    log_to_file("INFO", f"UFW: открыт порт {port}/{proto} для sing-box-{protocol_tag}")
    return True


def singbox_ufw_close(port: int, proto: str, protocol_tag: str,
                      listen: str = "0.0.0.0") -> bool:
    """Закрывает порт в UFW, если он открыт нашим правилом.

    Логика:
      • UFW не активен → return (нечего закрывать).
      • Нет нашего правила для port/proto → return.
      • Порт используется другим sing-box протоколом → НЕ закрываем (info).
      • Есть наше правило и больше никому не нужно → удаляем.
      • Чужие правила НЕ трогаем никогда.
    """
    if not _ufw_active():
        return True  # UFW не активен — нечего закрывать
    if _is_loopback_listen(listen):
        # loopback — порт в UFW не открывался, но проверим, не осталось ли
        # нашего правила от прежней конфигурации (listen менялся на loopback).
        pass

    comment = f"{SINGBOX_UFW_COMMENT_PREFIX}{protocol_tag}"
    rules = _ufw_parse_rules()

    ours = [r for r in rules
            if _parse_to(r["to"]) == (port, proto)
            and r["comment"] == comment]
    if not ours:
        return True  # нет нашего правила — нечего закрывать

    # Проверим, не используется ли порт другим sing-box протоколом.
    # Читаем state sing-box и смотрим все включённые inbounds.
    if _is_port_used_by_other_singbox_proto(port, proto, protocol_tag):
        info(f"Порт {port}/{proto} используется другим sing-box протоколом "
             f"— правило UFW не удаляется")
        return True

    # Удаляем наше правило (v4 + v6 — обе команды одним вызовом)
    r = _run(
        ["ufw", "delete", "allow", f"{port}/{proto}", "comment", comment],
        capture=True, quiet=True,
    )
    if r.returncode != 0:
        # Может быть, правило уже удалено или синтаксис не подошёл.
        # Попробуем удалить по номерам.
        _ufw_delete_by_numbers(ours)
    success(f"Порт {port}/{proto} закрыт в UFW (правило sing-box-{protocol_tag} удалено)")
    log_to_file("INFO", f"UFW: закрыт порт {port}/{proto} для sing-box-{protocol_tag}")
    return True


def singbox_ufw_close_all() -> int:
    """Закрывает ВСЕ sing-box правила в UFW. Для uninstall.

    Возвращает количество удалённых правил.
    """
    if not _ufw_active():
        return 0
    rules = _ufw_parse_rules()
    ours = [r for r in rules if r["comment"].startswith(SINGBOX_UFW_COMMENT_PREFIX)]
    if not ours:
        return 0
    # Удаляем по номерам — с конца, чтобы номера не сбивались.
    # ufw delete <num> требует подтверждения, посылаем "y".
    deleted = 0
    for r in sorted(ours, key=lambda x: x["num"], reverse=True):
        result = _run(
            ["ufw", "delete", str(r["num"])],
            capture=True, quiet=True,
        )
        # ufw delete <num> спрашивает y/n. Передаём через stdin.
        if result.returncode != 0:
            # Повторим с явным "y"
            import subprocess as _sp
            try:
                _sp.run(
                    ["ufw", "delete", str(r["num"])],
                    input="y\n", capture_output=True, text=True, timeout=10,
                )
            except Exception:
                pass
        deleted += 1
    if deleted:
        success(f"Удалено {deleted} sing-box правил UFW")
        log_to_file("INFO", f"UFW: удалено {deleted} sing-box правил")
    return deleted


def singbox_ufw_status() -> list:
    """Возвращает список наших правил (для отображения в меню)."""
    if not _ufw_active():
        return []
    rules = _ufw_parse_rules()
    return [r for r in rules if r["comment"].startswith(SINGBOX_UFW_COMMENT_PREFIX)]


# ============================================================================
#  Внутренние хелперы
# ============================================================================
def _is_port_used_by_other_singbox_proto(port: int, proto: str,
                                          exclude_tag: str) -> Optional[str]:
    """Проверяет, не использует ли другой sing-box протокол тот же port/proto.

    Читает sing-box state, проверяет все enabled inbounds.
    Возвращает tag протокола-конкурента или None.
    """
    try:
        from vless_installer.modules.singbox_state import singbox_state_load
        state = singbox_state_load()
        inbounds = state.get("inbounds", {})
    except Exception:
        return None

    # Маппинг sing-box inbound name → наш tag в комментарии
    proto_map = {
        "shadowtls":     "shadowtls",
        "anytls":        "anytls",
        "tuic":          "tuic",
        "vless_ws_cdn":  "vless_ws_cdn",
    }
    for ib_name, tag in proto_map.items():
        if tag == exclude_tag:
            continue
        ib = inbounds.get(ib_name, {})
        if not ib.get("enabled", False):
            continue
        ib_port = ib.get("listen_port", 0)
        if ib_port != port:
            continue
        # Для TUIC — UDP, для остальных TCP
        ib_proto = "udp" if ib_name == "tuic" else "tcp"
        if ib_proto != proto:
            continue
        # Listen должен быть не-loopback (иначе порт не открывался в UFW)
        if _is_loopback_listen(ib.get("listen", "127.0.0.1")):
            continue
        return tag
    return None


def _ufw_delete_by_numbers(rules: list) -> bool:
    """Удаляет правила по номерам (fallback если delete allow не сработал).

    Удаляем с конца — номера не сбиваются.
    """
    import subprocess as _sp
    success_flag = True
    for r in sorted(rules, key=lambda x: x["num"], reverse=True):
        try:
            result = _sp.run(
                ["ufw", "delete", str(r["num"])],
                input="y\n", capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                success_flag = False
        except Exception:
            success_flag = False
    return success_flag
