"""
telemt_self_route.py
====================
Маршрутизация исходящего трафика самого процесса Telemt через xray.

Проблема
--------
Telemt запускается под root и сам инициирует соединения к Telegram DC
для инициализации DC/ME. Эти соединения идут напрямую с entry-ноды,
минуя xray туннель — потому что:

  1. Telemt стартует раньше xray (нет After=xray.service)
  2. iptables REDIRECT применяются в ExecStartPost xray-cold-boot-restore.sh
  3. К моменту появления правил соединение Telemt уже ESTABLISHED

Решение
-------
1. Добавить ``After=xray.service`` в telemt.service — гарантирует что
   iptables правила уже применены когда Telemt стартует.
2. Добавить ``--uid-owner xray`` RETURN rule на позицию 1 в nat OUTPUT —
   xray не попадает в петлю редиректа.

Оба изменения идемпотентны и безопасны:
- Если xray не установлен — After= игнорируется systemd (wants, not requires)
- RETURN rule для xray uid не мешает работе без xray
- При удалении модуля всё откатывается через disable()

Принципы
--------
* Одна функция — один файл: вся логика здесь.
* Безопасность: изменения минимальны, откатываемы, не трогают конфиг xray.
* Универсальность: работает для всех режимов (A, B, AWG).
* Миграция на nftables (этап 1.7) — RETURN rule для uid теперь через
  nft_mangle_return_uid(uid, comment="telemt-tproxy-bypass").

Публичное API
-------------
    enable()   -> tuple[bool, str]   — применить
    disable()  -> tuple[bool, str]   — откатить
    status()   -> dict               — текущее состояние
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# nftables — централизованная обёртка (этап 1.7 миграции).
from chimera.modules.nft_common import (
    nft_rule_exists, nft_rule_delete_by_comment,
    nft_mangle_return_uid, nft_persist, nft_persist_enable_systemd,
)
from chimera.modules.nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_OUTPUT,
    COMMENT_TELEMT_TPROXY_BYPASS, NFT_PERSIST_FILE,
)

__all__ = ["enable", "disable", "status"]

# ---------------------------------------------------------------------------
#  Константы
# ---------------------------------------------------------------------------
_TELEMT_SERVICE   = Path("/etc/systemd/system/telemt.service")
_XRAY_SERVICE     = "xray.service"
_AFTER_MARKER     = "After=xray.service"          # строка которую добавляем
_XRAY_USER        = "xray"                         # под каким uid работает xray
# Comment-tag для RETURN rule (соответствует COMMENT_TELEMT_TPROXY_BYPASS).
# Заменяет старый _IPT = "iptables" — больше не нужен, работаем через nft.
_COMMENT_TAG      = COMMENT_TELEMT_TPROXY_BYPASS   # "telemt-tproxy-bypass"


# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _xray_uid() -> int | None:
    """Возвращает uid пользователя xray или None если не существует."""
    import pwd
    try:
        return pwd.getpwnam(_XRAY_USER).pw_uid
    except KeyError:
        return None


def _return_rule_exists() -> bool:
    """Проверяет наличие RETURN правила для uid xray (через nft_rule_exists).

    Заменяет: iptables -t nat -C OUTPUT -m owner --uid-owner <uid> -j RETURN.
    Теперь: nft_rule_exists(comment="telemt-tproxy-bypass").
    """
    uid = _xray_uid()
    if uid is None:
        return False
    return nft_rule_exists(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_OUTPUT,
        comment=_COMMENT_TAG, family=NFT_TABLE_FAMILY,
    )


def _add_return_rule() -> bool:
    """Вставляет RETURN правило для uid xray в начало nat OUTPUT chain.

    Заменяет: iptables -t nat -I OUTPUT 1 -m owner --uid-owner <uid> -j RETURN.
    Теперь: nft_mangle_return_uid(uid=<uid>, comment="telemt-tproxy-bypass").
    """
    if _return_rule_exists():
        return True
    uid = _xray_uid()
    if uid is None:
        return False
    return nft_mangle_return_uid(
        uid=uid, chain=NFT_CHAIN_OUTPUT,
        comment=_COMMENT_TAG, idempotent=False,
    )


def _del_return_rule() -> None:
    """Удаляет RETURN правило для uid xray (через nft_rule_delete_by_comment).

    Заменяет цикл `iptables -t nat -D OUTPUT ... -j RETURN` (5 итераций).
    Теперь: один вызов nft_rule_delete_by_comment (max_iterations=10).
    """
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_OUTPUT,
        comment=_COMMENT_TAG, family=NFT_TABLE_FAMILY, max_iterations=10,
    )


def _service_has_after() -> bool:
    """Проверяет наличие After=xray.service в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    return _AFTER_MARKER in _TELEMT_SERVICE.read_text()


def _add_after_to_service() -> bool:
    """Добавляет After=xray.service в секцию [Unit] telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    if _service_has_after():
        return True

    text = _TELEMT_SERVICE.read_text()

    # Ищем строку After= в секции [Unit] и дописываем xray.service
    lines = text.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.startswith("After="):
            # Дописываем xray.service к существующей строке After=
            new_lines[-1] = line.rstrip() + " xray.service"
            inserted = True

    if not inserted:
        # Нет строки After= — вставляем после [Unit]
        final = []
        for line in new_lines:
            final.append(line)
            if line.strip() == "[Unit]":
                final.append(_AFTER_MARKER)
                inserted = True
        new_lines = final

    if not inserted:
        return False

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _remove_after_from_service() -> bool:
    """Убирает xray.service из After= в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return True
    text = _TELEMT_SERVICE.read_text()
    if _AFTER_MARKER not in text and "xray.service" not in text:
        return True

    lines = text.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith("After=") and "xray.service" in line:
            # Убираем xray.service из строки
            parts = line.split()
            parts = [p for p in parts if p != "xray.service"]
            line = " ".join(parts)
            # Если After= стала пустой — пропускаем
            if line.strip() == "After=":
                continue
        new_lines.append(line)

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _systemd_reload() -> None:
    _run(["systemctl", "daemon-reload"])


def _iptables_persist() -> None:
    """Сохраняет nftables ruleset для выживания после ребута (этап 1.7 миграции).

    Заменяет: netfilter-persistent save / iptables-save > /etc/iptables/rules.v4.
    Теперь: nft_persist() → /etc/nftables.conf + nft_persist_enable_systemd().
    """
    try:
        nft_persist(NFT_PERSIST_FILE)
        nft_persist_enable_systemd()
    except Exception:
        pass


# ---------------------------------------------------------------------------
#  Публичное API
# ---------------------------------------------------------------------------

def enable() -> tuple[bool, str]:
    """
    Активирует маршрутизацию трафика telemt через xray:
      1. Вставляет RETURN rule для uid xray перед REDIRECT правилами
      2. Добавляет After=xray.service в telemt.service
      3. Перезагружает systemd daemon

    Безопасно вызывать повторно (идемпотентно).
    """
    uid = _xray_uid()
    if uid is None:
        return False, (
            "Пользователь xray не найден. "
            "Убедитесь что xray установлен корректно."
        )

    # 1. RETURN rule
    if not _add_return_rule():
        return False, "Не удалось добавить nft RETURN rule для uid xray"

    # 2. After=xray.service
    if not _TELEMT_SERVICE.exists():
        return False, "telemt.service не найден — Telemt не установлен"

    if not _add_after_to_service():
        return False, "Не удалось обновить telemt.service"

    # 3. Перезагрузка systemd
    _systemd_reload()

    # 4. Сохранить nftables ruleset
    _iptables_persist()

    return True, (
        f"Готово: RETURN rule для uid {_XRAY_USER}({uid}) добавлен в nftables output, "
        f"telemt.service теперь стартует после xray.service. "
        f"Перезапустите telemt: systemctl restart telemt"
    )


def disable() -> tuple[bool, str]:
    """
    Откатывает изменения:
      1. Удаляет RETURN rule для uid xray
      2. Убирает After=xray.service из telemt.service
      3. Перезагружает systemd daemon
    """
    _del_return_rule()
    _remove_after_from_service()
    _systemd_reload()
    _iptables_persist()
    return True, "Маршрутизация трафика telemt через xray отключена"


def status() -> dict:
    """
    Возвращает текущее состояние:
      {
        "return_rule": bool,   — RETURN rule для xray uid активен
        "after_xray":  bool,   — After=xray.service в telemt.service
        "xray_uid":    int|None
      }
    """
    return {
        "return_rule": _return_rule_exists(),
        "after_xray":  _service_has_after(),
        "xray_uid":    _xray_uid(),
    }
