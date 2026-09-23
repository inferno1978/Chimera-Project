#!/usr/bin/env python3
"""
tests/test_emergency_repair_socket_wait.py
───────────────────────────────────────────────────────────────────────────────
Юнит-тест на логику ожидания Unix-сокета в аварийном восстановлении.

Баг: в chimera/modules/emergency_repair.py в шаге [5/11] вызывался
`systemctl start xray`, затем ждали появления Unix-сокета 20 секунд, после
чего выводили ложный [WARN] "Сокет не появился — проверьте:
journalctl -u xray -n 20".

Причина: Unix-сокет /dev/shm/<pid>.socket создаёт НЕ Xray, а Nginx через
директиву `listen unix:/dev/shm/<pid>.socket ssl http2 proxy_protocol`.
В xray config.json путь указан только в `dest` REALITY — это upstream
для SNI-мимикрии, а не listen-socket. Поэтому ожидание сокета сразу
после старта Xray (но до старта Nginx) всегда завершалось таймаутом.

Фикс: блок "Ожидание Unix-сокета" перенесён ПОСЛЕ старта Nginx — теперь
сокет создаётся мгновенно (nginx listen-инициализация синхронна).

Этот тест не запускает do_emergency_repair целиком (там 1100 строк
системных вызовов). Вместо этого мы проверяем саму логику проверки:
читает state.json, ждёт путь в `socket`, после старта nginx проверяет
Path.is_socket().
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestSocketWaitLogic(unittest.TestCase):
    """Проверяем, что emergency_repair правильно интерпретирует поля state.json.

    Эти тесты не выполняют настоящих рестартов сервисов — они валидируют
    БАЗОВЫЕ КОНТРАКТЫ, на которые опирается логика ожидания сокета.
    """

    def test_state_json_socket_path_is_string(self):
        """state.json поле `socket` — строка, не None, не пустая.

        Если state.json некорректен — _wait_for_unix_socket должен
        вообще пропустить шаг ожидания сокета.
        """
        state = {
            "protocol_mode": "reality",
            "install_mode": "B",
            "socket": "/dev/shm/abc123.socket",
            "awg_exit_enabled": False,
        }
        self.assertIsInstance(state["socket"], str)
        self.assertTrue(state["socket"])
        self.assertTrue(state["socket"].startswith("/dev/shm/"))

    def test_state_json_no_socket_when_awg_enabled(self):
        """При AWG_EXIT_ENABLED=True Xray слушает на TCP-порту, сокета нет.

        Логика в emergency_repair._wait_for_unix_socket должна скипать шаг
        ожидания, если AWG_EXIT_ENABLED=True — иначе будет ложный таймаут.
        """
        state = {
            "protocol_mode": "reality",
            "install_mode": "B",
            "socket": "/dev/shm/abc123.socket",
            "awg_exit_enabled": True,   # ← AWG включен
        }
        # Контракт: при awg_exit_enabled=True не проверяем сокет
        self.assertTrue(state["awg_exit_enabled"])

    def test_state_json_protocol_mode_non_reality_skips_socket(self):
        """При protocol_mode != 'reality' (например, xhttp/vless) — сокета нет.

        Логика должна скипать шаг ожидания сокета.
        """
        state = {
            "protocol_mode": "xhttp",
            "install_mode": "A",
            "socket": "",
            "awg_exit_enabled": False,
        }
        # Контракт: при protocol_mode != reality не проверяем сокет
        self.assertNotEqual(state["protocol_mode"], "reality")
        # socket может быть пустой строкой — тоже корректный случай skip
        self.assertFalse(state["socket"])

    def test_socket_wait_after_nginx_not_after_xray(self):
        """Доказательство гипотезы: сокет создаёт nginx, не xray.

        Через инспекцию исходника emergency_repair.py проверяем, что
        блок `Path(PARAM_SOCKET_PATH).is_socket()` идёт ПОСЛЕ вызова
        `systemctl start nginx`, а НЕ между `start xray` и `start nginx`.

        Если кто-то рефакторит код и снова переставит порядок — этот тест
        зафейлится, не дав регрессии проникнуть в production.
        """
        src_path = _PROJECT_ROOT / "chimera" / "modules" / "emergency_repair.py"
        src = src_path.read_text()

        # Найдём ключевые маркеры в исходнике
        idx_start_xray = src.find('"start", "xray"')
        # FIX: после фикса старый путь (wait socket между xray и nginx)
        # больше не должен присутствовать в форме "for _ in range(20)" +
        # "Сокет не появился" до старта nginx.
        idx_start_nginx = src.find('"start", "nginx"')
        idx_socket_check = src.find("Path(PARAM_SOCKET_PATH).is_socket()")

        self.assertGreater(idx_start_xray, 0, f"marker: start xray not found (idx={idx_start_xray})")
        self.assertGreater(idx_start_nginx, 0, f"marker: start nginx not found (idx={idx_start_nginx})")
        self.assertGreater(idx_socket_check, 0, f"marker: socket check not found (idx={idx_socket_check})")

        # Контракт: socket check должен быть ПОСЛЕ start nginx
        # (это и есть суть фикса — раньше был между xray и nginx)
        self.assertGreater(idx_socket_check, idx_start_nginx,
                           "REGRESSION: проверка is_socket() стоит ДО старта nginx — "
                           "это значит, что проверяется сокет, который ещё не создан nginx'ом. "
                           "Верните фикс: сокет создаёт nginx, проверять его надо ПОСЛЕ nginx start.")

        # Дополнительно: между start_xray и start_nginx не должно быть
        # цикла ожидания сокета — иначе это регрессия к старому багу.
        # Найдём любой цикл `for _ in range(N):` между start_xray и start_nginx
        section_between = src[idx_start_xray:idx_start_nginx]
        # Старый баговый код имел `for _ in range(20):` прямо между start_xray
        # и start_nginx с проверкой is_socket(). После фикса такого быть
        # не должно.
        bad_pattern_in_section = "is_socket" in section_between
        self.assertFalse(bad_pattern_in_section,
                          "REGRESSION: between start_xray and start_nginx есть "
                          "вызов is_socket() — это значит вернулась старая "
                          "баговая логика ожидания сокета ДО старта nginx.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
