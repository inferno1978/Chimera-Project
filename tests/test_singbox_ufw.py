#!/usr/bin/env python3
"""
tests/test_singbox_ufw.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/singbox_ufw.py (v4.23.14).

Покрывает:
  1. _ufw_parse_rules — парсинг `ufw status numbered`
  2. _ufw_active — определение активен ли UFW
  3. singbox_ufw_ensure_open — идемпотентность, не трогать чужое
  4. singbox_ufw_close — удаление только нашего правила
  5. _is_loopback_listen — loopback-проверка
  6. _is_port_used_by_other_singbox_proto — конкуренция протоколов

Все тесты мокают _run, чтобы не вызывать реальный ufw.
"""
from __future__ import annotations

import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class _Base(unittest.TestCase):
    """Базовый класс с setup'ом общих моков."""

    def setUp(self):
        self.stack = ExitStack()
        for p in [
            patch('os.geteuid', return_value=0),
            patch('os.chown', lambda *a, **k: None),
            patch.object(Path, 'mkdir', lambda s, *a, **k: None),
            patch.object(Path, 'touch', lambda s, *a, **k: None),
            patch.object(Path, 'chmod', lambda s, *a, **k: None),
        ]:
            self.stack.enter_context(p)
        _setup_core()
        from chimera.modules import singbox_ufw
        self.ufw = singbox_ufw
        # Список вызовов _run
        self.run_calls = []
        # Дефолтные ответы _run по команде
        self.run_responses = {}

        def fake_run(cmd, **kwargs):
            self.run_calls.append(cmd)
            key = " ".join(cmd[:3]) if len(cmd) >= 3 else " ".join(cmd)
            response = self.run_responses.get(key) or self.run_responses.get(" ".join(cmd))
            if response is None:
                # Дефолтный успех с пустым stdout
                m = MagicMock()
                m.returncode = 0
                m.stdout = ""
                m.stderr = ""
                return m
            return response

        self.run_patcher = patch('chimera.modules.singbox_ufw._run',
                                 side_effect=fake_run)
        self.run_patcher.start()

    def tearDown(self):
        self.run_patcher.stop()
        self.stack.close()

    def _mock_response(self, cmd_str, returncode=0, stdout="", stderr=""):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        self.run_responses[cmd_str] = m


# ============================================================================
#  1. _ufw_parse_rules
# ============================================================================
class TestParseRules(_Base):
    def test_parse_empty_status(self):
        self._mock_response("ufw status numbered", stdout="Status: inactive\n")
        rules = self.ufw._ufw_parse_rules()
        self.assertEqual(rules, [])

    def test_parse_active_no_rules(self):
        self._mock_response(
            "ufw status numbered",
            stdout="Status: active\n\nTo  Action  From\n--  ------  -----\n",
        )
        rules = self.ufw._ufw_parse_rules()
        self.assertEqual(rules, [])

    def test_parse_rules_with_comments(self):
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "     To                         Action      From\n"
                "     --                         ------      ----\n"
                "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
                "[ 2] 9443/tcp                   ALLOW IN    Anywhere                # sing-box-shadowtls\n"
                "[ 3] 9443/tcp (v6)              ALLOW IN    Anywhere (v6)           # sing-box-shadowtls\n"
                "[ 4] 443/udp                    ALLOW IN    Anywhere                # sing-box-tuic\n"
                "[ 5] 8080/tcp                   ALLOW IN    Anywhere                # my-custom-app\n"
            ),
        )
        rules = self.ufw._ufw_parse_rules()
        self.assertEqual(len(rules), 5)
        # Проверяем конкретные правила
        rule2 = rules[1]
        self.assertEqual(rule2["num"], 2)
        self.assertEqual(rule2["to"], "9443/tcp")
        self.assertEqual(rule2["comment"], "sing-box-shadowtls")
        self.assertFalse(rule2["v6"])
        rule3 = rules[2]
        self.assertTrue(rule3["v6"])
        rule4 = rules[3]
        self.assertEqual(rule4["to"], "443/udp")
        self.assertEqual(rule4["comment"], "sing-box-tuic")


# ============================================================================
#  2. _ufw_active
# ============================================================================
class TestUfwActive(_Base):
    def test_active(self):
        self._mock_response("ufw status", stdout="Status: active\n")
        self.assertTrue(self.ufw._ufw_active())

    def test_inactive(self):
        self._mock_response("ufw status", stdout="Status: inactive\n")
        self.assertFalse(self.ufw._ufw_active())

    def test_not_installed(self):
        # ufw не установлен — returncode != 0
        m = MagicMock()
        m.returncode = 127
        m.stdout = ""
        m.stderr = "command not found"
        self.run_responses["ufw status"] = m
        self.assertFalse(self.ufw._ufw_active())


# ============================================================================
#  3. singbox_ufw_ensure_open
# ============================================================================
class TestEnsureOpen(_Base):
    def test_ufw_inactive_returns_false(self):
        """UFW выключен — ничего не делаем."""
        self._mock_response("ufw status", stdout="Status: inactive\n")
        result = self.ufw.singbox_ufw_ensure_open(9443, "tcp", "shadowtls",
                                                   listen="0.0.0.0")
        self.assertFalse(result)
        # Не должно быть allow-команды
        allow_calls = [c for c in self.run_calls if "allow" in c]
        self.assertEqual(allow_calls, [])

    def test_loopback_listen_skips(self):
        """listen=127.0.0.1 — порт не открывается."""
        self._mock_response("ufw status", stdout="Status: active\n")
        result = self.ufw.singbox_ufw_ensure_open(9443, "tcp", "shadowtls",
                                                   listen="127.0.0.1")
        self.assertTrue(result)
        allow_calls = [c for c in self.run_calls if "allow" in c]
        self.assertEqual(allow_calls, [])

    def test_already_opened_by_us_idempotent(self):
        """Порт уже открыт нашим правилом — не добавляем дубликат."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 9443/tcp                   ALLOW IN    Anywhere                # sing-box-shadowtls\n"
            ),
        )
        result = self.ufw.singbox_ufw_ensure_open(9443, "tcp", "shadowtls",
                                                   listen="0.0.0.0")
        self.assertTrue(result)
        allow_calls = [c for c in self.run_calls if "allow" in c]
        self.assertEqual(allow_calls, [])

    def test_already_opened_foreign_warn_no_touch(self):
        """Порт открыт чужим правилом — warn и НЕ трогаем."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 9443/tcp                   ALLOW IN    Anywhere                # my-custom-app\n"
            ),
        )
        result = self.ufw.singbox_ufw_ensure_open(9443, "tcp", "shadowtls",
                                                   listen="0.0.0.0")
        self.assertTrue(result)  # порт доступен
        allow_calls = [c for c in self.run_calls if "allow" in c]
        self.assertEqual(allow_calls, [])  # не добавляем

    def test_opens_new_port(self):
        """Порт не открыт — добавляем правило."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response("ufw status numbered",
                            stdout="Status: active\n\n[ 1] 22/tcp  ALLOW IN  Anywhere\n")
        self._mock_response("ufw allow 9443/tcp comment sing-box-shadowtls")
        result = self.ufw.singbox_ufw_ensure_open(9443, "tcp", "shadowtls",
                                                   listen="0.0.0.0")
        self.assertTrue(result)
        # Должна быть команда allow с комментарием
        allow_calls = [c for c in self.run_calls if "allow" in c]
        self.assertEqual(len(allow_calls), 1)
        self.assertIn("9443/tcp", allow_calls[0])
        self.assertIn("comment", allow_calls[0])
        self.assertIn("sing-box-shadowtls", allow_calls[0])


# ============================================================================
#  4. singbox_ufw_close
# ============================================================================
class TestClose(_Base):
    def test_ufw_inactive_noop(self):
        self._mock_response("ufw status", stdout="Status: inactive\n")
        result = self.ufw.singbox_ufw_close(9443, "tcp", "shadowtls")
        self.assertTrue(result)
        delete_calls = [c for c in self.run_calls if "delete" in c]
        self.assertEqual(delete_calls, [])

    def test_no_our_rule_noop(self):
        """Нет нашего правила — нечего удалять."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout="Status: active\n\n[ 1] 22/tcp  ALLOW IN  Anywhere\n",
        )
        result = self.ufw.singbox_ufw_close(9443, "tcp", "shadowtls")
        self.assertTrue(result)
        delete_calls = [c for c in self.run_calls if "delete" in c]
        self.assertEqual(delete_calls, [])

    def test_deletes_our_rule(self):
        """Есть наше правило — удаляем через `ufw delete allow`."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 9443/tcp  ALLOW IN  Anywhere  # sing-box-shadowtls\n"
            ),
        )
        # close проверяет, не использует ли порт другой sing-box протокол
        # Мокаем singbox_state_load — нет других протоколов
        with patch('chimera.modules.singbox_state.singbox_state_load',
                   return_value={"inbounds": {}}):
            self._mock_response("ufw delete allow 9443/tcp comment sing-box-shadowtls")
            result = self.ufw.singbox_ufw_close(9443, "tcp", "shadowtls")
        self.assertTrue(result)
        delete_calls = [c for c in self.run_calls if "delete" in c]
        self.assertEqual(len(delete_calls), 1)
        self.assertIn("9443/tcp", delete_calls[0])
        self.assertIn("sing-box-shadowtls", delete_calls[0])

    def test_does_not_touch_foreign_rule(self):
        """Чужое правило не трогаем."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 9443/tcp  ALLOW IN  Anywhere  # my-custom-app\n"
            ),
        )
        result = self.ufw.singbox_ufw_close(9443, "tcp", "shadowtls")
        self.assertTrue(result)
        delete_calls = [c for c in self.run_calls if "delete" in c]
        self.assertEqual(delete_calls, [])

    def test_does_not_close_if_other_singbox_proto_uses_port(self):
        """Если порт использует другой sing-box протокол — не закрываем."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 9443/tcp  ALLOW IN  Anywhere  # sing-box-shadowtls\n"
            ),
        )
        # Мокаем state — vless_ws_cdn тоже использует 9443/tcp на 0.0.0.0
        mock_state = {
            "inbounds": {
                "vless_ws_cdn": {
                    "enabled": True,
                    "listen": "0.0.0.0",
                    "listen_port": 9443,
                },
            }
        }
        with patch('chimera.modules.singbox_state.singbox_state_load',
                   return_value=mock_state):
            result = self.ufw.singbox_ufw_close(9443, "tcp", "shadowtls")
        self.assertTrue(result)
        delete_calls = [c for c in self.run_calls if "delete" in c]
        self.assertEqual(delete_calls, [])


# ============================================================================
#  5. _is_loopback_listen
# ============================================================================
class TestLoopbackListen(_Base):
    def test_ipv4_loopback(self):
        self.assertTrue(self.ufw._is_loopback_listen("127.0.0.1"))

    def test_ipv6_loopback(self):
        self.assertTrue(self.ufw._is_loopback_listen("::1"))

    def test_localhost(self):
        self.assertTrue(self.ufw._is_loopback_listen("localhost"))

    def test_all_ipv4_not_loopback(self):
        self.assertFalse(self.ufw._is_loopback_listen("0.0.0.0"))

    def test_all_ipv6_not_loopback(self):
        self.assertFalse(self.ufw._is_loopback_listen("::"))

    def test_concrete_ip_not_loopback(self):
        self.assertFalse(self.ufw._is_loopback_listen("203.0.113.42"))


# ============================================================================
#  6. singbox_ufw_close_all
# ============================================================================
class TestCloseAll(_Base):
    def test_inactive_noop(self):
        self._mock_response("ufw status", stdout="Status: inactive\n")
        count = self.ufw.singbox_ufw_close_all()
        self.assertEqual(count, 0)

    def test_no_singbox_rules(self):
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout="Status: active\n\n[ 1] 22/tcp  ALLOW IN  Anywhere\n",
        )
        count = self.ufw.singbox_ufw_close_all()
        self.assertEqual(count, 0)

    def test_deletes_only_singbox_rules(self):
        """Удаляет только sing-box-* правила, чужие не трогает."""
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
                "[ 2] 9443/tcp  ALLOW IN  Anywhere  # sing-box-shadowtls\n"
                "[ 3] 8080/tcp  ALLOW IN  Anywhere  # my-app\n"
            ),
        )
        # ufw delete <num> — мокаем
        m = MagicMock()
        m.returncode = 0
        m.stdout = "Rule deleted"
        m.stderr = ""
        self.run_responses["ufw delete 2"] = m

        count = self.ufw.singbox_ufw_close_all()
        # Должно вернуться 1 (только sing-box правило)
        # (мы считаем все наши правила как "deleted", даже если что-то не вышло)
        self.assertGreaterEqual(count, 1)
        # Проверим, что была попытка удалить именно правило 2
        delete_calls = [c for c in self.run_calls if "delete" in c and len(c) >= 3]
        # Должна быть команда "ufw delete 2"
        self.assertTrue(any("2" in c for c in delete_calls),
                        f"Expected delete 2 in {delete_calls}")


# ============================================================================
#  7. singbox_ufw_status
# ============================================================================
class TestStatus(_Base):
    def test_returns_only_singbox_rules(self):
        self._mock_response("ufw status", stdout="Status: active\n")
        self._mock_response(
            "ufw status numbered",
            stdout=(
                "Status: active\n\n"
                "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
                "[ 2] 9443/tcp  ALLOW IN  Anywhere  # sing-box-shadowtls\n"
                "[ 3] 443/udp  ALLOW IN  Anywhere  # sing-box-tuic\n"
            ),
        )
        rules = self.ufw.singbox_ufw_status()
        self.assertEqual(len(rules), 2)
        self.assertTrue(all(r["comment"].startswith("sing-box-") for r in rules))


if __name__ == "__main__":
    unittest.main()
