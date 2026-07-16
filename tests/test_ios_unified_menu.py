#!/usr/bin/env python3
"""
tests/test_ios_unified_menu.py
───────────────────────────────────────────────────────────────────────────────
Тесты для мини-патча №3: пункт K в do_unified_user_manager + функция
do_user_show_link_ios_by_uuid.

Контекст:
  Патч №2 добавил пункт K в do_user_menu() из users_manager.py, но эта
  функция не вызывается из главного меню (dead code). Реальный путь:
    main_menu → пункт "2" → do_unified_user_manager() (в _core.py)
  Этот патч добавляет пункт K туда, плюс новую функцию
  do_user_show_link_ios_by_uuid(uuid), которая берёт email НАПРЯМУЮ из
  clients[] config.json (а не из _unified_load_users, где email может
  быть рассинхронизирован с clients[]).

Покрытие:
  T1: do_user_show_link_ios_by_uuid — берёт email из clients[] по UUID
      (не из аргумента, не из users.json).
  T2: Рассинхрон email — UUID есть в users.json с email_A, в clients[]
      с email_B. Функция использует email_B (из clients[]).
  T3: UUID не найден в clients[] → явное предупреждение, не None.
  T4: Email в clients[] пустой → явное предупреждение.
  T5: Пункт K в _core.py статически присутствует и активен (не закомментирован).
  T6: Пункт K вызывает именно do_user_show_link_ios_by_uuid (static-чек).
  T7: Логика выбора пункта K дословно совпадает с пунктом 3 (static-чек
      по ключевым строкам — паттерн `raw.isdigit() and 1 <= int(raw) <= len(users)`).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import types
import unittest
import uuid as _uuid_mod
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_users_manager.py."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _make_reality_config(clients_list):
    """Создаёт временный config.json с REALITY-inbound и заданным clients[]."""
    tmpdir = Path(tempfile.mkdtemp())
    cfg_path = tmpdir / "config.json"
    config = {
        "inbounds": [{
            "protocol": "vless",
            "port": 443,
            "settings": {"clients": list(clients_list)},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": ["sni.example.com"],
                    "publicKey": "TEST_PUB_KEY",
                    "shortIds": ["abcd1234"],
                },
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    cfg_path.write_text(json.dumps(config, indent=2))
    return tmpdir, cfg_path


def _mock_core(fake_core):
    """Базовые стабы для helpers ядра."""
    fake_core.gen_uuid = lambda: str(_uuid_mod.uuid4())
    fake_core.get_server_country_cached = MagicMock(return_value=("RU", "Russia", ""))
    fake_core.PARAM_DOMAIN = "example.com"
    fake_core._fp_from_state = MagicMock(return_value="chrome")
    fake_core.STATE_FILE = Path("/nonexistent-state.json")
    fake_core.log_to_file = MagicMock()
    fake_core.warn = MagicMock()
    fake_core.info = MagicMock()
    fake_core._xray_safe_apply_config = MagicMock()
    fake_core._nginx_restart_if_reality = MagicMock()
    fake_core._run = MagicMock()
    fake_core._box_link = MagicMock()
    fake_core._box_top = MagicMock()
    fake_core._box_row = MagicMock()
    fake_core._box_bottom = MagicMock()
    fake_core._box_sep = MagicMock()
    fake_core._box_ok = MagicMock()
    fake_core._box_warn = MagicMock()
    fake_core.CYAN = ""
    fake_core.BOLD = ""
    fake_core.NC = ""
    fake_core.DIM = ""
    fake_core.BLUE = ""
    return fake_core


# ══════════════════════════════════════════════════════════════════════════════
#  T1: do_user_show_link_ios_by_uuid берёт email из clients[] (не из аргумента)
# ══════════════════════════════════════════════════════════════════════════════
class TestEmailFromClientsNotFromArg(unittest.TestCase):
    """Функция do_user_show_link_ios_by_uuid(uuid) НЕ принимает email
    как аргумент — она извлекает его из clients[] по UUID."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core(self._fake_core)
        self._tmpdir, self._cfg_path = _make_reality_config([
            {"id": "aaaaaaaa-0000-0000-0000-000000000001",
             "email": "real_email_in_config@example.com",
             "flow": "xtls-rprx-vision"},
        ])

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_email_comes_from_clients_not_from_arg(self):
        from chimera.modules import users_manager

        # Перехватываем ссылку через _box_link.
        captured = []
        self._fake_core._box_link = lambda link: captured.append(link)

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None):
            users_manager.do_user_show_link_ios_by_uuid(
                "aaaaaaaa-0000-0000-0000-000000000001"
            )

        self.assertEqual(len(captured), 1, "Должна быть выведена 1 ссылка")
        link = captured[0]

        # В clients[] должен появиться shadow с email оттуда же.
        c = json.loads(self._cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        shadows = [cl for cl in clients if "__ios" in cl.get("email", "")]
        self.assertEqual(len(shadows), 1)
        shadow_email = shadows[0]["email"]
        # Shadow-имя = real_email + "__ios" — это доказывает, что email
        # взят из clients[], а не из какого-то другого источника.
        self.assertEqual(shadow_email, "real_email_in_config@example.com__ios")

        # Ссылка содержит UUID shadow (а не оригинальный).
        shadow_uuid = shadows[0]["id"]
        self.assertIn(shadow_uuid, link)
        self.assertNotIn("aaaaaaaa-0000-0000-0000-000000000001", link)


# ══════════════════════════════════════════════════════════════════════════════
#  T2: рассинхрон email — берётся из clients[], а не из users.json
# ══════════════════════════════════════════════════════════════════════════════
class TestEmailDesyncResolvedFromClients(unittest.TestCase):
    """Сценарий: в users.json UUID имеет email_A, в clients[] тот же UUID
    имеет email_B (админ редактировал пункт 8, обновил users.json но не
    применил список). Функция должна использовать email_B (из clients[]),
    иначе _users_get_or_create_ios_shadow не найдёт клиента и молча
    вернёт None."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core(self._fake_core)
        self._tmpdir, self._cfg_path = _make_reality_config([
            # В clients[] — email_B
            {"id": "bbbbbbbb-0000-0000-0000-000000000002",
             "email": "email_B_in_clients@example.com",
             "flow": "xtls-rprx-vision"},
        ])
        # В users.json — email_A (рассинхрон)
        self._users_file = self._tmpdir / "users.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "bbbbbbbb-0000-0000-0000-000000000002",
             "email": "email_A_in_users_json@example.com",
             "name": "alice"},
        ]))
        self._fake_core.USERS_FILE = self._users_file

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_uses_email_from_clients_not_users_json(self):
        from chimera.modules import users_manager

        captured = []
        self._fake_core._box_link = lambda link: captured.append(link)

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None):
            users_manager.do_user_show_link_ios_by_uuid(
                "bbbbbbbb-0000-0000-0000-000000000002"
            )

        self.assertEqual(len(captured), 1)
        # Shadow создан с email_B (из clients[]), а НЕ с email_A (из users.json).
        c = json.loads(self._cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        shadows = [cl for cl in clients if "__ios" in cl.get("email", "")]
        self.assertEqual(len(shadows), 1)
        self.assertEqual(shadows[0]["email"],
                         "email_B_in_clients@example.com__ios")
        self.assertNotIn("email_A_in_users_json", shadows[0]["email"])


# ══════════════════════════════════════════════════════════════════════════════
#  T3: UUID не найден в clients[] → явное предупреждение
# ══════════════════════════════════════════════════════════════════════════════
class TestUuidNotFoundInClientsExplicitWarn(unittest.TestCase):
    """Если UUID есть в users.json, но в clients[] его нет — функция
    должна выдать явное предупреждение, а не молча вернуть None."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core(self._fake_core)
        # clients[] с одним юзером, но другим UUID.
        self._tmpdir, self._cfg_path = _make_reality_config([
            {"id": "cccccccc-0000-0000-0000-000000000003",
             "email": "someone_else@example.com",
             "flow": "xtls-rprx-vision"},
        ])

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_explicit_warn_when_uuid_missing_in_clients(self):
        from chimera.modules import users_manager

        captured_warns = []
        self._fake_core.warn = lambda msg: captured_warns.append(msg)

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None):
            users_manager.do_user_show_link_ios_by_uuid(
                "deadbeef-0000-0000-0000-000000000099"  # нет в clients[]
            )

        # Должно быть хотя бы одно предупреждение со словом "не найден".
        self.assertTrue(
            any("не найден" in w.lower() or "not found" in w.lower()
                for w in captured_warns),
            f"Должно быть явное предупреждение о ненайденном UUID, got: {captured_warns}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  T4: email пустой в clients[] → явное предупреждение
# ══════════════════════════════════════════════════════════════════════════════
class TestEmptyEmailInClientsExplicitWarn(unittest.TestCase):
    """Если у клиента в clients[] пустой email — shadow-функция не сможет
    его найти (она ищет по email). Явное предупреждение."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core(self._fake_core)
        self._tmpdir, self._cfg_path = _make_reality_config([
            {"id": "dddddddd-0000-0000-0000-000000000004",
             "email": "",   # пустой email
             "flow": "xtls-rprx-vision"},
        ])

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_explicit_warn_when_email_empty(self):
        from chimera.modules import users_manager

        captured_warns = []
        self._fake_core.warn = lambda msg: captured_warns.append(msg)

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None):
            users_manager.do_user_show_link_ios_by_uuid(
                "dddddddd-0000-0000-0000-000000000004"
            )

        self.assertTrue(
            any("email" in w.lower() and ("нет" in w.lower() or "пуст" in w.lower())
                for w in captured_warns),
            f"Должно быть явное предупреждение о пустом email, got: {captured_warns}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  T5-T7: статические проверки _core.py — пункт K в do_unified_user_manager
# ══════════════════════════════════════════════════════════════════════════════
class TestUnifiedMenuKItemStatic(unittest.TestCase):
    """Статические проверки кода _core.py — пункт K в
    do_unified_user_manager должен быть активен, вызывать именно
    do_user_show_link_ios_by_uuid, и логика выбора должна совпадать
    с пунктом 3."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _extract_unified_user_manager_block(self):
        """Достаёт исходник функции do_unified_user_manager из _core.py."""
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        # От `def do_unified_user_manager` до следующего `def ` на том же уровне.
        m = re.search(
            r'def do_unified_user_manager\(\).*?(?=\ndef [a-z_])',
            src, re.DOTALL
        )
        self.assertIsNotNone(m, "do_unified_user_manager не найдена в _core.py")
        return m.group(0)

    def test_t5_k_item_active_in_menu(self):
        """Пункт K в do_unified_user_manager должен быть активен (не в комментарии)."""
        block = self._extract_unified_user_manager_block()
        # Активная строка _box_item("K" — не закомментирована.
        # Берём все строки и ищем.
        lines = block.split("\n")
        found_active = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('_box_item("K"'):
                found_active = True
                break
        self.assertTrue(found_active,
                        "Пункт K должен быть активен в do_unified_user_manager. "
                        "Возможно, он закомментирован или отсутствует.")

    def test_t6_k_calls_do_user_show_link_ios_by_uuid(self):
        """Обработчик ch == 'k' должен вызывать именно
        do_user_show_link_ios_by_uuid (а не do_user_show_link_ios или
        какой-то другой вариант)."""
        block = self._extract_unified_user_manager_block()
        self.assertIn(
            "do_user_show_link_ios_by_uuid(u[\"uuid\"])",
            block,
            "Обработчик пункта K должен вызывать "
            "do_user_show_link_ios_by_uuid(u[\"uuid\"]) — это та функция, "
            "которая берёт email из clients[], а не из users.json"
        )

    def test_t7_k_uses_same_selection_as_item_3(self):
        """Логика выбора в пункте K должна ДОСЛОВНО совпадать с пунктом 3:
        тот же паттерн `raw.isdigit() and 1 <= int(raw) <= len(users)`."""
        block = self._extract_unified_user_manager_block()

        # Находим все вхождения этого паттерна — должно быть ≥2 (пункты 3 и K).
        pattern = r'raw\.isdigit\(\)\s*and\s*1\s*<=\s*int\(raw\)\s*<=\s*len\(users\)'
        matches = re.findall(pattern, block)
        self.assertGreaterEqual(
            len(matches), 2,
            f"Паттерн выбора `raw.isdigit() and 1 <= int(raw) <= len(users)` "
            f"должен встречаться минимум 2 раза (пункты 3 и K), "
            f"найдено {len(matches)}. Если K использует другой способ матчинга — "
            f"это второй источник правды в одном меню."
        )

        # Также проверяем что и `raw = input("  Номер пользователя: ")`
        # встречается минимум 2 раза — тот же prompt.
        prompt_pattern = r'raw\s*=\s*input\(\s*"  Номер пользователя: "\s*\)'
        prompt_matches = re.findall(prompt_pattern, block)
        self.assertGreaterEqual(
            len(prompt_matches), 2,
            f"Промпт 'Номер пользователя:' должен быть одинаковым в "
            f"пунктах 3 и K, найдено {len(prompt_matches)}."
        )

    def test_t5b_main_menu_k_item_never_in_top_menu(self):
        """В top-level main_menu (главное меню 1-17) НЕТ пункта K —
        там никогда не было iOS-точки.

        Активные пункты K живут только в ПОДменю:
          • do_unified_user_manager (патч №3) → do_user_show_link_ios_by_uuid
          • _menu_users (патч №4)             → generate_client_links_ios

        Этот тест защищает от случайной вставки K в main_menu — там
        ему не место, поскольку главный menu — это разделы (1-Установка,
        2-Пользователи, 3-Сеть и т.д.), а не конкретные действия."""
        import re
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        # Извлекаем main_menu (top-level).
        m = re.search(r'def main_menu\(\).*', src, re.DOTALL)
        self.assertIsNotNone(m, "main_menu не найдена в _core.py")
        main_menu_block = m.group(0)
        for i, line in enumerate(main_menu_block.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith('_box_item("K"'):
                self.fail(
                    f"Строка {i} в main_menu: пункт K не должен быть в "
                    f"top-level меню. Got: {line!r}"
                )


# ══════════════════════════════════════════════════════════════════════════════
#  T_extra: импорт do_user_show_link_ios_by_uuid в _core.py работает
# ══════════════════════════════════════════════════════════════════════════════
class TestImportWorks(unittest.TestCase):
    """Импорт do_user_show_link_ios_by_uuid в _core.py должен работать
    (защита от опечатки в имени при import)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_import_succeeds(self):
        # Компилируем _core.py (он делает import в верхней части).
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        compile(src, "_core.py", "exec")
        # Если import сломан — exec упадёт с ImportError.
        # Делаем минимальный smoke-test: import users_manager и проверяем функцию.
        from chimera.modules.users_manager import (
            do_user_show_link_ios_by_uuid
        )
        self.assertTrue(callable(do_user_show_link_ios_by_uuid))


if __name__ == "__main__":
    unittest.main(verbosity=2)
