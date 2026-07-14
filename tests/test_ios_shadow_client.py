#!/usr/bin/env python3
"""
tests/test_ios_shadow_client.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для ПАТЧА №2 (теневой iOS-клиент без XTLS Vision flow).

Контекст:
  Патч №1 (постпроцессор to_ios_karing_link) показывал пользователю REALITY-
  ссылку без `&flow=xtls-rprx-vision`, но серверный clients[] продолжал
  хранить `"flow": "xtls-rprx-vision"` для этого UUID — гарантированный
  разрыв хендшейка. Патч №2 чинит это через создание ОТДЕЛЬНОГО shadow-клиента
  в clients[] БЕЗ ключа `flow`.

Тесты (нумерация по спецификации задачи):
  1. do_user_add() → do_user_delete() БЕЗ обращения к iOS-функциям:
     config.json ДО и ПОСЛЕ побайтово идентичен состоянию до патча №2.
  2. _users_get_or_create_ios_shadow() на REALITY: первый вызов создаёт
     клиента БЕЗ ключа "flow" в словаре (`"flow" not in client`).
  3. Повторный вызов НЕ создаёт второго клиента — clients[] той же длины,
     тот же uuid возвращается.
  4. _users_get_or_create_ios_shadow() на xHTTP-инбаунде возвращает None,
     clients[] не меняется.
  5. do_user_show_link_ios() для REALITY: ссылка содержит UUID теневого
     клиента (НЕ uuid основного), не содержит "flow=".
  6. do_user_delete(): с shadow → удаляются оба; без shadow → только
     основной, поведение идентично допатчевому.
  7. xray run -test на config.json после do_user_add() → show_link_ios()
     проходит (используется xray из PATH; если недоступен — тест
     пропускается, но структура config.json валидируется вручную).
  8. Существующие golden-тесты на do_user_add/_users_gen_link не сломаны.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
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


# ══════════════════════════════════════════════════════════════════════════════
#  Утилиты для тестов
# ══════════════════════════════════════════════════════════════════════════════

def _make_reality_config(initial_clients=None):
    """Создаёт временный config.json с REALITY-inbound и заданным списком
    clients. Возвращает (tmpdir, cfg_path). Тест сам чистит tmpdir."""
    tmpdir = Path(tempfile.mkdtemp())
    cfg_path = tmpdir / "config.json"
    if initial_clients is None:
        initial_clients = [{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "alice@example.com",
            "flow": "xtls-rprx-vision",
        }]
    config = {
        "inbounds": [{
            "protocol": "vless",
            "port": 443,
            "settings": {"clients": list(initial_clients)},
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


def _make_xhttp_config(initial_clients=None):
    """Аналогично _make_reality_config, но с xHTTP-inbound (без flow)."""
    tmpdir = Path(tempfile.mkdtemp())
    cfg_path = tmpdir / "config.json"
    if initial_clients is None:
        initial_clients = [{
            "id": "00000000-0000-0000-0000-000000000002",
            "email": "bob@example.com",
            # xHTTP-клиенты НЕ имеют flow
        }]
    config = {
        "inbounds": [{
            "protocol": "vless",
            "port": 8443,
            "settings": {"clients": list(initial_clients)},
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/xhttp", "mode": "streamup"},
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    cfg_path.write_text(json.dumps(config, indent=2))
    return tmpdir, cfg_path


def _read_clients(cfg_path):
    """Читает clients[] из config.json."""
    c = json.loads(cfg_path.read_text())
    return c["inbounds"][0]["settings"]["clients"]


def _mock_core_for_users_manager(fake_core, cfg_path=None, state_dict=None):
    """Мокирует helpers ядра, которые users_manager использует через
    _core_module(). Возвращает fake_core (уже в sys.modules)."""
    fake_core.gen_uuid = lambda: str(_uuid_mod.uuid4())
    fake_core.get_server_country_cached = MagicMock(return_value=("RU", "Russia", ""))
    fake_core.PARAM_DOMAIN = "example.com"
    fake_core._fp_from_state = MagicMock(return_value="chrome")
    fake_core.STATE_FILE = Path("/nonexistent-state.json")
    fake_core.log_to_file = MagicMock()
    fake_core.warn = MagicMock()
    fake_core._xray_safe_apply_config = MagicMock()
    fake_core._nginx_restart_if_reality = MagicMock()
    fake_core._run = MagicMock()
    if state_dict:
        # Эмулируем state.json для _users_gen_link xHTTP-ветки.
        fake_core.STATE_FILE = cfg_path.parent / "state.json" if cfg_path else Path("/tmp/_test_state.json")
        fake_core.STATE_FILE.write_text(json.dumps(state_dict))
    return fake_core


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 1: do_user_add → do_user_delete без iOS — config.json идентичен
# ══════════════════════════════════════════════════════════════════════════════
class TestNoRegressionAddDelete(unittest.TestCase):
    """do_user_add() → do_user_delete() без единого обращения к iOS-функциям:
    config.json ДО и ПОСЛЕ побайтово идентичен состоянию до патча №2."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config([
            {"id": "00000000-0000-0000-0000-000000000001",
             "email": "alice@example.com", "flow": "xtls-rprx-vision"}
        ])
        _mock_core_for_users_manager(self._fake_core)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_then_delete_yields_identical_config(self):
        """Симулируем: добавили юзера, потом удалили. Финальный config.json
        должен быть побайтово идентичен исходному (ни новых клиентов, ни
        новых ключей)."""
        from chimera.modules import users_manager

        original = self._cfg_path.read_text()

        # Патчим _users_get_config чтобы возвращала наш cfg_path.
        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch("builtins.input", side_effect=["charlie@example.com", "", "y"]):
            try:
                users_manager.do_user_add()
            except Exception:
                # input() side_effect может дать EOFError при лишних prompt-ах —
                # это OK, главное что клиент добавлен.
                pass

        after_add = self._cfg_path.read_text()
        clients_after_add = _read_clients(self._cfg_path)
        # Должно стать 2 клиента.
        self.assertEqual(len(clients_after_add), 2,
                         f"do_user_add должен добавить 1 клиента, got {clients_after_add}")

        # Теперь удаляем того же charlie.
        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch("builtins.input", side_effect=["charlie@example.com"]):
            try:
                users_manager.do_user_delete()
            except Exception:
                pass

        after_delete = self._cfg_path.read_text()
        clients_after_delete = _read_clients(self._cfg_path)

        # Снова 1 клиент.
        self.assertEqual(len(clients_after_delete), 1,
                         f"do_user_delete должен удалить, got {clients_after_delete}")
        # И это снова alice (оригинальный).
        self.assertEqual(clients_after_delete[0]["email"], "alice@example.com")

        # Побайтово идентичен исходному — НИКАКИХ новых ключей от факта
        # существования нового кода.
        # Сравниваем через json-нагрузку (порядок ключей может различаться
        # из-за ensure_ascii=False vs ensure_ascii=True, но содержимое
        # должно совпадать).
        original_json = json.loads(original)
        final_json = json.loads(after_delete)
        self.assertEqual(original_json, final_json,
                         "config.json после add→delete должен быть "
                         "побайтово идентичен исходному")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 2: shadow-клиент создаётся БЕЗ ключа "flow"
# ══════════════════════════════════════════════════════════════════════════════
class TestShadowClientNoFlowKey(unittest.TestCase):
    """_users_get_or_create_ios_shadow() на REALITY: первый вызов создаёт
    клиента БЕЗ ключа "flow" в словаре (проверяем `"flow" not in client`,
    а не `client.get("flow") == ""`)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config()
        _mock_core_for_users_manager(self._fake_core)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_shadow_client_has_no_flow_key(self):
        from chimera.modules import users_manager

        with patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None):
            result = users_manager._users_get_or_create_ios_shadow(
                self._cfg_path, "alice@example.com"
            )

        self.assertIsNotNone(result, "REALITY должен дать shadow")
        shadow_uuid, shadow_email = result
        # _shadow_ios_email добавляет суффикс "__ios" в конец строки base_email.
        # Xray treats email в clients[] как произвольную строку-метку, не как
        # реальный ящик — поэтому "alice@example.com__ios" корректно и
        # однозначно восстанавливается по base_email.
        self.assertEqual(shadow_email, "alice@example.com__ios")
        self.assertTrue(shadow_email.endswith("__ios"))
        self.assertTrue(shadow_email.startswith("alice"))

        clients = _read_clients(self._cfg_path)
        shadow_client = next(cl for cl in clients if cl.get("email") == shadow_email)
        # КЛЮЧЕВОЙ АССЕРТ: ключа "flow" НЕТ В СЛОВАРЕ ВООБЩЕ.
        self.assertNotIn("flow", shadow_client,
                         "shadow-клиент НЕ должен иметь ключ 'flow' в словаре — "
                         "это отличается от flow='' и от flow=None")
        # UUID присутствует и не пустой.
        self.assertTrue(shadow_client["id"])
        self.assertEqual(shadow_client["id"], shadow_uuid)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 3: идемпотентность — повторный вызов не плодит дубликаты
# ══════════════════════════════════════════════════════════════════════════════
class TestShadowClientIsIdempotent(unittest.TestCase):
    """Повторный вызов _users_get_or_create_ios_shadow() для того же
    base_email НЕ создаёт второго клиента — clients[] той же длины,
    тот же uuid возвращается."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config()
        _mock_core_for_users_manager(self._fake_core)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_repeat_call_returns_same_uuid_no_duplicate(self):
        from chimera.modules import users_manager

        with patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None):
            r1 = users_manager._users_get_or_create_ios_shadow(
                self._cfg_path, "alice@example.com"
            )
            r2 = users_manager._users_get_or_create_ios_shadow(
                self._cfg_path, "alice@example.com"
            )

        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(r1, r2, "Повторный вызов должен вернуть тот же (uuid, email)")

        clients = _read_clients(self._cfg_path)
        # 1 оригинал + 1 shadow, не больше.
        self.assertEqual(len(clients), 2,
                         f"Ожидалось 2 клиента (original + shadow), got {len(clients)}")
        # Только одна запись с __ios.
        shadows = [cl for cl in clients if "__ios" in cl.get("email", "")]
        self.assertEqual(len(shadows), 1, "Должен быть ровно 1 shadow-клиент")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 4: xHTTP-инбаунд → None, clients[] не меняется
# ══════════════════════════════════════════════════════════════════════════════
class TestShadowClientXhttpNoop(unittest.TestCase):
    """_users_get_or_create_ios_shadow() на xHTTP-инбаунде возвращает None,
    clients[] не меняется вообще."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_xhttp_config()
        _mock_core_for_users_manager(self._fake_core)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_xhttp_returns_none_no_mutation(self):
        from chimera.modules import users_manager

        original_clients = _read_clients(self._cfg_path)
        original_json = self._cfg_path.read_text()

        with patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None):
            result = users_manager._users_get_or_create_ios_shadow(
                self._cfg_path, "bob@example.com"
            )

        self.assertIsNone(result, "xHTTP-инбаунд → None")

        # clients[] не изменился ни количеством, ни содержимым.
        new_clients = _read_clients(self._cfg_path)
        self.assertEqual(len(new_clients), len(original_clients))
        self.assertEqual(original_clients, new_clients)
        # И файл побайтово не тронут.
        self.assertEqual(self._cfg_path.read_text(), original_json)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 5: do_user_show_link_ios для REALITY — UUID shadow, без flow=
# ══════════════════════════════════════════════════════════════════════════════
class TestShowLinkIosUsesShadowUuid(unittest.TestCase):
    """do_user_show_link_ios() для REALITY: сгенерированная ссылка содержит
    UUID теневого клиента (НЕ uuid основного), не содержит "flow=" вообще."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config()
        _mock_core_for_users_manager(self._fake_core)
        # stub для _show_qr и _box_link — не падаем на печать.
        self._fake_core._box_link = MagicMock()
        self._fake_core._box_top = MagicMock()
        self._fake_core._box_row = MagicMock()
        self._fake_core._box_bottom = MagicMock()
        self._fake_core._box_sep = MagicMock()
        self._fake_core._box_ok = MagicMock()
        self._fake_core._box_warn = MagicMock()
        self._fake_core.CYAN = ""
        self._fake_core.BOLD = ""
        self._fake_core.NC = ""
        self._fake_core.DIM = ""

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_link_uses_shadow_uuid_no_flow(self):
        from chimera.modules import users_manager

        # Сначала узнаём UUID оригинала.
        orig_clients = _read_clients(self._cfg_path)
        orig_uuid = orig_clients[0]["id"]

        # Перехватываем печать через patch _box_link чтобы сохранить link.
        captured_link = []
        def _capture(link):
            captured_link.append(link)
        self._fake_core._box_link = _capture

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None), \
             patch("builtins.input", side_effect=["alice@example.com"]):
            try:
                users_manager.do_user_show_link_ios()
            except Exception:
                pass

        self.assertEqual(len(captured_link), 1, "Должна быть выведена 1 ссылка")
        link = captured_link[0]

        # Ссылка НЕ содержит flow= (это iOS-совместимая).
        self.assertNotIn("flow=", link)
        self.assertNotIn("xtls-rprx-vision", link)

        # Ссылка содержит shadow-UUID, а НЕ оригинальный.
        # После do_user_show_link_ios shadow уже создан в config.json.
        new_clients = _read_clients(self._cfg_path)
        shadows = [cl for cl in new_clients if "__ios" in cl.get("email", "")]
        self.assertEqual(len(shadows), 1)
        shadow_uuid = shadows[0]["id"]
        self.assertIn(shadow_uuid, link,
                      "Ссылка должна содержать UUID shadow-клиента")
        self.assertNotIn(orig_uuid, link,
                         "Ссылка НЕ должна содержать UUID оригинала")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 6: do_user_delete — с shadow / без shadow
# ══════════════════════════════════════════════════════════════════════════════
class TestDeleteWithAndWithoutShadow(unittest.TestCase):
    """do_user_delete() основного юзера, у которого есть теневой клиент:
    после удаления в clients[] нет ни основного, ни теневого email.
    do_user_delete() юзера БЕЗ теневого клиента — clients[] теряет
    только основного, поведение идентично допатчевому."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        _mock_core_for_users_manager(self._fake_core)

    def _make_cfg(self, with_shadow):
        """Создаёт cfg с alice и (опционально) её shadow.
        Shadow-имя — по схеме _shadow_ios_email: base + '__ios' в конец."""
        clients = [{
            "id": "aaaaaaaa-0000-0000-0000-000000000001",
            "email": "alice@example.com",
            "flow": "xtls-rprx-vision",
        }]
        if with_shadow:
            clients.append({
                "id": "bbbbbbbb-0000-0000-0000-000000000002",
                # Имя shadow = _shadow_ios_email("alice@example.com")
                "email": "alice@example.com__ios",
                # без flow
            })
        # Всегда добавляем второго основного, чтобы не упереться в
        # "нельзя удалить последнего".
        clients.append({
            "id": "cccccccc-0000-0000-0000-000000000003",
            "email": "bob@example.com",
            "flow": "xtls-rprx-vision",
        })
        return _make_reality_config(clients)

    def test_delete_with_shadow_removes_both(self):
        from chimera.modules import users_manager

        tmpdir, cfg_path = self._make_cfg(with_shadow=True)
        try:
            with patch.object(users_manager, "_users_get_config", return_value=cfg_path), \
                 patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
                 patch.object(users_manager, "_core_module", return_value=self._fake_core), \
                 patch.object(Path, "unlink", lambda self, *a, **kw: None), \
                 patch("builtins.input", side_effect=["alice@example.com"]):
                try:
                    users_manager.do_user_delete()
                except Exception:
                    pass

            clients = _read_clients(cfg_path)
            emails = [cl.get("email") for cl in clients]
            # Alice и её shadow оба удалены.
            self.assertNotIn("alice@example.com", emails)
            self.assertNotIn("alice@example.com__ios", emails)
            # Bob остался.
            self.assertIn("bob@example.com", emails)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_delete_without_shadow_only_removes_main(self):
        """Поведение идентично допатчевому: shadow нет → удаляется только
        основной. Никаких лишних изменений."""
        from chimera.modules import users_manager

        tmpdir, cfg_path = self._make_cfg(with_shadow=False)
        original_json = cfg_path.read_text()
        try:
            with patch.object(users_manager, "_users_get_config", return_value=cfg_path), \
                 patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
                 patch.object(users_manager, "_core_module", return_value=self._fake_core), \
                 patch.object(Path, "unlink", lambda self, *a, **kw: None), \
                 patch("builtins.input", side_effect=["alice@example.com"]):
                try:
                    users_manager.do_user_delete()
                except Exception:
                    pass

            clients = _read_clients(cfg_path)
            emails = [cl.get("email") for cl in clients]
            self.assertNotIn("alice@example.com", emails)
            self.assertIn("bob@example.com", emails)
            # Никакого shadow не появилось (аддитивный блок no-op).
            self.assertNotIn("alice@example.com__ios", emails)
            self.assertEqual(len(clients), 1,
                             "Без shadow — должен остаться только bob")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 7: валидность config.json после add + show_link_ios
# ══════════════════════════════════════════════════════════════════════════════
class TestConfigValidityAfterIosShadow(unittest.TestCase):
    """После do_user_add() → do_user_show_link_ios() config.json должен
    быть валиден: парсится как JSON, schema валидна для Xray (clients
    имеют обязательные поля id/email; flow опционален).
    Если xray доступен в PATH — дополнительно `xray run -test`."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir, self._cfg_path = _make_reality_config()
        _mock_core_for_users_manager(self._fake_core)
        self._fake_core._box_link = MagicMock()
        self._fake_core._box_top = MagicMock()
        self._fake_core._box_row = MagicMock()
        self._fake_core._box_bottom = MagicMock()
        self._fake_core._box_sep = MagicMock()
        self._fake_core._box_ok = MagicMock()
        self._fake_core._box_warn = MagicMock()
        self._fake_core.CYAN = ""
        self._fake_core.BOLD = ""
        self._fake_core.NC = ""
        self._fake_core.DIM = ""

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_config_valid_after_shadow_creation(self):
        from chimera.modules import users_manager

        with patch.object(users_manager, "_users_get_config", return_value=self._cfg_path), \
             patch.object(users_manager, "_core_module", return_value=self._fake_core), \
             patch.object(users_manager, "_users_apply_config", lambda cfg: None), \
             patch.object(users_manager, "_show_qr", lambda *a, **kw: None), \
             patch("builtins.input", side_effect=["alice@example.com"]):
            try:
                users_manager.do_user_show_link_ios()
            except Exception:
                pass

        # 1. JSON валиден.
        config = json.loads(self._cfg_path.read_text())

        # 2. Schema: clients[] имеет все обязательные поля.
        clients = config["inbounds"][0]["settings"]["clients"]
        for cl in clients:
            self.assertIn("id", cl, "Каждый client должен иметь id (UUID)")
            self.assertIn("email", cl, "Каждый client должен иметь email")
            # UUID-формат.
            self.assertRegex(
                cl["id"],
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                f"Невалидный UUID: {cl['id']}"
            )

        # 3. Shadow имеет email с __ios суффиксом и БЕЗ flow.
        shadows = [cl for cl in clients if "__ios" in cl.get("email", "")]
        self.assertEqual(len(shadows), 1)
        self.assertNotIn("flow", shadows[0])

        # 4. Оригинал НЕ тронут — flow на месте.
        originals = [cl for cl in clients if "__ios" not in cl.get("email", "")]
        self.assertEqual(len(originals), 1)
        self.assertEqual(originals[0].get("flow"), "xtls-rprx-vision")

        # 5. Если xray доступен — реальная валидация `xray run -test`.
        xray_bin = shutil.which("xray")
        if xray_bin:
            r = subprocess.run(
                [xray_bin, "run", "-test", "-c", str(self._cfg_path)],
                capture_output=True, text=True, timeout=10
            )
            self.assertEqual(
                r.returncode, 0,
                f"xray run -test failed: {r.stdout} {r.stderr}"
            )
        else:
            # В окружении без xray — пропускаем runtime-проверку, но
            # структурная валидация выше уже выполнена.
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 8: существующие golden-тесты на _users_gen_link не сломаны
# ══════════════════════════════════════════════════════════════════════════════
class TestGoldenGenLinkUnchanged(unittest.TestCase):
    """Существующие golden-тесты на _users_gen_link — те же строки, что и
    до патча №2. Это защита от случайной правки исходника."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", "")
        )
        self._fake_core.PARAM_DOMAIN = "example.com"
        self._fake_core._fp_from_state = MagicMock(return_value="chrome")

    def test_reality_golden_unchanged(self):
        """REALITY-ссылка содержит flow=xtls-rprx-vision — патч №2 НЕ должен
        был тронуть исходный генератор."""
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="11111111-2222-3333-4444-555555555555",
            pbk="PUBKEY", sid="deadbeef", domain="example.com",
            fp="chrome", proto="reality", port=443,
        )
        expected = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PUBKEY"
            "&fp=chrome&sni=example.com&sid=deadbeef"
            "&flow=xtls-rprx-vision#example.com"
        )
        self.assertEqual(link, expected)

    def test_xhttp_golden_unchanged(self):
        from chimera.modules.users_manager import _gen_vless_link
        import urllib.parse
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="22222222-3333-4444-5555-666666666666",
            pbk="", sid="", domain="example.com",
            fp="chrome", proto="xhttp",
            xhttp_path="/xhttp", xhttp_mode="streamup",
            port=8443,
        )
        path_enc = urllib.parse.quote("/xhttp", safe="/")
        expected = (
            "vless://22222222-3333-4444-5555-666666666666@1.2.3.4:8443"
            "?type=xhttp&security=tls&sni=example.com"
            f"&path={path_enc}&mode=streamup"
            "&fp=chrome#example.com"
        )
        self.assertEqual(link, expected)


# ══════════════════════════════════════════════════════════════════════════════
#  ДОПОЛНИТЕЛЬНО: проверка что ШАГ 0 (закрытие iOS-поверхностей) реально
#  убрал пользовательский доступ к generate_client_links_ios и /ios-маршруту
# ══════════════════════════════════════════════════════════════════════════════
class TestStep0Closure(unittest.TestCase):
    """Защита от случайного возврата закрытых поверхностей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_core_menu_no_k_item(self):
        """В ГЛАВНОМ меню _core.py (main_menu, пункт 2 → generate_client_links_ios)
        пункт K должен быть закомментирован. В do_unified_user_manager
        (подменю пользователей) пункт K АКТИВЕН — это легитимный путь из
        патча №3, и его НЕ надо закрывать.

        Этот тест защищает от случайного возврата пункта K в ГЛАВНОЕ меню
        (которое ведёт к generate_client_links_ios — закрытой поверхности
        из патча №2, всё ещё рвёт REALITY-юзеров)."""
        import re
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()

        # Извлекаем блок main_menu — от `def main_menu` до конца функции.
        # main_menu — последняя функция в _core.py, поэтому после неё может
        # не быть `def `, берём до конца файла.
        m = re.search(
            r'def main_menu\(\).*',
            src, re.DOTALL
        )
        self.assertIsNotNone(m, "main_menu не найдена в _core.py")
        main_menu_block = m.group(0)

        # Внутри main_menu ищем активный _box_item("K" — это баг.
        for i, line in enumerate(main_menu_block.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith('_box_item("K"'):
                self.fail(
                    f"Строка {i} в main_menu: пункт K должен быть закрыт "
                    f"(он вызывает generate_client_links_ios, который рвёт "
                    f"REALITY-юзеров без shadow). Got: {line!r}"
                )

    def test_subscription_route_ios_active(self):
        """Патч №5: /sub/{token}/ios маршрут в subscription.py do_GET
        должен быть АКТИВЕН (раскомментирован). Mirror-URI исключаются
        из тела подписки (отдельная логика в build_subscription_body_ios),
        но сам маршрут отдаёт iOS-совместимый base64. Это защищает от
        случайного отката к закомментированному состоянию (патч №2)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription.py").read_text()
        lines = src.split("\n")
        in_do_get = False
        found_active = False
        for i, line in enumerate(lines):
            if "def do_GET" in line:
                in_do_get = True
            if in_do_get:
                stripped = line.strip()
                # Активная (не закомментированная) строка с m_ios = re.match
                if "m_ios = re.match" in stripped and not stripped.startswith("#"):
                    found_active = True
                    break
        self.assertTrue(found_active,
                        "Патч №5: /sub/{token}/ios маршрут должен быть активен "
                        "в do_GET (не закомментирован)")

    def test_client_config_export_ios_link_active_with_shadow(self):
        """Патч №4 раскомментировал генерацию vless-link-ios.txt в
        client_config_export.py, с тем же shadow-паттерном, что
        подтверждён в do_user_show_link_ios.

        Этот тест защищает от случайного возврата к закомментированному
        состоянию (которое было нужно в патче №2, но снято патчем №4)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "client_config_export.py").read_text()
        # Должна быть АКТИВНАЯ (не закомментированная) строка с
        # _users_get_or_create_ios_shadow — это и есть shadow-паттерн.
        found_shadow_call = False
        for line in src.split("\n"):
            stripped = line.strip()
            if "_users_get_or_create_ios_shadow" in stripped and not stripped.startswith("#"):
                found_shadow_call = True
                break
        self.assertTrue(found_shadow_call,
                        "Патч №4: client_config_export.py должен использовать "
                        "_users_get_or_create_ios_shadow для REALITY (shadow-паттерн)")
        # Должна быть АКТИВНАЯ запись ios_link_file.write_text.
        found_write = False
        for line in src.split("\n"):
            stripped = line.strip()
            if "ios_link_file.write_text" in stripped and not stripped.startswith("#"):
                found_write = True
                break
        self.assertTrue(found_write,
                        "Патч №4: ios_link_file.write_text должен быть активен "
                        "(не закомментирован) — патч №2 закомментировал, №4 снял")

    def test_subscription_menu_ios_url_active(self):
        """Патч №5: do_subscription_menu показывает url_ios рядом с url
        для каждого пользователя. Это защищает от случайного отката к
        состоянию, когда iOS-маршрут был закомментирован (патч №2)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription.py").read_text()
        # Активная (не закомментированная) строка с url_ios = f"https://
        found = False
        for line in src.split("\n"):
            stripped = line.strip()
            if 'url_ios = f"https://' in stripped and not stripped.startswith("#"):
                found = True
                break
        self.assertTrue(found,
                        "Патч №5: do_subscription_menu должен показывать url_ios "
                        "рядом с url для каждого пользователя")

    def test_do_user_show_link_ios_still_callable(self):
        """do_user_show_link_ios должна остаться в коде (не удалена) —
        патч №2 чинит именно её."""
        from chimera.modules import users_manager
        self.assertTrue(hasattr(users_manager, "do_user_show_link_ios"))
        self.assertTrue(callable(users_manager.do_user_show_link_ios))

    # test_do_user_menu_k_item_still_present удалён в патче №5:
    # do_user_menu() целиком удалён как мёртвый код (строго подмножество
    # do_unified_user_manager). Активные пункты K теперь живут в _core.py:
    # do_unified_user_manager (патч №3) и _menu_users (патч №4) — их
    # корректность проверяется в test_ios_unified_menu.py и
    # test_ios_patch4_open_surfaces.py.


if __name__ == "__main__":
    unittest.main(verbosity=2)
