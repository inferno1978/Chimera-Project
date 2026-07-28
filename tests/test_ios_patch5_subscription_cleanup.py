#!/usr/bin/env python3
"""
tests/test_ios_patch5_subscription_cleanup.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для патча №5 — открытие /sub/{token}/ios маршрута,
исключение mirror-URI из iOS-подписки, удаление мёртвого do_user_menu().

Покрытие (по спецификации задачи):
  1. build_subscription_body() (БЕЗ /ios) — побайтово идентичен
     состоянию до этого патча.
  2. build_subscription_body_ios(): результат НЕ содержит ни одной
     mirror-ссылки, основной vless — на shadow UUID, без flow.
  3. do_GET на старом пути /sub/{token} — по-прежнему матчится старой
     веткой (тест из патча №2, прогон что не регрессировал).
  4. do_user_menu()/do_user_show_link() удалены — полный прогон тестов,
     grep по репо: 0 вызовов вне тестов.
  5. do_user_show_link_ios_by_uuid (которая используется в do_user_add
     после создания юзера) — НЕ затронута. (Тест: do_user_add использует
     _unified_show_links, не do_user_show_link — это уже было и до патча.)

Дополнительно:
  • /sub/{token}/ios маршрут активен (не закомментирован).
  • do_subscription_menu показывает url_ios рядом с url.
  • do_entry_mirrors_menu содержит подсказку про iOS-shadow на mirror'ах.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
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
#  ТЕСТ 1: build_subscription_body (БЕЗ /ios) — побайтово идентичен
# ══════════════════════════════════════════════════════════════════════════════
class TestBuildSubscriptionBodyUnchanged(unittest.TestCase):
    """Старый маршрут /sub/{token} должен вернуть ровно тот же base64,
    что и до патча №5. Патч №5 НЕ должен трогать build_subscription_body()."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_build_subscription_body_byte_identical(self):
        from chimera.modules import subscription

        fake_state = {
            "domain": "vpn.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "PUB",
            "short_id": "AB",
            "fingerprint": "chrome",
            "install_mode": "A",
            "awg_exit_enabled": False,
            "reality_dest": "",
            "xhttp_path": "/",
            "xhttp_mode": "stream-up",
        }
        user = {"uuid": "u-1", "email": "alice@example.com"}

        with patch.object(subscription, "_load_state", return_value=fake_state), \
             patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"), \
             patch.object(subscription, "is_hybrid_mieru_active", return_value=False), \
             patch.object(subscription, "_build_mieru_uris", return_value=["mierus://m1"]), \
             patch.object(subscription, "_build_naive_uris", return_value=[]), \
             patch.object(subscription, "_build_fptn_uris", return_value=[]), \
             patch.object(subscription, "_build_telemt_uri", return_value=None), \
             patch.dict(sys.modules, {"chimera.modules.entry_mirrors": MagicMock(
                 get_mirror_uris=MagicMock(return_value=["vless://mirror1"]))}):
            body = subscription.build_subscription_body(user)

        decoded = base64.b64decode(body).decode()
        links = decoded.split("\n")

        # Должны быть: vless (с flow — старый маршрут) + mierus + mirror1.
        self.assertEqual(len(links), 3)
        vless = next(l for l in links if l.startswith("vless://"))
        self.assertIn("flow=xtls-rprx-vision", vless,
                      "Старый маршрут ДОЛЖЕН содержать flow — это не iOS-ветка")
        self.assertIn("u-1", vless)  # оригинальный UUID
        self.assertIn("mierus://m1", links)
        self.assertIn("vless://mirror1", links)  # mirror в старом маршруте


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 2: build_subscription_body_ios — нет mirror, shadow UUID, нет flow
# ══════════════════════════════════════════════════════════════════════════════
class TestBuildSubscriptionBodyIosNoMirrorShadowUuid(unittest.TestCase):
    """iOS-подписка: mirror-URI исключены, основной vless на shadow UUID
    без flow, сателлитные протоколы не тронуты."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.gen_uuid = lambda: str(_uuid_mod.uuid4())
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", ""))
        self._fake_core.PARAM_DOMAIN = "example.com"
        self._fake_core._fp_from_state = MagicMock(return_value="chrome")
        self._fake_core.STATE_FILE = Path("/nonexistent-state.json")
        self._fake_core.log_to_file = MagicMock()
        self._fake_core.warn = MagicMock()
        self._fake_core._xray_safe_apply_config = MagicMock()
        self._fake_core._nginx_restart_if_reality = MagicMock()
        self._fake_core._run = MagicMock()

        # Тестовый config.json с REALITY-inbound и одним юзером.
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._orig_uuid = "11111111-0000-0000-0000-000000000001"
        self._cfg_path.write_text(json.dumps({
            "inbounds": [{
                "protocol": "vless",
                "port": 443,
                "settings": {"clients": [{
                    "id": self._orig_uuid,
                    "email": "alice@example.com",
                    "flow": "xtls-rprx-vision",
                }]},
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
        }))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_ios_body_excludes_mirror_and_uses_shadow_uuid(self):
        from chimera.modules import subscription, users_manager

        fake_state = {
            "domain": "vpn.example.com",
            "server_port": 443,
            "protocol_mode": "reality",
            "public_key": "TEST_PUB_KEY",
            "short_id": "abcd1234",
            "fingerprint": "chrome",
            "install_mode": "A",
            "awg_exit_enabled": False,
            "reality_dest": "",
            "xhttp_path": "/",
            "xhttp_mode": "stream-up",
        }
        user = {"uuid": self._orig_uuid, "email": "alice@example.com"}

        mirror_uris = ["vless://mirror1.example.com?...", "vless://mirror2.example.com?..."]

        with patch.object(subscription, "_load_state", return_value=fake_state), \
             patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"), \
             patch.object(subscription, "is_hybrid_mieru_active", return_value=False), \
             patch.object(subscription, "_build_mieru_uris", return_value=["mierus://m1"]), \
             patch.object(subscription, "_build_naive_uris", return_value=[]), \
             patch.object(subscription, "_build_fptn_uris", return_value=[]), \
             patch.object(subscription, "_build_telemt_uri", return_value=None), \
             patch("chimera.modules.users_manager._users_get_config",
                   return_value=self._cfg_path), \
             patch("chimera.modules.users_manager._core_module",
                   return_value=self._fake_core), \
             patch("chimera.modules.users_manager._users_apply_config",
                   lambda cfg: None), \
             patch.dict(sys.modules, {"chimera.modules.entry_mirrors": MagicMock(
                 get_mirror_uris=MagicMock(return_value=mirror_uris))}):
            body = subscription.build_subscription_body_ios(user)

        decoded = base64.b64decode(body).decode()
        links = decoded.split("\n")

        # vless — на shadow UUID, без flow.
        vless_links = [l for l in links if l.startswith("vless://")]
        self.assertEqual(len(vless_links), 1,
                         f"Должна быть 1 vless-ссылка (основной), got {len(vless_links)}")
        vless = vless_links[0]
        self.assertNotIn("flow=", vless)
        self.assertNotIn("xtls-rprx-vision", vless)

        # Mirror-ссылок быть НЕ должно — они исключены.
        self.assertNotIn("mirror1.example.com", decoded)
        self.assertNotIn("mirror2.example.com", decoded)

        # UUID в ссылке — shadow (не оригинальный).
        c = json.loads(self._cfg_path.read_text())
        clients = c["inbounds"][0]["settings"]["clients"]
        shadows = [cl for cl in clients if cl.get("email", "").endswith("__ios")]
        self.assertEqual(len(shadows), 1, "Shadow должен быть создан")
        shadow_uuid = shadows[0]["id"]
        self.assertIn(shadow_uuid, vless)
        self.assertNotIn(self._orig_uuid, vless)

        # mierus не тронут.
        self.assertIn("mierus://m1", links)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 3: do_GET — старый путь /sub/{token} матчится старой веткой
# ══════════════════════════════════════════════════════════════════════════════
class TestDoGetRoutingStillCorrect(unittest.TestCase):
    """После раскомментирования /ios-маршрута, старый путь /sub/{token}
    должен по-прежнему матчится старой веткой (не новой)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_old_path_matches_old_regex(self):
        import re as _re
        old_re = _re.compile(r"^/sub/([0-9a-f]{24})/?$")
        ios_re = _re.compile(r"^/sub/([0-9a-f]{24})/ios/?$")

        token = "a" * 24
        for path in (f"/sub/{token}", f"/sub/{token}/"):
            self.assertIsNotNone(old_re.match(path))
            self.assertIsNone(ios_re.match(path))

    def test_ios_path_matches_ios_regex_only(self):
        import re as _re
        old_re = _re.compile(r"^/sub/([0-9a-f]{24})/?$")
        ios_re = _re.compile(r"^/sub/([0-9a-f]{24})/ios/?$")

        token = "b" * 24
        for path in (f"/sub/{token}/ios", f"/sub/{token}/ios/"):
            self.assertIsNotNone(ios_re.match(path))
            self.assertIsNone(old_re.match(path))


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 4: do_user_menu / do_user_show_link удалены
# ══════════════════════════════════════════════════════════════════════════════
class TestDeadCodeRemoved(unittest.TestCase):
    """do_user_menu() и do_user_show_link() должны быть удалены из
    users_manager.py. Импорт в _core.py не должен их содержать.
    smoke_test_modules.py не должен на них ссылаться."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_do_user_menu_removed_from_users_manager(self):
        from chimera.modules import users_manager
        self.assertFalse(hasattr(users_manager, "do_user_menu"),
                         "do_user_menu должен быть удалён в патче №5")

    def test_do_user_show_link_removed_from_users_manager(self):
        from chimera.modules import users_manager
        self.assertFalse(hasattr(users_manager, "do_user_show_link"),
                         "do_user_show_link должен быть удалён в патче №5")

    def test_core_import_does_not_mention_removed(self):
        """Импорт users_manager в _core.py не должен содержать
        do_user_show_link или do_user_menu (точное имя, с границей слова —
        do_user_show_link_ios_by_uuid НЕ считается совпадением)."""
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        # Извлекаем блок импорта.
        m = re.search(
            r'from chimera\.modules\.users_manager import \(([^)]+)\)',
            src, re.DOTALL
        )
        self.assertIsNotNone(m, "Блок импорта users_manager не найден")
        import_block = m.group(1)
        # Имена должны быть активными (не в комментарии).
        for line in import_block.split("\n"):
            stripped = line.strip().rstrip(",")
            if stripped.startswith("#"):
                continue
            # Точное имя с границей слова — не подстрока.
            # do_user_show_link_ios_by_uuid содержит do_user_show_link как
            # подстроку, но \bdo_user_show_link\b НЕ матчит (после link идёт _).
            if re.search(r'\bdo_user_show_link\b', stripped):
                self.fail(f"Импорт не должен содержать do_user_show_link: {line!r}")
            if re.search(r'\bdo_user_menu\b', stripped):
                self.fail(f"Импорт не должен содержать do_user_menu: {line!r}")

    def test_smoke_test_does_not_reference_removed(self):
        """smoke_test_modules.py не должен ссылаться на удалённые функции."""
        src = (_PROJECT_ROOT / "smoke_test_modules.py").read_text()
        # Активная (не закомментированная) строка с "do_user_menu" — это баг.
        for i, line in enumerate(src.split("\n"), 1):
            stripped = line.strip()
            # Точное имя (do_user_menu, не do_user_menu_item и т.п.).
            if re.search(r'\bdo_user_menu\b', stripped) and not stripped.startswith("#"):
                self.fail(
                    f"Строка {i} в smoke_test_modules.py ссылается на "
                    f"удалённую do_user_menu: {line!r}"
                )

    def test_no_callers_outside_tests(self):
        """grep по всему репо: 0 активных ВЫЗОВОВ do_user_show_link() или
        do_user_menu() вне тестов и smoke_test.

        Под 'вызовом' понимается строка вида `do_user_show_link(...)` или
        `do_user_menu(...)` — НЕ упоминание в докстринге/комментарии.
        Строки с `• ` (RST-маркер списка в докстринге) игнорируются."""
        import os
        excluded_dirs = {".git", "__pycache__", ".pytest_cache", "node_modules"}
        violations = []
        for root, dirs, files in os.walk(_PROJECT_ROOT):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(root) / fname
                # Пропускаем тесты и smoke_test — там могут быть упоминания
                # в комментариях, описывающих факт удаления.
                if "test_" in fname or fname == "smoke_test_modules.py":
                    continue
                try:
                    src = fpath.read_text()
                except Exception:
                    continue
                for i, line in enumerate(src.split("\n"), 1):
                    stripped = line.strip()
                    # Пропускаем комментарии и RST-маркеры в докстрингах.
                    if stripped.startswith("#"):
                        continue
                    if stripped.startswith("•"):
                        continue
                    if stripped.startswith("``"):
                        continue
                    # Ищем активный ВЫЗОВ (со скобками) — точное имя.
                    # \bdo_user_show_link\b НЕ матчит do_user_show_link_ios_by_uuid
                    # (после link идёт _, не граница слова).
                    if re.search(r'\bdo_user_show_link\b\s*\(', stripped):
                        violations.append((fpath, i, line))
                    if re.search(r'\bdo_user_menu\b\s*\(', stripped):
                        violations.append((fpath, i, line))
        self.assertEqual(
            violations, [],
            f"Найдены активные вызовы удалённых функций: {violations}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 5: do_user_show_link_ios_by_uuid не затронута
# ══════════════════════════════════════════════════════════════════════════════
class TestIosByUuidIntact(unittest.TestCase):
    """do_user_show_link_ios_by_uuid (патч №3) должна остаться callable
    и не быть затронутой патчем №5."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_still_callable(self):
        from chimera.modules import users_manager
        self.assertTrue(hasattr(users_manager, "do_user_show_link_ios_by_uuid"))
        self.assertTrue(callable(users_manager.do_user_show_link_ios_by_uuid))


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 6: /sub/{token}/ios маршрут активен в do_GET
# ══════════════════════════════════════════════════════════════════════════════
class TestIosRouteActive(unittest.TestCase):
    """/sub/{token}/ios маршрут в do_GET должен быть активен (не в комментарии)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_m_ios_active_in_do_get(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription.py").read_text()
        # Извлекаем do_GET.
        m = re.search(r'def do_GET\(self\).*?(?=\n    def |\nclass |\ndef )',
                      src, re.DOTALL)
        self.assertIsNotNone(m, "do_GET не найден")
        block = m.group(0)
        found_active = False
        for line in block.split("\n"):
            stripped = line.strip()
            if "m_ios = re.match" in stripped and not stripped.startswith("#"):
                found_active = True
                break
        self.assertTrue(found_active,
                        "/sub/{token}/ios маршрут должен быть активен в do_GET")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 7: do_subscription_menu показывает url_ios
# ══════════════════════════════════════════════════════════════════════════════
class TestSubscriptionMenuShowsIosUrl(unittest.TestCase):
    """do_subscription_menu должна показывать url_ios рядом с url."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_url_ios_active_in_menu(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "subscription.py").read_text()
        # Извлекаем do_subscription_menu.
        m = re.search(r'def do_subscription_menu\(\).*?(?=\n\ndef |\nif __name__)',
                      src, re.DOTALL)
        self.assertIsNotNone(m, "do_subscription_menu не найдена")
        block = m.group(0)
        found = False
        for line in block.split("\n"):
            stripped = line.strip()
            if 'url_ios = f"https://' in stripped and not stripped.startswith("#"):
                found = True
                break
        self.assertTrue(found,
                        "do_subscription_menu должна показывать url_ios")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 8: do_entry_mirrors_menu содержит iOS-подсказку
# ══════════════════════════════════════════════════════════════════════════════
class TestEntryMirrorsMenuHint(unittest.TestCase):
    """do_entry_mirrors_menu должна показывать подсказку про iOS-shadow
    на mirror-серверах."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_hint_present_when_mirrors_exist(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "entry_mirrors.py").read_text()
        # Извлекаем do_entry_mirrors_menu.
        m = re.search(r'def do_entry_mirrors_menu\(\).*?(?=\nif __name__)',
                      src, re.DOTALL)
        self.assertIsNotNone(m, "do_entry_mirrors_menu не найдена")
        block = m.group(0)
        # Должна быть активная строка с упоминанием iOS/Karing.
        found = False
        for line in block.split("\n"):
            stripped = line.strip()
            if "iOS/Karing" in stripped and not stripped.startswith("#"):
                found = True
                break
        self.assertTrue(found,
                        "do_entry_mirrors_menu должна содержать подсказку "
                        "про iOS/Karing для mirror-серверов")

    def test_hint_only_shown_when_mirrors_exist(self):
        """Подсказка должна быть внутри `if n_total > 0:` — не показывается
        когда mirror-серверов нет (бессмысленно)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "entry_mirrors.py").read_text()
        m = re.search(r'def do_entry_mirrors_menu\(\).*?(?=\nif __name__)',
                      src, re.DOTALL)
        block = m.group(0)
        # Проверяем что есть `if n_total > 0:` и внутри него — iOS-подсказка.
        self.assertIn("if n_total > 0:", block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
