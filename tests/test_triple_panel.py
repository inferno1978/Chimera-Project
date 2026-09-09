#!/usr/bin/env python3
"""
tests/test_triple_panel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/triple_panel.py + triple_panel_web.py.

Тестируем (чистая логика + контракты делегации на фейках):
  1. Версии: _version_key / _strip_v / _update_availability (кэш+сравнение)
  2. Порты: _validate_web_port (конфликт-чек через port_registry)
  3. Фронт: _front_mirror_urls (URL тарболлов) + _extract_front
     (реальный tar.gz: структура panel/public, LICENSE-кредит,
     path-traversal guard)
  4. Админ-креды: _set_admin_password/_check_credentials (salt+sha256)
  5. Сессии: create/user/drop/TTL
  6. Unified-view: _panel_user_row (protocols/expiry/quota/used)
  7. Конвертеры: _expiry_to_days / _quota_to_gb
  8. Статика: _safe_join (traversal, каталоги, SPA-фолбэк на уровне роутинга)
  9. Подписка: _sub_response (format routing на фейке subscription.py)
 10. CRUD: _create_panel_user / _delete_panel_user / _update_panel_user
     (фейковые rest_api / ttl_users / user_lifecycle / naiveproxy / mieru)
 11. v82 SSE: шина (publish/subscribe/unsubscribe/drop) + логи (_logs_response)
 12. v82 SSE-шим: _inject_sse_shim (до app.js, идемпотентность, фолбэк)
 13. v82 юзеры: ротация пароля (set_password_full) + rename email
     (мост v4.25 + перенос TTL/квот)
 14. v82 порты: _set_naive_port / _set_mieru_ports (валидация, конфликты,
     port_registry-перерегистрация, откат)
 15. v82 каскад/WARP: view/apply/reset + normalize_upstream + взаимное
     исключение (BUG-150) + деградация full→runet без SSH-IP
"""
from __future__ import annotations

import io
import json
import queue
import sys
import tarfile
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ── хелперы подмены модулей ──────────────────────────────────────────────
# ВАЖНО: `from X import Y` резолвится ЧЕРЕЗ атрибут родительского пакета,
# если реальный модуль уже был импортирован (например, соседним тест-
# сьютом в общем прогоне). Одного sys.modules-фейка мало — патчим и
# атрибут родителя, иначе фейк тихо обходится и тесты падают на
# AttributeError в РЕАЛЬНОМ модуле.

def _install_fake(name: str, mod) -> None:
    sys.modules[name] = mod
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    if parent_mod is not None:
        setattr(parent_mod, child, mod)


def _snapshot_module(name: str) -> tuple:
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    had_attr = parent_mod is not None and hasattr(parent_mod, child)
    return (sys.modules.get(name),
            getattr(parent_mod, child, None) if had_attr else None,
            had_attr)


def _restore_module(name: str, snap: tuple) -> None:
    mod, attr, had_attr = snap
    if mod is not None:
        sys.modules[name] = mod
    else:
        sys.modules.pop(name, None)
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    if parent_mod is not None:
        if had_attr:
            setattr(parent_mod, child, attr)
        elif hasattr(parent_mod, child):
            delattr(parent_mod, child)


from chimera.modules import triple_panel as tp
from chimera.modules import triple_panel_web as web


# ══════════════════════════════════════════════════════════════════════════════
#  1. ВЕРСИИ
# ══════════════════════════════════════════════════════════════════════════════
class TestVersionLogic(unittest.TestCase):

    def test_version_key_parses(self):
        self.assertEqual(tp._version_key("v1.11.2"), (1, 11, 2))
        self.assertEqual(tp._version_key("1.11.2"), (1, 11, 2))
        self.assertEqual(tp._version_key("v2.0"), (2, 0))
        self.assertEqual(tp._version_key(""), (0,))
        self.assertEqual(tp._version_key(None), (0,))

    def test_version_key_ordering(self):
        self.assertTrue(tp._version_key("1.11.2") > tp._version_key("1.11.1"))
        self.assertTrue(tp._version_key("1.12.0") > tp._version_key("1.11.99"))
        self.assertTrue(tp._version_key("2.0.0") > tp._version_key("1.99.99"))

    def test_strip_v(self):
        self.assertEqual(tp._strip_v("v1.2.3"), "1.2.3")
        self.assertEqual(tp._strip_v("1.2.3"), "1.2.3")
        self.assertEqual(tp._strip_v(""), "")

    def test_update_availability_matrix(self):
        cases = [
            ("1.11.2", "1.11.2", "up-to-date"),
            ("1.11.2", "1.11.3", "update-available"),
            ("1.12.0", "1.11.9", "up-to-date"),
            ("", "1.11.2", "unknown"),
            ("1.11.2", "", "unknown"),
        ]
        for front, upstream, expected in cases:
            with patch.object(tp, "_load_state",
                              return_value={"front_version": front}), \
                 patch.object(tp, "_refresh_upstream_cache",
                              return_value=upstream):
                self.assertEqual(tp._update_availability(), expected,
                                 f"front={front} upstream={upstream}")


# ══════════════════════════════════════════════════════════════════════════════
#  2. ПОРТЫ
# ══════════════════════════════════════════════════════════════════════════════
class TestPortValidation(unittest.TestCase):

    def test_range_rejected(self):
        for bad in (0, 80, 1023, 65536, -1):
            ok, conflicts = tp._validate_web_port(bad)
            self.assertFalse(ok)

    def test_valid_port_no_conflicts(self):
        with patch.object(tp, "_port_conflicts", return_value=[]), \
             patch.object(tp, "_port_busy_system", return_value=[]):
            ok, conflicts = tp._validate_web_port(9760)
            self.assertTrue(ok)
            self.assertEqual(conflicts, [])

    def test_conflict_detected(self):
        with patch.object(tp, "_port_conflicts",
                          return_value=["занят: vless-web (tcp)"]), \
             patch.object(tp, "_port_busy_system", return_value=[]):
            ok, conflicts = tp._validate_web_port(8443)
            self.assertFalse(ok)
            self.assertIn("занят: vless-web (tcp)", conflicts)


# ══════════════════════════════════════════════════════════════════════════════
#  3. ФРОНТ: URL + РАСПАКОВКА
# ══════════════════════════════════════════════════════════════════════════════
class TestFrontFetch(unittest.TestCase):

    def test_mirror_urls_from_tag(self):
        urls = tp._front_mirror_urls("triple-panel-front-v1.11.2.tar.gz")
        self.assertEqual(len(urls), 2)
        self.assertIn("archive/refs/tags/v1.11.2.tar.gz", urls[0])
        self.assertIn("codeload.github.com", urls[1])
        self.assertIn(tp._UPSTREAM_REPO, urls[0])

    def test_mirror_urls_latest(self):
        urls = tp._front_mirror_urls("triple-panel-front-latest.tar.gz")
        self.assertTrue(all("main" in u for u in urls))

    def _make_front_tarball(self, tmp: Path) -> Path:
        """Собирает тарболл со структурой апстрима + poison-файл с '../'."""
        tar_path = tmp / "front.tar.gz"
        payload_files = {
            "Panel-Naive-Mieru-by-RIXXX-1.11.2/panel/public/index.html":
                b"<html>panel</html>",
            "Panel-Naive-Mieru-by-RIXXX-1.11.2/panel/public/app.js":
                b"console.log(1);",
            "Panel-Naive-Mieru-by-RIXXX-1.11.2/panel/public/locales/ru.json":
                b'{"a":1}',
            "Panel-Naive-Mieru-by-RIXXX-1.11.2/README.md": b"readme",
            "Panel-Naive-Mieru-by-RIXXX-1.11.2/panel/server/index.js": b"x",
        }
        with tarfile.open(tar_path, "w:gz") as tar:
            for name, data in payload_files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            # Poison: traversal-член должен быть отброшен экстрактором
            poison = tarfile.TarInfo(
                "Panel-Naive-Mieru-by-RIXXX-1.11.2/../../etc/evil")
            poison.size = 5
            tar.addfile(poison, io.BytesIO(b"EVIL!"))
        return tar_path

    def test_extract_front(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            tar_path = self._make_front_tarball(tmpdir)
            dest = tmpdir / "www"
            self.assertTrue(tp._extract_front(tar_path, dest))
            # только panel/public/* — остальное (README, server/) не едет
            self.assertTrue((dest / "index.html").exists())
            self.assertTrue((dest / "app.js").exists())
            self.assertTrue((dest / "locales" / "ru.json").exists())
            self.assertFalse((dest / "README.md").exists())
            # traversal-файл не создан
            self.assertFalse((tmpdir / "etc").exists() or
                             Path("/etc/evil").exists())
            # LICENSE-кредит апстриму
            self.assertTrue((dest / "LICENSE.upstream").exists())

    def test_extract_front_bad_tarball(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bad = tmpdir / "bad.tar.gz"
            bad.write_bytes(b"not a tarball at all")
            self.assertFalse(tp._extract_front(bad, tmpdir / "www"))


# ══════════════════════════════════════════════════════════════════════════════
#  4. АДМИН-КРЕДЫ
# ══════════════════════════════════════════════════════════════════════════════
class TestAdminAuth(unittest.TestCase):

    def test_set_and_check(self):
        state = {}
        tp._set_admin_password(state, "s3cret-pass")
        self.assertTrue(state["admin_pass_salt"])
        self.assertTrue(state["admin_pass_sha256"])
        self.assertTrue(web._check_credentials(state, "any", "s3cret-pass"))
        self.assertFalse(web._check_credentials(state, "any", "wrong"))
        self.assertFalse(web._check_credentials(state, "any", ""))

    def test_empty_state_rejects(self):
        self.assertFalse(web._check_credentials({}, "admin", "x"))
        self.assertFalse(web._check_credentials(
            {"admin_pass_salt": "s", "admin_pass_sha256": ""}, "a", "b"))

    def test_different_salts_differ(self):
        s1, s2 = {}, {}
        tp._set_admin_password(s1, "same-password")
        tp._set_admin_password(s2, "same-password")
        self.assertNotEqual(s1["admin_pass_sha256"], s2["admin_pass_sha256"])


# ══════════════════════════════════════════════════════════════════════════════
#  5. СЕССИИ
# ══════════════════════════════════════════════════════════════════════════════
class TestSessions(unittest.TestCase):

    def setUp(self):
        web._SESSIONS.clear()

    def test_create_and_lookup(self):
        token = web._session_create("admin")
        self.assertTrue(token)
        self.assertEqual(web._session_user(token), "admin")
        self.assertIsNone(web._session_user("bogus"))
        self.assertIsNone(web._session_user(None))

    def test_drop(self):
        token = web._session_create("admin")
        web._session_drop(token)
        self.assertIsNone(web._session_user(token))

    def test_expiry(self):
        token = web._session_create("admin")
        web._SESSIONS[token]["exp"] = time.time() - 1
        self.assertIsNone(web._session_user(token))
        self.assertNotIn(token, web._SESSIONS)

    def test_token_unguessable(self):
        t1, t2 = web._session_create("a"), web._session_create("a")
        self.assertNotEqual(t1, t2)


# ══════════════════════════════════════════════════════════════════════════════
#  6. UNIFIED-VIEW: _panel_user_row
# ══════════════════════════════════════════════════════════════════════════════
class TestPanelUserRow(unittest.TestCase):

    NAIVE = [{"username": "vasya", "password": "pw1"}]
    MIERU = [{"username": "vasya", "password": "pw2"},
             {"username": "petya", "password": "pw3"}]
    TTL = {"vasya@x.com": {"expires_at": "2026-12-31T23:59:59+00:00",
                            "days": 7, "notified_24h": False}}
    LIMITS = {"vasya@x.com": {"limit_gb": 5, "used_bytes": 1048576}}

    def test_row_shape(self):
        user = {"email": "vasya@x.com", "uuid": "u-1", "name": "vasya",
                "created": "2026-01-01T00:00:00"}
        with patch.object(web, "_sub_token_for_user", return_value="tok42"):
            row = web._panel_user_row(user, self.NAIVE, self.MIERU,
                                      self.TTL, self.LIMITS)
        self.assertEqual(row["id"], "vasya@x.com")
        self.assertEqual(row["username"], "vasya")
        self.assertEqual(sorted(row["protocols"]), ["mieru", "naive"])
        self.assertEqual(row["expiry"], "2026-12-31T23:59:59+00:00")
        self.assertEqual(row["quotaMB"], 5 * 1024)
        self.assertEqual(row["usedMB"], 1.0)   # 1 MiB
        self.assertEqual(row["subToken"], "tok42")
        self.assertTrue(row["active"])
        self.assertEqual(row["createdAt"], "2026-01-01T00:00:00")

    def test_row_without_extras(self):
        user = {"email": "petya@x.com", "uuid": "u-2", "name": "",
                "created": "c"}
        with patch.object(web, "_sub_token_for_user", return_value="t"):
            row = web._panel_user_row(user, self.NAIVE, self.MIERU,
                                      {}, {})
        self.assertEqual(sorted(row["protocols"]), ["mieru"])
        self.assertIsNone(row["expiry"])
        self.assertEqual(row["quotaMB"], 0)
        self.assertEqual(row["usedMB"], 0)
        # name пуст → username из префикса email
        self.assertEqual(row["username"], "petya")

    def test_disabled_user(self):
        user = {"email": "d@x.com", "uuid": "u-3", "name": "d",
                "created": "c", "disabled": True}
        with patch.object(web, "_sub_token_for_user", return_value="t"):
            row = web._panel_user_row(user, [], [], {},
                                      {"d@x.com": {"limit_gb": 1,
                                                   "used_bytes": 0,
                                                   "disabled": True}})
        self.assertFalse(row["active"])


# ══════════════════════════════════════════════════════════════════════════════
#  7. КОНВЕРТЕРЫ
# ══════════════════════════════════════════════════════════════════════════════
class TestConverters(unittest.TestCase):

    def test_expiry_to_days_future(self):
        import datetime
        future = (datetime.date.today() + datetime.timedelta(days=6)).isoformat()
        days = web._expiry_to_days(future)
        self.assertTrue(6 <= days <= 7)

    def test_expiry_to_days_past(self):
        self.assertEqual(web._expiry_to_days("2020-01-01"), 1)

    def test_expiry_to_days_garbage(self):
        self.assertIsNone(web._expiry_to_days(""))
        self.assertIsNone(web._expiry_to_days(None))
        self.assertIsNone(web._expiry_to_days("not-a-date"))
        self.assertIsNone(web._expiry_to_days("2026-13-99"))

    def test_quota_to_gb(self):
        self.assertEqual(web._quota_to_gb(1024, None), 1)
        self.assertEqual(web._quota_to_gb(1, None), 1)      # min 1
        self.assertEqual(web._quota_to_gb(1536, None), 2)   # ceil
        self.assertEqual(web._quota_to_gb(0, 3), 3)
        self.assertEqual(web._quota_to_gb(None, None), 0)
        self.assertEqual(web._quota_to_gb("abc", "x"), 0)


# ══════════════════════════════════════════════════════════════════════════════
#  8. СТАТИКА: _safe_join
# ══════════════════════════════════════════════════════════════════════════════
class TestSafeJoin(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.www = Path(self.tmp.name) / "www"
        (self.www / "locales").mkdir(parents=True)
        (self.www / "index.html").write_text("<html>")
        (self.www / "app.js").write_text("1")
        (self.www / "locales" / "ru.json").write_text("{}")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ok_files(self):
        self.assertIsNotNone(web._safe_join(self.www, "index.html"))
        self.assertIsNotNone(web._safe_join(self.www, "/app.js"))
        self.assertIsNotNone(web._safe_join(self.www, "locales/ru.json"))
        # %2F-кодированный путь
        self.assertIsNotNone(
            web._safe_join(self.www, "locales%2Fru.json"))

    def test_traversal_blocked(self):
        self.assertIsNone(web._safe_join(self.www, "../etc/passwd"))
        self.assertIsNone(web._safe_join(self.www, "..%2F..%2Fetc"))
        self.assertIsNone(web._safe_join(self.www, "a/../../x"))

    def test_missing_and_dir(self):
        self.assertIsNone(web._safe_join(self.www, "nope.js"))
        self.assertIsNone(web._safe_join(self.www, "locales"))

    def test_www_missing(self):
        self.assertIsNone(web._safe_join(Path("/nonexistent-www"), "x"))


# ══════════════════════════════════════════════════════════════════════════════
#  9. ПОДПИСКА: _sub_response (фейковый subscription)
# ══════════════════════════════════════════════════════════════════════════════
def _fake_subscription_module():
    mod = types.ModuleType("chimera.modules.subscription")
    mod._load_sub_conf = lambda: {}
    mod._ensure_pepper = lambda cfg: "pepper"
    mod._find_user_by_token = (
        lambda token, pepper: {"email": "u@x.com", "uuid": "u1"}
        if token == "goodtoken" else None)
    mod._resolve_format = (
        lambda requested, ua: requested or
        {"nekobox": "singbox", "nyamebox": "singbox",
         "clash": "clash", "mihomo": "clash",
         "karing": "base64_safe"}.get(
             next((k for k in ("nekobox", "nyamebox", "clash", "mihomo",
                               "karing") if k in (ua or "").lower()), ""),
             "base64"))
    mod.build_subscription_body = (
        lambda user: __import__("base64").b64encode(
            b"naive+https://a:b@c\nmierus://link"))
    mod.build_subscription_singbox_config = (
        lambda user: '{"outbounds":[{"type":"direct"}]}')
    mod._filter_safe_links = (
        lambda links: [l for l in links
                       if not l.startswith("naive+https://")
                       and not l.startswith("mierus://")])
    mod._build_userinfo_header = (
        lambda user: "upload=0; download=1048576; total=5368709120")
    return mod


class TestSubResponse(unittest.TestCase):

    def setUp(self):
        self._snap = _snapshot_module("chimera.modules.subscription")
        _install_fake("chimera.modules.subscription",
                      _fake_subscription_module())

    def tearDown(self):
        _restore_module("chimera.modules.subscription", self._snap)

    def _run(self, token="goodtoken", fmt="", ua=""):
        return web._sub_response(token, fmt, ua)

    def test_404_unknown_token(self):
        status, _, _ = self._run(token="badtoken")
        self.assertEqual(status, 404)

    def test_base64_default(self):
        status, headers, body = self._run()
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))
        self.assertIn(b"naive+https://", __import__("base64").b64decode(body))
        self.assertIn("Subscription-Userinfo", headers)

    def test_ua_singbox(self):
        status, headers, body = self._run(ua="NekoBox/1.2")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertIn(b"outbounds", body)

    def test_ua_clash_builder_ok(self):
        fake_mn = types.ModuleType("chimera.modules.subscription_multinode")
        fake_mn.build_mihomo_config = lambda user: "proxies: []"
        snap_mn = _snapshot_module("chimera.modules.subscription_multinode")
        _install_fake("chimera.modules.subscription_multinode", fake_mn)
        try:
            status, headers, body = self._run(ua="ClashMeta/1.18")
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith("text/yaml"))
        finally:
            _restore_module("chimera.modules.subscription_multinode",
                            snap_mn)

    def test_ua_karing_base64_safe(self):
        status, headers, body = self._run(ua="Karing/1.0")
        self.assertEqual(status, 200)
        decoded = __import__("base64").b64decode(body).decode()
        self.assertNotIn("naive+https://", decoded)
        self.assertNotIn("mierus://", decoded)


# ══════════════════════════════════════════════════════════════════════════════
# 10. CRUD (фейковые rest_api / ttl_users / user_lifecycle / naiveproxy / mieru)
# ══════════════════════════════════════════════════════════════════════════════
class _FakeStore:
    """Мини-реплики хранилищ для CRUD-тестов."""
    def __init__(self):
        self.users = [{"email": "existing@x.com", "uuid": "u0",
                       "name": "existing", "portal_password": "p",
                       "created": "2026-01-01"}]
        self.ttl = {}
        self.limits = {}
        self.naive_removed = []
        self.mieru_removed = []
        self.applied = []


def _install_fakes(store: _FakeStore):
    ra = types.ModuleType("chimera.modules.rest_api")
    ra._get_users = lambda: list(store.users)
    ra._save_users = lambda users: setattr(store, "users", list(users))
    ra._sync_users_from_config = lambda: 0
    ra._sync_ensure_user = lambda name, user=None: {"naiveproxy": True,
                                                    "mieru": True}
    ra._sync_remove_user = lambda name, user=None: {}
    _install_fake("chimera.modules.rest_api", ra)

    ttl = types.ModuleType("chimera.modules.ttl_users")
    ttl._ttl_set = lambda email, days: store.ttl.update(
        {email: {"expires_at": f"days={days}", "days": days}})
    ttl._ttl_remove = lambda email: store.ttl.pop(email, None)
    _install_fake("chimera.modules.ttl_users", ttl)

    ul = types.ModuleType("chimera.modules.user_lifecycle")
    ul._set_traffic_limit = lambda email, gb: store.limits.update(
        {email: {"limit_gb": gb}})
    ul._remove_traffic_limit = lambda email: store.limits.pop(email, None)
    _install_fake("chimera.modules.user_lifecycle", ul)

    naive = types.ModuleType("chimera.modules.naiveproxy")
    naive.ensure_user_full = lambda user: True
    naive.remove_user_full = lambda user: store.naive_removed.append(
        user.get("email"))
    _install_fake("chimera.modules.naiveproxy", naive)

    mieru = types.ModuleType("chimera.modules.mieru")
    mieru.ensure_user_full = lambda user: True
    mieru.remove_user_full = lambda user: store.mieru_removed.append(
        user.get("email"))
    _install_fake("chimera.modules.mieru", mieru)

    core = types.ModuleType("chimera._core")
    core.gen_uuid = lambda: "fake-uuid-1234"
    core._users_apply_to_config = lambda users: store.applied.append(
        len(users))
    # КРИТИЧНО: положить в sys.modules (+ атрибут пакета chimera) ДО
    # вызовов — иначе importlib погрузит настоящий _core.py (mkdir
    # /var/backups + топ-левел импорты).
    _install_fake("chimera._core", core)
    return core


class TestCrud(unittest.TestCase):

    def setUp(self):
        self.store = _FakeStore()
        self._saved = {name: _snapshot_module(name) for name in (
            "chimera.modules.rest_api", "chimera.modules.ttl_users",
            "chimera.modules.user_lifecycle", "chimera.modules.naiveproxy",
            "chimera.modules.mieru", "chimera._core")}
        self.fake_core = _install_fakes(self.store)

    def tearDown(self):
        for name, snap in self._saved.items():
            _restore_module(name, snap)

    def test_create_user_full(self):
        status, resp = web._create_panel_user({
            "email": "new@x.com", "username": "new",
            "expiry": "2099-01-01", "quotaMB": 2048,
            "protocols": ["naive", "mieru"]})
        self.assertEqual(status, 201)
        self.assertEqual(resp["status"], "created")
        self.assertEqual(resp["uuid"], "fake-uuid-1234")
        # юзер в users.json, конфиг применён
        self.assertTrue(any(u["email"] == "new@x.com" for u in self.store.users))
        self.assertTrue(self.store.applied)
        # TTL поставлен, квота поставлена
        self.assertIn("new@x.com", self.store.ttl)
        self.assertEqual(self.store.limits["new@x.com"]["limit_gb"], 2)
        # протоколы НЕ снимались
        self.assertEqual(self.store.naive_removed, [])
        self.assertEqual(self.store.mieru_removed, [])

    def test_create_user_protocol_optout(self):
        status, _ = web._create_panel_user({
            "email": "onlynaive@x.com", "protocols": ["naive"]})
        self.assertEqual(status, 201)
        self.assertIn("onlynaive@x.com", self.store.mieru_removed)
        self.assertEqual(self.store.naive_removed, [])

    def test_create_user_invalid_email(self):
        for bad in ("", "no-at-sign", "a@b", None):
            status, resp = web._create_panel_user({"email": bad})
            self.assertEqual(status, 400)

    def test_create_user_duplicate(self):
        status, resp = web._create_panel_user({"email": "existing@x.com"})
        self.assertEqual(status, 409)

    def test_delete_user(self):
        status, resp = web._delete_panel_user("existing@x.com")
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "deleted")
        self.assertEqual(
            [u["email"] for u in self.store.users], [])
        self.assertTrue(self.store.applied)

    def test_delete_user_missing(self):
        status, _ = web._delete_panel_user("ghost@x.com")
        self.assertEqual(status, 404)

    def test_update_user(self):
        self.store.ttl["existing@x.com"] = {"expires_at": "x"}
        status, resp = web._update_panel_user("existing@x.com", {
            "expiry": None, "quotaMB": 5120,
            "protocols": ["naive"]})
        self.assertEqual(status, 200)
        self.assertIn("expiry", resp["changed"])
        self.assertIn("quota", resp["changed"])
        self.assertIn("protocols", resp["changed"])
        # TTL снят, квота 5 GiB, mieru снят
        self.assertNotIn("existing@x.com", self.store.ttl)
        self.assertEqual(self.store.limits["existing@x.com"]["limit_gb"], 5)
        self.assertIn("existing@x.com", self.store.mieru_removed)

    def test_update_user_missing(self):
        status, _ = web._update_panel_user("ghost@x.com", {"expiry": None})
        self.assertEqual(status, 404)


# ══════════════════════════════════════════════════════════════════════════════
#  11. STATE-ЗАВИСИМЫЕ ФУНКЦИИ ВЕБА (фейковый state-файл)
# ══════════════════════════════════════════════════════════════════════════════
class TestStateFunctions(unittest.TestCase):

    def test_load_state_missing_file(self):
        with patch.object(web, "_STATE_FILE",
                          Path("/nonexistent/triple.json")):
            self.assertEqual(web._load_state(), {})

    def test_load_state_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "state.json"
            f.write_text(json.dumps({"web_port": 9999}))
            with patch.object(web, "_STATE_FILE", f):
                self.assertEqual(web._load_state()["web_port"], 9999)


# ══════════════════════════════════════════════════════════════════════════════
#  11. v82: SSE-ШИНА + ЛОГИ
# ══════════════════════════════════════════════════════════════════════════════
class TestSSEBus(unittest.TestCase):

    def test_publish_delivers_to_subscriber(self):
        q = web._sse_subscribe()
        try:
            web._sse_publish("metrics", {"type": "metrics", "cpu": 3.0})
            event, data = q.get_nowait()
            self.assertEqual(event, "metrics")
            self.assertIn("cpu", json.loads(data))
        finally:
            web._sse_unsubscribe(q)

    def test_unsubscribe_stops_delivery(self):
        q = web._sse_subscribe()
        web._sse_unsubscribe(q)
        web._sse_publish("users", [])
        with self.assertRaises(queue.Empty):
            q.get_nowait()

    def test_slow_client_dropped_not_blocked(self):
        # переполнение очереди клиента не блокирует рассылку (put_nowait/Full)
        q = web._sse_subscribe()
        try:
            for _ in range(300):  # > maxsize=256
                web._sse_publish("log", {"line": "x"})
        finally:
            web._sse_unsubscribe(q)
        # шина пережила переполнение — новое событие уходит без исключений
        q2 = web._sse_subscribe()
        try:
            web._sse_publish("log", {"line": "y"})
            self.assertEqual(q2.get_nowait()[0], "log")
        finally:
            web._sse_unsubscribe(q2)

    def test_log_ring_via_publish(self):
        saved = list(web._SSE_LOG_RING)
        web._SSE_LOG_RING.clear()
        try:
            web._log("INFO", "ring-test")
            self.assertTrue(any("ring-test" in l for l in web._SSE_LOG_RING))
        finally:
            web._SSE_LOG_RING[:] = saved


class TestLogsResponse(unittest.TestCase):

    def test_unknown_service_400(self):
        status, _ = web._logs_response("bogus", 100)
        self.assertEqual(status, 400)

    def test_panel_ring(self):
        saved = list(web._SSE_LOG_RING)
        web._SSE_LOG_RING.clear()
        web._SSE_LOG_RING.append("line-1")
        try:
            status, resp = web._logs_response("panel", 10)
            self.assertEqual(status, 200)
            self.assertIn("line-1", resp["logs"])
        finally:
            web._SSE_LOG_RING[:] = saved

    def test_service_map(self):
        self.assertEqual(web._LOG_SERVICES["naive"], "caddy-naive")
        self.assertEqual(web._LOG_SERVICES["caddy"], "caddy-naive")
        self.assertEqual(web._LOG_SERVICES["mieru"], "mita")
        self.assertEqual(web._LOG_SERVICES["hy2"], "hysteria-server")
        self.assertEqual(web._LOG_SERVICES["hysteria"], "hysteria-server")

    def test_journal_tail_monkeypatched(self):
        with patch.object(web, "_journal_tail", return_value="JOURNAL-TEXT"):
            status, resp = web._logs_response("naive", 50)
            self.assertEqual(status, 200)
            self.assertEqual(resp["logs"], "JOURNAL-TEXT")

    def test_lines_clamped_to_1000(self):
        with patch.object(web, "_journal_tail") as jt:
            web._logs_response("naive", 99999)
            jt.assert_called_once_with("caddy-naive", 1000)


# ══════════════════════════════════════════════════════════════════════════════
#  12. v82: SSE-ШИМ (инъекция во фронт)
# ══════════════════════════════════════════════════════════════════════════════
class TestSseShimInjection(unittest.TestCase):

    def test_inject_before_appjs_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            www = Path(tmp)
            (www / "index.html").write_text(
                '<html><head><title>t</title></head>'
                '<body><script src="app.js"></script></body></html>')
            self.assertTrue(tp._inject_sse_shim(www))
            html = (www / "index.html").read_text()
            self.assertIn("triple-sse.js", html)
            self.assertLess(html.index("triple-sse.js"), html.index("app.js"))
            shim = (www / "triple-sse.js").read_text()
            self.assertIn("EventSource", shim)
            self.assertIn("window.WebSocket", shim)
            # идемпотентность: повторная инъекция не дублирует тег
            self.assertTrue(tp._inject_sse_shim(www))
            self.assertEqual(
                (www / "index.html").read_text().count("triple-sse.js"), 1)

    def test_inject_fallback_no_appjs(self):
        with tempfile.TemporaryDirectory() as tmp:
            www = Path(tmp)
            (www / "index.html").write_text(
                "<html><head></head><body>x</body></html>")
            self.assertTrue(tp._inject_sse_shim(www))
            self.assertIn("triple-sse.js", (www / "index.html").read_text())

    def test_inject_no_index_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(tp._inject_sse_shim(Path(tmp)))

    def test_update_front_up_to_date_injects_shim(self):
        """v82: ветка «фронт актуален» до-вживляет шим в v81-инсталлы."""
        with tempfile.TemporaryDirectory() as tmp:
            www = Path(tmp)
            (www / "index.html").write_text(
                '<html><body><script src="app.js"></script></body></html>')
            with patch.object(tp, "_load_state", return_value={
                    "front_version": "1.11.2"}), \
                 patch.object(tp, "_refresh_upstream_cache",
                              return_value="1.11.2"), \
                 patch.object(tp, "_WWW_DIR", www), \
                 patch.object(tp, "_service_active", return_value=False), \
                 patch.object(tp, "_pause"):
                self.assertTrue(tp._update_front())
            self.assertTrue((www / "triple-sse.js").exists())
            self.assertIn("triple-sse.js",
                          (www / "index.html").read_text())


# ══════════════════════════════════════════════════════════════════════════════
#  13. v82: РОТАЦИЯ ПАРОЛЯ + RENAME (расширенные CRUD-фейки)
# ══════════════════════════════════════════════════════════════════════════════
class TestV82UserOps(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.store = types.SimpleNamespace(
            users=[{"email": "existing@x.com", "uuid": "u0",
                    "name": "existing", "portal_password": "p",
                    "created": "2026-01-01"}],
            ttl={}, limits={}, applied=[], renamed=[],
            pw_naive=[], pw_mieru=[])
        s = self.store
        self._saved = {name: _snapshot_module(name) for name in (
            "chimera.modules.rest_api", "chimera.modules.ttl_users",
            "chimera.modules.user_lifecycle", "chimera.modules.naiveproxy",
            "chimera.modules.mieru", "chimera.modules.subscription",
            "chimera._core")}

        ra = types.ModuleType("chimera.modules.rest_api")
        ra._get_users = lambda: list(s.users)
        ra._save_users = lambda users: setattr(s, "users", list(users))
        ra._sync_users_from_config = lambda: 0
        ra._sync_rename_user = lambda old, new, old_user=None, \
            new_user=None: s.renamed.append((old, new))
        _install_fake("chimera.modules.rest_api", ra)

        ttl = types.ModuleType("chimera.modules.ttl_users")
        ttl._ttl_set = lambda e, d: s.ttl.update(
            {e: {"expires_at": f"days={d}", "days": d}})
        ttl._ttl_remove = lambda e: s.ttl.pop(e, None)
        ttl._ttl_load = lambda: dict(s.ttl)
        _install_fake("chimera.modules.ttl_users", ttl)

        ul = types.ModuleType("chimera.modules.user_lifecycle")
        ul._set_traffic_limit = lambda e, gb: s.limits.update(
            {e: {"limit_gb": gb}})
        ul._remove_traffic_limit = lambda e: s.limits.pop(e, None)
        _install_fake("chimera.modules.user_lifecycle", ul)

        sub = types.ModuleType("chimera.modules.subscription")
        sub._load_traffic_limits = lambda: dict(s.limits)
        _install_fake("chimera.modules.subscription", sub)

        import chimera.modules.proto_common as pc
        naive = types.ModuleType("chimera.modules.naiveproxy")
        naive._MODULE_STATE = tmp / "naive.json"
        pc.proto_save_state(naive._MODULE_STATE, {
            "users": [{"username": "existing", "password": "oldpw",
                       "password_hash": "h"}],
            "domain": "d.example", "port": 443, "upstream": ""})
        naive.set_password_full = lambda user, pw=None: (
            s.pw_naive.append((user.get("email"), pw)) or (pw or "gen-naive"))
        _install_fake("chimera.modules.naiveproxy", naive)

        mieru = types.ModuleType("chimera.modules.mieru")
        mieru._MODULE_STATE = tmp / "mieru.json"
        pc.proto_save_state(mieru._MODULE_STATE, {
            "users": [{"username": "existing", "password": "oldpw"}],
            "port_start": 2012, "port_end": 2022, "protocol": "TCP"})
        mieru.set_password_full = lambda user, pw=None: (
            s.pw_mieru.append((user.get("email"), pw)) or (pw or "gen-mieru"))
        _install_fake("chimera.modules.mieru", mieru)

        core = types.ModuleType("chimera._core")
        core.gen_uuid = lambda: "fake-uuid-v82"
        core._users_apply_to_config = lambda users: s.applied.append(
            len(users))
        _install_fake("chimera._core", core)

    def tearDown(self):
        for name, snap in self._saved.items():
            _restore_module(name, snap)
        self._tmp.cleanup()

    def test_password_rotation(self):
        status, resp = web._update_panel_user("existing@x.com",
                                              {"password": "newpass123"})
        self.assertEqual(status, 200)
        self.assertIn("password", resp["changed"])
        self.assertTrue(resp["ok"])
        # один и тот же пароль уехал в оба протокола
        self.assertEqual(self.store.pw_naive,
                         [("existing@x.com", "newpass123")])
        self.assertEqual(self.store.pw_mieru,
                         [("existing@x.com", "newpass123")])

    def test_password_too_short_400(self):
        status, resp = web._update_panel_user("existing@x.com",
                                              {"password": "short"})
        self.assertEqual(status, 400)
        self.assertEqual(self.store.pw_naive, [])

    def test_password_absent_no_rotation(self):
        status, _ = web._update_panel_user("existing@x.com", {"quotaMB": 1024})
        self.assertEqual(status, 200)
        self.assertEqual(self.store.pw_naive, [])

    def test_rename_email(self):
        self.store.ttl["existing@x.com"] = {"days": 30, "expires_at": "x"}
        self.store.limits["existing@x.com"] = {"limit_gb": 5}
        status, resp = web._update_panel_user(
            "existing@x.com", {"email": "renamed@x.com"})
        self.assertEqual(status, 200)
        self.assertIn("email", resp["changed"])
        self.assertEqual(resp["id"], "renamed@x.com")
        # users.json: uuid сохранён, email/name обновлены (name = префикс)
        u = self.store.users[0]
        self.assertEqual(u["email"], "renamed@x.com")
        self.assertEqual(u["uuid"], "u0")
        self.assertEqual(u["name"], "renamed")
        # мост rename вызван, конфиг перезаписан
        self.assertTrue(self.store.renamed)
        self.assertTrue(self.store.applied)
        # TTL и квота переехали на новый email
        self.assertNotIn("existing@x.com", self.store.ttl)
        self.assertIn("renamed@x.com", self.store.ttl)
        self.assertIn("renamed@x.com", self.store.limits)
        self.assertNotIn("existing@x.com", self.store.limits)

    def test_rename_email_conflict_409(self):
        self.store.users.append({"email": "other@x.com", "uuid": "u1",
                                 "name": "other"})
        status, _ = web._update_panel_user("existing@x.com",
                                           {"email": "other@x.com"})
        self.assertEqual(status, 409)

    def test_rename_invalid_email_400(self):
        status, _ = web._update_panel_user("existing@x.com",
                                           {"email": "not-an-email"})
        self.assertEqual(status, 400)


# ══════════════════════════════════════════════════════════════════════════════
#  14-15. v82: ПОРТЫ ПРОТОКОЛОВ + КАСКАД/WARP (фейки port_registry и warp)
# ══════════════════════════════════════════════════════════════════════════════
class TestV82Settings(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.s = types.SimpleNamespace(
            registry=[], conflicts=[], warp_calls=[], warp_uninstalled=0,
            warp_state={"WARP_CONNECTED": False, "WARP_MODE": "",
                        "WARP_SSH_CLIENT_IP": ""})
        s = self.s
        self._saved = {name: _snapshot_module(name) for name in (
            "chimera.modules.naiveproxy", "chimera.modules.mieru",
            "chimera.modules.port_registry", "chimera.modules.warp")}

        import chimera.modules.proto_common as pc
        naive = types.ModuleType("chimera.modules.naiveproxy")
        naive._MODULE_STATE = tmp / "naive.json"
        pc.proto_save_state(naive._MODULE_STATE, {
            "users": [{"username": "u", "password": "p"}],
            "domain": "d", "port": 443, "upstream": ""})
        naive._apply_config = lambda domain, port, users, fu, ps, up="": (
            s.registry.append(("apply-naive", port)) or None)
        _install_fake("chimera.modules.naiveproxy", naive)

        mieru = types.ModuleType("chimera.modules.mieru")
        mieru._MODULE_STATE = tmp / "mieru.json"
        pc.proto_save_state(mieru._MODULE_STATE, {
            "users": [], "port_start": 2012, "port_end": 2022,
            "protocol": "TCP"})
        mieru._MIERU_TRAFFIC_PRESETS = {}
        mieru._build_server_config = lambda users, ps, pe, proto, \
            traffic_pattern=None: {"ports": (ps, pe)}
        mieru._apply_server_config = lambda cfg: None
        _install_fake("chimera.modules.mieru", mieru)

        pr = types.ModuleType("chimera.modules.port_registry")
        pr.SERVICE_NAIVEPROXY = "naiveproxy"
        pr.SERVICE_MIERU = "mieru"
        pr.port_get_conflicts = lambda port, proto="tcp", \
            exclude_service=None: list(s.conflicts)
        pr.port_check_system = lambda port, proto="tcp": []
        pr.port_register = lambda tag, port, proto="tcp", comment="", \
            force=False: (s.registry.append(("reg", tag, port))
                          or (True, "ok"))
        pr.port_unregister = lambda tag, port=None, proto=None: (
            s.registry.append(("unreg", tag, port)) or True)
        pr.port_register_range = lambda tag, ps, pe, proto="tcp", \
            comment="": (s.registry.append(("reg-range", tag, ps, pe))
                         or (True, "ok"))
        pr.port_unregister_range = lambda tag, ps, pe, proto=None: (
            s.registry.append(("unreg-range", tag, ps, pe)) or True)
        pr.ufw_open_port = lambda port, proto, tag, comment=None: (
            s.registry.append(("ufw-open", port)))
        pr.ufw_close_port = lambda port, proto, tag, \
            legacy_comments=None: (s.registry.append(("ufw-close", port)))
        pr.ufw_open_port_range = lambda ps, pe, proto, tag, \
            comment=None: (s.registry.append(("ufw-open-range", ps, pe)))
        pr.ufw_close_port_range = lambda ps, pe, proto, tag, \
            legacy=None: (s.registry.append(("ufw-close-range", ps, pe)))
        _install_fake("chimera.modules.port_registry", pr)

        warp = types.ModuleType("chimera.modules.warp")
        warp._state_get = lambda name, default=None: s.warp_state.get(
            name, default)
        warp._state_set = lambda name, value: s.warp_state.update(
            {name: value})
        warp.configure_warp = lambda mode, ssh, custom_ips=None, \
            custom_domains=None: (
                s.warp_state.update({"WARP_CONNECTED": True})
                or s.warp_calls.append((mode, ssh)) or True)
        warp.uninstall_warp = lambda: (
            s.warp_state.update({"WARP_CONNECTED": False})
            or setattr(s, "warp_uninstalled", s.warp_uninstalled + 1)
            or True)
        warp.WG_SERVICE = "wg-quick@wgcf"
        _install_fake("chimera.modules.warp", warp)

        self._svc_patch = patch.object(web, "_svc_active", return_value=True)
        self._svc_patch.start()

    def tearDown(self):
        self._svc_patch.stop()
        for name, snap in self._saved.items():
            _restore_module(name, snap)
        self._tmp.cleanup()

    def _naive_state(self):
        import chimera.modules.proto_common as pc
        from chimera.modules import naiveproxy as nv
        return pc.proto_load_state(nv._MODULE_STATE)

    def _mieru_state(self):
        import chimera.modules.proto_common as pc
        from chimera.modules import mieru as mr
        return pc.proto_load_state(mr._MODULE_STATE)

    # ── порты naive ───────────────────────────────────────────────────────
    def test_naive_port_change(self):
        status, resp = web._set_naive_port({"port": 8443})
        self.assertEqual(status, 200)
        self.assertTrue(resp["ok"])
        self.assertIn("8443", resp["message"])
        self.assertEqual(self._naive_state()["port"], 8443)
        ops = [op[0] for op in self.s.registry]
        self.assertIn("reg", ops)          # перерегистрация за naiveproxy
        self.assertIn("unreg", ops)
        self.assertIn("ufw-open", ops)
        self.assertIn("apply-naive", ops)  # Caddyfile пересобран

    def test_naive_port_invalid(self):
        for bad in (0, 70000, "x"):
            status, _ = web._set_naive_port({"port": bad})
            self.assertEqual(status, 400)

    def test_naive_port_conflict_409_no_state_change(self):
        self.s.conflicts = [{"type": "registry", "detail": "занят: vless-web",
                             "service": "vless"}]
        status, resp = web._set_naive_port({"port": 8443})
        self.assertEqual(status, 409)
        self.assertIn("занят", resp["error"])
        self.assertEqual(self._naive_state()["port"], 443)

    def test_naive_port_same_noop(self):
        status, resp = web._set_naive_port({"port": 443})
        self.assertEqual(status, 200)
        self.assertIn("уже", resp["message"])

    def test_naive_port_apply_error_rollback(self):
        from chimera.modules import naiveproxy as nv
        orig = nv._apply_config
        nv._apply_config = lambda d, p, u, f, pr_, up="": "Caddyfile error"
        try:
            status, resp = web._set_naive_port({"port": 8443})
            self.assertEqual(status, 500)
            self.assertEqual(self._naive_state()["port"], 443)  # откат
        finally:
            nv._apply_config = orig

    # ── порты mieru ───────────────────────────────────────────────────────
    def test_mieru_ports_change(self):
        status, resp = web._set_mieru_ports({"portStart": 3000,
                                             "portEnd": 3010})
        self.assertEqual(status, 200)
        self.assertTrue(resp["ok"])
        st = self._mieru_state()
        self.assertEqual((st["port_start"], st["port_end"]), (3000, 3010))
        ops = [op[0] for op in self.s.registry]
        self.assertIn("reg-range", ops)
        self.assertIn("unreg-range", ops)
        self.assertIn("ufw-open-range", ops)

    def test_mieru_ports_invalid(self):
        status, _ = web._set_mieru_ports({"portStart": 2000, "portEnd": 1990})
        self.assertEqual(status, 400)
        status, _ = web._set_mieru_ports({"portStart": 100, "portEnd": 200})
        self.assertEqual(status, 400)

    def test_mieru_ports_conflict_409(self):
        self.s.conflicts = [{"type": "registry", "detail": "занят: singbox",
                             "service": "singbox"}]
        status, _ = web._set_mieru_ports({"portStart": 3000,
                                          "portEnd": 3010})
        self.assertEqual(status, 409)
        st = self._mieru_state()
        self.assertEqual((st["port_start"], st["port_end"]), (2012, 2022))

    # ── каскад ─────────────────────────────────────────────────────────
    def test_cascade_view_disabled(self):
        view = web._cascade_view()
        self.assertFalse(view["cascadeEnabled"])
        self.assertEqual(view["cascadeNaiveUpstream"], "")
        self.assertFalse(view["cascadeMieru"]["hasPass"])
        self.assertEqual(view["cascadeMieru"]["portStart"], 2012)

    def test_cascade_enable_and_disable(self):
        status, resp = web._cascade_apply({
            "cascadeEnabled": True,
            "cascadeNaiveUpstream": "https://u:p@exit.example:443"})
        self.assertEqual(status, 200)
        self.assertTrue(resp["ok"])
        self.assertEqual(self._naive_state()["upstream"],
                         "https://u:p@exit.example:443")
        self.assertTrue(web._cascade_view()["cascadeEnabled"])
        # WARP не трогался (не был включен)
        self.assertEqual(self.s.warp_uninstalled, 0)
        # отключение
        status, resp = web._cascade_apply({"cascadeEnabled": False})
        self.assertEqual(status, 200)
        self.assertEqual(self._naive_state()["upstream"], "")

    def test_cascade_enable_tears_warp(self):
        self.s.warp_state["WARP_CONNECTED"] = True
        status, resp = web._cascade_apply({
            "cascadeEnabled": True,
            "cascadeNaiveUpstream": "https://u:p@exit.example:443"})
        self.assertEqual(status, 200)
        self.assertEqual(self.s.warp_uninstalled, 1)
        self.assertIn("взаимоисключение", resp["message"])

    def test_cascade_enable_requires_upstream(self):
        status, _ = web._cascade_apply({"cascadeEnabled": True,
                                        "cascadeNaiveUpstream": ""})
        self.assertEqual(status, 400)

    def test_cascade_mieru_leg_ignored_honestly(self):
        status, resp = web._cascade_apply({
            "cascadeEnabled": True,
            "cascadeNaiveUpstream": "https://u:p@h:443",
            "cascadeMieru": {"host": "exit.example", "user": "u"}})
        self.assertEqual(status, 200)
        self.assertIn("не применяется", resp["message"])

    def test_normalize_upstream(self):
        cases = [
            ("naive+https://u:p@h:443#tag", "https://u:p@h:443"),
            ("https://u:p@h:443/", "https://u:p@h:443"),
            ("h.example:8443", "https://h.example:8443"),
            ("", ""),
            ("garbage@@@", ""),
        ]
        for raw, expected in cases:
            self.assertEqual(web._normalize_upstream(raw), expected,
                             f"raw={raw!r}")

    def test_cascade_reset(self):
        web._cascade_apply({"cascadeEnabled": True,
                            "cascadeNaiveUpstream": "https://u:p@h:443"})
        with patch.object(web, "_egress_ip", return_value="1.2.3.4"):
            status, resp = web._cascade_reset()
        self.assertEqual(status, 200)
        self.assertEqual(resp["nativeEgress"], "1.2.3.4")
        self.assertEqual(self._naive_state()["upstream"], "")

    def test_cascade_status_view(self):
        web._cascade_apply({"cascadeEnabled": True,
                            "cascadeNaiveUpstream": "https://u:p@h:443"})
        view = web._cascade_status_view()
        self.assertTrue(view["ok"])
        self.assertIn("https://u:p@h:443", view["output"])

    # ── WARP ─────────────────────────────────────────────────────────
    def test_warp_view_and_enable(self):
        view = web._warp_view()
        self.assertFalse(view["warpEnabled"])
        self.assertIn("ramMB", view)
        self.assertIn("lowRamWarning", view)
        # включение: режим по умолчанию runet (state пуст)
        with patch.object(web, "_egress_ip", return_value="5.6.7.8"):
            status, resp = web._set_warp({"warpEnabled": True})
        self.assertEqual(status, 200)
        self.assertTrue(resp["ok"])
        self.assertEqual(self.s.warp_calls, [("runet", "")])
        self.assertEqual(resp["egressIP"], "5.6.7.8")
        # warp.py отразил подключение → view видит включение
        self.assertTrue(web._warp_view()["warpEnabled"])

    def test_warp_enable_full_degrades_without_ssh_ip(self):
        self.s.warp_state["WARP_MODE"] = "full"
        with patch.object(web, "_egress_ip", return_value=""):
            status, resp = web._set_warp({"warpEnabled": True})
        self.assertEqual(status, 200)
        self.assertEqual(self.s.warp_calls[0][0], "runet")
        self.assertIn("runet", resp["message"])

    def test_warp_enable_full_with_ssh_ip_kept(self):
        self.s.warp_state["WARP_MODE"] = "full"
        self.s.warp_state["WARP_SSH_CLIENT_IP"] = "9.9.9.9"
        with patch.object(web, "_egress_ip", return_value=""):
            status, _ = web._set_warp({"warpEnabled": True})
        self.assertEqual(self.s.warp_calls[0][0], "full")

    def test_warp_enable_clears_cascade(self):
        web._cascade_apply({"cascadeEnabled": True,
                            "cascadeNaiveUpstream": "https://u:p@h:443"})
        with patch.object(web, "_egress_ip", return_value=""):
            web._set_warp({"warpEnabled": True})
        self.assertEqual(self._naive_state()["upstream"], "")

    def test_warp_disable_and_reset(self):
        with patch.object(web, "_egress_ip", return_value=""):
            status, resp = web._set_warp({"warpEnabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(resp["warpEnabled"])
        self.assertEqual(resp["warpResult"]["code"], "disabled")
        self.assertEqual(self.s.warp_uninstalled, 1)
        with patch.object(web, "_egress_ip", return_value="1.1.1.1"):
            status, resp = web._warp_reset()
        self.assertEqual(resp["nativeEgress"], "1.1.1.1")
        self.assertEqual(self.s.warp_uninstalled, 2)

    def test_warp_status_view(self):
        self.s.warp_state["WARP_CONNECTED"] = True
        self.s.warp_state["WARP_MODE"] = "runet"
        with patch.object(web, "_egress_ip", return_value="3.3.3.3"):
            view = web._warp_status_view()
        self.assertTrue(view["ok"])
        self.assertIn("runet", view["output"])
        self.assertIn("3.3.3.3", view["output"])


if __name__ == "__main__":
    unittest.main()
