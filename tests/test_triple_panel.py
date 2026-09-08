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
"""
from __future__ import annotations

import io
import json
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
        self._orig = sys.modules.get("chimera.modules.subscription")
        sys.modules["chimera.modules.subscription"] = _fake_subscription_module()

    def tearDown(self):
        if self._orig is not None:
            sys.modules["chimera.modules.subscription"] = self._orig
        else:
            sys.modules.pop("chimera.modules.subscription", None)

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
        orig_mn = sys.modules.get("chimera.modules.subscription_multinode")
        sys.modules["chimera.modules.subscription_multinode"] = fake_mn
        try:
            status, headers, body = self._run(ua="ClashMeta/1.18")
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith("text/yaml"))
        finally:
            if orig_mn is not None:
                sys.modules["chimera.modules.subscription_multinode"] = orig_mn
            else:
                sys.modules.pop(
                    "chimera.modules.subscription_multinode", None)

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
    sys.modules["chimera.modules.rest_api"] = ra

    ttl = types.ModuleType("chimera.modules.ttl_users")
    ttl._ttl_set = lambda email, days: store.ttl.update(
        {email: {"expires_at": f"days={days}", "days": days}})
    ttl._ttl_remove = lambda email: store.ttl.pop(email, None)
    sys.modules["chimera.modules.ttl_users"] = ttl

    ul = types.ModuleType("chimera.modules.user_lifecycle")
    ul._set_traffic_limit = lambda email, gb: store.limits.update(
        {email: {"limit_gb": gb}})
    ul._remove_traffic_limit = lambda email: store.limits.pop(email, None)
    sys.modules["chimera.modules.user_lifecycle"] = ul

    naive = types.ModuleType("chimera.modules.naiveproxy")
    naive.ensure_user_full = lambda user: True
    naive.remove_user_full = lambda user: store.naive_removed.append(
        user.get("email"))
    sys.modules["chimera.modules.naiveproxy"] = naive

    mieru = types.ModuleType("chimera.modules.mieru")
    mieru.ensure_user_full = lambda user: True
    mieru.remove_user_full = lambda user: store.mieru_removed.append(
        user.get("email"))
    sys.modules["chimera.modules.mieru"] = mieru

    core = types.ModuleType("chimera._core")
    core.gen_uuid = lambda: "fake-uuid-1234"
    core._users_apply_to_config = lambda users: store.applied.append(
        len(users))
    # КРИТИЧНО: положить в sys.modules ДО вызовов — иначе importlib
    # погрузит настоящий _core.py (mkdir /var/backups + топ-левел импорты).
    sys.modules["chimera._core"] = core
    return core


class TestCrud(unittest.TestCase):

    def setUp(self):
        self.store = _FakeStore()
        self._saved = {name: sys.modules.get(name) for name in (
            "chimera.modules.rest_api", "chimera.modules.ttl_users",
            "chimera.modules.user_lifecycle", "chimera.modules.naiveproxy",
            "chimera.modules.mieru", "chimera._core")}
        self.fake_core = _install_fakes(self.store)

    def tearDown(self):
        for name, mod in self._saved.items():
            if mod is not None:
                sys.modules[name] = mod
            else:
                sys.modules.pop(name, None)

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


if __name__ == "__main__":
    unittest.main()
