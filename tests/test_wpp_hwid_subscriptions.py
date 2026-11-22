#!/usr/bin/env python3
"""
tests/test_wpp_hwid_subscriptions.py

HWID-подписки WPP в порте Chimera (v2.9.1): «один ключ = один человек».

Полный цикл без HTTP-слоя (регрессия менеджера):
  • wpp_subscriptions v2.9.1: лимит устройств, HWID-хэши (salt по подписке),
    revoke/allow, rename-device, rotate, дефолтные connections из protocols
  • in-process ctl_subscription (замена внешнего panelctl, MANAGER=""):
      create → fetch(hwId1) → per-device профиль + мост add_user в chimera
      users.json; второй fetch(hwId2) → второе устройство; третий → 403
      device_limit; revoke → remove_user; rename → remove+add с тем же uuid
      (ссылка клиента не меняется); toggle → block/unblock; rotate/delete →
      remove всех профилей
  • откат моста: сбой add_user → DATA не сохраняется (семантика
    upstream-менеджера: runtime сначала, DB потом), инверсии применены
  • users(): живые chimera-юзеры с wppsub-email аннотируются метаданными
    подписки по совпадению uuid==secret
  • subscription-userinfo: счётчики берутся под ключом secret (uuid)
  • device-action: токен дашборда = HMAC(session_key, токен подписки)
"""
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chimera.modules import wpp_panel_web as pw  # noqa: E402
from chimera.modules import wpp_subscriptions as ws  # noqa: E402
from chimera.modules import user_lifecycle  # noqa: E402


class FakeUserLifecycle:
    """In-memory заглушка user_lifecycle: слежка за вызовами + батч-контекст."""

    def __init__(self):
        self.users = {}  # email -> {uuid, name, blocked}
        self.calls = []
        self.fail_on = None  # (email, op) — искусственный сбой

    # ── публичный API user_lifecycle, который дергает мост ──
    def add_user(self, email, protocols="all", ttl=None, traffic_limit=None,
                 name=None, uuid_str=None):
        self.calls.append(("add", email, uuid_str, name))
        if self.fail_on == (email, "add"):
            return {"success": False, "applied": [], "failed": list(protocols),
                    "errors": ["forced failure"]}
        self.users[email] = {"uuid": uuid_str, "name": name or email.split("@")[0],
                             "blocked": False}
        return {"success": True, "applied": list(protocols), "failed": [], "errors": []}

    def remove_user(self, email, protocols="all"):
        self.calls.append(("remove", email))
        if self.fail_on == (email, "remove"):
            return {"success": False, "applied": [], "failed": list(protocols),
                    "errors": ["forced failure"]}
        self.users.pop(email, None)
        return {"success": True, "applied": list(protocols), "failed": [], "errors": []}

    def block_user(self, email, reason="manual", protocols="all"):
        self.calls.append(("block", email, reason))
        if self.fail_on == (email, "block"):
            return {"success": False, "applied": [], "failed": [], "errors": ["forced failure"]}
        if email in self.users:
            self.users[email]["blocked"] = True
        return {"success": True, "applied": list(protocols), "failed": [], "errors": []}

    def unblock_user(self, email, protocols="all"):
        self.calls.append(("unblock", email))
        if self.fail_on == (email, "unblock"):
            return {"success": False, "applied": [], "failed": [], "errors": ["forced failure"]}
        if email in self.users:
            self.users[email]["blocked"] = False
        return {"success": True, "applied": list(protocols), "failed": [], "errors": []}

    @contextmanager
    def batch_context(self):
        yield


class HwidSubscriptionTestBase(unittest.TestCase):
    """Патчит пути панельного ФС и мост user_lifecycle на фейк."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.data_file = tmp / "wpp_panel_data.json"
        self.users_file = tmp / "users.json"
        self.users_file.write_text("[]", encoding="utf-8")
        self.traffic_file = tmp / "wpp_metrics.json"
        self.fake = FakeUserLifecycle()
        self._patches = [
            patch.object(pw, "DATA", str(self.data_file)),
            patch.object(pw, "USERS", str(self.users_file)),
            patch.object(pw, "PROFILES", str(self.users_file)),
            patch.object(pw, "TRAFFIC", str(self.traffic_file)),
            patch.object(pw, "PRIMARY", str(tmp / "absent-primary")),
            patch.object(user_lifecycle, "add_user", self.fake.add_user),
            patch.object(user_lifecycle, "remove_user", self.fake.remove_user),
            patch.object(user_lifecycle, "block_user", self.fake.block_user),
            patch.object(user_lifecycle, "unblock_user", self.fake.unblock_user),
            patch.object(user_lifecycle, "batch_context", self.fake.batch_context),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def _chimera_users_write(self, entries):
        self.users_file.write_text(json.dumps(entries), encoding="utf-8")

    def _data(self):
        if not self.data_file.exists():
            return {}
        return json.loads(self.data_file.read_text(encoding="utf-8"))


# ─── wpp_subscriptions v2.9.1: чистая логика подписок ─────────────────────

class TestUpstreamSubscriptionSemantics(unittest.TestCase):
    BASE = {"users": [], "subscriptions": [], "traffic": {}}

    def _create(self, data, name="Александр", max_devices=2, protocols=None):
        request = {"operation": "create", "name": name, "max_devices": max_devices,
                   "protocols": protocols or ["vless"]}
        data, result = ws.mutate(data, request)
        self.assertTrue(result.get("ok"))
        return data

    def test_create_defaults_connections_from_protocols(self):
        data = self._create(json.loads(json.dumps(self.BASE)))
        sub = data["subscriptions"][0]
        self.assertEqual(sub["max_devices"], 2)
        self.assertEqual(sub["protocols"], ["vless"])
        # v2.9.1: дефолтные connections строятся из protocols
        self.assertEqual(sub["connections"][0]["id"], "vless-direct")
        self.assertEqual(sub["connections"][0]["protocol"], "vless")
        self.assertTrue(sub["failover_enabled"])
        self.assertEqual(sub["devices"], [])
        self.assertTrue(sub["token"] and len(sub["token"]) == 64)

    def test_issue_hwid_registers_device_with_name(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=2)
        token = data["subscriptions"][0]["token"]
        data, result = ws.issue(data, {"operation": "fetch", "token": token,
                                       "hwid": "device-hwid-aaa",
                                       "device_name": "iPhone / iPad"})
        self.assertTrue(result["ok"])
        sub = data["subscriptions"][0]
        self.assertEqual(len(sub["devices"]), 1)
        self.assertEqual(sub["devices"][0]["name"], "iPhone / iPad")
        # per-device VLESS профиль с собственным секретом
        self.assertEqual(len(data["users"]), 1)
        profile = data["users"][0]
        self.assertEqual(profile["protocol"], "vless")
        self.assertEqual(profile["connection_id"], "vless-direct")
        self.assertEqual(profile["subscription_id"], sub["id"])
        self.assertEqual(profile["device_id"], sub["devices"][0]["id"])
        self.assertTrue(profile["secret"])

    def test_issue_device_limit(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=2)
        token = data["subscriptions"][0]["token"]
        for hwid in ("device-hwid-a", "device-hwid-b"):
            data, result = ws.issue(data, {"operation": "fetch", "token": token, "hwid": hwid})
            self.assertTrue(result["ok"])
        # третий — за лимитом
        with self.assertRaises(ws.SubscriptionError) as ctx:
            ws.issue(data, {"operation": "fetch", "token": token, "hwid": "device-hwid-ccc"})
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.code, "device_limit")

    def test_issue_requires_hwid_when_limited(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=1)
        token = data["subscriptions"][0]["token"]
        with self.assertRaises(ws.SubscriptionError) as ctx:
            ws.issue(data, {"operation": "fetch", "token": token, "hwid": ""})
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.code, "hwid_required")

    def test_issue_shared_mode_without_hwid(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=0)
        token = data["subscriptions"][0]["token"]
        data, result = ws.issue(data, {"operation": "fetch", "token": token})
        self.assertTrue(result["ok"])
        self.assertFalse(result["limited"])
        sub = data["subscriptions"][0]
        self.assertEqual(sub["devices"][0]["name"], "Общий профиль")

    def test_hwid_hash_is_salted_by_subscription(self):
        d1 = self._create(json.loads(json.dumps(self.BASE)))
        d2 = self._create(json.loads(json.dumps(self.BASE)))
        t1, t2 = d1["subscriptions"][0]["token"], d2["subscriptions"][0]["token"]
        d1, _ = ws.issue(d1, {"operation": "fetch", "token": t1, "hwid": "same-hwid"})
        d2, _ = ws.issue(d2, {"operation": "fetch", "token": t2, "hwid": "same-hwid"})
        h1 = d1["subscriptions"][0]["devices"][0]["hwid_hash"]
        h2 = d2["subscriptions"][0]["devices"][0]["hwid_hash"]
        # один и тот же HWID в разных подписках даёт разные записи:
        # записи нельзя коррелировать между аккаунтами
        self.assertNotEqual(h1, h2)

    def test_revoke_then_allow(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=2)
        sub = data["subscriptions"][0]
        data, _ = ws.issue(data, {"operation": "fetch", "token": sub["token"],
                                   "hwid": "device-hwid-aaa"})
        sub = data["subscriptions"][0]
        device_id = sub["devices"][0]["id"]
        self.assertEqual(len(data["users"]), 1)
        data, _ = ws.mutate(data, {"operation": "revoke", "id": sub["id"],
                                   "device_id": device_id})
        # ключи отозванного устройства удалены, устройство помечено
        self.assertEqual(len(data["users"]), 0)
        self.assertTrue(data["subscriptions"][0]["devices"][0]["revoked"])
        # отозванное устройство получает отказ
        with self.assertRaises(ws.SubscriptionError) as ctx:
            ws.issue(data, {"operation": "fetch", "token": sub["token"], "hwid": "device-hwid-aaa"})
        self.assertEqual(ctx.exception.code, "revoked")
        # allow возвращает слот
        data, _ = ws.mutate(data, {"operation": "allow", "id": sub["id"],
                                   "device_id": device_id})
        self.assertEqual(data["subscriptions"][0]["devices"], [])

    def test_rename_device_renames_profiles(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=2)
        sub = data["subscriptions"][0]
        data, _ = ws.issue(data, {"operation": "fetch", "token": sub["token"],
                                   "hwid": "device-hwid-aaa", "device_name": "Android"})
        sub = data["subscriptions"][0]
        device_id = sub["devices"][0]["id"]
        data, _ = ws.mutate(data, {"operation": "rename-device", "id": sub["id"],
                                   "device_id": device_id, "name": "Телефон жены"})
        self.assertEqual(data["subscriptions"][0]["devices"][0]["name"], "Телефон жены")
        self.assertEqual(data["users"][0]["name"], "Александр / Телефон жены")

    def test_switching_limit_revokes_old_keys(self):
        data = self._create(json.loads(json.dumps(self.BASE)), max_devices=0)
        sub = data["subscriptions"][0]
        data, _ = ws.issue(data, {"operation": "fetch", "token": sub["token"]})
        self.assertEqual(len(data["users"]), 1)
        data, _ = ws.mutate(data, {"operation": "update", "id": sub["id"],
                                   "max_devices": 3})
        # переход 0 → лимит отзывает старые ключи
        self.assertEqual(data["users"], [])
        self.assertEqual(data["subscriptions"][0]["devices"], [])
        self.assertEqual(data["subscriptions"][0]["max_devices"], 3)


# ─── in-process менеджер + мост в chimera (главное) ────────────────────────

class TestCtlSubscriptionBridge(HwidSubscriptionTestBase):

    def _create(self, **kw):
        result = pw.ctl_subscription({"operation": "create", "name": kw.pop("name", "Александр"),
                                     "max_devices": kw.pop("max_devices", 2),
                                     "protocols": ["vless"]})
        self.assertTrue(result.get("ok"), result)
        data = self._data()
        return data["subscriptions"][0]

    def test_full_hwid_lifecycle_with_chimera_bridge(self):
        sub = self._create(max_devices=2)
        token = sub["token"]

        # устройство 1: Happ передал X-HWID
        r = pw.ctl_subscription({"operation": "fetch", "token": token,
                                 "hwid": "hwid-iphone", "device_name": "iPhone / iPad"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["limited"], True)
        self.assertEqual(len(r["users"]), 1)
        secret1 = r["users"][0]["secret"]
        # мост: в chimera появился юзер с uuid = per-device секрет
        self.assertEqual(len(self.fake.users), 1)
        email1 = next(iter(self.fake.users))
        self.assertTrue(email1.startswith("wppsub-"))
        self.assertIn("@wpp.local", email1)
        self.assertEqual(self.fake.users[email1]["uuid"], secret1)

        # устройство 2
        r = pw.ctl_subscription({"operation": "fetch", "token": token,
                                 "hwid": "hwid-android", "device_name": "Android"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(self.fake.users), 2)

        # третье устройство — за лимитом (мост не дергается)
        before_calls = len(self.fake.calls)
        r = pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-mac"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "device_limit")
        self.assertEqual(r["status"], 403)
        self.assertEqual(len(self.fake.calls), before_calls)

        # повторный fetch первого устройства — тот же ключ (без нового юзера)
        r = pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-iphone"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["users"][0]["secret"], secret1)
        self.assertEqual(len(self.fake.users), 2)

        # DATA сохранён: устройства + профили
        data = self._data()
        self.assertEqual(len(data["subscriptions"][0]["devices"]), 2)
        self.assertEqual(len(data["users"]), 2)

        # revoke устройства 1 → remove_user
        device_id = data["subscriptions"][0]["devices"][0]["id"]
        r = pw.ctl_subscription({"operation": "revoke", "id": data["subscriptions"][0]["id"],
                                 "device_id": device_id})
        self.assertTrue(r["ok"], r)
        self.assertNotIn(email1, self.fake.users)

    def test_rename_device_keeps_client_link(self):
        sub = self._create(max_devices=2)
        token = sub["token"]
        r = pw.ctl_subscription({"operation": "fetch", "token": token,
                                 "hwid": "hwid-0001", "device_name": "Android"})
        self.assertTrue(r["ok"])
        secret = r["users"][0]["secret"]
        email = next(iter(self.fake.users))
        data = self._data()
        device_id = data["subscriptions"][0]["devices"][0]["id"]
        sid = data["subscriptions"][0]["id"]

        r = pw.ctl_subscription({"operation": "rename-device", "id": sid,
                                 "device_id": device_id, "name": "Телефон жены"})
        self.assertTrue(r["ok"], r)
        # тот же email, тот же uuid — ссылка клиента не изменилась
        self.assertIn(email, self.fake.users)
        self.assertEqual(self.fake.users[email]["uuid"], secret)
        self.assertEqual(self.fake.users[email]["name"], "Александр / Телефон жены")

    def test_toggle_blocks_and_unblocks(self):
        sub = self._create(max_devices=1)
        token = sub["token"]
        pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0001"})
        email = next(iter(self.fake.users))
        sid = self._data()["subscriptions"][0]["id"]

        r = pw.ctl_subscription({"operation": "toggle", "id": sid})
        self.assertTrue(r["ok"])
        self.assertTrue(self.fake.users[email]["blocked"])

        r = pw.ctl_subscription({"operation": "toggle", "id": sid})
        self.assertTrue(r["ok"])
        self.assertFalse(self.fake.users[email]["blocked"])

    def test_rotate_removes_all_profiles(self):
        sub = self._create(max_devices=2)
        token = sub["token"]
        for hwid in ("hwid-0001", "hwid-0002"):
            pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": hwid})
        self.assertEqual(len(self.fake.users), 2)
        sid = self._data()["subscriptions"][0]["id"]

        r = pw.ctl_subscription({"operation": "rotate", "id": sid})
        self.assertTrue(r["ok"])
        self.assertEqual(self.fake.users, {})
        # новый токен: старая ссылка мертва
        data = self._data()
        self.assertNotEqual(data["subscriptions"][0]["token"], token)

    def test_delete_removes_subscription_and_profiles(self):
        sub = self._create(max_devices=1)
        token = sub["token"]
        pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0001"})
        sid = self._data()["subscriptions"][0]["id"]
        r = pw.ctl_subscription({"operation": "delete", "id": sid})
        self.assertTrue(r["ok"])
        self.assertEqual(self.fake.users, {})
        self.assertEqual(self._data().get("subscriptions"), [])

    def test_fetch_failure_keeps_data_unsaved_and_rolls_back(self):
        sub = self._create(max_devices=3)
        token = sub["token"]
        # два живых устройства
        pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0001"})
        pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0002"})
        data_before = self._data()
        self.assertEqual(len(self.fake.users), 2)

        # третье устройство: add_user падает → мост должен откатиться,
        # а DATA — не сохраниться (runtime сначала, DB потом)
        self.fake.fail_on = None
        # узнаём email будущего профиля, не заводя его: сбой делаем на
        # любом add_user после первого — поднимаем fail после 1-го вызова
        original_add = self.fake.add_user
        state = {"n": 0}
        def flaky_add(email, **kw):
            state["n"] += 1
            if state["n"] >= 1:
                return {"success": False, "applied": [], "failed": ["vless"],
                        "errors": ["forced failure"]}
            return original_add(email, **kw)
        self.fake.fail_on = None
        with patch.object(user_lifecycle, "add_user", flaky_add):
            r = pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0003"})
        self.assertEqual(r.get("ok"), False)
        self.assertEqual(r.get("code"), "backend")
        self.assertEqual(r.get("status"), 503)
        # DATA не сохранился: устройство 3 не появилось в реестре
        data_after = self._data()
        self.assertEqual(data_after, data_before)
        # существующие юзеры моста живы (откат не тронул их)
        self.assertEqual(len(self.fake.users), 2)

    def test_rename_failure_restores_removed_user(self):
        sub = self._create(max_devices=2)
        token = sub["token"]
        r = pw.ctl_subscription({"operation": "fetch", "token": token, "hwid": "hwid-0001"})
        self.assertTrue(r["ok"])
        secret = r["users"][0]["secret"]
        email = next(iter(self.fake.users))
        data = self._data()
        sid = data["subscriptions"][0]["id"]
        device_id = data["subscriptions"][0]["devices"][0]["id"]
        data_before = self._data()

        # rename = remove+add: add_user падает ПОСЛЕ успешного remove —
        # мост обязан откатить remove (инверсия) и не сохранять DATA.
        # Сбой одноразовый (transient): инверсионный add должен пройти.
        original_add = self.fake.add_user
        def oneshot_add(email, protocols="all", **kw):
            if oneshot_add.failed:
                oneshot_add.failed = False
                return {"success": False, "applied": [], "failed": ["vless"],
                        "errors": ["forced failure"]}
            return original_add(email, protocols=protocols, **kw)
        oneshot_add.failed = True
        with patch.object(user_lifecycle, "add_user", oneshot_add):
            r = pw.ctl_subscription({"operation": "rename-device", "id": sid,
                                     "device_id": device_id, "name": "Слом"})
        self.assertFalse(r.get("ok"))
        self.assertEqual(r.get("code"), "backend")
        # remove откачен: юзер снова на месте с тем же uuid
        self.assertIn(email, self.fake.users)
        self.assertEqual(self.fake.users[email]["uuid"], secret)
        # DATA не сохранился: старое имя устройства
        self.assertEqual(self._data(), data_before)
        self.fake.fail_on = None

    def test_subscription_action_create_vless_only(self):
        # chimera-форма создаёт vless-only подписку (hysteria в chimera —
        # общий пароль, per-device ключи невозможны)
        result = pw.ctl_subscription({"operation": "create", "name": "Тест",
                                      "max_devices": "2", "protocols": ["vless"]})
        self.assertTrue(result.get("ok"))
        sub = self._data()["subscriptions"][0]
        self.assertEqual(sub["protocols"], ["vless"])
        self.assertEqual(sub["connections"][0]["protocol"], "vless")


# ─── users()/traffic() интеграция ─────────────────────────────────────────

class TestUsersAdapter(HwidSubscriptionTestBase):

    def test_subscription_profiles_annotated_on_live_chimera_users(self):
        # создаём подписку + одно устройство (мост на фейке)
        pw.ctl_subscription({"operation": "create", "name": "Александр",
                             "max_devices": 2, "protocols": ["vless"]})
        data = self._data()
        sub = data["subscriptions"][0]
        pw.ctl_subscription({"operation": "fetch", "token": sub["token"],
                             "hwid": "hwid-iphone", "device_name": "iPhone / iPad"})
        data = self._data()
        profile = data["users"][0]
        # живой chimera users.json (как его записал бы мост)
        self._chimera_users_write([{
            "uuid": profile["secret"], "email": pw._profile_email(profile),
            "name": profile["name"], "disabled": False, "blocked": False,
        }])
        profiles = pw.users()
        # ровно один profile на живого юзера — без дубликата из DATA
        self.assertEqual(len(profiles), 1)
        u = profiles[0]
        self.assertEqual(u["subscription_id"], sub["id"])
        self.assertEqual(u["device_id"], profile["device_id"])
        self.assertEqual(u["connection_id"], "vless-direct")
        self.assertEqual(u["protocol"], "vless")
        self.assertEqual(u["secret"], profile["secret"])
        self.assertTrue(u["email"].startswith("wppsub-"))

    def test_plain_chimera_users_stay_unowned(self):
        self._chimera_users_write([{
            "uuid": "11111111-2222-3333-4444-555555555555",
            "email": "alice@example.com", "name": "Alice",
            "disabled": False, "blocked": False,
        }])
        profiles = pw.users()
        self.assertEqual(len(profiles), 1)
        self.assertIsNone(profiles[0]["subscription_id"])
        self.assertEqual(profiles[0]["email"], "alice@example.com")


# ─── serve-хелперы v2.9.1 ─────────────────────────────────────────────────

class TestServeHelpers(unittest.TestCase):

    def test_subscription_device_name_from_user_agent(self):
        f = pw.subscription_device_name
        self.assertEqual(f("Mozilla/5.0 (Linux; Android 13)"), "Android")
        self.assertEqual(f("Mozilla/5.0 (iPhone; CPU iOS 17_0)"), "iPhone / iPad")
        self.assertEqual(f("Mozilla/5.0 (Windows NT 10.0)"), "Windows")
        self.assertEqual(f("Mozilla/5.0 (Macintosh; Mac OS X 10_15)"), "macOS")
        self.assertEqual(f("Mozilla/5.0 (X11; Linux x86_64)"), "Linux")
        self.assertEqual(f(""), "Устройство")

    def test_dashboard_token_is_stable_hmac(self):
        a = pw.subscription_dashboard_token("a" * 64)
        b = pw.subscription_dashboard_token("a" * 64)
        c = pw.subscription_dashboard_token("b" * 64)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 64)

    def test_profile_email_slug_sanitized(self):
        email = pw._profile_email({"subscription_id": "ab12cd34",
                                   "device_id": "ef56ab78",
                                   "connection_id": "vless-direct"})
        self.assertEqual(email, "wppsub-ab12cd34-ef56ab78-vless-direct@wpp.local")
        # экзотический connection_id не ломает email
        email2 = pw._profile_email({"subscription_id": "x", "device_id": "y",
                                    "connection_id": "Weird/ID 42"})
        self.assertNotIn("/", email2)
        self.assertNotIn(" ", email2)

    def test_proxy_connection_name(self):
        self.assertEqual(pw.proxy_connection_name(
            {"connection_id": "vless-direct"}, "VLESS"), "VLESS XHTTP · напрямую")
        self.assertEqual(pw.proxy_connection_name({}, "VLESS"), "VLESS")


if __name__ == "__main__":
    unittest.main()
