#!/usr/bin/env python3
"""
tests/test_wpp_awg_adapters.py — адаптеры rest_api-стиля для WPP-хендлера.

awg_rest_api ожидает handler._require_admin() / handler._require_user()
(методы rest_api.Handler). При делегировании /api/awg/* из WPP-панели
(wpp_admin_extras) хендлер — WPP-шный, без этих методов: каждый вызов
падал с AttributeError (500), из-за чего вкладка AmneziaWG в юзер-портале
НЕ появлялась никогда — даже у пира с корректным owner_email.

_ensure_awg_adapters() цепляет адаптеры поверх WPP-механизмов:
  _require_admin(realm) -> handler.auth()
  _require_user()       -> wpp_portal._require_user(handler)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))


class _FakeWPPHandler:
    """Минимальный WPP-хендлер: auth() + send_json()."""

    def __init__(self, *, admin: bool = False, user: dict | None = None):
        self._admin = admin
        self._user = user
        self.sent = []

    def auth(self) -> bool:
        return self._admin

    def send_json(self, data, status: int = 200):
        self.sent.append((data, status))


class TestEnsureAwgAdapters(unittest.TestCase):

    def _extras(self):
        from chimera.modules import wpp_admin_extras
        return wpp_admin_extras

    def test_adapters_attached(self):
        sb = self._extras()
        h = _FakeWPPHandler()
        for m in ("_require_admin", "_require_user", "_send_json",
                  "_check_admin_auth"):
            self.assertFalse(hasattr(h, m), m)
        sb._ensure_awg_adapters(h)
        for m in ("_require_admin", "_require_user", "_send_json",
                  "_check_admin_auth"):
            self.assertTrue(callable(getattr(h, m)), m)

    def test_send_json_adapter(self):
        sb = self._extras()
        h = _FakeWPPHandler()
        sb._ensure_awg_adapters(h)
        h._send_json({"a": 1}, 201)
        self.assertEqual(h.sent, [({"a": 1}, 201)])

    def test_check_admin_auth_adapter(self):
        sb = self._extras()
        h_yes = _FakeWPPHandler(admin=True)
        h_no = _FakeWPPHandler(admin=False)
        sb._ensure_awg_adapters(h_yes)
        sb._ensure_awg_adapters(h_no)
        self.assertTrue(h_yes._check_admin_auth())
        self.assertFalse(h_no._check_admin_auth())
        self.assertEqual(h_no.sent, [])  # silent probe, no 401 sent

    def test_idempotent(self):
        sb = self._extras()
        h = _FakeWPPHandler()
        sb._ensure_awg_adapters(h)
        first_admin, first_user = h._require_admin, h._require_user
        sb._ensure_awg_adapters(h)
        self.assertIs(h._require_admin, first_admin)
        self.assertIs(h._require_user, first_user)

    def test_require_admin_true_when_authed(self):
        sb = self._extras()
        h = _FakeWPPHandler(admin=True)
        sb._ensure_awg_adapters(h)
        self.assertTrue(h._require_admin("AWG Admin"))
        self.assertEqual(h.sent, [])

    def test_require_admin_sends_401_when_not_authed(self):
        sb = self._extras()
        h = _FakeWPPHandler(admin=False)
        sb._ensure_awg_adapters(h)
        self.assertFalse(h._require_admin("AWG Admin"))
        self.assertEqual(len(h.sent), 1)
        data, status = h.sent[0]
        self.assertEqual(status, 401)
        self.assertIn("error", data)

    def test_require_user_delegates_to_portal(self):
        sb = self._extras()
        user = {"email": "user@chimeraprodvpn.online", "uuid": "u1"}
        h = _FakeWPPHandler(user=user)
        sb._ensure_awg_adapters(h)

        from chimera.modules import wpp_portal
        with patch.object(wpp_portal, "_require_user",
                          return_value=user) as m_portal:
            got = h._require_user()
        self.assertEqual(got, user)
        m_portal.assert_called_once_with(h)

    def test_real_portal_path_401(self):
        """Интеграционно: адаптер зовёт настоящий wpp_portal._require_user,
        который для API-пути без сессии отправляет 401 JSON."""
        sb = self._extras()
        h = _FakeWPPHandler()
        h.path = "/api/awg/my-peer"
        sb._ensure_awg_adapters(h)
        from chimera.modules import wpp_portal
        with patch.object(wpp_portal, "_get_user", return_value=None):
            got = h._require_user()
        self.assertIsNone(got)
        self.assertEqual(len(h.sent), 1)
        _, status = h.sent[0]
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
