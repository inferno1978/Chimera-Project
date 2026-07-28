#!/usr/bin/env python3
"""
tests/test_xhttp_cdn_masking.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/xhttp_cdn_masking.py — экспертный профиль XHTTP
для обхода белых списков через Beeline CDN.

Покрывает:
  1. build_xhttp_cdn_masking_inbound(domain, path, port) — все обязательные ключи
     в возвращаемом xhttpSettings присутствуют (extra поля из ТЗ).
  2. build_xhttp_cdn_masking_client_xhttp_settings(domain, path) — клиентский
     конфиг симметричен серверному.
  3. build_xhttp_cdn_masking_client_extra() — все extra-поля присутствуют.
  4. _verify_cdn_masking_password — проверка пароля (хеш + hmac.compare_digest).
  5. CDN_MASKING_INBOUND_PORT — корректное значение (7443).
  6. CDN_MASKING_EXTRA — все обязательные ключи из референса:
     xPaddingBytes(50-150), xPaddingHeader("X-Api-Key"), xPaddingMethod("tokenish"),
     xPaddingObfsMode(true), xPaddingPlacement("header"),
     seqKey("chunk_id"), seqPlacement("query"),
     sessionKey/sessionIDKey("auth")/sessionIDTable("Base62")/sessionIDLength("16-32"),
     sessionPlacement+sessionIDPlacement("query"),
     noSSEHeader/noGRPCHeader(true),
     scMaxBufferedPosts(100)/scMaxEachPostBytes(3000000)/scMinPostsIntervalMs("5-10")/
     scMaxConcurrentPosts(10)/serverMaxHeaderBytes(32768),
     uplinkHTTPMethod("POST")/downloadHTTPMethod("GET")/uplinkDataPlacement("body"),
     xmux.maxConcurrency("1").
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ── Обязательные extra-ключи из ТЗ ──────────────────────────────────────────
REQUIRED_EXTRA_KEYS = {
    # xPadding
    "xPaddingBytes", "xPaddingHeader", "xPaddingMethod",
    "xPaddingObfsMode", "xPaddingPlacement",
    # Sequence
    "seqKey", "seqPlacement",
    # Session
    "sessionKey", "sessionIDKey", "sessionIDTable", "sessionIDLength",
    "sessionPlacement", "sessionIDPlacement",
    # Headers
    "noSSEHeader", "noGRPCHeader",
    # Stream-up / packet-up limits
    "scMaxBufferedPosts", "scMaxEachPostBytes", "scMinPostsIntervalMs",
    "scMaxConcurrentPosts", "serverMaxHeaderBytes",
    # HTTP methods
    "uplinkHTTPMethod", "downloadHTTPMethod", "uplinkDataPlacement",
    # xmux
    "xmux",
}


class TestBuildCdnMaskingInbound(unittest.TestCase):
    """build_xhttp_cdn_masking_inbound: серверный xhttpSettings."""

    def setUp(self):
        from chimera.modules.xhttp_cdn_masking import (
            build_xhttp_cdn_masking_inbound,
        )
        self.build = build_xhttp_cdn_masking_inbound

    def test_returns_dict(self):
        """Возвращает словарь."""
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertIsInstance(result, dict)

    def test_has_path(self):
        """path присутствует и нормализован (с ведущим /)."""
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertIn("path", result)
        self.assertEqual(result["path"], "/api/v2/static.ts")

    def test_path_normalized_leading_slash(self):
        """path без ведущего / нормализуется."""
        result = self.build("example.com", "api/v2/static.ts")
        self.assertEqual(result["path"], "/api/v2/static.ts")

    def test_path_normalized_no_trailing_slash(self):
        """trailing / убирается."""
        result = self.build("example.com", "/api/v2/static.ts/")
        self.assertEqual(result["path"], "/api/v2/static.ts")

    def test_has_host(self):
        """host присутствует (CDN_MASKING_HOST или domain)."""
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertIn("host", result)
        # Если CDN_MASKING_HOST пустой — host = domain
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_HOST
        expected_host = CDN_MASKING_HOST or "example.com"
        self.assertEqual(result["host"], expected_host)

    def test_has_mode_auto(self):
        """mode=auto (stream-up + packet-up auto-detect)."""
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertEqual(result.get("mode"), "auto")

    def test_has_extra_block(self):
        """extra-блок присутствует."""
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertIn("extra", result)
        self.assertIsInstance(result["extra"], dict)

    def test_extra_has_all_required_keys(self):
        """extra содержит ВСЕ обязательные ключи из ТЗ."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        missing = REQUIRED_EXTRA_KEYS - set(extra.keys())
        self.assertEqual(missing, set(),
            f"Missing required extra keys: {missing}")

    def test_xpadding_values_correct(self):
        """xPadding* значения соответствуют референсу."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertEqual(extra["xPaddingBytes"], "50-150")
        self.assertEqual(extra["xPaddingHeader"], "X-Api-Key")
        self.assertEqual(extra["xPaddingMethod"], "tokenish")
        self.assertIs(extra["xPaddingObfsMode"], True)
        self.assertEqual(extra["xPaddingPlacement"], "header")

    def test_seq_values_correct(self):
        """seq* значения соответствуют референсу."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertEqual(extra["seqKey"], "chunk_id")
        self.assertEqual(extra["seqPlacement"], "query")

    def test_session_values_correct(self):
        """session* значения соответствуют референсу."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertEqual(extra["sessionIDKey"], "auth")
        self.assertEqual(extra["sessionIDTable"], "Base62")
        self.assertEqual(extra["sessionIDLength"], "16-32")
        self.assertEqual(extra["sessionPlacement"], "query")
        self.assertEqual(extra["sessionIDPlacement"], "query")

    def test_header_flags_correct(self):
        """noSSEHeader / noGRPCHeader — True (референс)."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertIs(extra["noSSEHeader"], True)
        self.assertIs(extra["noGRPCHeader"], True)

    def test_sc_values_correct(self):
        """sc* значения соответствуют референсу."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertEqual(extra["scMaxBufferedPosts"], 100)
        self.assertEqual(extra["scMaxEachPostBytes"], 3000000)
        self.assertEqual(extra["scMinPostsIntervalMs"], "5-10")
        self.assertEqual(extra["scMaxConcurrentPosts"], 10)
        self.assertEqual(extra["serverMaxHeaderBytes"], 32768)

    def test_http_methods_correct(self):
        """uplinkHTTPMethod=POST, downloadHTTPMethod=GET, uplinkDataPlacement=body."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertEqual(extra["uplinkHTTPMethod"], "POST")
        self.assertEqual(extra["downloadHTTPMethod"], "GET")
        self.assertEqual(extra["uplinkDataPlacement"], "body")

    def test_xmux_max_concurrency_one(self):
        """xmux.maxConcurrency = '1' (референс)."""
        result = self.build("example.com", "/api/v2/static.ts")
        extra = result["extra"]
        self.assertIn("xmux", extra)
        self.assertEqual(extra["xmux"]["maxConcurrency"], "1")

    def test_has_backend_port_meta(self):
        """Возвращаемый dict содержит __backend_port (мета для nginx_setup)."""
        result = self.build("example.com", "/api/v2/static.ts", port=7443)
        self.assertIn("__backend_port", result)
        self.assertEqual(result["__backend_port"], 7443)

    def test_default_port_is_7443(self):
        """По умолчанию backend port = 7443 (CDN_MASKING_INBOUND_PORT)."""
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_INBOUND_PORT
        result = self.build("example.com", "/api/v2/static.ts")
        self.assertEqual(result["__backend_port"], CDN_MASKING_INBOUND_PORT)
        self.assertEqual(CDN_MASKING_INBOUND_PORT, 7443)

    def test_custom_port(self):
        """Произвольный backend port корректно сохраняется."""
        result = self.build("example.com", "/api/v2/static.ts", port=9999)
        self.assertEqual(result["__backend_port"], 9999)

    def test_empty_path_raises(self):
        """Пустой path вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.build("example.com", "")

    def test_empty_domain_raises(self):
        """Пустой domain вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.build("", "/api/v2/static.ts")

    def test_extra_independent_between_calls(self):
        """extra-блок независим между вызовами (deepcopy, не shared mutable)."""
        r1 = self.build("example.com", "/api/v2/static.ts")
        r2 = self.build("example.com", "/api/v2/static.ts")
        self.assertIsNot(r1["extra"], r2["extra"])
        # Мутируем r1 — r2 не должен измениться
        r1["extra"]["xPaddingBytes"] = "999-999"
        self.assertNotEqual(r1["extra"]["xPaddingBytes"],
                            r2["extra"]["xPaddingBytes"])


class TestBuildClientExtra(unittest.TestCase):
    """build_xhttp_cdn_masking_client_extra: клиентский extra-блок."""

    def setUp(self):
        from chimera.modules.xhttp_cdn_masking import (
            build_xhttp_cdn_masking_client_extra,
        )
        self.build = build_xhttp_cdn_masking_client_extra

    def test_returns_dict(self):
        r = self.build()
        self.assertIsInstance(r, dict)

    def test_has_all_required_keys(self):
        """Клиентский extra содержит все обязательные ключи (симметрично серверу)."""
        r = self.build()
        missing = REQUIRED_EXTRA_KEYS - set(r.keys())
        self.assertEqual(missing, set(),
            f"Missing required client extra keys: {missing}")

    def test_independent_from_server_constant(self):
        """Клиентский extra — глубокая копия, мутация не влияет на константу."""
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_EXTRA
        r = self.build()
        self.assertIsNot(r, CDN_MASKING_EXTRA)
        r["xPaddingBytes"] = "999-999"
        self.assertNotEqual(CDN_MASKING_EXTRA["xPaddingBytes"], "999-999")


class TestBuildClientXhttpSettings(unittest.TestCase):
    """build_xhttp_cdn_masking_client_xhttp_settings: клиентский xhttpSettings."""

    def setUp(self):
        from chimera.modules.xhttp_cdn_masking import (
            build_xhttp_cdn_masking_client_xhttp_settings,
        )
        self.build = build_xhttp_cdn_masking_client_xhttp_settings

    def test_returns_dict_with_required_keys(self):
        r = self.build("example.com", "/api/v2/static.ts")
        self.assertIsInstance(r, dict)
        self.assertIn("mode", r)
        self.assertIn("path", r)
        self.assertIn("host", r)
        self.assertIn("extra", r)

    def test_mode_auto(self):
        r = self.build("example.com", "/api/v2/static.ts")
        self.assertEqual(r["mode"], "auto")

    def test_path_normalized(self):
        r = self.build("example.com", "api/v2/static.ts/")
        self.assertEqual(r["path"], "/api/v2/static.ts")

    def test_extra_has_required_keys(self):
        r = self.build("example.com", "/api/v2/static.ts")
        missing = REQUIRED_EXTRA_KEYS - set(r["extra"].keys())
        self.assertEqual(missing, set())

    def test_no_backend_port_meta(self):
        """Клиентский xhttpSettings НЕ содержит __backend_port (только сервер)."""
        r = self.build("example.com", "/api/v2/static.ts")
        self.assertNotIn("__backend_port", r)

    def test_empty_path_raises(self):
        with self.assertRaises(ValueError):
            self.build("example.com", "")

    def test_empty_domain_raises(self):
        with self.assertRaises(ValueError):
            self.build("", "/api/v2/static.ts")


class TestCdnMaskingConstants(unittest.TestCase):
    """CDN_MASKING_* константы."""

    def test_inbound_port_7443(self):
        """CDN_MASKING_INBOUND_PORT = 7443 (отдельный от 8443 simple-XHTTP)."""
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_INBOUND_PORT
        self.assertEqual(CDN_MASKING_INBOUND_PORT, 7443)

    def test_extra_is_dict(self):
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_EXTRA
        self.assertIsInstance(CDN_MASKING_EXTRA, dict)

    def test_extra_has_all_required_keys(self):
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_EXTRA
        missing = REQUIRED_EXTRA_KEYS - set(CDN_MASKING_EXTRA.keys())
        self.assertEqual(missing, set())

    def test_headers_is_dict(self):
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_HEADERS
        self.assertIsInstance(CDN_MASKING_HEADERS, dict)

    def test_headers_contain_browser_keys(self):
        """CDN_MASKING_HEADERS содержит ключевые браузерные заголовки."""
        from chimera.modules.xhttp_cdn_masking import CDN_MASKING_HEADERS
        for k in ("Accept", "Accept-Language", "User-Agent", "Origin",
                  "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site"):
            self.assertIn(k, CDN_MASKING_HEADERS,
                f"Missing required browser header: {k}")


class TestPasswordVerification(unittest.TestCase):
    """_verify_cdn_masking_password: проверка пароля."""

    def setUp(self):
        from chimera.modules.xhttp_cdn_masking import _verify_cdn_masking_password
        self.verify = _verify_cdn_masking_password

    def test_empty_password_returns_false(self):
        self.assertFalse(self.verify(""))

    def test_wrong_password_returns_false(self):
        self.assertFalse(self.verify("definitely-not-the-right-password"))

    def test_short_wrong_password_returns_false(self):
        self.assertFalse(self.verify("a"))

    def test_correct_password_returns_true(self):
        """Тестовый пароль из ТЗ — должен проходить проверку."""
        # Тестовый пароль — сообщается юзеру вне кода. Длина ≥20, все
        # типы символов.
        test_pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self.assertTrue(self.verify(test_pwd))

    def test_password_case_sensitive(self):
        """Пароль чувствителен к регистру."""
        test_pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self.assertFalse(self.verify(test_pwd.lower()))
        self.assertFalse(self.verify(test_pwd.upper()))

    def test_password_no_plaintext_in_module(self):
        """Plaintext-пароль НЕ хранится в коде модуля."""
        from chimera.modules import xhttp_cdn_masking
        import inspect
        src = inspect.getsource(xhttp_cdn_masking)
        # Проверяем, что тестовый пароль не встречается в исходнике
        # целиком — ни в comments, ни в docstrings, ни в коде.
        test_pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self.assertNotIn(test_pwd, src,
            "Plaintext password must NOT appear in module source!")

    def test_only_hash_in_module(self):
        """В коде хранится только SHA-256 hash, не plaintext."""
        from chimera.modules import xhttp_cdn_masking
        # Проверяем что есть hash константа
        self.assertTrue(hasattr(xhttp_cdn_masking, "_CDN_MASKING_PASSWORD_HASH"))
        h = xhttp_cdn_masking._CDN_MASKING_PASSWORD_HASH
        # Hash — 64-символьная hex строка SHA-256
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h),
            f"Hash is not a valid SHA-256 hex: {h!r}")


class TestPasswordHashScript(unittest.TestCase):
    """chimera/scripts/generate_cdn_masking_password_hash.py: утилита админа."""

    @classmethod
    def setUpClass(cls):
        """Загружаем скрипт напрямую через importlib — он не в пакете."""
        import importlib.util
        script_path = _PROJECT_ROOT / "chimera" / "scripts" / "generate_cdn_masking_password_hash.py"
        cls._spec = importlib.util.spec_from_file_location(
            "generate_cdn_masking_password_hash", script_path)
        cls._module = importlib.util.module_from_spec(cls._spec)
        cls._spec.loader.exec_module(cls._module)

    def _check(self, password: str):
        return self._module.check_password_strength(password)

    def test_check_password_strength_validates_min_length(self):
        """Минимальная длина пароля — 20 символов."""
        ok, errs = self._check("Ab1!short")
        self.assertFalse(ok)
        self.assertTrue(any("длина" in e for e in errs))

    def test_check_password_strength_requires_uppercase(self):
        ok, errs = self._check("alllowercase1!longenough")
        self.assertFalse(ok)
        self.assertTrue(any("заглавных" in e for e in errs))

    def test_check_password_strength_requires_lowercase(self):
        ok, errs = self._check("ALLUPPERCASE1!LONGENOUGH")
        self.assertFalse(ok)
        self.assertTrue(any("прописных" in e for e in errs))

    def test_check_password_strength_requires_special(self):
        ok, errs = self._check("OnlyAlphaNumeric1234567890")
        self.assertFalse(ok)
        self.assertTrue(any("спец" in e for e in errs))

    def test_check_password_strength_accepts_valid(self):
        ok, errs = self._check("Ch1mera_CDN_Beeline_2026_Pa$$w0rd!")
        self.assertTrue(ok)
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
