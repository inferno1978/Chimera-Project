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
  4. _verify_cdn_masking_password — проверка пароля через PBKDF2-HMAC-SHA256,
     hash хранится в state-файле /var/lib/xray-installer/cdn_premium.hash
     (НЕ в коде, НЕ в git). Тесты мокают CDN_MASKING_HASH_FILE на tmp_path.
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
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
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
    """_verify_cdn_masking_password: PBKDF2 проверка через state-file.

    Все тесты мокают chimera.modules.xhttp_cdn_masking.CDN_MASKING_HASH_FILE
    на временный файл в tmp_path. Реальный /var/lib/xray-installer/cdn_premium.hash
    НЕ затрагивается.
    """

    def setUp(self):
        # Импорт модуля — должен происходить ПОСЛЕ установки sys.path.
        from chimera.modules import xhttp_cdn_masking
        self._cm = xhttp_cdn_masking
        self.verify = xhttp_cdn_masking._verify_cdn_masking_password
        # Запоминаем оригинальный путь к hash-файлу.
        self._orig_hash_file = xhttp_cdn_masking.CDN_MASKING_HASH_FILE
        # Создаём временный каталог для тестового hash-файла.
        self._tmp = tempfile.mkdtemp(prefix="cdn_masking_test_")
        self._hash_file = Path(self._tmp) / "cdn_premium.hash"
        # Подменяем путь.
        xhttp_cdn_masking.CDN_MASKING_HASH_FILE = self._hash_file

    def tearDown(self):
        # Возвращаем оригинальный путь.
        self._cm.CDN_MASKING_HASH_FILE = self._orig_hash_file
        # Чистим temp.
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_hash_file(self, password: str, iterations: int = 10000) -> dict:
        """Записывает в тестовый hash-файл PBKDF2-hash от password.

        Использует МАЛЕНЬКОЕ iterations (10000) для скорости тестов —
        не 600000 как в проде. Тестируется логика, не KDF-стойкость.
        """
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        ).hex()
        data = {
            "salt": salt.hex(),
            "hash": pwd_hash,
            "iterations": iterations,
            "algo": "pbkdf2_sha256",
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        return data

    # ── Тест 1: файла нет → verify() всегда False ──────────────────────────
    def test_no_hash_file_returns_false_for_any_password(self):
        """Если CDN_MASKING_HASH_FILE не существует → return False."""
        # Файл не создавали в setUp — его нет.
        self.assertFalse(self._hash_file.exists(),
            "Test setup error: hash file should not exist")
        # Любой пароль → False.
        self.assertFalse(self.verify(""))
        self.assertFalse(self.verify("anything"))
        self.assertFalse(self.verify("Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"))
        self.assertFalse(self.verify("a" * 100))
        self.assertFalse(self.verify("wrong-password-12345"))

    # ── Тест 2: правильный пароль → True, неправильный → False ─────────────
    def test_correct_password_returns_true(self):
        """Установленный пароль (через мок записи JSON) → verify()==True."""
        pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self._write_hash_file(pwd)
        self.assertTrue(self.verify(pwd),
            "verify() must return True for the correct password")

    def test_wrong_password_returns_false(self):
        """Неправильный пароль → verify()==False."""
        pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self._write_hash_file(pwd)
        self.assertFalse(self.verify("definitely-not-the-right-password"))
        self.assertFalse(self.verify(""))
        self.assertFalse(self.verify("a"))
        self.assertFalse(self.verify("Ch1mera_CDN_Beeline_2026_Pa$$w0rd"))
        self.assertFalse(self.verify("ch1mera_cdn_beeline_2026_pa$$w0rd!"))  # lower

    def test_password_case_sensitive(self):
        """Пароль чувствителен к регистру."""
        pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self._write_hash_file(pwd)
        self.assertFalse(self.verify(pwd.lower()))
        self.assertFalse(self.verify(pwd.upper()))

    def test_empty_password_returns_false_even_with_file(self):
        """Пустой пароль → False даже при существующем hash-файле."""
        self._write_hash_file("SomeValidPassword!2026#Strong")
        self.assertFalse(self.verify(""))

    # ── Тест 4: битый JSON / отсутствующие ключи → False без исключения ────
    def test_corrupted_json_returns_false(self):
        """Файл с битым JSON → verify() возвращает False, не бросает."""
        self._hash_file.write_text("not a valid json {{{", encoding="utf-8")
        # Не должно бросать исключение.
        result = self.verify("any-password")
        self.assertFalse(result)

    def test_empty_file_returns_false(self):
        """Пустой файл → verify() возвращает False."""
        self._hash_file.write_text("", encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_missing_salt_key_returns_false(self):
        """JSON без 'salt' → False, не бросает KeyError."""
        data = {"hash": "abc", "iterations": 10000, "algo": "pbkdf2_sha256"}
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_missing_hash_key_returns_false(self):
        """JSON без 'hash' → False, не бросает KeyError."""
        data = {"salt": "ab" * 16, "iterations": 10000, "algo": "pbkdf2_sha256"}
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_missing_iterations_key_returns_false(self):
        """JSON без 'iterations' (старый формат) → False, не бросает.

        Это ключевая гарантия безопасности: мы НЕ пытаемся автоматически
        мигрировать старый формат, а просто отказываем.
        """
        # Старый формат: только salt + hash, без iterations/algo.
        data = {
            "salt": "ab" * 16,
            "hash": "cd" * 32,
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"),
            "Old format without 'iterations' must return False, not raise")

    def test_missing_algo_key_returns_false(self):
        """JSON без 'algo' (старый формат) → False."""
        data = {
            "salt": "ab" * 16,
            "hash": "cd" * 32,
            "iterations": 10000,
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_unknown_algo_returns_false(self):
        """JSON с неизвестным algo → False (не падает)."""
        data = {
            "salt": "ab" * 16,
            "hash": "cd" * 32,
            "iterations": 10000,
            "algo": "argon2id",  # будущий алгоритм, пока не поддерживается
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_invalid_iterations_type_returns_false(self):
        """iterations — не число → False, не бросает."""
        data = {
            "salt": "ab" * 16,
            "hash": "cd" * 32,
            "iterations": "not-a-number",
            "algo": "pbkdf2_sha256",
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_invalid_salt_hex_returns_false(self):
        """salt — не hex → False, не бросает."""
        data = {
            "salt": "this-is-not-hex!",
            "hash": "cd" * 32,
            "iterations": 10000,
            "algo": "pbkdf2_sha256",
        }
        self._hash_file.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(self.verify("any-password"))

    def test_constant_time_compare_used(self):
        """Верификация использует hmac.compare_digest (constant-time).

        Косвенная проверка: правильный пароль проходит, неправильный — нет.
        Прямая проверка через inspect — сравнение должно вызывать
        hmac.compare_digest, не ==.
        """
        import inspect
        src = inspect.getsource(self._cm._verify_cdn_masking_password)
        self.assertIn("hmac.compare_digest", src,
            "_verify_cdn_masking_password must use hmac.compare_digest "
            "(constant-time comparison)")

    # ── Тест: plaintext-пароля нет в исходнике модуля ─────────────────────
    def test_no_plaintext_password_in_module_source(self):
        """Plaintext-пароль НЕ хранится в коде модуля.

        Это была критическая проблема старой версии (хеш в коде).
        Теперь в коде не должно быть ни plaintext, ни хеша — только
        путь к state-файлу.
        """
        import inspect
        src = inspect.getsource(self._cm)
        # Известные тестовые пароли не должны встречаться в исходнике.
        for test_pwd in (
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            "TestPass!Strong2026Secret#",
        ):
            self.assertNotIn(test_pwd, src,
                f"Plaintext password must NOT appear in module source: {test_pwd!r}")

    def test_no_hardcoded_hash_constant_in_module(self):
        """В модуле нет захардкоженного хеша (старая _CDN_MASKING_PASSWORD_HASH).

        Старая константа _CDN_MASKING_PASSWORD_HASH удалена — проверяем,
        что атрибута больше нет.
        """
        self.assertFalse(hasattr(self._cm, "_CDN_MASKING_PASSWORD_HASH"),
            "_CDN_MASKING_PASSWORD_HASH must be removed — hash now lives in state-file")

    def test_hash_file_path_constant_exists(self):
        """Модуль экспортирует CDN_MASKING_HASH_FILE — путь к state-файлу.

        Проверяем через исходник модуля (а не через атрибут), т.к. в setUp
        мы мокаем CDN_MASKING_HASH_FILE на tmp-путь для тестов верификации.
        """
        import inspect
        import re
        src = inspect.getsource(self._cm)
        m = re.search(r'CDN_MASKING_HASH_FILE[^=]*=\s*Path\("([^"]+)"\)', src)
        self.assertIsNotNone(m,
            "CDN_MASKING_HASH_FILE must be defined as Path(...) in module source")
        path_str = m.group(1)
        # Путь должен быть в /var/lib/xray-installer/ (как другие state-файлы).
        self.assertEqual(path_str, "/var/lib/xray-installer/cdn_premium.hash",
            f"CDN_MASKING_HASH_FILE must point to /var/lib/xray-installer/cdn_premium.hash, "
            f"got {path_str!r}")

    def test_iterations_and_algo_constants_exist(self):
        """Модуль экспортирует дефолтные iterations и algo."""
        self.assertTrue(hasattr(self._cm, "_CDN_MASKING_DEFAULT_ITERATIONS"))
        # OWASP 2025-2026 рекомендует ≥100000.
        self.assertGreaterEqual(self._cm._CDN_MASKING_DEFAULT_ITERATIONS, 100000)
        self.assertTrue(hasattr(self._cm, "_CDN_MASKING_ALGO"))
        self.assertEqual(self._cm._CDN_MASKING_ALGO, "pbkdf2_sha256")


class TestPasswordHashScript(unittest.TestCase):
    """chimera/scripts/generate_cdn_masking_password_hash.py — утилита админа.

    Тестирует делегирование в access_control (master + OTP).
    """

    @classmethod
    def setUpClass(cls):
        """Загружаем скрипт напрямую через importlib — он не в пакете."""
        import importlib.util
        script_path = (_PROJECT_ROOT / "chimera" / "scripts"
                       / "generate_cdn_masking_password_hash.py")
        cls._spec = importlib.util.spec_from_file_location(
            "generate_cdn_masking_password_hash", script_path)
        cls._module = importlib.util.module_from_spec(cls._spec)
        cls._spec.loader.exec_module(cls._module)

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="cdn_hash_script_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _check(self, password: str):
        return self._module._check_password_strength(password)

    def test_check_password_strength_validates_min_length(self):
        issues = self._check("Short1!")
        self.assertTrue(any("длина" in i for i in issues))

    def test_check_password_strength_requires_uppercase(self):
        issues = self._check("alllowercase123!")
        self.assertTrue(any("заглавных" in i for i in issues))

    def test_check_password_strength_requires_lowercase(self):
        issues = self._check("ALLUPPERCASE123!")
        self.assertTrue(any("прописных" in i for i in issues))

    def test_check_password_strength_requires_special(self):
        issues = self._check("NoSpecialChars123")
        self.assertTrue(any("спец" in i for i in issues))

    def test_check_password_strength_accepts_valid(self):
        issues = self._check("ValidPass123!")
        self.assertEqual(issues, [])

    def test_script_has_hash_file_constant(self):
        self.assertTrue(hasattr(self._module, "HASH_FILE"))

    def test_script_imports_access_control(self):
        """Скрипт должен импортировать из access_control."""
        import inspect
        src = inspect.getsource(self._module)
        self.assertIn("access_control", src)
        self.assertIn("init_master", src)
