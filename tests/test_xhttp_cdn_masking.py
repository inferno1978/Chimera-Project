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

    Тестирует:
      - check_password_strength (без изменений, эта часть была верной).
      - write_hash_file — запись PBKDF2 JSON в state-файл с chmod 0600.
      - Случайность соли между прогонами (один и тот же пароль → разный salt).
      - Отсутствие инструкций "закоммитьте/запушьте" в выводе скрипта.
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
        return self._module.check_password_strength(password)

    # ── check_password_strength — без изменений (эта часть была верной) ────
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

    # ── write_hash_file — новая функция (PBKDF2 + salt + 0600) ────────────
    def test_write_hash_file_creates_file(self):
        """write_hash_file создаёт файл по указанному пути."""
        dest = Path(self._tmp) / "test.hash"
        self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        self.assertTrue(dest.exists(),
            "Hash file must be created")

    def test_write_hash_file_writes_valid_json(self):
        """Файл содержит валидный JSON с правильной структурой."""
        dest = Path(self._tmp) / "test.hash"
        data = self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        # Читаем обратно из файла.
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(loaded, data)
        # Обязательные ключи.
        self.assertIn("salt", loaded)
        self.assertIn("hash", loaded)
        self.assertIn("iterations", loaded)
        self.assertIn("algo", loaded)
        self.assertEqual(loaded["algo"], "pbkdf2_sha256")
        self.assertEqual(loaded["iterations"], 10000)

    def test_write_hash_file_sets_permissions_0600(self):
        """Файл записывается с правами 0600 (rw------- only owner)."""
        dest = Path(self._tmp) / "test.hash"
        self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        st = dest.stat()
        mode = stat.S_IMODE(st.st_mode)
        self.assertEqual(mode, 0o600,
            f"Hash file must have 0600 permissions, got {oct(mode)}")

    def test_write_hash_file_salt_is_16_bytes_hex(self):
        """Соль — 16 байт, в hex (32 символа)."""
        dest = Path(self._tmp) / "test.hash"
        data = self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        self.assertEqual(len(data["salt"]), 32,
            f"salt hex must be 32 chars (16 bytes), got {len(data['salt'])}")
        # Валидный hex.
        int(data["salt"], 16)  # бросит если не hex

    def test_write_hash_file_hash_is_pbkdf2_sha256_hex(self):
        """Hash — 64 символа hex (SHA-256 = 32 байта)."""
        dest = Path(self._tmp) / "test.hash"
        data = self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        self.assertEqual(len(data["hash"]), 64,
            f"hash hex must be 64 chars (SHA-256), got {len(data['hash'])}")
        int(data["hash"], 16)  # бросит если не hex

    # ── ТЕСТ 3 (из ТЗ): два прогона одного пароля → РАЗНЫЕ salt и hash ────
    def test_two_runs_same_password_give_different_salt_and_hash(self):
        """Два прогона ОДНОГО И ТОГО ЖЕ пароля дают РАЗНЫЕ salt и hash.

        Соль реально случайна каждый раз — детерминированности нет.
        """
        dest1 = Path(self._tmp) / "run1.hash"
        dest2 = Path(self._tmp) / "run2.hash"
        pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        data1 = self._module.write_hash_file(pwd, dest=dest1, iterations=10000)
        data2 = self._module.write_hash_file(pwd, dest=dest2, iterations=10000)
        # Разные salt.
        self.assertNotEqual(data1["salt"], data2["salt"],
            "Salt must be different between runs (random per-run)")
        # Разные hash (т.к. salt разный → pbkdf2 даёт разный результат).
        self.assertNotEqual(data1["hash"], data2["hash"],
            "Hash must be different between runs (different salt → different hash)")

    def test_two_runs_different_passwords_give_different_hashes(self):
        """Разные пароли → разные hash (даже если бы salt совпал)."""
        dest1 = Path(self._tmp) / "pwd1.hash"
        dest2 = Path(self._tmp) / "pwd2.hash"
        data1 = self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!", dest=dest1, iterations=10000)
        data2 = self._module.write_hash_file(
            "DifferentValidPass#2026!Strong", dest=dest2, iterations=10000)
        self.assertNotEqual(data1["hash"], data2["hash"])

    def test_write_hash_file_overwrites_existing(self):
        """Перезапись существующего файла обновляет hash (смена пароля)."""
        dest = Path(self._tmp) / "overwrite.hash"
        # Первый пароль.
        data1 = self._module.write_hash_file(
            "FirstPassword!2026#Strong", dest=dest, iterations=10000)
        # Второй пароль — перезаписывает.
        data2 = self._module.write_hash_file(
            "SecondPassword!2026#Strong", dest=dest, iterations=10000)
        # Файл один, но hash от второго пароля.
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(loaded["hash"], data2["hash"])
        self.assertNotEqual(loaded["hash"], data1["hash"])

    def test_write_hash_file_creates_parent_dir(self):
        """Если родительский каталог не существует — он создаётся."""
        dest = Path(self._tmp) / "subdir" / "nested" / "test.hash"
        self._module.write_hash_file(
            "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!",
            dest=dest,
            iterations=10000,
        )
        self.assertTrue(dest.exists())

    # ── Круговая проверка: write_hash_file → _verify_cdn_masking_password ─
    def test_written_hash_passes_verification(self):
        """Hash, записанный скриптом, проходит проверку verify()."""
        dest = Path(self._tmp) / "roundtrip.hash"
        pwd = "Ch1mera_CDN_Beeline_2026_Pa$$w0rd!"
        self._module.write_hash_file(pwd, dest=dest, iterations=10000)

        # Мокаем CDN_MASKING_HASH_FILE в модуле на наш temp-файл.
        from chimera.modules import xhttp_cdn_masking
        orig = xhttp_cdn_masking.CDN_MASKING_HASH_FILE
        xhttp_cdn_masking.CDN_MASKING_HASH_FILE = dest
        try:
            self.assertTrue(xhttp_cdn_masking._verify_cdn_masking_password(pwd))
            self.assertFalse(
                xhttp_cdn_masking._verify_cdn_masking_password("wrong"))
        finally:
            xhttp_cdn_masking.CDN_MASKING_HASH_FILE = orig

    # ── ТЕСТ 7 (из ТЗ): никаких "закоммитьте/запушьте/git commit" ──────────
    def test_no_commit_push_instructions_in_script_source(self):
        """В исходнике скрипта нет инструкций про git commit/push.

        Старая версия велела "закоммитьте и запушьте в репозиторий" —
        это и был корень проблемы. Не должно остаться ни одной такой
        фразы применительно к хешу пароля.
        """
        import inspect
        src = inspect.getsource(self._module)
        # Запрещённые фразы.
        # Русские фразы — case-insensitive (они не появляются в именах файлов).
        # Python-идентификатор _CDN_MASKING_PASSWORD_HASH — case-sensitive,
        # т.к. всегда uppercase; case-insensitive даст ложное срабатывание
        # на подстроку '_cdn_masking_password_hash' внутри имени файла
        # 'generate_cdn_masking_password_hash.py'.
        case_insensitive_patterns = [
            "закоммитьте",
            "закоммить",
            "запушьте",
            "запушь",
            "git commit",
            "git push",
            "commit и push",
            "push в репозиторий",
            "замените значение константы",  # старая инструкция
        ]
        case_sensitive_patterns = [
            "_CDN_MASKING_PASSWORD_HASH",   # старая константа (exact case)
        ]
        src_lower = src.lower()
        for pat in case_insensitive_patterns:
            self.assertNotIn(pat.lower(), src_lower,
                f"Forbidden phrase '{pat}' found in generate_cdn_masking_password_hash.py source")
        for pat in case_sensitive_patterns:
            self.assertNotIn(pat, src,
                f"Forbidden Python identifier '{pat}' found in generate_cdn_masking_password_hash.py source")

    def test_no_commit_push_instructions_in_main_output(self):
        """Вывод main() не содержит git/commit/push инструкций."""
        # Перехватываем stdout и вызываем main с пустым stdin (getpass
        # сразу получит EOFError → main() вернёт 1, но успеет напечатать
        # заголовок и требования).
        import io
        import contextlib
        buf = io.StringIO()
        # Подменяем реальный stdin на пустой StringIO → getpass.getpass()
        # при отсутствии TTY использует fallback_getpass, который читает
        # из sys.stdin и сразу получает EOF → main() выходит с кодом 1.
        orig_stdin = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            with contextlib.redirect_stdout(buf):
                with contextlib.redirect_stderr(buf):
                    try:
                        self._module.main()
                    except (EOFError, SystemExit):
                        pass
        finally:
            sys.stdin = orig_stdin
        output = buf.getvalue().lower()
        forbidden = ["закоммитьте", "запушьте", "git commit", "git push",
                     "commit и push", "push в репозиторий"]
        for pat in forbidden:
            self.assertNotIn(pat.lower(), output,
                f"Forbidden phrase '{pat}' in script output")

    def test_hash_file_path_constant_matches_module(self):
        """HASH_FILE в скрипте совпадает с CDN_MASKING_HASH_FILE в модуле."""
        from chimera.modules import xhttp_cdn_masking
        # Восстанавливаем оригинальное значение (мок из других тестов мог изменить).
        # Используем importlib reload чтобы получить чистое значение.
        import importlib
        # Не reload — это может сломать другие тесты. Просто сравниваем строковые пути.
        script_path = str(self._module.HASH_FILE)
        module_path = str(xhttp_cdn_masking.CDN_MASKING_HASH_FILE)
        # Если module был замокан в setUp другого теста, это может не совпасть.
        # Поэтому используем абсолютное значение из исходника.
        import inspect
        module_src = inspect.getsource(xhttp_cdn_masking)
        # Извлекаем путь из исходника: CDN_MASKING_HASH_FILE: Path = Path("...")
        import re
        m = re.search(r'CDN_MASKING_HASH_FILE[^=]*=\s*Path\("([^"]+)"\)', module_src)
        self.assertIsNotNone(m, "Cannot extract CDN_MASKING_HASH_FILE path from source")
        module_path_from_src = m.group(1)
        self.assertEqual(script_path, module_path_from_src,
            f"HASH_FILE in script ({script_path}) must match CDN_MASKING_HASH_FILE "
            f"in module ({module_path_from_src})")

    def test_default_iterations_at_least_100000(self):
        """ITERATIONS в скрипте ≥ 100000 (OWASP минимум)."""
        self.assertGreaterEqual(self._module.ITERATIONS, 100000,
            f"ITERATIONS must be ≥ 100000 (OWASP), got {self._module.ITERATIONS}")

    def test_algo_constant_is_pbkdf2_sha256(self):
        """ALGO в скрипте = 'pbkdf2_sha256'."""
        self.assertEqual(self._module.ALGO, "pbkdf2_sha256")


if __name__ == "__main__":
    unittest.main()
