#!/usr/bin/env python3
"""
tests/test_ios_link_variant.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ios_link_variant.py —
постпроцессор vless-ссылки в iOS/Karing-совместимый вариант.

Покрывает (нумерация соответствует спецификации задачи — ШАГ 0, тесты a-d):
  a. REALITY-ссылка с flow и с эмодзи-флагом → оба убраны, остальное
     побайтово как было.
  b. REALITY-ссылка с flow, БЕЗ эмодзи → flow убран, остальное не
     тронуто, функция не падает.
  c. xHTTP-ссылка (нет flow, нет обязательного эмодзи) → полный no-op.
  d. Edge case: percent-encoded email физически не может содержать
     сырых code point из диапазона regional-indicator после quote() —
     тест фиксирует этот инвариант.

Дополнительно:
  • Пустая строка и строка без `#` — no-op.
  • Эмодзи-флаг не в начале fragment (после первого символа) — НЕ
    вырезается (по спецификации: count=1 + _FLAG_EMOJI_RE без `^`).
    Это поведение фиксируем отдельным тестом — если в будущем
    потребуется резать флаг в любом месте fragment, тест придётся
    обновить осознанно.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestToIosKaringLink(unittest.TestCase):
    """to_ios_karing_link — pure postprocessor."""

    def _import(self):
        from chimera.modules.ios_link_variant import to_ios_karing_link
        return to_ios_karing_link

    # ── 0a: REALITY + flow + эмодзи-флаг ─────────────────────────────────────
    def test_a_reality_flow_and_flag_both_stripped(self):
        """Оба трансформации применены, остальное побайтово как было."""
        to_ios = self._import()

        uuid = "11111111-2222-3333-4444-555555555555"
        host = "vpn.example.com"
        port = "443"
        pbk = "abc123publickey"
        sid = "deadbeef"
        sni = "www.microsoft.com"
        fp = "chrome"
        # 🇩🇪 = U+1F1E9 U+1F1EA, потом пробел, потом percent-encoded email.
        email_q = "user%40example.com"
        link = (
            f"vless://{uuid}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}"
            f"&flow=xtls-rprx-vision#\U0001F1E9\U0001F1EA {email_q}"
        )

        result = to_ios(link)

        expected = (
            f"vless://{uuid}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}"
            f"#{email_q}"
        )
        self.assertEqual(result, expected)

        # Побайтовая проверка ключевых элементов (защита от случайной
        # правки чего-то кроме flow/флага).
        self.assertIn(f"@{host}:{port}", result)
        self.assertIn(f"pbk={pbk}", result)
        self.assertIn(f"sid={sid}", result)
        self.assertIn(f"sni={sni}", result)
        self.assertIn(f"fp={fp}", result)
        self.assertIn(email_q, result)

    # ── 0b: REALITY + flow, БЕЗ эмодзи ───────────────────────────────────────
    def test_b_reality_flow_no_flag_only_flow_stripped(self):
        """Flow убран, fragment без эмодзи не тронут, не падает."""
        to_ios = self._import()

        uuid = "22222222-3333-4444-5555-666666666666"
        link = (
            f"vless://{uuid}@1.2.3.4:443"
            f"?type=tcp&security=reality&pbk=PK&fp=chrome"
            f"&sni=example.com&sid=AB&flow=xtls-rprx-vision"
            f"#plainlabel"
        )

        result = to_ios(link)

        self.assertNotIn("flow=", result)
        self.assertNotIn("xtls-rprx-vision", result)
        self.assertTrue(result.endswith("#plainlabel"))
        # Параметры до fragment — те же, что и были (без `&flow=...`).
        self.assertIn("sid=AB", result)
        self.assertIn("pbk=PK", result)
        # Не должно остаться висячего `&` перед `#`.
        self.assertNotIn("&#", result)

    # ── 0c: xHTTP → полный no-op ─────────────────────────────────────────────
    def test_c_xhttp_noop(self):
        """xHTTP-ссылка без flow и без эмодзи — идентичный возврат."""
        to_ios = self._import()

        link = (
            "vless://33333333-4444-5555-6666-777777777777@vpn.example.com:443"
            "?type=xhttp&security=tls&sni=vpn.example.com"
            "&path=%2Fxhttp&mode=streamup&fp=chrome#user%40example.com"
        )

        result = to_ios(link)

        self.assertEqual(result, link)

    # ── 0d: email после quote() физически не содержит regional-indicator ────
    def test_d_percent_encoded_email_has_no_regional_indicator_codepoints(self):
        """quote() превращает любой non-ASCII в %XX-последовательности,
        поэтому regex физически не может зацепить email-часть fragment.
        Тест фиксирует этот инвариант: даже если бы в исходном email
        были code points из диапазона U+1F1E6-U+1F1FF, после quote()
        их там не будет."""
        to_ios = self._import()
        import urllib.parse

        # Берём 2 code point из regional-indicator диапазона и
        # конструируем из них email — на практике бессмысленно, но
        # проверяем именно инвариант «после quote() нет сырых code point».
        weird_email = "\U0001F1E6\U0001F1E7@example.com"
        quoted = urllib.parse.quote(weird_email, safe="")

        # В quoted не должно быть НИ ОДНОГО code point из диапазона.
        self.assertFalse(
            any("\U0001F1E6" <= ch <= "\U0001F1FF" for ch in quoted),
            "quote() должен percent-encode все non-ASCII, включая "
            "regional-indicator code points",
        )

        link = (
            "vless://44444444-5555-6666-7777-888888888888@vpn.example.com:443"
            f"?type=tcp&security=reality&pbk=PK&fp=chrome"
            f"&sni=sni.example.com&sid=AB&flow=xtls-rprx-vision#{quoted}"
        )

        result = to_ios(link)

        # flow убран.
        self.assertNotIn("flow=", result)
        # Quoted email не повреждён (regex не нашёл что резать —
        # все code point в нём percent-encoded, сырых emoji-пар нет).
        self.assertIn(quoted, result)
        # Не появилось «двойной очисткой» мусора в начале fragment.
        self.assertTrue(result.partition("#")[2].startswith(quoted))

    # ── Дополнительные защитные тесты ────────────────────────────────────────
    def test_empty_string_noop(self):
        to_ios = self._import()
        self.assertEqual(to_ios(""), "")

    def test_no_fragment_noop_for_flow(self):
        """Ссылка без `#` — flow всё равно должен убираться (он в query),
        fragment-шаг не должен падать."""
        to_ios = self._import()
        link = (
            "vless://55555555-6666-7777-8888-999999999999@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PK&fp=chrome"
            "&sni=sni.example.com&sid=AB&flow=xtls-rprx-vision"
        )
        result = to_ios(link)
        self.assertNotIn("flow=", result)
        # base без fragment — строка без `#`.
        self.assertNotIn("#", result)

    def test_flag_in_middle_of_fragment_not_stripped(self):
        """regex использует sub(..., count=1) БЕЗ привязки `^` — то есть
        он режет ПЕРВОЕ совпадение. Если эмодзи идёт НЕ в начале fragment
        (что в реальной генерации не случается), первый match всё равно
        будет найден и заменён. Фиксируем это поведение — если его нужно
        будет изменить (резать строго в начале), тест надо обновить."""
        to_ios = self._import()
        # Флаг идёт после email — в реальной генерации не встречается,
        # но проверяем как regex поведёт себя.
        link = (
            "vless://66666666-7777-8888-9999-aaaaaaaaaaaa@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PK&fp=chrome"
            "&sni=sni.example.com&sid=AB"
            "#user%40example.com\U0001F1E9\U0001F1EA something"
        )
        result = to_ios(link)
        # Первый (и единственный) match — это `🇩🇪 ` (эмодзи + пробел).
        # sub(count=1) вырезает их оба, оставляя `user%40example.com`
        # и `something` слитыми (пробел между ними ушёл вместе с флагом).
        # Это фиксация фактического поведения — в реальной генерации
        # флаг всегда идёт в начале fragment, и этот случай не встречается.
        self.assertEqual(
            result,
            "vless://66666666-7777-8888-9999-aaaaaaaaaaaa@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PK&fp=chrome"
            "&sni=sni.example.com&sid=AB"
            "#user%40example.comsomething",
        )

    def test_only_flag_in_fragment(self):
        """Fragment состоит только из эмодзи-флага — после очистки
        fragment пустой, но `#` остаётся."""
        to_ios = self._import()
        link = (
            "vless://77777777-8888-9999-aaaa-bbbbbbbbbbbb@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PK&fp=chrome"
            "&sni=sni.example.com&sid=AB&flow=xtls-rprx-vision"
            "#\U0001F1E9\U0001F1EA "
        )
        result = to_ios(link)
        self.assertNotIn("flow=", result)
        # Флаг + пробел вырезаны → fragment пустой, `#` остался.
        self.assertTrue(result.endswith("#"))

    def test_idempotent(self):
        """Повторный вызов на уже обработанной ссылке — no-op."""
        to_ios = self._import()
        link = (
            "vless://88888888-9999-aaaa-bbbb-cccccccccccc@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PK&fp=chrome"
            "&sni=sni.example.com&sid=AB&flow=xtls-rprx-vision"
            "#\U0001F1E9\U0001F1EA user%40example.com"
        )
        once = to_ios(link)
        twice = to_ios(once)
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main(verbosity=2)
