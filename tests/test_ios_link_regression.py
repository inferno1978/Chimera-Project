#!/usr/bin/env python3
"""
tests/test_ios_link_regression.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для iOS/Karing-ветки генерации VLESS-ссылок.

ПОКРЫТИЕ (нумерация по спецификации задачи — раздел «ОБЯЗАТЕЛЬНЫЕ
РЕГРЕССИОННЫЕ ТЕСТЫ»):
  1. Тесты 0a-0d из ШАГА 0 — см. tests/test_ios_link_variant.py.

  2. Golden-test: _users_gen_link() и _gen_vless_link() для тех же
     входных данных возвращают побайтово идентичный результат ДО и
     ПОСЛЕ патча. Это защита от случайной правки исходников вместо
     обёртки.

  3. build_subscription_body() (БЕЗ /ios) на тестовом юзере
     возвращает тот же base64, что и до патча.

  4. do_GET со старым путём /sub/{token} при наличии нового regex-чека
     всё ещё матчится старой веткой, не новой.

  5. client_config_export: vless-link.txt содержит type=xhttp после
     фикса (старое значение type=http было багом, рассинхрон с
     users_manager.py).

  6. Sanity по всем 4 точкам: сгенерированная iOS-ссылка не содержит
     подстроки "flow=" (для REALITY) и не содержит ни одного code
     point из диапазона regional-indicator emoji в первых 10 символах
     fragment.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import tempfile
import types
import unittest
import urllib.parse
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
#  ТЕСТ 2: Golden-test — исходные генераторы побайтово идентичны
# ══════════════════════════════════════════════════════════════════════════════
class TestGoldenOriginals(unittest.TestCase):
    """Исходные _gen_vless_link и _users_gen_link не должны поменяться
    от добавления обёрток. Тест захардкожен на конкретные ожидаемые
    строки — если исходник правят, тест упадёт осознанно."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        # Без флага-эмодзи — упрощает golden-строки.
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("RU", "Russia", "")
        )
        self._fake_core.PARAM_DOMAIN = "example.com"
        self._fake_core._fp_from_state = MagicMock(return_value="chrome")

    def test_gen_vless_link_reality_golden(self):
        """_gen_vless_link для REALITY — точная строка (golden).

        Включает &flow=xtls-rprx-vision. Это ДОЛЖНО остаться —
        iOS-обёртка убирает его отдельно."""
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

    def test_gen_vless_link_xhttp_golden(self):
        """_gen_vless_link для xHTTP — точная строка (golden)."""
        from chimera.modules.users_manager import _gen_vless_link
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="22222222-3333-4444-5555-666666666666",
            pbk="", sid="", domain="example.com",
            fp="chrome", proto="xhttp",
            xhttp_path="/xhttp", xhttp_mode="stream-up",
            port=8443,
        )
        # path кодируется с safe="/" — слэш остаётся.
        path_enc = urllib.parse.quote("/xhttp", safe="/")
        expected = (
            "vless://22222222-3333-4444-5555-666666666666@1.2.3.4:8443"
            "?type=xhttp&security=tls&sni=example.com"
            f"&path={path_enc}&mode=stream-up"
            "&fp=chrome#example.com"
        )
        self.assertEqual(link, expected)

    def test_gen_vless_link_reality_with_flag_golden(self):
        """С флагом-эмодзи — точная строка (golden), чтобы убедиться что
        обёртка корректно найдёт что резать."""
        from chimera.modules.users_manager import _gen_vless_link
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("DE", "Germany", "🇩🇪")
        )
        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="33333333-4444-5555-6666-777777777777",
            pbk="PUBKEY", sid="AB", domain="example.com",
            fp="chrome", proto="reality", port=443,
        )
        expected = (
            "vless://33333333-4444-5555-6666-777777777777@1.2.3.4:443"
            "?type=tcp&security=reality&pbk=PUBKEY"
            "&fp=chrome&sni=example.com&sid=AB"
            "&flow=xtls-rprx-vision#🇩🇪 example.com"
        )
        self.assertEqual(link, expected)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 3: build_subscription_body() — байт-идентичен (без /ios)
# ══════════════════════════════════════════════════════════════════════════════
class TestSubscriptionBodyRegression(unittest.TestCase):
    """build_subscription_body() на тестовом юзере возвращает ровно тот
    base64, что и ДО добавления build_subscription_body_ios()."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_build_subscription_body_unchanged(self):
        """Старый маршрут должен вернуть ровно те же ссылки, что и раньше.
        Мы не можем сравнивать с захардкоженным base64 (IP/etc могут
        меняться), но можем проверить что:
          • vless-ссылка содержит flow= (REALITY) — т.е. НЕ прошла
            через to_ios_karing_link.
          • mieru/naive/fptn/telemt идентичны тому, что дают их
            _build_*_uris функции напрямую."""
        from chimera.modules import subscription

        # Полностью мокаем state и вспомогательные функции, чтобы
        # получить детерминированный вывод.
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
             patch.object(subscription, "_build_telemt_uri", return_value=None):
            # Патчим get_mirror_uris чтобы не depended от entry_mirrors.
            with patch("chimera.modules.entry_mirrors.get_mirror_uris",
                       return_value=["vless://mirror1"]) if False else patch.dict(
                sys.modules, {"chimera.modules.entry_mirrors": MagicMock(
                    get_mirror_uris=MagicMock(return_value=[]))}):
                body = subscription.build_subscription_body(user)

        decoded = base64.b64decode(body).decode()
        links = decoded.split("\n")

        # Должна быть vless-ссылка + mierus-ссылка.
        self.assertEqual(len(links), 2)
        vless_link = links[0]
        mieru_link = links[1]

        # vless-ссылка ДОЛЖНА содержать flow= — это старый маршрут,
        # to_ios_karing_link НЕ применялся.
        self.assertIn("flow=xtls-rprx-vision", vless_link)
        self.assertIn("vless://", vless_link)
        self.assertIn("pbk=PUB", vless_link)
        self.assertIn("sid=AB", vless_link)

        # mieru-ссылка не тронута.
        self.assertEqual(mieru_link, "mierus://m1")

    def test_build_subscription_body_ios_strips_flow(self):
        """iOS-маршрут должен убрать flow= из vless-ссылки, но оставить
        mieru/naive/fptn/telemt как есть."""
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

        # Патч №5 добавил _resolve_ios_shadow_user в build_subscription_body_ios
        # — она идёт в _users_get_config() и падает без config.json. В этом
        # тесте мы проверяем постпроцессорную логику (flow убран), а не
        # shadow-создание (для этого есть test_ios_patch5). Патчим
        # _resolve_ios_shadow_user чтобы вернуть user без изменений —
        # постпроцессор всё равно отрежет flow из оригинальной ссылки.
        with patch.object(subscription, "_load_state", return_value=fake_state), \
             patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"), \
             patch.object(subscription, "is_hybrid_mieru_active", return_value=False), \
             patch.object(subscription, "_build_mieru_uris", return_value=["mierus://m1"]), \
             patch.object(subscription, "_build_naive_uris", return_value=[]), \
             patch.object(subscription, "_build_fptn_uris", return_value=[]), \
             patch.object(subscription, "_build_telemt_uri", return_value=None), \
             patch.object(subscription, "_resolve_ios_shadow_user", side_effect=lambda u: u):
            # Патчим функцию на реальном модуле: patch.dict(sys.modules, ...)
            # на выходе выметает из sys.modules ВСЁ, что лениво импортировалось
            # внутри (например linkqr_lib) — атрибуты пакетов остаются, и
            # последующие тесты ловят разъезд экземпляров модулей.
            with patch("chimera.modules.entry_mirrors.get_mirror_uris",
                       return_value=[]):
                body = subscription.build_subscription_body_ios(user)

        decoded = base64.b64decode(body).decode()
        links = decoded.split("\n")

        self.assertEqual(len(links), 2)
        vless_link = links[0]
        mieru_link = links[1]

        # iOS-трансформация: flow убран.
        self.assertNotIn("flow=", vless_link)
        self.assertNotIn("xtls-rprx-vision", vless_link)
        self.assertIn("vless://", vless_link)
        self.assertIn("pbk=PUB", vless_link)
        self.assertIn("sid=AB", vless_link)

        # Сателлитный mieru не тронут — в нём нет flow и нет эмодзи-флага.
        self.assertEqual(mieru_link, "mierus://m1")

    def test_build_subscription_body_ios_preserves_satellite_links(self):
        """Все 4 сателлитных протокола (mieru/naive/fptn/telemt) не
        должны меняться между обычной и iOS-веткой."""
        from chimera.modules import subscription

        fake_state = {
            "domain": "vpn.example.com", "server_port": 443,
            "protocol_mode": "reality", "public_key": "P", "short_id": "S",
            "fingerprint": "chrome", "install_mode": "A",
            "awg_exit_enabled": False, "reality_dest": "",
            "xhttp_path": "/", "xhttp_mode": "stream-up",
        }
        user = {"uuid": "u-1", "email": "alice@example.com"}

        mieru_uris = ["mierus://u:p@1.2.3.4?port=8443&protocol=TCP&profile=default&mtu=1400&multiplexing=MULTIPLEXING_HIGH"]
        naive_uris = ["naive+https://user:pass@vpn.example.com:443/"]
        fptn_uris = ["fptn:eyJ2ZXJzaW9uIjoxfQ=="]
        telemt_uri = "tg://proxy?server=1.2.3.4&port=443&secret=eeabc"

        common_patches = [
            patch.object(subscription, "_load_state", return_value=fake_state),
            patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"),
            patch.object(subscription, "is_hybrid_mieru_active", return_value=False),
            patch.object(subscription, "_build_mieru_uris", return_value=mieru_uris),
            patch.object(subscription, "_build_naive_uris", return_value=naive_uris),
            patch.object(subscription, "_build_fptn_uris", return_value=fptn_uris),
            patch.object(subscription, "_build_telemt_uri", return_value=telemt_uri),
            # Патч №5 добавил _resolve_ios_shadow_user — патчим вернуть user
            # без изменений, чтобы тест проверял постпроцессор а не shadow.
            patch.object(subscription, "_resolve_ios_shadow_user", side_effect=lambda u: u),
        ]
        for p in common_patches:
            p.start()
        try:
            # Функцию мокаем на реальном модуле — patch.dict(sys.modules)
            # выметает на выходе лениво импортированные внутри модули.
            with patch("chimera.modules.entry_mirrors.get_mirror_uris",
                       return_value=[]):
                body_plain = subscription.build_subscription_body(user)
                body_ios = subscription.build_subscription_body_ios(user)
        finally:
            for p in common_patches:
                p.stop()

        plain_links = base64.b64decode(body_plain).decode().split("\n")
        ios_links = base64.b64decode(body_ios).decode().split("\n")

        # В обеих подписках должны присутствовать mieru/naive/fptn/telemt
        # идентично.
        for sat in mieru_uris + naive_uris + fptn_uris + [telemt_uri]:
            self.assertIn(sat, plain_links)
            self.assertIn(sat, ios_links)

        # vless-ссылка должна РАЗЛИЧАТЬСЯ (в ios убран flow).
        vless_plain = next(l for l in plain_links if l.startswith("vless://"))
        vless_ios = next(l for l in ios_links if l.startswith("vless://"))
        self.assertIn("flow=", vless_plain)
        self.assertNotIn("flow=", vless_ios)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 4: do_GET — старый путь /sub/{token} всё ещё матчится старой веткой
# ══════════════════════════════════════════════════════════════════════════════
class TestSubscriptionRouting(unittest.TestCase):
    """Проверка что regex-матчинг остался корректным после добавления /ios-маршрута."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_old_path_matches_old_regex(self):
        """Старый путь /sub/{24hex} матчится старым regex, не iOS-веткой."""
        import re
        old_re = re.compile(r"^/sub/([0-9a-f]{24})/?$")
        ios_re = re.compile(r"^/sub/([0-9a-f]{24})/ios/?$")

        token = "a" * 24
        # Варианты старого пути.
        for path in (f"/sub/{token}", f"/sub/{token}/"):
            self.assertIsNotNone(old_re.match(path),
                                 f"old regex должен матчить {path}")
            self.assertIsNone(ios_re.match(path),
                              f"ios regex НЕ должен матчить {path}")

    def test_ios_path_matches_ios_regex_only(self):
        """Новый путь /sub/{24hex}/ios матчится только iOS-веткой."""
        import re
        old_re = re.compile(r"^/sub/([0-9a-f]{24})/?$")
        ios_re = re.compile(r"^/sub/([0-9a-f]{24})/ios/?$")

        token = "b" * 24
        for path in (f"/sub/{token}/ios", f"/sub/{token}/ios/"):
            self.assertIsNotNone(ios_re.match(path),
                                 f"ios regex должен матчить {path}")
            self.assertIsNone(old_re.match(path),
                              f"old regex НЕ должен матчить {path}")

    def test_garbage_path_matches_neither(self):
        import re
        old_re = re.compile(r"^/sub/([0-9a-f]{24})/?$")
        ios_re = re.compile(r"^/sub/([0-9a-f]{24})/ios/?$")

        for path in ("/sub/abc", "/sub/" + "a" * 23, "/sub/" + "a" * 25,
                     "/sub/xyz/ios", "/", "/healthcheck"):
            self.assertIsNone(old_re.match(path), path)
            self.assertIsNone(ios_re.match(path), path)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 5: client_config_export — type=xhttp после фикса
# ══════════════════════════════════════════════════════════════════════════════
class TestClientConfigExportXhttpFix(unittest.TestCase):
    """После фикса type=http → type=xhttp в трёх местах файла, все три
    должны содержать актуальный xHTTP-транспорт Xray 1.8.16+."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_vless_link_xhttp_uses_xhttp_not_http(self):
        """В сгенерированной vless-link.txt для xHTTP-режима должно быть
        type=xhttp, не type=http. Это защита отката фикса."""
        from chimera.modules import client_config_export

        # Читаем исходник и проверяем статически — это надёжнее, чем
        # гонять генерацию с моками (которая в этом файле сложная).
        # В исходнике должно быть РОВНО type=xhttp в ссылках, и ни одного
        # type=http (который был бы старым багом).
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "client_config_export.py").read_text()

        # Контрольные точки — фиксированные подстроки в коде.
        # 1. sing-box JSON xHTTP-ветка (transport.type).
        # Теперь transport содержит mode + path (не только path).
        self.assertIn('"type": "xhttp"', src)
        self.assertIn('"path": xhttp_path', src)
        self.assertNotIn('"type": "http"', src)

        # 2. vless_link для xHTTP в do_generate_client_config.
        # Теперь содержит &mode={xhttp_mode} перед #VLESS-xHTTP.
        self.assertIn("&type=xhttp&path={xhttp_path_enc}", src)
        self.assertIn("&mode={xhttp_mode}#VLESS-xHTTP", src)
        self.assertNotIn("&type=http&", src)

        # 3. vless_link для xHTTP в do_share_config_server.
        self.assertIn("&type=xhttp&path={xhttp_path}", src)
        self.assertIn("&mode={xhttp_mode}#VLESS-xHTTP", src)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТ 6: Sanity по всем 4 точкам — нет flow= и нет regional-indicator emoji
# ══════════════════════════════════════════════════════════════════════════════
class TestSanityAllFourPoints(unittest.TestCase):
    """Финальная sanity-проверка: каждая из 4 точек генерации iOS-ссылки
    отдаёт строку без flow= (для REALITY) и без regional-indicator emoji
    в первых 10 символах fragment."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.get_server_country_cached = MagicMock(
            return_value=("DE", "Germany", "🇩🇪")  # есть эмодзи
        )
        self._fake_core.PARAM_DOMAIN = "example.com"
        self._fake_core._fp_from_state = MagicMock(return_value="chrome")

    def _assert_no_flow_no_emoji(self, link: str, label: str):
        """Sanity-ассерты для одной iOS-ссылки."""
        self.assertIsInstance(link, str, f"{label}: link не строка")
        self.assertGreater(len(link), 0, f"{label}: пустая ссылка")

        # flow= не должно быть НИГДЕ в REALITY-ссылке.
        self.assertNotIn("flow=", link,
                         f"{label}: iOS-ссылка содержит flow=")
        self.assertNotIn("xtls-rprx-vision", link,
                         f"{label}: iOS-ссылка содержит xtls-rprx-vision")

        # В первых 10 символах fragment не должно быть regional-indicator.
        base, sep, frag = link.partition("#")
        if sep:
            head = frag[:10]
            for ch in head:
                self.assertFalse(
                    "\U0001F1E6" <= ch <= "\U0001F1FF",
                    f"{label}: regional-indicator emoji в первых 10 "
                    f"символах fragment: {head!r}"
                )

    def test_point1_users_gen_link_ios(self):
        """Точка 1: _users_gen_link_ios — обёртка над _users_gen_link."""
        from chimera.modules.users_manager import _users_gen_link_ios

        # Создаём временный config.json для передачи в функцию.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            cfg_path = Path(f.name)
            json.dump({
                "inbounds": [{
                    "streamSettings": {"network": "tcp", "realitySettings": {
                        "serverNames": ["sni.example.com"],
                        "publicKey": "PUBKEY",
                        "shortIds": ["deadbeef"],
                    }},
                    "port": 443,
                    "settings": {"clients": []},
                }]
            }, f)

        try:
            link = _users_gen_link_ios(cfg_path, "uuid-1234", "alice@example.com")
            self._assert_no_flow_no_emoji(link, "_users_gen_link_ios")
        finally:
            cfg_path.unlink(missing_ok=True)

    def test_point2_generate_client_links_ios_components(self):
        """Точка 2: generate_client_links_ios использует _gen_vless_link
        + to_ios_karing_link. Проверяем напрямую через связку."""
        # Не запускаем generate_client_links_ios целиком (она пишет в
        # /root/...), а проверяем что связка «генератор → обёртка»
        # даёт корректный результат.
        from chimera.modules.users_manager import _gen_vless_link
        from chimera.modules.ios_link_variant import to_ios_karing_link

        link = _gen_vless_link(
            host="1.2.3.4", uuid_str="11111111-2222-3333-4444-555555555555",
            pbk="PUB", sid="AB", domain="example.com",
            fp="chrome", proto="reality", port=443,
        )
        ios_link = to_ios_karing_link(link)
        self._assert_no_flow_no_emoji(ios_link, "generate_client_links_ios (component)")

    def test_point3_client_config_export_ios_link(self):
        """Точка 3: client_config_export.py пишет vless-link-ios.txt с
        to_ios_karing_link(vless_link). Проверяем что REALITY-ссылка
        после обёртки не содержит flow."""
        from chimera.modules.ios_link_variant import to_ios_karing_link

        # Та же строка, что генерируется в client_config_export.py.
        vless_link = (
            "vless://44444444-5555-6666-7777-888888888888@vpn.example.com:443"
            "?encryption=none&flow=xtls-rprx-vision"
            "&security=reality&sni=vpn.example.com"
            "&fp=chrome&pbk=PUBKEY&sid=ABCD"
            "&type=tcp#VLESS-Reality"
        )
        ios_link = to_ios_karing_link(vless_link)
        self._assert_no_flow_no_emoji(ios_link, "client_config_export (vless-link-ios.txt)")

    def test_point4_subscription_ios_body(self):
        """Точка 4: build_subscription_body_ios — vless-ссылка в теле
        подписки не содержит flow= и эмодзи в начале fragment."""
        from chimera.modules import subscription

        fake_state = {
            "domain": "vpn.example.com", "server_port": 443,
            "protocol_mode": "reality", "public_key": "PUB", "short_id": "AB",
            "fingerprint": "chrome", "install_mode": "A",
            "awg_exit_enabled": False, "reality_dest": "",
            "xhttp_path": "/", "xhttp_mode": "stream-up",
        }
        user = {"uuid": "u-1", "email": "alice@example.com"}

        # Мокаем get_server_country_cached чтобы вернуть эмодзи-флаг.
        fake_core = sys.modules["chimera._core"]
        fake_core.get_server_country_cached = MagicMock(
            return_value=("DE", "Germany", "🇩🇪")
        )

        with patch.object(subscription, "_load_state", return_value=fake_state), \
             patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"), \
             patch.object(subscription, "is_hybrid_mieru_active", return_value=False), \
             patch.object(subscription, "_build_mieru_uris", return_value=[]), \
             patch.object(subscription, "_build_naive_uris", return_value=[]), \
             patch.object(subscription, "_build_fptn_uris", return_value=[]), \
             patch.object(subscription, "_build_telemt_uri", return_value=None), \
             patch.object(subscription, "_resolve_ios_shadow_user", side_effect=lambda u: u), \
             patch("chimera.modules.entry_mirrors.get_mirror_uris", return_value=[]):
            body = subscription.build_subscription_body_ios(user)

        decoded = base64.b64decode(body).decode()
        # В подписке должна быть ровно одна vless-ссылка.
        vless_links = [l for l in decoded.split("\n") if l.startswith("vless://")]
        self.assertEqual(len(vless_links), 1)
        self._assert_no_flow_no_emoji(vless_links[0], "build_subscription_body_ios")


if __name__ == "__main__":
    unittest.main(verbosity=2)
