#!/usr/bin/env python3
"""
tests/test_wpp_nodes_geo_cache.py

Регрессия бага вкладки «Ноды» (инцидент 22.11: переход висел ~21.7 с):

  1. Кэш-промах из-за ключа: cascade_to_wpp_nodes записывал город в поле
     "name" (canonical WPP-формат), а _geolocate_host читал его из "city" —
     кэш никогда не попадал, каждый рендер гнал полный гео-резолв
     (ip-api.com из РФ недоступен → 5 с таймаута на ноду + фолбэк ipinfo.io;
     4 ноды × ~5.4 с ≈ 21.7 с).
  2. Синхронный refresh в GET /panel/nodes блокировал рендер вкладки —
     теперь _refresh_nodes_async(): мгновенный рендер из кэша,
     гео-обновление в daemon-потоке с дебаунсом 60 с.

Проверки:
  • кэш-хит по "name" (nodes.json-форма) — сеть не дёргается вовсе
  • негативный кэш (пустой город) — ретрай не чаще GEO_NEGATIVE_TTL, не на
    каждом рендере
  • просроченный кэш — сетевой путь вызывается, город обновляется
  • refresh_nodes_file пишет город в "name" (форма, которую читает UI)
  • _refresh_nodes_async: неблокирующий + дебаунс (второй вызов подряд
    не плодит потоки)
"""
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chimera.modules import wpp_cascade_bridge as bridge  # noqa: E402
from chimera.modules import wpp_panel_web  # noqa: E402


def _no_network(*_args, **_kwargs):
    raise AssertionError("network geo lookup must not fire on a cache hit")


def _fake_geo(ip):
    return {"country_code": "DE", "country_name": "Германия", "city": "Франкфурт"}


class TestGeoCacheKeyFix(unittest.TestCase):
    """Город лежит в "name" — кэш должен попадать (баг: читали "city")."""

    def test_cache_hit_reads_name_field(self):
        cached = {
            "id": "abc", "url": "https://total-shadows.ru",
            "country_code": "NL", "country_name": "Нидерланды",
            "name": "Eygelshoven",           # canonical nodes.json field
            "enabled": True, "version": "cascade-reality",
            "protocols": "VLESS REALITY",
            "geo_time": int(time.time()),
            "_cascade": True,
        }
        with patch.object(bridge, "_resolve_ip", _no_network), \
             patch.object(bridge, "_geolocate_ip", _no_network), \
             patch.object(bridge, "_geolocate_ipinfo", _no_network):
            geo = bridge._geolocate_host("total-shadows.ru", cached)
        self.assertEqual(geo["country_code"], "NL")
        self.assertEqual(geo["city"], "Eygelshoven")
        self.assertEqual(geo["country_name"], "Нидерланды")

    def test_cache_hit_legacy_city_field(self):
        """Старый внутренний формат ("city") тоже читается — обратная совместимость."""
        cached = {
            "country_code": "DE", "country_name": "Германия",
            "city": "Франкфурт", "geo_time": int(time.time()),
        }
        with patch.object(bridge, "_resolve_ip", _no_network), \
             patch.object(bridge, "_geolocate_ip", _no_network), \
             patch.object(bridge, "_geolocate_ipinfo", _no_network):
            geo = bridge._geolocate_host("example.com", cached)
        self.assertEqual(geo["city"], "Франкфурт")

    def test_negative_cache_short_ttl(self):
        """Пустой город: недавний неудачный резолв не ретраится на каждом рендере."""
        cached = {
            "country_code": "NL", "country_name": "Нидерланды",
            "name": "—",                        # failed lookup marker
            "geo_time": int(time.time()),
        }
        with patch.object(bridge, "_resolve_ip", _no_network), \
             patch.object(bridge, "_geolocate_ip", _no_network), \
             patch.object(bridge, "_geolocate_ipinfo", _no_network):
            geo = bridge._geolocate_host("example.com", cached)
        # страна сохранена, город пустой, сеть не дёргалась
        self.assertEqual(geo["country_code"], "NL")
        self.assertEqual(geo["city"], "")

    def test_negative_cache_expires_and_retries(self):
        """Через GEO_NEGATIVE_TTL неудачный резолв ретраится (сетевой путь)."""
        cached = {
            "country_code": "NL", "country_name": "Нидерланды",
            "name": "—",
            "geo_time": int(time.time()) - bridge.GEO_NEGATIVE_TTL - 5,
        }
        with patch.object(bridge, "_resolve_ip", lambda h: "1.2.3.4"), \
             patch.object(bridge, "_geolocate_ip", _fake_geo), \
             patch.object(bridge, "_geolocate_ipinfo", _no_network):
            geo = bridge._geolocate_host("example.com", cached)
        self.assertEqual(geo["city"], "Франкфурт")

    def test_stale_positive_cache_retries(self):
        """Позитивный кэш старше 7 дней — полный резолв (geo_time обновится)."""
        cached = {
            "country_code": "NL", "country_name": "Нидерланды",
            "name": "Eygelshoven",
            "geo_time": int(time.time()) - bridge.GEO_CACHE_TTL - 60,
        }
        with patch.object(bridge, "_resolve_ip", lambda h: "5.6.7.8"), \
             patch.object(bridge, "_geolocate_ip", _fake_geo), \
             patch.object(bridge, "_geolocate_ipinfo", _no_network):
            geo = bridge._geolocate_host("example.com", cached)
        self.assertEqual(geo["city"], "Франкфурт")


class TestRefreshNodesFile(unittest.TestCase):
    """refresh_nodes_file пишет nodes.json в форме, которую читает кэш/UI."""

    def test_write_and_reread_roundtrip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            nodes_file = Path(tmp) / "nodes.json"
            state_file.write_text(json.dumps({
                "chain_nodes": [
                    {"host": "a.example.com", "port": 443, "proto": "reality"},
                    {"host": "b.example.com", "port": 443, "proto": "xhttp"},
                ],
            }), encoding="utf-8")
            with patch.object(bridge, "STATE_FILE", state_file), \
                 patch.object(bridge, "NODES_FILE", nodes_file), \
                 patch.object(bridge, "_resolve_ip", lambda h: "1.2.3.4"), \
                 patch.object(bridge, "_geolocate_ip", _fake_geo), \
                 patch.object(bridge, "_geolocate_ipinfo", _no_network):
                count = bridge.refresh_nodes_file()
            self.assertEqual(count, 2)
            saved = json.loads(nodes_file.read_text(encoding="utf-8"))
            by_host = {n["url"]: n for n in saved}
            # город живёт в "name" — той же форме, что и кэш-чтение ниже
            self.assertEqual(by_host["https://a.example.com"]["name"], "Франкфурт")
            # повторный refresh — кэш-хит, гео-API не дёргается вообще
            calls = {"geo": 0}

            def must_not_fire(ip):
                calls["geo"] += 1
                raise AssertionError("geo lookup fired on warm cache")

            with patch.object(bridge, "STATE_FILE", state_file), \
                 patch.object(bridge, "NODES_FILE", nodes_file), \
                 patch.object(bridge, "_resolve_ip", _no_network), \
                 patch.object(bridge, "_geolocate_ip", must_not_fire), \
                 patch.object(bridge, "_geolocate_ipinfo", _no_network):
                again = bridge.refresh_nodes_file()
            self.assertEqual(again, 2)
            self.assertEqual(calls["geo"], 0)

    def test_chain_exit_host_fallback(self):
        """chain_nodes пуст, но chain_exit_host задан — одна нода из хоста."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            nodes_file = Path(tmp) / "nodes.json"
            state_file.write_text(json.dumps({
                "chain_nodes": [],
                "chain_exit_host": "exit.example.com",
                "chain_exit_port": 8443,
            }), encoding="utf-8")
            with patch.object(bridge, "STATE_FILE", state_file), \
                 patch.object(bridge, "NODES_FILE", nodes_file), \
                 patch.object(bridge, "_resolve_ip", lambda h: "9.9.9.9"), \
                 patch.object(bridge, "_geolocate_ip", _fake_geo), \
                 patch.object(bridge, "_geolocate_ipinfo", _no_network):
                count = bridge.refresh_nodes_file()
            self.assertEqual(count, 1)


class _FakeThread:
    """Мок threading.Thread: записывает target, .start() ничего не запускает."""

    def __init__(self, target=None, **_kwargs):
        self.target = target
        SPAWNED.append(target)

    def start(self):
        pass


SPAWNED = []


class TestAsyncRefreshDebounce(unittest.TestCase):
    """GET /nodes больше не блокируется: refresh в фоне, дебаунс 60 с."""

    def setUp(self):
        self._backup = wpp_panel_web._NODES_REFRESH_LAST
        SPAWNED.clear()

    def tearDown(self):
        wpp_panel_web._NODES_REFRESH_LAST = self._backup

    def test_debounce_second_call_is_noop(self):
        wpp_panel_web._NODES_REFRESH_LAST = 0.0
        called = {"n": 0}

        def fake_refresh():
            called["n"] += 1

        with patch.object(bridge, "refresh_nodes_file", fake_refresh), \
             patch.object(threading, "Thread", _FakeThread):
            first = wpp_panel_web._refresh_nodes_async()
            second = wpp_panel_web._refresh_nodes_async()
        self.assertTrue(first)
        self.assertFalse(second)          # дебаунс: поток не плодится на каждый клик
        self.assertEqual(len(SPAWNED), 1)
        self.assertEqual(called["n"], 0)  # refresh идёт в потоке, не в рендере

    def test_debounce_expires_after_interval(self):
        wpp_panel_web._NODES_REFRESH_LAST = time.time() - wpp_panel_web._NODES_REFRESH_MIN_INTERVAL - 1
        with patch.object(bridge, "refresh_nodes_file", lambda: 0), \
             patch.object(threading, "Thread", _FakeThread):
            ok = wpp_panel_web._refresh_nodes_async()
        self.assertTrue(ok)
        self.assertEqual(len(SPAWNED), 1)

    def test_get_nodes_handler_uses_async_refresh(self):
        """Рендер вкладки не вызывает синхронный refresh_nodes_file."""
        import inspect
        src = inspect.getsource(wpp_panel_web.Handler.do_GET)
        nodes_block = src.split('PANEL_PATH+"/nodes"')[1][:600]
        self.assertIn("_refresh_nodes_async()", nodes_block)
        self.assertNotIn("refresh_nodes_file()", nodes_block)


if __name__ == "__main__":
    unittest.main()
