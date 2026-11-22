#!/usr/bin/env python3
"""
tests/test_wpp_user_geo.py

Chimera-твик «Гео · IP» вкладки «Пользователи» (IP / страна / город / флаг):

  • record_subscription_seen: sub: + dev: записи, мусорный IP не пишется,
    файл атомарный, старые визиты вычищаются;
  • _scan_access_log: парсинг access.log (+ротированный .1) с email → IP,
    пропуск observatory/outbound (не клиентские), «from DNS», легаси без
    from; свежее событие побеждает; IPv4-mapped нормализуется;
  • client_geo: подписка берёт самое свежее событие из (token-seen,
    device-seen, access-log email), прямые VLESS — из access-log,
    MTProto/AWG/primary без email не попадают; гео из кэша не дёргает сеть;
    отсутствующее гео → pending + фоновый refresh (дебаунс);
  • users_ui: колонка «Гео · IP» и ячейка с флагом/страной/городом/IP;
    пустая ячейка «нет данных»; OpenFlux — прочерк;
  • refresh_geo_async: неблокирующий, дебаунс (второй подряд не плодит
    потоки) — паттерн фикс вкладки «Ноды» (инцидент 22.11).
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chimera.modules import wpp_user_geo as ugeo  # noqa: E402
from chimera.modules import wpp_ui  # noqa: E402

TOKEN_OK = "a" * 64


def _no_network(*_args, **_kwargs):
    raise AssertionError("render path must never call network geo lookups")


class _TmpState(unittest.TestCase):
    """Фикстуры: seen/geo/access.log в temp-каталоге (модульные константы)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.seen = base / "wpp_user_seen.json"
        self.geo = base / "wpp_user_geo.json"
        self.log = base / "access.log"
        self.log1 = base / "access.log.1"
        patches = [
            patch.object(ugeo, "SEEN_FILE", self.seen),
            patch.object(ugeo, "GEO_FILE", self.geo),
            patch.object(ugeo, "ACCESS_LOG", self.log),
            patch.object(ugeo, "ACCESS_LOG_1", self.log1),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        # свежий in-memory scan-кэш для каждого теста
        self._scan = patch.object(ugeo, "_SCAN_CACHE", {"ts": 0.0, "by_email": {}})
        self._scan.start()
        self.addCleanup(self._scan.stop)
        self._refresh = patch.object(ugeo, "refresh_geo_async")
        self.refresh_mock = self._refresh.start()
        self.addCleanup(self._refresh.stop)


class TestRecordSeen(_TmpState):

    def test_writes_sub_and_device_entries(self):
        ok = ugeo.record_subscription_seen(TOKEN_OK, "203.0.113.7",
                                           "v2rayNG/1.8", "device-hwid-1")
        self.assertTrue(ok)
        data = json.loads(self.seen.read_text())
        self.assertIn("sub:" + TOKEN_OK, data)
        self.assertEqual(data["sub:" + TOKEN_OK]["ip"], "203.0.113.7")
        self.assertTrue(data["sub:" + TOKEN_OK]["ts"] > 0)
        # dev-ключ — sha256(hwid)[:16], не сырой HWID
        dev_keys = [k for k in data if k.startswith("dev:" + TOKEN_OK + ":")]
        self.assertEqual(len(dev_keys), 1)
        self.assertNotIn("device-hwid-1", dev_keys[0])

    def test_invalid_ip_not_written(self):
        ok = ugeo.record_subscription_seen(TOKEN_OK, "not-an-ip")
        self.assertFalse(ok)
        self.assertFalse(self.seen.exists())

    def test_prunes_stale_entries(self):
        stale = {"sub:" + "b" * 64: {"ip": "203.0.113.9", "ts": 1, "ua": ""}}
        self.seen.write_text(json.dumps(stale), encoding="utf-8")
        ugeo.record_subscription_seen(TOKEN_OK, "203.0.113.7")
        data = json.loads(self.seen.read_text())
        self.assertIn("sub:" + TOKEN_OK, data)
        self.assertNotIn("sub:" + "b" * 64, data)

    def test_file_is_root_only(self):
        ugeo.record_subscription_seen(TOKEN_OK, "203.0.113.7")
        mode = (self.seen.stat().st_mode & 0o777)
        self.assertEqual(mode, 0o600)


class TestScanAccessLog(_TmpState):

    def _write(self, path, lines):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_parses_client_lines_with_email(self):
        self._write(self.log, [
            "2026/11/22 10:00:01.123456 from 203.0.113.20:52359 accepted tcp:example.com:443 email: alex@example.com",
            "2026/11/22 10:05:00.000001 from [2001:db8::1]:63698 accepted tcp:example.com:443 email: bob@example.com",
        ])
        scan = ugeo._scan_access_log(force=True)
        self.assertEqual(scan["alex@example.com"]["ip"], "203.0.113.20")
        self.assertEqual(scan["bob@example.com"]["ip"], "2001:db8::1")

    def test_skips_non_client_lines(self):
        self._write(self.log, [
            "2026/11/22 10:00:01 from 198.51.100.7:999 accepted tcp:chain-exit-1:443 (app/observatory)",
            "2026/11/22 10:00:02 from 198.51.100.7:999 accepted tcp:1.2.3.4:443 (proxy/direct/outbound)",
            "2026/11/22 10:00:03 from DNS accepted udp:127.0.0.1:53 [xray.system.dns]",
            "2026/11/22 10:00:04 accepted tcp:198.51.100.7:49775 dst:example.com email: legacy@example.com",
        ])
        scan = ugeo._scan_access_log(force=True)
        self.assertEqual(scan, {})

    def test_latest_event_wins_and_rotated_merged(self):
        self._write(self.log1, [
            "2026/11/21 09:00:00 from 203.0.113.20:1 accepted tcp:x:443 email: alex@example.com",
        ])
        self._write(self.log, [
            "2026/11/22 12:00:00 from 198.51.100.9:2 accepted tcp:x:443 email: alex@example.com",
        ])
        scan = ugeo._scan_access_log(force=True)
        # свежая запись из текущего лога перетирает старую из .1
        self.assertEqual(scan["alex@example.com"]["ip"], "198.51.100.9")
        self.assertGreater(scan["alex@example.com"]["ts"], 0)

    def test_ipv4_mapped_normalized(self):
        self._write(self.log, [
            "2026/11/22 10:00:00 from [::ffff:203.0.113.31]:44444 accepted tcp:x:443 email: v4@example.com",
        ])
        scan = ugeo._scan_access_log(force=True)
        self.assertEqual(scan["v4@example.com"]["ip"], "203.0.113.31")

    def test_scan_cached_no_reread(self):
        self._write(self.log, [
            "2026/11/22 10:00:00 from 203.0.113.20:5 accepted tcp:x:443 email: alex@example.com",
        ])
        first = ugeo._scan_access_log(force=True)
        self.log.unlink()  # файл исчез — кэш всё равно отвечает
        second = ugeo._scan_access_log(force=False)
        self.assertEqual(first, second)


class TestClientGeo(_TmpState):

    def _geo_cache(self, mapping):
        self.geo.write_text(json.dumps(mapping), encoding="utf-8")

    def test_subscription_picks_freshest_event(self):
        now = int(time.time())
        self.seen.write_text(json.dumps({
            "sub:" + TOKEN_OK: {"ip": "203.0.113.5", "ts": now - 3600, "ua": ""},
            "dev:" + TOKEN_OK + ":abc": {"ip": "203.0.113.6", "ts": now - 60, "ua": ""},
        }), encoding="utf-8")
        self._write_log([
            "2026/11/21 10:00:00 from 198.51.100.9:2 accepted tcp:x:443 email: dev1@example.com",
        ])
        subs = [{"id": "sub-1", "token": TOKEN_OK}]
        profiles = [{"id": "uuid-1", "email": "dev1@example.com", "subscription_id": "sub-1"}]
        with patch.object(ugeo, "_scan_access_log", lambda force=False:
                          ugeo._parse_tail(self.log.read_text().splitlines())):
            result = ugeo.client_geo(subs, profiles)
        self.assertIn("sub-1", result)
        # самое свежее — device-seen (now-60)
        self.assertEqual(result["sub-1"]["ip"], "203.0.113.6")
        # гео нет в кэше → pending + запланированный фоновый резолв
        self.assertTrue(result["sub-1"]["pending"])
        self.refresh_mock.assert_called_once()
        self.assertIn("203.0.113.6", self.refresh_mock.call_args[0][0])

    def test_geo_cache_hit_no_network(self):
        now = int(time.time())
        self.seen.write_text(json.dumps({
            "sub:" + TOKEN_OK: {"ip": "203.0.113.5", "ts": now, "ua": ""},
        }), encoding="utf-8")
        self._geo_cache({"203.0.113.5": {
            "cc": "DE", "country": "Германия", "city": "Франкфурт",
            "ts": now, "neg": False}})
        subs = [{"id": "sub-1", "token": TOKEN_OK}]
        with patch.object(ugeo, "_scan_access_log", lambda force=False: {}), \
             patch.object(ugeo, "_geo_lookup", _no_network):
            result = ugeo.client_geo(subs, [])
        self.assertFalse(result["sub-1"]["pending"])
        self.assertEqual(result["sub-1"]["cc"], "DE")
        self.assertEqual(result["sub-1"]["city"], "Франкфурт")
        self.refresh_mock.assert_not_called()

    def test_negative_cache_not_refreshed_within_ttl(self):
        now = int(time.time())
        self.seen.write_text(json.dumps({
            "sub:" + TOKEN_OK: {"ip": "203.0.113.5", "ts": now, "ua": ""},
        }), encoding="utf-8")
        self._geo_cache({"203.0.113.5": {
            "cc": "UN", "country": "", "city": "", "ts": now, "neg": True}})
        subs = [{"id": "sub-1", "token": TOKEN_OK}]
        with patch.object(ugeo, "_scan_access_log", lambda force=False: {}):
            result = ugeo.client_geo(subs, [])
        # негативный кэш свежий — сеть не дёргаем, показываем IP без гео
        self.assertFalse(result["sub-1"]["pending"])
        self.refresh_mock.assert_not_called()

    def test_direct_profile_from_access_log(self):
        self._write_log([
            "2026/11/22 10:00:00 from 203.0.113.40:5 accepted tcp:x:443 email: direct@example.com",
        ])
        profiles = [{"id": "uuid-2", "email": "direct@example.com", "subscription_id": None},
                    {"id": "mtproto-u", "email": None, "subscription_id": None}]
        with patch.object(ugeo, "_scan_access_log", lambda force=False:
                          ugeo._parse_tail(self.log.read_text().splitlines())):
            result = ugeo.client_geo([], profiles)
        self.assertIn("uuid-2", result)
        self.assertEqual(result["uuid-2"]["ip"], "203.0.113.40")
        self.assertNotIn("mtproto-u", result)   # без email — нет данных

    def test_no_data_records_absent(self):
        subs = [{"id": "sub-9", "token": "c" * 64}]
        with patch.object(ugeo, "_scan_access_log", lambda force=False: {}):
            result = ugeo.client_geo(subs, [])
        self.assertEqual(result, {})
        self.refresh_mock.assert_not_called()

    def _write_log(self, lines):
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestGeoRefreshDebounce(unittest.TestCase):
    """refresh_geo_async — паттерн _refresh_nodes_async (инцидент 22.11)."""

    def test_debounce_second_call_no_thread(self):
        # LAST = now-120: первый вызов проходит, ставит LAST=now → второй дебаунсится
        with patch.object(ugeo, "_GEO_REFRESH_LAST", time.time() - 120):
            with patch("threading.Thread") as thread_cls:
                first = ugeo.refresh_geo_async(["1.2.3.4"])
                second = ugeo.refresh_geo_async(["1.2.3.4"])
        self.assertTrue(first)
        self.assertFalse(second)
        thread_cls.assert_called_once()

    def test_empty_ip_list_no_thread(self):
        with patch("threading.Thread") as thread_cls:
            self.assertFalse(ugeo.refresh_geo_async([]))
            self.assertFalse(ugeo.refresh_geo_async(["", None]))
        thread_cls.assert_not_called()


class TestUsersUiGeoColumn(_TmpState):

    def _subs(self):
        return [{"id": "sub-1", "name": "Александр", "protocols": ["vless"],
                 "token": TOKEN_OK, "enabled": True, "created_at": 1,
                 "profile_ids": [], "devices": [], "max_devices": 2}]

    def _profiles(self):
        return [{"id": "primary", "name": "Основной WEB Proxy", "secret": "s",
                 "protocol": "web", "enabled": True, "backend_port": 443}]

    def test_renders_geo_cell_with_flag_and_place(self):
        now = int(time.time())
        geo_map = {"sub-1": {"ip": "203.0.113.5", "ts": now - 300,
                             "cc": "DE", "country": "Германия",
                             "city": "Франкфурт", "pending": False}}
        page = wpp_ui.users_ui(self._subs(), self._profiles(), {}, "/panel",
                                "example.com", "csrf", lambda *a, **k: "https://l",
                                openflux_profiles=[],
                                client_geo=geo_map)
        self.assertIn('<th class="geo-cell">Гео · IP</th>', page)
        self.assertIn('<td class="geo-cell" data-label="Гео · IP">', page)
        self.assertIn('/panel/__flag/de.svg', page)
        self.assertIn('Германия', page)
        self.assertIn('Франкфурт', page)
        self.assertIn('203.0.113.5', page)
        self.assertIn('data-geo-sig="203.0.113.5|de|r|', page)

    def test_renders_dash_without_geo(self):
        page = wpp_ui.users_ui(self._subs(), self._profiles(), {}, "/panel",
                                "example.com", "csrf", lambda *a, **k: "https://l",
                                openflux_profiles=[])
        self.assertIn('geo-empty', page)
        self.assertIn('нет данных', page)
        # primary-строка не падает без гео
        self.assertIn('Основной WEB Proxy', page)

    def test_pending_cell_shows_ip_without_place(self):
        geo_map = {"sub-1": {"ip": "203.0.113.5", "ts": int(time.time()),
                             "cc": "", "country": "", "city": "", "pending": True}}
        page = wpp_ui.users_ui(self._subs(), self._profiles(), {}, "/panel",
                                "example.com", "csrf", lambda *a, **k: "https://l",
                                openflux_profiles=[],
                                client_geo=geo_map)
        self.assertIn('гео определяется…', page)
        self.assertNotIn('/panel/__flag/', page)

    def test_geo_payload_for_matches_initial_render(self):
        """/clients-state отдаёт тот же html, что и первичная отрисовка."""
        now = int(time.time())
        geo_map = {"sub-1": {"ip": "203.0.113.5", "ts": now - 60,
                             "cc": "DE", "country": "Германия",
                             "city": "Франкфурт", "pending": False}}
        page = wpp_ui.users_ui(self._subs(), self._profiles(), {}, "/panel",
                                "example.com", "csrf", lambda *a, **k: "https://l",
                                openflux_profiles=[],
                                client_geo=geo_map)
        payload = wpp_ui.geo_payload_for(["sub-1"], geo_map, "/panel")
        # сигнатуры совпадают → pollClients не перерисует ячейку зря
        self.assertIn('data-geo-sig="%s"' % payload["sub-1"]["sig"], page)
        # содержимое ячейки из payload байт-в-байт присутствует на странице
        self.assertIn(payload["sub-1"]["html"], page)

    def test_openflux_row_has_geo_dash(self):
        page = wpp_ui.users_ui(self._subs(), self._profiles(), {}, "/panel",
                                "example.com", "csrf", lambda *a, **k: "https://l",
                                openflux_profiles=[{"id": "of1", "name": "iPhone Анны",
                                                     "enabled": True, "active": False,
                                                     "platform": "ios",
                                                     "transport": "yandex",
                                                     "created_at": 1}])
        self.assertIn('OpenFlux · отдельная служба', page)
        self.assertIn('data-geo-sig="none"', page)


class TestRefreshGeoWorker(_TmpState):

    def test_worker_refreshes_stale_and_skips_fresh(self):
        now = int(time.time())
        self.geo.write_text(json.dumps({
            "1.2.3.4": {"cc": "DE", "country": "Г", "city": "Ф", "ts": now, "neg": False},
            "5.6.7.8": {"cc": "UN", "country": "", "city": "", "ts": now, "neg": True},
        }), encoding="utf-8")
        looked = []

        def fake_lookup(ip):
            looked.append(ip)
            return {"country_code": "FR", "country_name": "Франция", "city": "Париж"}

        with patch.object(ugeo, "_geo_lookup", fake_lookup):
            ugeo._refresh_geo_worker(["1.2.3.4", "5.6.7.8", "9.9.9.9"])
        self.assertEqual(looked, ["9.9.9.9"])   # живые кэши не тронуты
        data = json.loads(self.geo.read_text())
        self.assertEqual(data["9.9.9.9"]["cc"], "FR")
        self.assertEqual(data["9.9.9.9"]["city"], "Париж")
        self.assertFalse(data["9.9.9.9"]["neg"])

    def test_worker_respects_batch_limit(self):
        ips = ["10.0.0.%d" % i for i in range(50)]
        looked = []
        with patch.object(ugeo, "_geo_lookup", lambda ip: (looked.append(ip) or
                          {"country_code": "XX", "country_name": "", "city": ""})):
            ugeo._refresh_geo_worker(ips)
        self.assertEqual(len(looked), ugeo.GEO_BATCH_LIMIT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
