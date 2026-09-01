#!/usr/bin/env python3
"""
tests/test_v73_geo_resistant_dns.py
───────────────────────────────────────────────────────────────────────────────
v73: гео-резистентность DNS-стека Chimera — добивка после v67/v72.

КОНТЕКСТ (реальные инциденты августа 2026 на Entry-нодах в РФ):
  • ТСПУ начал глушить DoH/DoT Google/Cloudflare и отравлять plain
    UDP:53 (1.1.1.1/8.8.8.8 DNAT-ятся на НСДИ 195.208.5.1, NXDomain-spoof);
  • v67 (dnscrypt_setup/xray_install) и v72 (IPv6) уже вычистили шаблон
    [R], генератор Xray (главный) и listen_addresses;
  • ОСТАВАЛИСЬ мины (весь этот фикс — v73):
      1. dnscrypt_advanced._SECURITY_PARAMS: bootstrap/fallback =
         ['9.9.9.9:53','8.8.8.8:53','1.1.1.1:53'] — переприменение пресета
         [RA] возвращало отраву в вычищенный конфиг;
      2. dnscrypt_advanced._safe_apply_preset: phase1_names =
         cloudflare/google — фаза-1 из РФ мертва → [RA] всегда откат;
      3. там же: временный resolv.conf = 8.8.8.8/1.1.1.1 (отрава) без
         try/finally — Ctrl+C/обрыв SSH посреди фазы оставлял систему
         на отравленных резолверах (и противоречил докстрингу модуля);
      4. dnscrypt_setup.apply_dnscrypt_tuning [T]: fallback_resolvers =
         ['1.1.1.1:53','8.8.8.8:53'] — единственная оставшаяся отрава;
      5. xray_install.generate_xray_config_xhttp не получил v67-живой
         Quad9-fallback (рассинхрон с главным генератором);
      6. dnscry.pt-moscow в ГЛАВЕ пула [RA] (RU-юрисдикция, риск
         hoster-level отравления рекурсии) + мёртвый из РФ хвост
         cloudflare/google.

Тестируем:
  1. Пины [RA]: bootstrap/fallback/netprobe без отравы (9.9.9.9+77.88.8.8);
  2. Пул: 192 сервера, нет moscow/cloudflare/google, голова — kyiv;
     маршруты: 194, нет moscow/CF/GG, wildcard на месте;
  3. [T] fallback_resolvers = v67-канон; шаблон [R] не сломан;
  4. xhttp-генератор синхронен с главным (4 живых Quad9-fallback);
  5. _safe_apply_preset (моки): фаза-1 = quad9-dnscrypt; resolv.conf
     подменяется на живые 9.9.9.9/77.88.8.8 и ВОССТАНАВЛИВАЕТСЯ
     (успех, отказ фазы-2, Ctrl+C); фаза-1 ждёт netprobe-окно (ретраи).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import chimera.modules.dnscrypt_advanced as adv                      # noqa: E402
from chimera.modules.dnscrypt_advanced import (                       # noqa: E402
    _SERVER_NAMES, _ANON_ROUTES, _SECURITY_PARAMS, _safe_apply_preset,
)

_SETUP_SRC = (_PROJECT_ROOT / "chimera" / "modules" / "dnscrypt_setup.py").read_text(encoding="utf-8")
_XRAY_SRC = (_PROJECT_ROOT / "chimera" / "modules" / "xray_install.py").read_text(encoding="utf-8")

_QUAD9_PHASE1 = ["quad9-dnscrypt-ip4-nofilter-pri",
                 "quad9-dnscrypt-ip6-nofilter-pri"]
_ORIG_RESOLV = "nameserver 127.0.0.1\n"
_TEMP_RESOLV = "nameserver 9.9.9.9\nnameserver 77.88.8.8\n"


class _FakeResolv:
    """Фейковый /etc/resolv.conf: существует, читается, пишет в журнал."""

    def __init__(self, initial: str):
        self._content = initial
        self.writes: list[str] = []

    def exists(self) -> bool:
        return True

    def read_text(self, errors=None):
        return self._content

    def write_text(self, content):
        self.writes.append(content)
        self._content = content


class TestGeoResistantPins(unittest.TestCase):
    """1. Пины [RA] и [T] не содержат отравленных в РФ резолверов."""

    def test_security_params_bootstrap_fallback(self):
        self.assertEqual(_SECURITY_PARAMS["bootstrap_resolvers"],
                         "['9.9.9.9:53', '77.88.8.8:53']")
        self.assertEqual(_SECURITY_PARAMS["fallback_resolvers"],
                         "['9.9.9.9:53', '77.88.8.8:53']")
        for key in ("bootstrap_resolvers", "fallback_resolvers"):
            self.assertNotIn("8.8.8.8", _SECURITY_PARAMS[key])
            self.assertNotIn("1.1.1.1", _SECURITY_PARAMS[key])

    def test_netprobe_address(self):
        self.assertEqual(_SECURITY_PARAMS["netprobe_address"], "'9.9.9.9:53'")

    def test_tuning_fallback_geo_resistant(self):
        # [T] apply_dnscrypt_tuning: TOP_PARAMS больше не возвращает отраву.
        self.assertIn('"fallback_resolvers": "[\'9.9.9.9:53\', \'77.88.8.8:53\']"',
                      _SETUP_SRC)
        self.assertNotIn('"fallback_resolvers": "[\'1.1.1.1:53\', \'8.8.8.8:53\']"',
                         _SETUP_SRC)

    def test_v67_template_not_broken(self):
        # Регрессия: v67-канон в шаблоне [R] должен остаться нетронутым.
        self.assertIn("bootstrap_resolvers = ['9.9.9.9:53', '77.88.8.8:53']", _SETUP_SRC)
        self.assertIn("fallback_resolvers = ['9.9.9.9:53', '77.88.8.8:53']", _SETUP_SRC)
        self.assertIn("netprobe_address = '9.9.9.9:53'", _SETUP_SRC)


class TestServerPool(unittest.TestCase):
    """2. Пул [RA]: 192 сервера, moscow/CF/GG исключены, голова — kyiv."""

    def test_pool_size_and_head(self):
        self.assertEqual(len(_SERVER_NAMES), 192)
        self.assertEqual(_SERVER_NAMES[0], "dnscry.pt-kyiv-ipv4")
        self.assertEqual(_SERVER_NAMES[1], "dnscry.pt-kyiv-ipv6")

    def test_no_moscow(self):
        for name in _SERVER_NAMES:
            self.assertNotIn("moscow", name,
                             f"dnscry.pt-moscow вернулся в пул: {name}")

    def test_no_cloudflare_google_tail(self):
        # «голые» cloudflare/google (DoH) — мёртвый груз из РФ.
        for name in ("cloudflare", "cloudflare-ipv6", "google", "google-ipv6"):
            self.assertNotIn(name, _SERVER_NAMES)

    def test_quad9_dnscrypt_in_pool(self):
        # Фаза-1 имена обязаны жить в пуле полного пресета.
        for name in _QUAD9_PHASE1:
            self.assertIn(name, _SERVER_NAMES)

    def test_routes_size_and_no_excluded(self):
        self.assertEqual(len(_ANON_ROUTES), 194)
        joined = "\n".join(_ANON_ROUTES)
        self.assertNotIn("moscow", joined)
        for name in ("'cloudflare'", "'google'"):
            self.assertNotIn(f"server_name={name}", joined)

    def test_wildcard_route_present(self):
        self.assertTrue(any("server_name='*'" in r for r in _ANON_ROUTES))


class TestXrayGeneratorsSync(unittest.TestCase):
    """4. xhttp-генератор синхронен с главным (v67 + v73)."""

    def test_quad9_live_fallback_count(self):
        # 2 в generate_xray_config (v67) + 2 в generate_xray_config_xhttp (v73).
        needle = '"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False'
        self.assertEqual(_XRAY_SRC.count(needle), 4)


class TestSafeApplyPreset(unittest.TestCase):
    """5. Функциональное поведение _safe_apply_preset (моки)."""

    def _run(self, *, apply_side_effect=None, apply_return=True,
             restart_side_effect=None, restart_return=True,
             resolves_side_effect=None, resolves_return=True,
             interrupt=False):
        fake = _FakeResolv(_ORIG_RESOLV)
        apply_mock = MagicMock(return_value=apply_return)
        if apply_side_effect is not None:
            apply_mock.side_effect = apply_side_effect
        restart_mock = MagicMock(return_value=restart_return)
        if restart_side_effect is not None:
            restart_mock.side_effect = restart_side_effect
        resolves_mock = MagicMock(return_value=resolves_return)
        if resolves_side_effect is not None:
            resolves_mock.side_effect = resolves_side_effect

        with patch.object(adv, "Path", side_effect=lambda p: fake), \
             patch.object(adv, "_backup_config", return_value="/fake/bak.toml"), \
             patch.object(adv.shutil, "copy2"), \
             patch.object(adv, "_run"), \
             patch("time.sleep"), \
             patch.object(adv, "_apply_preset", apply_mock), \
             patch.object(adv, "_restart_dnscrypt", restart_mock), \
             patch.object(adv, "_dnscrypt_resolves", resolves_mock):
            if interrupt:
                with self.assertRaises(KeyboardInterrupt):
                    _safe_apply_preset(["srv-full"], {"k": "v"}, ["r1"])
                result = None
            else:
                result = _safe_apply_preset(["srv-full"], {"k": "v"}, ["r1"])
        return result, fake, apply_mock, resolves_mock

    def test_success_phase1_quad9_and_resolv_restored(self):
        ok, fake, apply_mock, _ = self._run()
        self.assertTrue(ok)
        calls = [c.args[0] for c in apply_mock.call_args_list]
        self.assertEqual(calls[0], _QUAD9_PHASE1, "фаза-1 обязана идти на quad9-dnscrypt")
        self.assertEqual(calls[1], ["srv-full"])
        # resolv.conf: подмена на живые 9.9.9.9/77.88.8.8 → восстановление.
        self.assertEqual(fake.writes, [_TEMP_RESOLV, _ORIG_RESOLV])
        self.assertNotIn("nameserver 8.8.8.8", fake.writes[0])

    def test_resolv_restored_on_keyboard_interrupt(self):
        # Ctrl+C посреди фазы-1: исключение пробрасывается, resolv восстановлен.
        _, fake, _, _ = self._run(apply_side_effect=KeyboardInterrupt, interrupt=True)
        self.assertEqual(fake.writes, [_TEMP_RESOLV, _ORIG_RESOLV])

    def test_phase1_waits_for_netprobe_window(self):
        # netprobe/latency-ranking на старте — :5300 не отвечает первые
        # ~15-20с. Одиночный dig ложно проваливал фазу-1 → теперь ретраи.
        # (3 значения: 2 неудачи в фазе-1 + успех; 4-е — фаза-2 после рестарта.)
        ok, fake, _, resolves_mock = self._run(
            resolves_side_effect=[False, False, True, True])
        self.assertTrue(ok)
        self.assertEqual(resolves_mock.call_count, 4)
        self.assertEqual(fake.writes, [_TEMP_RESOLV, _ORIG_RESOLV])

    def test_phase1_failure_rollback_and_restore(self):
        ok, fake, _, resolves_mock = self._run(resolves_return=False)
        self.assertFalse(ok)
        self.assertEqual(resolves_mock.call_count, 4, "фаза-1 делает до 4 попыток")
        self.assertEqual(fake.writes, [_TEMP_RESOLV, _ORIG_RESOLV])

    def test_phase2_restart_failure_rolls_back_to_quad9(self):
        ok, fake, apply_mock, _ = self._run(restart_side_effect=[True, False])
        self.assertFalse(ok)
        calls = [c.args[0] for c in apply_mock.call_args_list]
        self.assertEqual(calls[0], _QUAD9_PHASE1)
        self.assertEqual(calls[1], ["srv-full"])
        self.assertEqual(calls[2], _QUAD9_PHASE1,
                         "откат фазы-2 обязан возвращать quad9-базу, а не cloudflare/google")
        self.assertEqual(fake.writes, [_TEMP_RESOLV, _ORIG_RESOLV])


if __name__ == "__main__":
    unittest.main()
