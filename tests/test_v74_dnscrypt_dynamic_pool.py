#!/usr/bin/env python3
"""
tests/test_v74_dnscrypt_dynamic_pool.py
───────────────────────────────────────────────────────────────────────────────
Unit + integration тесты v74 (динамический пул DNSCrypt):

  1. Пул 245: счётчики, уникальность, отсутствие мёртвых из кладбища
  2. Маршруты: DoH-серверы не маршрутятся; релеи маршрутов — из wildcard/набора;
     wildcard присутствует единожды
  3. Параметры: http3_probe удалён; refresh_delay = 25; dnscry.pt-источники
     удалены; jsdelivr-зеркало добавлено
  4. dnscrypt_update: state-файл (read/update), строки шапок, версия
  5. Интеграция pool-sync: standalone-скрипт в песочнице (tmp-пути) —
     генерация конфига, идемпотентность, воскрешение, откат при провале
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import dnscrypt_advanced as adv
from chimera.modules import dnscrypt_update as upd


# ─────────────────────────────────────────────────────────────────────────────
#  1-3. Статические проверки пула/маршрутов/параметров
# ─────────────────────────────────────────────────────────────────────────────
class TestPoolV74(unittest.TestCase):
    def test_pool_size(self):
        self.assertEqual(len(adv._SERVER_NAMES), 245)
        self.assertEqual(len(set(adv._SERVER_NAMES)), 245)

    def test_graveyard_excluded(self):
        self.assertEqual(len(adv._POOL_GRAVEYARD), 37)
        self.assertFalse(set(adv._POOL_GRAVEYARD) & set(adv._SERVER_NAMES),
                         "мёртвые имена не должны быть в пуле")

    def test_routes_shape(self):
        routes = upd._routes_from_advanced()
        self.assertEqual(len(routes), 179)
        wild = [r for r in adv._ANON_ROUTES if "server_name='*'" in r]
        self.assertEqual(len(wild), 1)
        self.assertEqual(len(adv._ANON_ROUTES), 180)

    def test_no_doh_in_routes(self):
        """DoH-серверы (из живого списка) не должны иметь маршрутов."""
        # фикстура: имена, известные как DoH-протокол в живом списке
        doh_names = {"dns.sb", "mullvad-doh", "switch", "nic.cz",
                     "circl-doh", "doh.appliedprivacy.net", "njalla-doh",
                     "dnsforge.de-nofilter", "doh.ffmuc.net",
                     "dnscry.pt-doh-dublin-ipv4"}
        routes = upd._routes_from_advanced()
        self.assertFalse(doh_names & set(routes),
                         "DoH-серверы не должны быть в маршрутах")

    def test_security_params_v74(self):
        self.assertNotIn("http3_probe", adv._SECURITY_PARAMS)
        self.assertIn("bootstrap_resolvers", adv._SECURITY_PARAMS)

    def test_sources_v74(self):
        secs = re.findall(r'\[sources\.([^\]]+)\]', adv._EXTRA_SOURCES)
        self.assertEqual(secs, ["odoh-servers", "odoh-relays"])
        self.assertNotIn("dnscry.pt", " ".join(secs))
        self.assertIn("cdn.jsdelivr.net", adv._EXTRA_SOURCES)

    def test_wildcard_relays(self):
        self.assertEqual(len(adv._WILDCARD_RELAYS), 30)
        # мёртвые релеи v73 не должны попасть в wildcard
        for dead in ("anon-cs-ch6", "anon-cs-swe6",
                     "dnscry.pt-anon-frankfurt-ipv4"):
            self.assertNotIn(dead, adv._WILDCARD_RELAYS)


# ─────────────────────────────────────────────────────────────────────────────
#  4. dnscrypt_update: state и строки шапок
# ─────────────────────────────────────────────────────────────────────────────
class TestStateAndHeaders(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._state = Path(self._tmp) / "state.json"
        self._orig = upd.STATE_FILE
        upd.STATE_FILE = self._state

    def tearDown(self):
        upd.STATE_FILE = self._orig

    def test_update_state_merge(self):
        upd.update_state(pool={"total": 245, "alive": 240, "countries": 51})
        upd.update_state(pool={"alive": 239})
        upd.update_state(version={"installed": "2.1.18"})
        st = json.loads(self._state.read_text())
        self.assertEqual(st["pool"]["total"], 245)
        self.assertEqual(st["pool"]["alive"], 239)
        self.assertEqual(st["version"]["installed"], "2.1.18")

    def test_pool_status_line(self):
        upd.update_state(pool={"total": 245, "alive": 240, "countries": 51,
                               "last_sync": "2026-09-01 08:30"})
        line = upd.get_pool_status_line()
        self.assertIn("245", line)
        self.assertIn("51", line)
        self.assertIn("08:30", line)

    def test_version_status_line_fallback(self):
        line = upd.get_version_status_line()
        self.assertTrue(line)  # не падает без state

    def test_norm_versions(self):
        self.assertGreater(upd._norm("2.1.18"), upd._norm("2.1.5"))
        self.assertEqual(upd._norm("2.1.18"), upd._norm("2.1.18"))


# ─────────────────────────────────────────────────────────────────────────────
#  5. Интеграция: standalone pool-sync в песочнице
# ─────────────────────────────────────────────────────────────────────────────
def _fixture_lists(tmp: Path, live_extra: list | None = None,
                   drop: list | None = None):
    """Мини-фикстуры живых списков из РЕАЛЬНОГО снапшота."""
    src_srv = Path("/home/z/my-project/scripts/public-resolvers.md")
    src_rel = Path(
        "/home/z/my-project/scripts/ra-test/cache-B3-pool-clean/relays.md")
    srv_names, rel_names = [], []
    if src_srv.exists() and src_rel.exists():
        srv_names = [l[3:].strip() for l in src_srv.read_text(errors="replace")
                     .splitlines() if l.startswith("## ")]
        rel_names = [l[3:].strip() for l in src_rel.read_text(errors="replace")
                     .splitlines() if l.startswith("## ")]
    else:
        srv_names = list(adv._SERVER_NAMES[:50])
        rel_names = list(adv._WILDCARD_RELAYS)

    keep_srv = [n for n in srv_names if n not in (drop or [])]
    keep_srv = keep_srv + (live_extra or [])

    (tmp / "public-resolvers.md").write_text(
        "\n\n".join(f"## {n}\n\nsdns://AQ" for n in keep_srv))
    (tmp / "relays.md").write_text(
        "\n\n".join(f"## {n}\n\ntext" for n in rel_names))
    return set(keep_srv), set(rel_names)


class TestPoolSyncIntegration(unittest.TestCase):
    """POOL_SYNC_SH запускается в tmp-песочнице с переписанными путями."""

    def _make_env(self, live_extra=None, drop=None, current_names=None):
        tmp = Path(tempfile.mkdtemp())
        conf_dir = tmp / "etc" / "dnscrypt-proxy"
        conf_dir.mkdir(parents=True)
        _fixture_lists(conf_dir, live_extra, drop)
        # шаблон из живого модуля
        template = {
            "servers": adv._SERVER_NAMES,
            "routes": upd._routes_from_advanced(),
            "wildcard": adv._WILDCARD_RELAYS,
            "graveyard": adv._POOL_GRAVEYARD,
            "countries": 51,
            "params": adv._SECURITY_PARAMS,
        }
        (conf_dir / "pool-template.json").write_text(
            json.dumps(template))
        # текущий конфиг
        cur = list(current_names if current_names is not None
                   else adv._SERVER_NAMES)
        (conf_dir / "dnscrypt-proxy.toml").write_text(
            "listen_addresses = ['127.0.0.1:5300']\n\nserver_names = "
            + json.dumps(cur).replace('"', "'") + "\n")
        state = tmp / "state.json"
        # скрипт с переписанными путями
        script = upd.POOL_SYNC_SH
        script = script.replace('CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")',
                                f'CONF = Path("{conf_dir / "dnscrypt-proxy.toml"}")')
        script = script.replace('TEMPLATE = Path("/etc/dnscrypt-proxy/pool-template.json")',
                                f'TEMPLATE = Path("{conf_dir / "pool-template.json"}")')
        script = script.replace('LIVE_SRV = Path("/etc/dnscrypt-proxy/public-resolvers.md")',
                                f'LIVE_SRV = Path("{conf_dir / "public-resolvers.md"}")')
        script = script.replace('LIVE_REL = Path("/etc/dnscrypt-proxy/relays.md")',
                                f'LIVE_REL = Path("{conf_dir / "relays.md"}")')
        script = script.replace('STATE = Path("/var/lib/chimera/dnscrypt-state.json")',
                                f'STATE = Path("{state}")')
        # systemctl/dig → заглушки (сервис «работает», резолв «ок»)
        fake_bin = tmp / "fakebin"
        fake_bin.mkdir()
        (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n")
        (fake_bin / "dig").write_text("#!/bin/sh\necho 93.184.216.34\n")
        (fake_bin / "systemctl").chmod(0o755)
        (fake_bin / "dig").chmod(0o755)
        script_path = tmp / "pool_sync_test.py"
        script_path.write_text(script)
        return tmp, conf_dir, state, script_path, str(fake_bin)

    def _run(self, script_path, fake_bin):
        env = {"PATH": fake_bin + ":/usr/bin:/bin", "HOME": "/tmp"}
        return subprocess.run([sys.executable, str(script_path)],
                              capture_output=True, text=True, env=env,
                              timeout=120)

    def test_no_change_no_config_rewrite(self):
        tmp, conf_dir, state, script, fake_bin = self._make_env()
        # первый прогон нормализует конфиг к канонической форме
        r1 = self._run(script, fake_bin)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        before = (conf_dir / "dnscrypt-proxy.toml").read_text()
        # второй прогон: пул не изменился → конфиг не трогаем
        r2 = self._run(script, fake_bin)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        after = (conf_dir / "dnscrypt-proxy.toml").read_text()
        self.assertEqual(before, after, "без дрейфа конфиг не должен меняться")
        st = json.loads(state.read_text())
        self.assertFalse(st["pool"]["changed"])
        self.assertIn("рестарта нет", r2.stdout)

    def test_dead_server_removed(self):
        # убиваем 20 серверов из живого списка
        drop = adv._SERVER_NAMES[:20]
        tmp, conf_dir, state, script, fake_bin = self._make_env(drop=drop)
        r = self._run(script, fake_bin)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (conf_dir / "dnscrypt-proxy.toml").read_text()
        for name in drop:
            self.assertNotIn(f"'{name}'", conf)
        st = json.loads(state.read_text())
        self.assertEqual(st["pool"]["total"], 245 - 20)
        self.assertTrue(st["pool"]["changed"])

    def test_graveyard_resurrection(self):
        # «оживляем» 3 имени из кладбища
        resurrect = adv._POOL_GRAVEYARD[:3]
        tmp, conf_dir, state, script, fake_bin = self._make_env(
            live_extra=list(resurrect))
        r = self._run(script, fake_bin)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (conf_dir / "dnscrypt-proxy.toml").read_text()
        for name in resurrect:
            self.assertIn(f"'{name}'", conf)
        st = json.loads(state.read_text())
        self.assertEqual(st["pool"]["resurrected"], 3)

    def test_generated_config_shape(self):
        drop = adv._SERVER_NAMES[:5]
        tmp, conf_dir, state, script, fake_bin = self._make_env(drop=drop)
        r = self._run(script, fake_bin)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (conf_dir / "dnscrypt-proxy.toml").read_text()
        # ключевые секции конфига
        self.assertIn("listen_addresses = ['127.0.0.1:5300']", conf)
        self.assertIn("[sources.public-resolvers]", conf)
        self.assertIn("[sources.relays]", conf)
        self.assertIn("[anonymized_dns]", conf)
        self.assertIn("cdn.jsdelivr.net", conf)
        self.assertNotIn("dnscry.pt-resolvers", conf)
        self.assertNotIn("http3_probe", conf)
        self.assertIn("refresh_delay = 25", conf)
        # listen сохранён, серверов стало 240
        m = re.search(r"server_names = \[(.+?)\]", conf, re.S)
        names = re.findall(r"'([^']+)'", m.group(1))
        self.assertEqual(len(names), 240)

    def test_tiny_live_list_aborts(self):
        # живой список подозрительно мал → конфиг не трогаем
        tmp, conf_dir, state, script, fake_bin = self._make_env()
        (conf_dir / "public-resolvers.md").write_text(
            "\n\n".join(f"## {n}\n\nsdns://AQ" for n in adv._SERVER_NAMES[:10]))
        before = (conf_dir / "dnscrypt-proxy.toml").read_text()
        r = self._run(script, fake_bin)
        self.assertEqual(r.returncode, 0)  # мягкий выход
        self.assertEqual(before, (conf_dir / "dnscrypt-proxy.toml").read_text())
        st = json.loads(state.read_text())
        self.assertIn("too small", st["pool"]["error"])

    def test_autoupdate_script_template(self):
        self.assertIn("dnscrypt-autoupdate", upd.AUTOPD_SH)
        # bash-синтаксис валиден (bash -n)
        import shutil as _sh
        if _sh.which("bash"):
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
                f.write(upd.AUTOPD_SH.lstrip())
                path = f.name
            try:
                r = subprocess.run(["bash", "-n", path],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
            finally:
                Path(path).unlink(missing_ok=True)
        # ключевые элементы bash-скрипта
        for token in ("BACKUP_DIR", "wait_dns", "reset-failed",
                      "releases/latest", "ghproxy.net"):
            self.assertIn(token, upd.AUTOPD_SH)

    def test_install_pool_sync_template(self):
        """install_pool_sync пишет валидный шаблон (tmp-пути)."""
        with tempfile.TemporaryDirectory() as td:
            tpl_path = Path(td) / "template.json"
            cron_path = Path(td) / "cron"
            script_path = Path(td) / "sync.py"
            with patch.object(upd, "POOL_TEMPLATE", tpl_path), \
                 patch.object(upd, "POOL_CRON", cron_path), \
                 patch.object(upd, "POOL_SYNC_BIN", script_path):
                self.assertTrue(upd.install_pool_sync())
            tpl = json.loads(tpl_path.read_text())
            self.assertEqual(len(tpl["servers"]), 245)
            self.assertEqual(len(tpl["routes"]), 179)
            self.assertEqual(len(tpl["graveyard"]), 37)
            self.assertEqual(len(tpl["wildcard"]), 30)
            self.assertIn("*/6", cron_path.read_text())
            # скрипт компилируется
            compile(script_path.read_text(), "pool_sync", "exec")


if __name__ == "__main__":
    unittest.main(verbosity=2)
