#!/usr/bin/env python3
"""
tests/test_system_doctor.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/system_doctor.py.

Контекст (кейс окт.2026 №13, флот-аудит 5 exit-нод + 2 RU-entry):
одинаковые ОС-болячки на каждой ноде (битый rc.local, фантомный netplan,
uncapped journald, crash-loop hysteria, правa на логи юнитов, мусор в
reboot-required) — модуль закрывает класс «гигиена ОС»: детект +
кастомизируемый авто-фикс.

Покрывает (чистые функции + tmp-IO, без сервера):
  1. parse_rc_local_issues     — битые редиректы rc.local
  2. parse_netplan_ifaces      — имена NIC из netplan-yaml (без PyYAML)
  3. classify_reboot_required  — валид/мусор (кейс PL/FI)
  4. parse_nrestarts           — NRestarts (кейс hysteria: 207865)
  5. parse_unit_log_rules      — append:-логи юнитов (кейс DE: dnscrypt)
  6. parse_journal_usage_mb    — '476.0M' / '4.0G'
  7. parse_kernel_pkgs         — ЧИСЛОВАЯ сортировка (35 < 147), откатные
  8. parse_listening_ports     — ss -tulnp
  9. parse_ufw_allowed         — ufw: одиночные + диапазоны (port-hopping)
 10. extract_cert_paths        — сертификаты из конфига Xray
 11. parse_xray_version        — CalVer '26.10.17' и semver '1.8.4'
 12. in_quiet_hours            — тихие часы через полночь
 13. merge_cfg                 — слияние конфига, принудительный выкл
                                 нефиксируемых пунктов
 14. build_logrotate_stanza    — drop-in ротации
 15. human_mb                  — форматирование
 16. Каталог: CHECKS/FIXES полнота, дефолты danger-политик
 17. DoctorCtx: dry-run не пишет на диск; бэкап перед записью
 18. load_cfg/save_cfg         — tmp-IO, битый файл = дефолты
 19. install/uninstall         — cron-файлы (tmp)
 20. build_console_report / build_tg_text — отчёты
 21. run_once(disabled)        — выключенный доктор = skip
 22. Wiring с tg_bot: иконки/подписи/паритет ev_keys/ev_labels
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Регистрирует chimera._core в sys.modules (нужен tg_bot для
    TUI-импортов; паттерн test_exit_switch_watcher)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules.setdefault("chimera._core", fake_core)


# ─── фиксстуры (примеры из живого флота, окт.2026) ────────────────────────────
RC_LOCAL = (
    "#!/bin/sh -e\n"
    "iptables-restore < /etc/iptables/rules.v4\n"
    "ip6tables-restore < /etc/iptables/rules.v6\n"
    "echo hi < /dev/null\n"
    "exit 0\n"
)
NETPLAN_PHANTOM = (
    "network:\n"
    "  version: 2\n"
    "  ethernets:\n"
    "    enp1s0:\n"
    "      dhcp4: true\n"
)
DPKG_KERNELS = [
    "ii  linux-image-6.8.0-146-generic   6.8.0-146.147 amd64",
    "ii  linux-image-6.8.0-147-generic   6.8.0-147.148 amd64",
    "ii  linux-image-6.8.0-35-generic    6.8.0-35.36   amd64",
    "rc  linux-image-6.8.0-87-generic    6.8.0-87.87   amd64",
]
SS_OUT = (
    "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
    "tcp   LISTEN 0      511    0.0.0.0:443         0.0.0.0:*\n"
    "tcp6  LISTEN 0      511    [::]:443            [::]:*\n"
    "udp   UNCONN 0      0      0.0.0.0:52831       0.0.0.0:*\n"
    "udp   UNCONN 0      0      0.0.0.0:2012        0.0.0.0:*\n"
)
UFW_OUT = (
    "Status: active\n"
    "To                         Action      From\n"
    "--                         ------      ----\n"
    "443/tcp                    ALLOW       Anywhere\n"
    "10000:20000/tcp            ALLOW       Anywhere  (port-hopping)\n"
    "52831/udp                  ALLOW       Anywhere\n"
    "2012:2022/udp              ALLOW       Anywhere (v6)\n"
    "22/tcp                     ALLOW IN    1.2.3.4\n"
)


class TestRcLocalParse(unittest.TestCase):
    """parse_rc_local_issues — битые редиректы (кейс NL/DE/PL/FI)."""

    def test_missing_file_flagged(self):
        from chimera.modules.system_doctor import parse_rc_local_issues
        iss = parse_rc_local_issues(
            RC_LOCAL, lambda p: p != "/etc/iptables/rules.v4")
        self.assertEqual(len(iss), 1)
        self.assertEqual(iss[0]["line_no"], 2)
        self.assertEqual(iss[0]["path"], "/etc/iptables/rules.v4")

    def test_all_ok_when_files_exist(self):
        from chimera.modules.system_doctor import parse_rc_local_issues
        self.assertEqual(parse_rc_local_issues(RC_LOCAL, lambda p: True), [])

    def test_comments_and_empty_skipped(self):
        from chimera.modules.system_doctor import parse_rc_local_issues
        text = "# iptables-restore < /nope\n\n   \nexit 0\n"
        self.assertEqual(parse_rc_local_issues(text, lambda p: False), [])

    def test_vars_and_dash_not_flagged(self):
        from chimera.modules.system_doctor import parse_rc_local_issues
        text = "cat < $CFG\ntr -d x < -something\n"
        self.assertEqual(parse_rc_local_issues(text, lambda p: False), [])


class TestNetplanParse(unittest.TestCase):
    """parse_netplan_ifaces — фантомные NIC (кейс enp1s0)."""

    def test_phantom_extracted(self):
        from chimera.modules.system_doctor import parse_netplan_ifaces
        self.assertEqual(parse_netplan_ifaces(NETPLAN_PHANTOM), ["enp1s0"])

    def test_empty(self):
        from chimera.modules.system_doctor import parse_netplan_ifaces
        self.assertEqual(parse_netplan_ifaces(""), [])
        self.assertEqual(parse_netplan_ifaces(None), [])

    def test_bonds_section(self):
        from chimera.modules.system_doctor import parse_netplan_ifaces
        yaml = ("network:\n  bonds:\n    bond0:\n"
                "      interfaces: [enp1s0]\n  version: 2\n")
        self.assertEqual(parse_netplan_ifaces(yaml), ["bond0"])

    def test_no_iface_keys(self):
        from chimera.modules.system_doctor import parse_netplan_ifaces
        yaml = "network:\n  version: 2\n  renderer: networkd\n"
        self.assertEqual(parse_netplan_ifaces(yaml), [])

    def test_match_keyword_not_iface(self):
        """Кейс RU-2: match: внутри ens3 не должен считаться интерфейсом
        (иначе — ложный 'фантом вперемешку с живыми')."""
        from chimera.modules.system_doctor import parse_netplan_ifaces
        yaml = ("network:\n  version: 2\n  ethernets:\n"
                "    ens3:\n      match:\n        name: en*\n"
                "      addresses: [10.0.0.2/32]\n")
        self.assertEqual(parse_netplan_ifaces(yaml), ["ens3"])

    def test_common_keys_not_ifaces(self):
        from chimera.modules.system_doctor import parse_netplan_ifaces
        yaml = ("network:\n  ethernets:\n    ens3:\n      routes:\n"
                "      nameservers:\n      wakeonlan: []\n")
        self.assertEqual(parse_netplan_ifaces(yaml), ["ens3"])


class TestRebootRequiredClassify(unittest.TestCase):
    """classify_reboot_required — кейс PL/FI: чей-то скрипт дописывал
    листинг /root в /var/run/reboot-required."""

    def test_valid_only(self):
        from chimera.modules.system_doctor import classify_reboot_required
        v, g = classify_reboot_required(
            ["*** System restart required ***", "linux-base",
             "linux-image-6.8.0-147-generic"])
        self.assertEqual(g, [])
        self.assertEqual(len(v), 3)

    def test_garbage_ls_listing(self):
        from chimera.modules.system_doctor import classify_reboot_required
        v, g = classify_reboot_required(
            ["*** System restart required ***", "linux-base",
             "-rw-r--r-- 1 root root 4096 Oct  3 /root/awg",
             "total 80", "drwxr-xr-x 2 root root 4096 Oct  3 ."])
        self.assertEqual(v, ["*** System restart required ***", "linux-base"])
        self.assertEqual(len(g), 3)

    def test_empty(self):
        from chimera.modules.system_doctor import classify_reboot_required
        self.assertEqual(classify_reboot_required([]), ([], []))
        self.assertEqual(classify_reboot_required(None), ([], []))


class TestNRestarts(unittest.TestCase):
    """parse_nrestarts — кейс hysteria-server: 207865 рестартов."""

    def test_pairs(self):
        from chimera.modules.system_doctor import parse_nrestarts
        out = parse_nrestarts(
            "Id=hysteria-server.service\nNRestarts=207865\n"
            "Id=xray.service\nNRestarts=0\n")
        self.assertEqual(out, {"hysteria-server.service": 207865,
                               "xray.service": 0})

    def test_bad_values_ignored(self):
        from chimera.modules.system_doctor import parse_nrestarts
        out = parse_nrestarts("Id=a.service\nNRestarts=none\nId=b.service\n")
        self.assertEqual(out, {"b.service": 0} if False else {})


class TestUnitLogRules(unittest.TestCase):
    """parse_unit_log_rules — кейс DE: dnscrypt-proxy-blocked.log."""

    SHOW_OUT = (
        "Id=dnscrypt-proxy.service\n"
        "User=dnscrypt\n"
        "StandardOutput=journal\n"
        "StandardError=append:/var/log/dnscrypt-proxy-blocked.log\n"
        "Id=xray.service\n"
        "User=root\n"
        "StandardOutput=append:/var/log/xray.log\n"
        "StandardError=append:/var/log/xray.log\n"
    )

    def test_dnscrypt_case(self):
        from chimera.modules.system_doctor import parse_unit_log_rules
        rules = parse_unit_log_rules(self.SHOW_OUT)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["unit"], "dnscrypt-proxy.service")
        self.assertEqual(rules[0]["user"], "dnscrypt")
        self.assertEqual(rules[0]["paths"],
                         ["/var/log/dnscrypt-proxy-blocked.log"])

    def test_paths_dedup(self):
        from chimera.modules.system_doctor import parse_unit_log_rules
        rules = parse_unit_log_rules(self.SHOW_OUT)
        self.assertEqual(rules[1]["paths"], ["/var/log/xray.log"])

    def test_no_user_defaults_root(self):
        from chimera.modules.system_doctor import parse_unit_log_rules
        rules = parse_unit_log_rules(
            "Id=u.service\nStandardOutput=append:/var/log/u.log\n")
        self.assertEqual(rules[0]["user"], "root")

    def test_file_prefix_also_counted(self):
        from chimera.modules.system_doctor import parse_unit_log_rules
        rules = parse_unit_log_rules(
            "Id=u.service\nStandardOutput=file:/var/log/u2.log\n")
        self.assertEqual(rules[0]["paths"], ["/var/log/u2.log"])

    def test_empty(self):
        from chimera.modules.system_doctor import parse_unit_log_rules
        self.assertEqual(parse_unit_log_rules(""), [])


class TestJournalUsage(unittest.TestCase):
    """parse_journal_usage_mb — '476.0M' / '4.0G' / '12K'."""

    def test_mb(self):
        from chimera.modules.system_doctor import parse_journal_usage_mb
        self.assertAlmostEqual(parse_journal_usage_mb(
            "Archived and active journals take up 476.0M on disk."), 476.0)

    def test_gb(self):
        from chimera.modules.system_doctor import parse_journal_usage_mb
        self.assertAlmostEqual(parse_journal_usage_mb("take up 4.0G"), 4096.0)

    def test_kb(self):
        from chimera.modules.system_doctor import parse_journal_usage_mb
        self.assertAlmostEqual(parse_journal_usage_mb("take up 2048K"), 2.0)

    def test_unparseable(self):
        from chimera.modules.system_doctor import parse_journal_usage_mb
        self.assertIsNone(parse_journal_usage_mb("nope"))
        self.assertIsNone(parse_journal_usage_mb(""))


class TestKernelPkgs(unittest.TestCase):
    """parse_kernel_pkgs — числовая сортировка ('35' НЕ больше '147'),
    откатные ядра, purge-кандидаты."""

    def test_numeric_sort_35_below_147(self):
        from chimera.modules.system_doctor import parse_kernel_pkgs
        info = parse_kernel_pkgs(DPKG_KERNELS, "6.8.0-147-generic", 1)
        self.assertEqual(info["newest"], "6.8.0-147-generic")
        self.assertEqual(info["installed"][0], "6.8.0-35-generic")

    def test_rollback_kept(self):
        from chimera.modules.system_doctor import parse_kernel_pkgs
        info = parse_kernel_pkgs(DPKG_KERNELS, "6.8.0-147-generic", 1)
        self.assertIn("6.8.0-146-generic", info["keep"])
        self.assertEqual(info["purge_candidates"], ["6.8.0-35-generic"])

    def test_keep_zero_purges_rollback_too(self):
        from chimera.modules.system_doctor import parse_kernel_pkgs
        info = parse_kernel_pkgs(DPKG_KERNELS, "6.8.0-147-generic", 0)
        self.assertEqual(info["keep"], ["6.8.0-147-generic"])
        self.assertEqual(info["purge_candidates"],
                         ["6.8.0-35-generic", "6.8.0-146-generic"])

    def test_running_below_newest_conservative(self):
        """Работает 146 при установленной 147: сосед 35 держим как откат
        (консервативно), purge пуст."""
        from chimera.modules.system_doctor import parse_kernel_pkgs
        info = parse_kernel_pkgs(DPKG_KERNELS, "6.8.0-146-generic", 1)
        self.assertEqual(info["purge_candidates"], [])
        self.assertEqual(set(info["keep"]),
                         {"6.8.0-146-generic", "6.8.0-147-generic",
                          "6.8.0-35-generic"})

    def test_rc_lines_ignored(self):
        from chimera.modules.system_doctor import parse_kernel_pkgs
        self.assertNotIn("6.8.0-87-generic",
                         parse_kernel_pkgs(DPKG_KERNELS,
                                           "6.8.0-147-generic", 1)["installed"])

    def test_empty(self):
        from chimera.modules.system_doctor import parse_kernel_pkgs
        info = parse_kernel_pkgs([], "6.8.0-147-generic", 1)
        self.assertEqual(info["purge_candidates"], [])
        self.assertEqual(info["newest"], "6.8.0-147-generic")


class TestListeningPorts(unittest.TestCase):
    """parse_listening_ports — ss -tulnp (tcp/tcp6/udp)."""

    def test_mixed(self):
        from chimera.modules.system_doctor import parse_listening_ports
        lp = parse_listening_ports(SS_OUT)
        self.assertIn(("tcp", 443), lp)
        self.assertIn(("udp", 52831), lp)
        self.assertIn(("udp", 2012), lp)
        # tcp6:443 схлопывается с tcp:443
        self.assertEqual(lp.count(("tcp", 443)), 1)

    def test_header_skipped(self):
        from chimera.modules.system_doctor import parse_listening_ports
        self.assertEqual(parse_listening_ports("State Recv-Q\n"), [])

    def test_empty(self):
        from chimera.modules.system_doctor import parse_listening_ports
        self.assertEqual(parse_listening_ports(""), [])


class TestUfwAllowed(unittest.TestCase):
    """parse_ufw_allowed — одиночные порты и диапазоны (port-hopping)."""

    def test_singles_and_ranges(self):
        from chimera.modules.system_doctor import parse_ufw_allowed
        singles, ranges = parse_ufw_allowed(UFW_OUT)
        self.assertIn(("tcp", 443), singles)
        self.assertIn(("udp", 52831), singles)
        self.assertIn(("tcp", 10000, 20000), ranges)
        self.assertIn(("udp", 2012, 2022), ranges)
        self.assertIn(("tcp", 22), singles)  # ALLOW IN тоже считается

    def test_star_proto_both(self):
        from chimera.modules.system_doctor import parse_ufw_allowed
        singles, _ = parse_ufw_allowed("35000/*    ALLOW    Anywhere\n")
        self.assertIn(("tcp", 35000), singles)
        self.assertIn(("udp", 35000), singles)

    def test_empty(self):
        from chimera.modules.system_doctor import parse_ufw_allowed
        self.assertEqual(parse_ufw_allowed(""), (set(), []))
        self.assertEqual(parse_ufw_allowed("Status: inactive"), (set(), []))


class TestCertPaths(unittest.TestCase):
    """extract_cert_paths — tls + reality сертификаты."""

    def test_tls_and_reality(self):
        from chimera.modules.system_doctor import extract_cert_paths
        cfg = {"inbounds": [
            {"streamSettings": {"tlsSettings": {"certificates": [
                {"certificateFile": "/etc/xray/a.crt"},
                {"certificateFile": "/etc/xray/a.crt"}]}}},
            {"streamSettings": {"realitySettings": {"certificates": [
                {"certificateFile": "/etc/xray/mask.crt"}]}}}]}
        self.assertEqual(extract_cert_paths(cfg),
                         ["/etc/xray/a.crt", "/etc/xray/mask.crt"])

    def test_empty(self):
        from chimera.modules.system_doctor import extract_cert_paths
        self.assertEqual(extract_cert_paths({}), [])
        self.assertEqual(extract_cert_paths(None), [])


class TestWgDump(unittest.TestCase):
    """parse_wg_dump / peer_for_target — честный сигнал туннеля
    (кейс NL: ICMP через AWG не ходит, хендшейк живой)."""

    DUMP = (
        "awg0\t(private)\tNMNaXx/0f4=\t52831\n"
        "awg0\teWfUaEV4=\t(none)\t91.224.87.154:6304\t"
        "172.16.91.4/32, fd66:66:91::4/128\t1760000000\t65250\t62030\toff\n"
        "awg0\taWslmD67=\t(none)\t138.124.255.238:60590\t"
        "172.16.91.3/32, fd66:66:91::3/128\t1760000005\t65310\t61860\toff\n"
    )

    def test_parse_peers(self):
        from chimera.modules.system_doctor import parse_wg_dump
        peers = parse_wg_dump(self.DUMP)
        self.assertEqual(len(peers), 2)  # interface-строка отфильтрована
        self.assertEqual(peers[0]["endpoint"], "91.224.87.154:6304")
        self.assertEqual(peers[0]["handshake_ts"], 1760000000)
        self.assertIn("172.16.91.4/32", peers[0]["allowed_ips"])

    def test_peer_for_target(self):
        from chimera.modules.system_doctor import peer_for_target, parse_wg_dump
        peers = parse_wg_dump(self.DUMP)
        p = peer_for_target(peers, "172.16.91.3")
        self.assertIsNotNone(p)
        self.assertEqual(p["endpoint"], "138.124.255.238:60590")
        self.assertIsNone(peer_for_target(peers, "10.9.9.9"))
        self.assertIsNone(peer_for_target([], "172.16.91.3"))

    def test_no_handshake_ts_zero(self):
        from chimera.modules.system_doctor import parse_wg_dump
        dump = ("awg0\tPUB\t(none)\t1.2.3.4:5\t10.0.0.2/32\t0\t0\t0\toff\n")
        peers = parse_wg_dump(dump)
        self.assertEqual(peers[0]["handshake_ts"], 0)

    def test_garbage(self):
        from chimera.modules.system_doctor import parse_wg_dump
        self.assertEqual(parse_wg_dump(""), [])
        self.assertEqual(parse_wg_dump("случайный текст\nбез табов"), [])


class TestXrayVersion(unittest.TestCase):
    """parse_xray_version — CalVer (26.10.17) и semver (1.8.4)."""

    def test_calver(self):
        from chimera.modules.system_doctor import parse_xray_version
        self.assertEqual(parse_xray_version(
            "Xray 26.10.17 (Xray, Penetrates Everything.) 92ccc93 "
            "(go1.27.2 linux/amd64)"), "26.10.17")

    def test_semver(self):
        from chimera.modules.system_doctor import parse_xray_version
        self.assertEqual(parse_xray_version("Xray 1.8.4 (Xray...)"), "1.8.4")

    def test_garbage(self):
        from chimera.modules.system_doctor import parse_xray_version
        self.assertEqual(parse_xray_version(""), "")
        self.assertEqual(parse_xray_version("xray binary not found"), "")


class TestQuietHours(unittest.TestCase):
    """in_quiet_hours — интервал через полночь (как у watcher'а)."""

    def test_disabled(self):
        from chimera.modules.system_doctor import in_quiet_hours
        self.assertFalse(in_quiet_hours("23:30", {"from": "", "to": ""}))
        self.assertFalse(in_quiet_hours("23:30", {}))

    def test_overnight(self):
        from chimera.modules.system_doctor import in_quiet_hours
        q = {"from": "23:00", "to": "08:00"}
        self.assertTrue(in_quiet_hours("23:59", q))
        self.assertTrue(in_quiet_hours("00:30", q))
        self.assertTrue(in_quiet_hours("07:59", q))
        self.assertFalse(in_quiet_hours("08:00", q))
        self.assertFalse(in_quiet_hours("12:00", q))

    def test_same_day(self):
        from chimera.modules.system_doctor import in_quiet_hours
        q = {"from": "13:00", "to": "14:00"}
        self.assertTrue(in_quiet_hours("13:30", q))
        self.assertFalse(in_quiet_hours("12:59", q))

    def test_bad_values(self):
        from chimera.modules.system_doctor import in_quiet_hours
        self.assertFalse(in_quiet_hours("13:30", {"from": "xx", "to": "yy"}))


class TestMergeCfg(unittest.TestCase):
    """merge_cfg — кастомизация: значения владельца не теряются, новые
    пункты будущих версий добираются дефолтами, нефиксируемое не чинится."""

    def test_scalar_override(self):
        from chimera.modules.system_doctor import DEFAULT_CONFIG, merge_cfg
        m = merge_cfg(DEFAULT_CONFIG, {"journald_cap_mb": 300})
        self.assertEqual(m["journald_cap_mb"], 300)
        self.assertEqual(m["big_log_mb"], DEFAULT_CONFIG["big_log_mb"])

    def test_checks_toggle_kept(self):
        from chimera.modules.system_doctor import DEFAULT_CONFIG, merge_cfg
        m = merge_cfg(DEFAULT_CONFIG, {"checks": {"rc_local": {"fix": True}}})
        self.assertTrue(m["checks"]["rc_local"]["fix"])

    def test_non_fixable_forced_off(self):
        from chimera.modules.system_doctor import DEFAULT_CONFIG, merge_cfg
        m = merge_cfg(DEFAULT_CONFIG,
                      {"checks": {"ssh_audit": {"fix": True}}})
        self.assertFalse(m["checks"]["ssh_audit"]["fix"])
        self.assertFalse(m["checks"]["ufw_audit"]["fix"])
        self.assertFalse(m["checks"]["xray_version"]["fix"])

    def test_new_check_items_default(self):
        """Конфиг до появления новых пунктов каталога добирает их."""
        from chimera.modules.system_doctor import DEFAULT_CONFIG, merge_cfg
        m = merge_cfg(DEFAULT_CONFIG, {"checks": {"journald_cap": {
            "check": True, "fix": True}}})
        self.assertIn("dns_check", m["checks"])
        self.assertTrue(m["checks"]["dns_check"]["check"])

    def test_broken_stored(self):
        from chimera.modules.system_doctor import DEFAULT_CONFIG, merge_cfg
        m = merge_cfg(DEFAULT_CONFIG, {"checks": "мусор"})
        self.assertIn("journald_cap", m["checks"])


class TestLogrotateStanza(unittest.TestCase):
    """build_logrotate_stanza — drop-in с copytruncate."""

    def test_contains_essentials(self):
        from chimera.modules.system_doctor import build_logrotate_stanza
        st = build_logrotate_stanza(["/var/log/hysteria.log"])
        for needle in ("/var/log/hysteria.log {", "copytruncate", "compress",
                       "missingok", "weekly", "rotate 4", "size 50M",
                       "su root root"):  # logrotate 3.21 требует su для /var/log
            self.assertIn(needle, st)

    def test_multiple_paths(self):
        from chimera.modules.system_doctor import build_logrotate_stanza
        st = build_logrotate_stanza(["/var/log/a.log", "/var/log/b.log"])
        self.assertEqual(st.count("{"), 2)


class TestHumanMb(unittest.TestCase):
    def test_m_and_g(self):
        from chimera.modules.system_doctor import human_mb
        self.assertEqual(human_mb(476), "476M")
        self.assertEqual(human_mb(2048), "2.0G")
        self.assertEqual(human_mb("x"), "?")


class TestCatalogIntegrity(unittest.TestCase):
    """Каталог: у каждого пункта есть проверка, у каждого fixable — фикс;
    опасные фиксы по умолчанию ВЫКЛ; CHECK_ORDER синхронен."""

    def test_all_checks_present(self):
        import chimera.modules.system_doctor as sd
        for cid in sd.CHECK_CATALOG:
            self.assertIn(cid, sd.CHECKS, f"нет chk_{cid}")
        self.assertEqual(set(sd.CHECKS), set(sd.CHECK_CATALOG))

    def test_fixable_have_fixes(self):
        import chimera.modules.system_doctor as sd
        for cid, meta in sd.CHECK_CATALOG.items():
            if meta[2]:
                self.assertIn(cid, sd.FIXES, f"нет fix_{cid}")
            else:
                self.assertNotIn(cid, sd.FIXES,
                                 f"{cid}: fixable=False, а фикс существует")

    def test_danger2_fixes_off_by_default(self):
        """Опасные фиксы выключены по умолчанию. reboot_flag — исключение:
        его «фикс» только чистит мусорные строки (не ребутит; сам ребут —
        отдельный флаг auto_reboot, по умолчанию ВЫКЛ)."""
        import chimera.modules.system_doctor as sd
        for cid in ("crash_loops", "old_kernels", "updates_pending",
                    "unattended"):
            self.assertFalse(sd.DEFAULT_CONFIG["checks"][cid]["fix"] if False
                             else sd.DEFAULT_CONFIG["checks"][cid]["fix"],
                             f"{cid}: fix должен быть выключен по умолчанию")
        self.assertFalse(sd.DEFAULT_CONFIG["auto_reboot"])
        self.assertFalse(sd.DEFAULT_CONFIG["apt_full_upgrade"])

    def test_catalog_fields(self):
        import chimera.modules.system_doctor as sd
        for cid, meta in sd.CHECK_CATALOG.items():
            self.assertEqual(len(meta), 6, f"{cid}: формат каталога")
            self.assertTrue(meta[3], f"{cid}: check по умолчанию должен быть ВКЛ")
            self.assertLessEqual(meta[1], 3)

    def test_order_matches(self):
        import chimera.modules.system_doctor as sd
        self.assertEqual(list(sd.CHECK_CATALOG.keys()), sd.CHECK_ORDER)

    def test_master_flags_default_off(self):
        from chimera.modules.system_doctor import DEFAULT_CONFIG as D
        for k in ("apt_full_upgrade", "kernel_purge", "enable_unattended",
                  "auto_reboot"):
            self.assertFalse(D[k], f"{k} должен быть выключен по умолчанию")
        self.assertEqual(D["crash_disable_allowlist"], [])


class TestDoctorCtx(unittest.TestCase):
    """DoctorCtx: dry-run ничего не пишет; запись делает бэкап."""

    def setUp(self):
        import chimera.modules.system_doctor as sd
        self.sd = sd
        self.tmp = Path(tempfile.mkdtemp())
        self.bak = self.tmp / "backups"
        self.ctx = sd.DoctorCtx(cfg=dict(sd.DEFAULT_CONFIG), mode="fix",
                                dry_run=False)
        self.ctx._backup_root = None  # маркер: патчим через BACKUP_ROOT

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_no_write(self):
        target = self.tmp / "sub" / "f.conf"
        ctx = self.sd.DoctorCtx(cfg={}, mode="fix", dry_run=True)
        self.assertTrue(ctx.write(target, "hello"))
        self.assertFalse(target.exists())
        self.assertTrue(any("DRY" in a for a in ctx.actions))
        r = ctx.cmd(["/bin/echo", "x"])
        self.assertEqual(r.returncode, 0)
        self.assertTrue(any("echo" in a for a in ctx.actions))

    def test_dry_run_quarantine(self):
        f = self.tmp / "phantom.yaml"
        f.write_text("network:")
        ctx = self.sd.DoctorCtx(cfg={}, mode="fix", dry_run=True)
        self.assertTrue(ctx.move_to_backup(f))
        self.assertTrue(f.exists())

    def test_write_creates_backup(self):
        with patch.multiple(self.sd, BACKUP_ROOT=self.bak):
            f = self.tmp / "conf.yaml"
            f.write_text("old")
            ctx = self.sd.DoctorCtx(cfg={}, mode="fix", dry_run=False)
            self.assertTrue(ctx.write(f, "new"))
            self.assertEqual(f.read_text(), "new")
            baks = list(self.bak.rglob("conf.yaml*"))
            self.assertEqual(len(baks), 1)
            self.assertEqual(baks[0].read_text(), "old")

    def test_quarantine_moves(self):
        with patch.multiple(self.sd, BACKUP_ROOT=self.bak):
            f = self.tmp / "50-cloud-init.yaml"
            f.write_text("network:")
            ctx = self.sd.DoctorCtx(cfg={}, mode="fix", dry_run=False)
            self.assertTrue(ctx.move_to_backup(f))
            self.assertFalse(f.exists())
            self.assertTrue(list((self.bak / ctx.stamp / "quarantine")
                                 .glob("50-cloud-init.yaml")))

    def test_fix_enabled_matrix(self):
        cfg = dict(self.sd.DEFAULT_CONFIG)
        ctx = self.sd.DoctorCtx(cfg=cfg, mode="check", dry_run=False)
        self.assertFalse(ctx.fix_enabled("journald_cap"))  # check-режим
        ctx2 = self.sd.DoctorCtx(cfg=cfg, mode="fix", dry_run=False)
        self.assertTrue(ctx2.fix_enabled("journald_cap"))
        self.assertFalse(ctx2.fix_enabled("crash_loops"))  # дефолт выкл
        self.assertFalse(ctx2.fix_enabled("ssh_audit"))    # нефиксируемое
        ctx3 = self.sd.DoctorCtx(cfg=cfg, mode="fix", only=["rc_local"])
        self.assertTrue(ctx3.fix_enabled("rc_local"))
        self.assertFalse(ctx3.fix_enabled("journald_cap"))


class TestCfgIO(unittest.TestCase):
    """load_cfg/save_cfg на tmp-путях; битый файл = дефолты."""

    def setUp(self):
        import chimera.modules.system_doctor as sd
        self.sd = sd
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = self.tmp / "system-doctor.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip(self):
        with patch.multiple(self.sd, CONFIG_FILE=self.cfg):
            cfg = self.sd.load_cfg()
            cfg["node_label"] = "TEST-NODE"
            cfg["journald_cap_mb"] = 777
            self.sd.save_cfg(cfg)
            reread = self.sd.load_cfg()
        self.assertEqual(reread["node_label"], "TEST-NODE")
        self.assertEqual(reread["journald_cap_mb"], 777)

    def test_missing_file_defaults(self):
        with patch.multiple(self.sd, CONFIG_FILE=self.cfg):
            cfg = self.sd.load_cfg()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["journald_cap_mb"], 500)

    def test_broken_file_defaults(self):
        self.cfg.write_text("{это не json")
        with patch.multiple(self.sd, CONFIG_FILE=self.cfg):
            cfg = self.sd.load_cfg()
        self.assertTrue(cfg["enabled"])


class TestInstallCron(unittest.TestCase):
    """install/uninstall — cron-файлы на tmp-путях."""

    def setUp(self):
        import chimera.modules.system_doctor as sd
        self.sd = sd
        self.tmp = Path(tempfile.mkdtemp())
        self.cron = self.tmp / "cron.d" / "system-doctor"
        self.script = self.tmp / "bin" / "system-doctor.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_writes_both(self):
        with patch.multiple(self.sd, CRON_FILE=self.cron,
                            CRON_SCRIPT=self.script):
            ok, msg = self.sd.install_system_doctor({"cron_hour": 5,
                                                      "cron_minute": 40,
                                                      "cron_mode": "fix"})
        self.assertTrue(ok, msg)
        cron_text = self.cron.read_text()
        self.assertIn("40 5 * * *", cron_text)
        self.assertIn("run_once", self.script.read_text())
        self.assertIn("mode='fix'", self.script.read_text())

    def test_uninstall_removes(self):
        with patch.multiple(self.sd, CRON_FILE=self.cron,
                            CRON_SCRIPT=self.script):
            self.cron.parent.mkdir(parents=True, exist_ok=True)
            self.cron.write_text("x")
            ok, _ = self.sd.uninstall_system_doctor()
            self.assertTrue(ok)
            self.assertFalse(self.cron.exists())
            self.assertFalse(self.script.exists())


class TestReports(unittest.TestCase):
    """build_console_report / build_tg_text."""

    REP = {
        "label": "NL", "mode": "fix", "dry_run": False,
        "ts": "2026-10-20 12:00:00",
        "counts": {"ok": 18, "info": 2, "warn": 2, "crit": 1},
        "findings": [
            {"check": "reboot_flag", "level": "warn", "msg": "требуется ребут"},
            {"check": "failed_units", "level": "crit", "msg": "failed: rc-local"},
            {"check": "journald_cap", "level": "ok", "msg": "476M ≤ 500M"},
        ],
        "fixed": [{"check": "rc_local", "msg": "закомментировано 1 строка"}],
        "fix_errors": [],
        "actions": ["cmd: systemctl reset-failed"],
    }

    def test_console(self):
        from chimera.modules.system_doctor import build_console_report
        txt = build_console_report(self.REP)
        self.assertIn("[NL] FIX", txt)
        self.assertIn("crit=1", txt)
        self.assertIn("rc_local", txt)
        self.assertIn("закомментировано 1 строка", txt)

    def test_tg_compact(self):
        from chimera.modules.system_doctor import build_tg_text
        txt = build_tg_text(self.REP)
        self.assertIn("<b>[NL] System Doctor</b>", txt)
        self.assertIn("failed: rc-local", txt)
        self.assertNotIn("476M", txt)  # ok-находки не уходят в TG

    def test_tg_truncates(self):
        from chimera.modules.system_doctor import build_tg_text
        rep = dict(self.REP)
        rep["findings"] = [{"check": "x", "level": "warn", "msg": "д" * 5000}]
        txt = build_tg_text(rep)
        self.assertLessEqual(len(txt), 3801)

    def test_dry_run_plan_in_console(self):
        from chimera.modules.system_doctor import build_console_report
        rep = dict(self.REP, dry_run=True)
        self.assertIn("план действий", build_console_report(rep))


class TestRunOnce(unittest.TestCase):
    """run_once: выключенный доктор — skip; отчёт пишется в LAST_FILE."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import chimera.modules.system_doctor as sd
        self.sd = sd
        self.tmp = Path(tempfile.mkdtemp())
        self.cfgf = self.tmp / "system-doctor.json"
        self.last = self.tmp / "system-doctor-last.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_disabled_skip(self):
        self.cfgf.write_text(json.dumps({"enabled": False}))
        with patch.multiple(self.sd, CONFIG_FILE=self.cfgf,
                            LAST_FILE=self.last), \
             patch.object(self.sd, "_notify_report") as nr:
            rep = self.sd.run_once(mode="fix")
        self.assertTrue(rep.get("skipped"))
        self.assertEqual(rep["findings"], [])
        nr.assert_not_called()

    def test_check_runs_and_saves_last(self):
        self.cfgf.write_text(json.dumps({"enabled": True}))
        with patch.multiple(self.sd, CONFIG_FILE=self.cfgf,
                            LAST_FILE=self.last), \
             patch.object(self.sd, "_notify_report"), \
             patch.object(self.sd, "chk_journald_cap",
                          lambda ctx: ctx.record("journald_cap", "ok",
                                                 "тест")):
            rep = self.sd.run_once(mode="fix", only=["journald_cap"])
        self.assertFalse(rep.get("skipped"))
        self.assertEqual(rep["counts"]["ok"], 1)
        self.assertEqual(rep["only"], ["journald_cap"])
        self.assertTrue(self.last.exists())
        saved = json.loads(self.last.read_text())
        self.assertEqual(saved["counts"]["ok"], 1)
        # фикс не применялся: в конфиге fix выключен для journald_cap
        self.assertEqual(rep["fixed"], [])


class TestTgWiring(unittest.TestCase):
    """Интеграция с меню tg_bot (управляемость событий доктора)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_doctor_events_in_event_labels(self):
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.do_manage_telegram)
        for ev in ("doctor_alert", "doctor_fixed", "doctor_report"):
            self.assertIn(f'"{ev}"', src, f"{ev} отсутствует в меню tg_bot")

    def test_ev_keys_labels_aligned(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        keys = re.findall(r'"([a-z_0-9]+)"',
                          re.search(r"ev_keys = \[(.*?)\]",
                                    src, re.S).group(1))
        labels = re.findall(r'"([^"]+)"',
                            re.search(r"ev_labels = \[(.*?)\]\n\s+events",
                                      src, re.S).group(1))
        self.assertEqual(len(keys), len(labels))
        for ev in ("doctor_alert", "doctor_fixed", "doctor_report"):
            self.assertIn(ev, keys)

    def test_icons_for_doctor_events(self):
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.tg_notify_event)
        for ev in ("doctor_alert", "doctor_fixed", "doctor_report"):
            self.assertIn(f'"{ev}"', src, f"нет иконки для {ev}")


class TestCliContract(unittest.TestCase):
    """main.py: флаг --system-doctor с подфлагами --fix/--dry-run/--only."""

    def test_flag_wired(self):
        src = (_PROJECT_ROOT / "main.py").read_text()
        self.assertIn('"--system-doctor" in sys.argv', src)
        self.assertIn("from chimera.modules.system_doctor import", src)

    def test_core_menu_wired(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("do_system_doctor_menu", src)
        self.assertIn('"SD"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
