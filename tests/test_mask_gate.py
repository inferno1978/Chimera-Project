#!/usr/bin/env python3
"""
tests/test_mask_gate.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mask_gate.py.

Покрывает:
  1. tcp_streams_from_pcap — свой парсер TCP-потоков (синтетический PCAP,
     адреса TEST-NET по политике leak_guard)
  2. tls_heuristics_verdict — builtin TLS-эвристики (валидный TLS-поток
     → clean_tls, мусор → suspect)
  3. _quick_udp_shape — форма UDP-пакетов (QUIC/STUN → clean, сырой → suspect)
  4. classify_tcp_flow / classify_udp_flow — вердикты с nDPI-классами
     (mock) и без них (builtin)
  5. run_mask_gate offline — полный гейт на синтетических PCAP:
     TLS-подобный трафик → PASS, VPN-подобный (nDPI: WireGuard) → FAIL,
     мусор без nDPI → SUSPECT/FAIL-пути
  6. run_ndpi / run_tshark_streams — парсеры вывода внешних инструментов
     (mock subprocess)
  7. get_xray_port_from_state / get_server_ip_from_state — чтение state.json
"""
from __future__ import annotations

import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import mask_gate as mg


# ── Синтетика: IP/TCP/UDP пакеты + PCAP ──────────────────────────────────────
def _ips(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def ipv4_tcp_packet(src: str, dst: str, sport: int, dport: int,
                    payload: bytes, flags: int = 0x18) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1,
                      0x50, flags, 0xFFFF, 0, 0) + payload
    total = 20 + len(tcp)
    return struct.pack(">BBHHHBBH4s4s",
                       0x45, 0, total, 1, 0, 64, 6, 0,
                       _ips(src), _ips(dst)) + tcp


def ipv4_udp_packet(src: str, dst: str, sport: int, dport: int,
                    payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    return struct.pack(">BBHHHBBH4s4s",
                       0x45, 0, total, 1, 0, 64, 17, 0,
                       _ips(src), _ips(dst)) + udp


def eth(ip: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip


def write_pcap(path: Path, frames: list, dlt: int = 1) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, dlt))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000, i * 1000, len(fr), len(fr)))
            f.write(fr)


def tls_stream_payloads(n_records: int = 6) -> list:
    """Сегменты, похожие на честный TLS: ClientHello → ServerHello → данные.

    Длина payload строго = полю length в записи (иначе парсер записей
    собьётся — это ровно то, что ловит no_garbage_records).
    """
    ch = bytes([0x16, 0x03, 0x01, 0x00, 0x51]) + bytes([0x01]) + b"\x00" * (0x51 - 1)
    sh = bytes([0x16, 0x03, 0x03, 0x00, 0x31]) + bytes([0x02]) + b"\x00" * (0x31 - 1)
    app = bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\xaa" * 0x20
    return [ch[:64], ch[64:], sh, app, app, app][:max(1, n_records)]


class TestTcpStreams(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_tcp_streams_basic(self):
        # Ключ = 4-tuple без направления: клиент→сервер и сервер→клиент —
        # два отдельных потока для анализа (каждый смотрится независимо)
        frames = [
            eth(ipv4_tcp_packet("192.0.2.10", "192.0.2.20", 5000, 443, b"hello")),
            eth(ipv4_tcp_packet("192.0.2.20", "192.0.2.10", 443, 5000, b"world")),
        ]
        p = self.tmp / "tcp.pcap"
        write_pcap(p, frames)
        res = mg.tcp_streams_from_pcap(p)
        self.assertEqual(len(res["tuples"]), 2)
        joined = b"".join(b"".join(v) for v in res["tuples"].values())
        self.assertIn(b"hello", joined)
        self.assertIn(b"world", joined)

    def test_tcp_streams_port_filter(self):
        frames = [
            eth(ipv4_tcp_packet("192.0.2.10", "192.0.2.20", 5000, 443, b"a")),
            eth(ipv4_tcp_packet("192.0.2.30", "192.0.2.40", 6000, 8443, b"b")),
        ]
        p = self.tmp / "tcp2.pcap"
        write_pcap(p, frames)
        res = mg.tcp_streams_from_pcap(p, port=443)
        self.assertEqual(len(res["tuples"]), 1)

    def test_tcp_streams_ignores_udp(self):
        frames = [eth(ipv4_udp_packet("192.0.2.1", "192.0.2.2", 1, 2, b"x"))]
        p = self.tmp / "udp_only.pcap"
        write_pcap(p, frames)
        res = mg.tcp_streams_from_pcap(p)
        self.assertEqual(len(res["tuples"]), 0)


class TestTlsHeuristics(unittest.TestCase):
    def test_valid_tls_stream_clean(self):
        h = mg.tls_heuristics_verdict(tls_stream_payloads())
        self.assertEqual(h["verdict"], "clean_tls")
        self.assertTrue(h["checks"]["first_is_tls"])
        self.assertTrue(h["checks"]["version_ok"])
        self.assertTrue(h["checks"]["has_handshake"])
        self.assertTrue(h["checks"]["no_garbage_records"])

    def test_garbage_stream_suspect(self):
        # WireGuard-подобный мусор: первый байт 0x01 (не TLS content-type)
        h = mg.tls_heuristics_verdict([b"\x01\x00\x00\x00" + b"\xaa" * 40])
        self.assertEqual(h["verdict"], "suspect")
        self.assertFalse(h["checks"]["first_is_tls"])

    def test_empty_stream_insufficient(self):
        h = mg.tls_heuristics_verdict([])
        self.assertEqual(h["verdict"], "insufficient")

    def test_alert_record_is_tls(self):
        # alert (0x15) — тоже валидная TLS-запись (REALITY может слать alert)
        alert = bytes([0x15, 0x03, 0x03, 0x00, 0x02]) + b"\x01\x00"
        h = mg.tls_heuristics_verdict([alert])
        self.assertEqual(h["verdict"], "clean_tls")


class TestQuickUdpShape(unittest.TestCase):
    def test_quic_long_header(self):
        pkt = bytes([0xC3]) + b"\x00" * 31
        self.assertEqual(mg._quick_udp_shape(pkt), "clean")

    def test_quic_short_header(self):
        pkt = bytes([0x40]) + b"\x00" * 31
        self.assertEqual(mg._quick_udp_shape(pkt), "clean")

    def test_stun_binding(self):
        pkt = bytes([0x00, 0x01, 0x00, 0x30, 0x21, 0x12, 0xA4, 0x42]) + b"\x00" * 0x30
        self.assertEqual(mg._quick_udp_shape(pkt), "clean")

    def test_raw_udp_suspect(self):
        # WireGuard-подобное: 0x01 00 00 00
        self.assertEqual(mg._quick_udp_shape(b"\x01\x00\x00\x00" + b"\xaa" * 40),
                         "suspect")
        self.assertEqual(mg._quick_udp_shape(b""), "insufficient")


class TestClassifyFlows(unittest.TestCase):
    def test_classify_tcp_with_ndpi_clean(self):
        flow = {"flow": "flow_abc", "l4": "tcp", "sport": 5000, "dport": 443,
                "first_bytes_b64": ""}
        ndpi = [{"flow": "flow_abc", "sport": 5000, "dport": 443,
                 "classification": "TLS"}]
        v = mg.classify_tcp_flow(flow, ndpi)
        self.assertEqual(v["verdict"], "clean")
        self.assertEqual(v["ndpi"], "TLS")

    def test_classify_tcp_with_ndpi_vpn_fail(self):
        flow = {"flow": "flow_abc", "l4": "tcp", "sport": 5000, "dport": 443,
                "first_bytes_b64": ""}
        ndpi = [{"flow": "flow_abc", "sport": 5000, "dport": 443,
                 "classification": "WireGuard"}]
        v = mg.classify_tcp_flow(flow, ndpi)
        self.assertEqual(v["verdict"], "fail")

    def test_classify_tcp_with_ndpi_unknown_suspect(self):
        flow = {"flow": "flow_abc", "l4": "tcp", "sport": 5000, "dport": 443,
                "first_bytes_b64": ""}
        ndpi = [{"flow": "flow_abc", "sport": 5000, "dport": 443,
                 "classification": "Unknown"}]
        v = mg.classify_tcp_flow(flow, ndpi)
        self.assertEqual(v["verdict"], "suspect")

    def test_classify_tcp_fallback_builtin(self):
        import base64
        first = tls_stream_payloads()[0]
        flow = {"flow": "flow_abc", "l4": "tcp", "sport": 5000, "dport": 443,
                "first_bytes_b64": base64.b64encode(first).decode()}
        v = mg.classify_tcp_flow(flow, None)
        self.assertEqual(v["verdict"], "clean_tls")

    def test_classify_udp_clean_quic(self):
        flow = {"flow": "flow_q", "l4": "udp", "sport": 5000, "dport": 443,
                "first_bytes_b64": ""}
        ndpi = [{"flow": "flow_q", "sport": 5000, "dport": 443,
                 "classification": "QUIC"}]
        v = mg.classify_udp_flow(flow, ndpi)
        self.assertEqual(v["verdict"], "clean")

    def test_classify_udp_fail_wireguard(self):
        flow = {"flow": "flow_w", "l4": "udp", "sport": 5000, "dport": 51820,
                "first_bytes_b64": ""}
        ndpi = [{"flow": "flow_w", "sport": 5000, "dport": 51820,
                 "classification": "WireGuard"}]
        v = mg.classify_udp_flow(flow, ndpi)
        self.assertEqual(v["verdict"], "fail")


class TestRunNdpiParser(unittest.TestCase):
    """Парсер вывода ndpiReader (mock subprocess)."""

    def test_run_ndpi_parses_numbered_proto(self):
        """ndpiReader 4.x формат: [proto: 91/TLS] — имя после номера/слэша."""
        sample = (
            "\n"
            "Detected protocols:\n"
            "  1\tTCP 192.0.2.10:443 <-> 192.0.2.20:50000 [proto: 91/TLS][Encrypted][Confidence: Match by port]\n"
            "  2\tTCP 192.0.2.10:443 <-> 192.0.2.21:50001 [proto: 89/WireGuard][Encrypted]\n"
        )
        with patch.object(mg, "_shutil_which", return_value="/usr/bin/ndpiReader"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=sample, returncode=0)
            flows = mg.run_ndpi(Path("/tmp/fake.pcap"))
        self.assertIsNotNone(flows)
        classes = {f["classification"] for f in flows}
        self.assertEqual(classes, {"TLS", "WireGuard"})
        # адреса обезличены (flow-теги, не сырые IP)
        for f in flows:
            self.assertTrue(f["flow"].startswith("flow_"))

    def test_run_ndpi_parses_legacy_proto(self):
        """Старый формат: [proto: TLS] и Detected protocol: QUIC."""
        sample = (
            "\n"
            "  1\t192.0.2.10:443      <->  192.0.2.20:50000   [proto: TLS]\n"
            "  2\t192.0.2.11:8443     <->  192.0.2.21:50001   Detected protocol: QUIC\n"
        )
        with patch.object(mg, "_shutil_which", return_value="/usr/bin/ndpiReader"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=sample, returncode=0)
            flows = mg.run_ndpi(Path("/tmp/fake.pcap"))
        self.assertIsNotNone(flows)
        self.assertEqual({f["classification"] for f in flows}, {"TLS", "QUIC"})

    def test_run_ndpi_none_when_binary_missing(self):
        with patch.object(mg, "_shutil_which", return_value=None):
            self.assertIsNone(mg.run_ndpi(Path("/tmp/fake.pcap")))


class TestRunTsharkParser(unittest.TestCase):
    """Парсер tshark -T json (mock subprocess)."""

    def test_run_tshark_streams(self):
        payload_hex = "16030100"  # первые байты TLS-записи
        sample = json.dumps([
            {"_source": {"layers": {
                "ip.src": ["192.0.2.10"], "tcp.srcport": ["5000"],
                "ip.dst": ["192.0.2.20"], "tcp.dstport": ["443"],
                "tcp.payload": [payload_hex],
            }}},
        ])
        with patch.object(mg, "_shutil_which", return_value="/usr/bin/tshark"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=sample, returncode=0)
            streams = mg.run_tshark_streams(Path("/tmp/fake.pcap"))
        self.assertIsNotNone(streams)
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]["l4"], "tcp")
        self.assertEqual(streams[0]["dport"], 443)
        import base64
        self.assertEqual(base64.b64decode(streams[0]["first_bytes_b64"]),
                         bytes.fromhex(payload_hex))


class TestRunMaskGateOffline(unittest.TestCase):
    """Полный offline-гейт на синтетических PCAP (инструменты выключены)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # все внешние инструменты «отсутствуют» → builtin-путь
        self._which_patch = patch.object(
            mg, "_shutil_which", side_effect=lambda n: None)
        self._which_patch.start()
        self._report_patch = patch.object(mg, "save_report_to_disk",
                                          return_value=None)
        self._report_patch.start()

    def tearDown(self):
        self._which_patch.stop()
        self._report_patch.stop()

    def _tls_pcap(self) -> Path:
        # Один полноценный клиент→сервер поток (все сегменты TLS) +
        # один сервер→клиент (ServerHello + данные)
        c2s = tls_stream_payloads()          # ch(2 кусками) + sh + app×3
        s2c = [tls_stream_payloads()[2]] + [tls_stream_payloads()[3]] * 2
        frames = []
        for s in c2s:
            frames.append(eth(ipv4_tcp_packet("192.0.2.10", "192.0.2.20",
                                              5000, 443, s)))
        for s in s2c:
            frames.append(eth(ipv4_tcp_packet("192.0.2.20", "192.0.2.10",
                                              443, 5000, s)))
        p = self.tmp / "tls.pcap"
        write_pcap(p, frames)
        return p

    def test_tls_pcap_pass(self):
        rep = mg.run_mask_gate(pcap_path=self._tls_pcap(), live=False,
                               port=443, save_report=False)
        self.assertEqual(rep["verdict"], "PASS")
        # оба направления (c2s + s2c) — чистые TLS-потоки
        self.assertEqual(rep["clean_flows"], 2)
        self.assertEqual(rep["fail_flows"], 0)

    def test_no_traffic_insufficient(self):
        p = self.tmp / "empty.pcap"
        write_pcap(p, [])
        rep = mg.run_mask_gate(pcap_path=p, live=False, port=443,
                               save_report=False)
        self.assertEqual(rep["verdict"], "INSUFFICIENT")

    def test_garbage_tcp_suspect(self):
        # мусорный TCP (не TLS) без nDPI → builtin → suspect → SUSPECT
        frames = [eth(ipv4_tcp_packet("192.0.2.10", "192.0.2.20", 5000, 443,
                                      b"\x01\x02\x03\x04" + b"\xaa" * 60))]
        p = self.tmp / "garbage.pcap"
        write_pcap(p, frames)
        rep = mg.run_mask_gate(pcap_path=p, live=False, port=443,
                               save_report=False)
        self.assertIn(rep["verdict"], ("SUSPECT", "FAIL"))
        self.assertGreaterEqual(rep["suspect_flows"], 1)

    def test_udp_quic_shape_clean(self):
        # QUIC long-header UDP без nDPI → builtin quick-shape → clean
        frames = [eth(ipv4_udp_packet("192.0.2.10", "192.0.2.20", 5000, 443,
                                      bytes([0xC3]) + b"\x00" * 31))
                  for _ in range(10)]
        p = self.tmp / "quic.pcap"
        write_pcap(p, frames)
        rep = mg.run_mask_gate(pcap_path=p, live=False, port=443,
                               save_report=False)
        self.assertEqual(rep["verdict"], "PASS")

    def test_live_without_tcpdump_skip(self):
        rep = mg.run_mask_gate(port=443, live=True, save_report=False)
        self.assertEqual(rep["verdict"], "SKIP")

    def test_offline_requires_pcap(self):
        rep = mg.run_mask_gate(live=False, save_report=False)
        self.assertFalse(rep["ok"])


class TestNdpiFailVerdict(unittest.TestCase):
    """Интеграционный путь: tshark-потоки + nDPI WireGuard → FAIL."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_wireguard_ndpi_fail(self):
        frames = [eth(ipv4_tcp_packet("192.0.2.10", "192.0.2.20", 5000, 443,
                                      b"\x01\x00\x00\x00" + b"\xaa" * 60))]
        p = self.tmp / "wg.pcap"
        write_pcap(p, frames)
        fake_streams = [{
            "flow": "flow_deadbeef", "l4": "tcp", "sport": 5000, "dport": 443,
            "first_bytes_b64": "AQAAAAAA",
        }]
        fake_ndpi = [{
            "flow": "flow_deadbeef", "sport": 5000, "dport": 443,
            "classification": "WireGuard",
        }]
        with patch.object(mg, "_shutil_which",
                          side_effect=lambda n: {"tshark": "/usr/bin/tshark",
                                                 "ndpiReader": "/usr/bin/ndpiReader",
                                                 "tcpdump": None}.get(n)), \
             patch.object(mg, "run_tshark_streams", return_value=fake_streams), \
             patch.object(mg, "run_ndpi", return_value=fake_ndpi), \
             patch.object(mg, "save_report_to_disk", return_value=None):
            rep = mg.run_mask_gate(pcap_path=p, live=False, port=443,
                                   save_report=False)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertEqual(rep["fail_flows"], 1)


class TestStateHelpers(unittest.TestCase):
    def test_get_xray_port_from_state(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state.json"
            p.write_text(json.dumps({"PARAM_PORT": 8443}), encoding="utf-8")
            self.assertEqual(mg.get_xray_port_from_state(p), 8443)
            p.write_text(json.dumps({"xray": {"port": 443}}), encoding="utf-8")
            self.assertEqual(mg.get_xray_port_from_state(p), 443)
            p.write_text(json.dumps({"other": 1}), encoding="utf-8")
            self.assertIsNone(mg.get_xray_port_from_state(p))
            self.assertIsNone(mg.get_xray_port_from_state(Path(td) / "no.json"))

    def test_get_xray_port_from_config(self):
        """Mode B chain: state.json порта не содержит — порт живёт
        в /etc/xray/config.json. Воспроизводит прод-ноды: vless на 443
        + dokodemo-door на loopback (их брать нельзя)."""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            # прод-формат: vless внешний + два dokodemo-door на 127.0.0.1
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "vless", "port": 443, "listen": "::"},
                {"protocol": "dokodemo-door", "port": 10085,
                 "listen": "127.0.0.1"},
                {"protocol": "dokodemo-door", "port": 10811,
                 "listen": "127.0.0.1"},
            ]}), encoding="utf-8")
            self.assertEqual(mg.get_xray_port_from_config(cfg), 443)
            # vless не первым: dokodemo-door скипается, vless всё равно найден
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "dokodemo-door", "port": 10085,
                 "listen": "127.0.0.1"},
                {"protocol": "vless", "port": 8443},
            ]}), encoding="utf-8")
            self.assertEqual(mg.get_xray_port_from_config(cfg), 8443)
            # порт-диапазон строкой — не берём
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "vless", "port": "1000-2000"},
            ]}), encoding="utf-8")
            self.assertIsNone(mg.get_xray_port_from_config(cfg))
            # не-vless внешний inbound — фолбэк
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "trojan", "port": "9443"},
            ]}), encoding="utf-8")
            self.assertEqual(mg.get_xray_port_from_config(cfg), 9443)
            # всё служебное/локальное → None; мусор/нет файла → None
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "socks", "port": 1080, "listen": "127.0.0.1"},
            ]}), encoding="utf-8")
            self.assertIsNone(mg.get_xray_port_from_config(cfg))
            cfg.write_text("{not json", encoding="utf-8")
            self.assertIsNone(mg.get_xray_port_from_config(cfg))
            self.assertIsNone(
                mg.get_xray_port_from_config(Path(td) / "no.json"))

    def test_get_xray_port_composite(self):
        """state.json приоритетнее; пустой state.json → конфиг Xray;
        нигде ничего → None (TUI предложит дефолт 443)."""
        with tempfile.TemporaryDirectory() as td:
            st = Path(td) / "state.json"
            cfg = Path(td) / "config.json"
            st.write_text(json.dumps({"PARAM_PORT": 2053}), encoding="utf-8")
            cfg.write_text(json.dumps({"inbounds": [
                {"protocol": "vless", "port": 443}]}), encoding="utf-8")
            with patch.object(mg, "STATE_FILE", st), \
                    patch.object(mg, "XRAY_CONFIG", cfg):
                self.assertEqual(mg.get_xray_port(), 2053)  # state.json выиграл
                st.write_text(json.dumps({"awg_installed": True}),
                              encoding="utf-8")  # Mode B: порта нет
                self.assertEqual(mg.get_xray_port(), 443)  # → конфиг Xray
                cfg.write_text("{}", encoding="utf-8")
                self.assertIsNone(mg.get_xray_port())      # нигде нет

    def test_get_server_ip_from_state(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state.json"
            p.write_text(json.dumps({"PARAM_SERVER_IP": "192.0.2.1"}),
                         encoding="utf-8")
            self.assertEqual(mg.get_server_ip_from_state(p), "192.0.2.1")
            self.assertIsNone(mg.get_server_ip_from_state(Path(td) / "no.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
