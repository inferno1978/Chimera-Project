#!/usr/bin/env python3
"""
tests/test_dpi_gate.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dpi_gate.py.

Покрывает:
  1. extract_features — бит-в-бит совместимость с эталоном AIVPN
     (features.py, REFERENCE_FEATURES) и краевые случаи
  2. f32/shannon_entropy/percentile — арифметика
  3. load_model / model_is_usable / score_window — GBDT-инференс
     на hand-crafted модели
  4. evaluate_udp_packets — окна, агрегированный вердикт
  5. parse_pcap / udp_flows_from_pcap — свой PCAP-парсер (генерируем
     синтетический PCAP в tmp, адреса — TEST-NET по политике leak_guard)
  6. train_synthetic_baseline — обучение/сохранение baseline
  7. evaluate_pcap — полный прогон с моделью
"""
from __future__ import annotations

import json
import math
import shutil
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import dpi_gate as dg


# ── Генератор синтетического PCAP (тестовые адреса — TEST-NET-1/3) ───────────
def ipv4_udp_packet(src: str, dst: str, sport: int, dport: int,
                    payload: bytes) -> bytes:
    def ip_bytes(s):
        return bytes(int(x) for x in s.split("."))
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = bytearray(struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0x1234, 0, 64, 17, 0,
        ip_bytes(src), ip_bytes(dst)))
    checksum = 0
    ip[10:12] = struct.pack(">H", checksum)
    return bytes(ip) + udp


def eth_frame(ip: bytes) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
            + b"\x08\x00" + ip)


def write_pcap(path: Path, packets: list, dlt: int = 1) -> None:
    """Классический PCAP, little-endian, usec."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, dlt))
        ts = 1_700_000_000
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", ts, i * 1000, len(pkt), len(pkt)))
            f.write(pkt)


class TestFeatureArithmetic(unittest.TestCase):
    """Арифметика признаков — эталон AIVPN."""

    def test_reference_features_match_aivpn(self):
        """23 признака из 6 пакетов AIVPN — отклонение ≤ 1e-3 относительное."""
        ok, worst = dg._selftest_features()
        self.assertTrue(ok, f"отклонение {worst} > 1e-3 от эталона AIVPN")
        self.assertLessEqual(worst, 1e-3)

    def test_empty_window_zeroes(self):
        feats = dg.extract_features([])
        self.assertEqual(feats, [0.0] * dg.N_FEATURES)

    def test_partial_window_count(self):
        w = [dg.stun_pkt(56, 76) for _ in range(5)]
        feats = dg.extract_features(w)
        self.assertEqual(feats[0], dg.f32(5.0))

    def test_f32_rounding(self):
        self.assertEqual(dg.f32(0.1), struct.unpack("<f", struct.pack("<f", 0.1))[0])
        self.assertEqual(dg.f32(1e50), math.inf)

    def test_shannon_entropy(self):
        self.assertEqual(dg.shannon_entropy(b""), 0.0)
        # равномерный байт: энтропия 0 для одного символа
        self.assertEqual(dg.shannon_entropy(b"\x00" * 16), 0.0)
        # два равных символа: 1 бит
        self.assertAlmostEqual(dg.shannon_entropy(b"\x00\x01"), 1.0, places=6)

    def test_percentile_round_half_even(self):
        # Семантика AIVPN: nearest-rank по round_half_even индексу.
        # [1,2,3,4], q=0.5: idx = rhe(0.5*3)=rhe(1.5)=2 → элемент 3.0
        self.assertEqual(dg.percentile([1, 2, 3, 4], 0.5), 3.0)
        # [1,2,3,4,5], q=0.5: idx = rhe(2.0)=2 → элемент 3.0
        self.assertEqual(dg.percentile([1, 2, 3, 4, 5], 0.5), 3.0)
        self.assertEqual(dg.percentile([], 0.5), 0.0)
        self.assertEqual(dg.percentile([7], 0.1), 7.0)

    def test_header_flags_quic_short_normalization(self):
        """Schema v2: QUIC short header (0x40-0x7F) → byte0 нормализуется в 0x40."""
        pkt = bytes([0x41]) + b"\x00" * 31   # 0x41 & 0xC0 == 0x40
        h = dg.header_flags(pkt)
        self.assertEqual(h["byte0"], 0x40)
        pkt2 = bytes([0x80]) + b"\x00" * 31  # не short header
        h2 = dg.header_flags(pkt2)
        self.assertEqual(h2["byte0"], 0x80)

    def test_header_flags_stun_detection(self):
        pkt = dg.stun_pkt(56, 76)
        h = dg.header_flags(pkt)
        self.assertEqual(h["stun_type"], 1.0)
        self.assertEqual(h["magic_ok"], 1.0)
        self.assertEqual(h["stun_lenok"], 1.0)


def _tiny_model() -> dict:
    """Hand-crafted 1-деревная модель для инференс-тестов.

    Дерево по stun_type_frac (признак 19): STUN-окно (frac=1.0 > 0.5)
    → правая ветка → benign; сырой UDP (frac=0.0 <= 0.5) → левая → tunnel.
    """
    return {
        "schema_version": dg.GATE_MODEL_SCHEMA,
        "feature_schema_version": dg.FEATURE_SCHEMA_VERSION,
        "window": dg.WINDOW,
        "classes": ["benign", "tunnel"],
        "base_score": 0.0,
        "threshold": 0.5,
        "trees": [
            {"nodes": [
                {"feature": 19, "threshold": 0.5, "left": 1, "right": 2, "value": 0.0},
                {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": 3.0},
                {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": -3.0},
            ]},
        ],
    }


class TestGbdtInference(unittest.TestCase):
    """GBDT-инференс на JSON-модели."""

    def test_load_model_rejects_garbage(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.json"
            p.write_text("not json", encoding="utf-8")
            self.assertIsNone(dg.load_model(p))
            p.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
            self.assertIsNone(dg.load_model(p))
            self.assertIsNone(dg.load_model(Path(td) / "missing.json"))

    def test_load_model_accepts_valid(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.json"
            p.write_text(json.dumps(_tiny_model()), encoding="utf-8")
            m = dg.load_model(p)
            self.assertIsNotNone(m)
            self.assertTrue(dg.model_is_usable(m))

    def test_model_is_usable(self):
        self.assertFalse(dg.model_is_usable(None))
        bad = _tiny_model()
        bad["classes"] = ["only_one"]
        self.assertFalse(dg.model_is_usable(bad))

    def test_score_window_stun_benign(self):
        """Окно STUN: stun_type_frac=1.0 → левая ветка → benign."""
        model = _tiny_model()
        win = [dg.stun_pkt(56, 76) for _ in range(dg.WINDOW)]
        res = dg.score_window(model, dg.extract_features(win))
        self.assertEqual(res["verdict"], "benign")
        self.assertLess(res["p_tunnel"], 0.5)

    def test_score_window_rnd_tunnel(self):
        """Окно случайного UDP: stun_type_frac=0 → правая ветка → tunnel."""
        model = _tiny_model()
        win = [dg.rnd_pkt(1200, k) for k in range(dg.WINDOW)]
        res = dg.score_window(model, dg.extract_features(win))
        self.assertEqual(res["verdict"], "tunnel")
        self.assertGreater(res["p_tunnel"], 0.5)

    def test_score_window_bad_len(self):
        with self.assertRaises(ValueError):
            dg.score_window(_tiny_model(), [0.0] * 5)

    def test_evaluate_udp_packets_insufficient(self):
        model = _tiny_model()
        res = dg.evaluate_udp_packets([b"x" * 10], model)
        self.assertEqual(res["verdict"], "insufficient")
        self.assertEqual(res["windows"], 0)

    def test_evaluate_udp_packets_mixed(self):
        """48 STUN-пакетов: 2 полных окна (stride 16), оба benign."""
        model = _tiny_model()
        pkts = [dg.stun_pkt(56, 76) for _ in range(48)]
        res = dg.evaluate_udp_packets(pkts, model, stride=16)
        self.assertEqual(res["windows"], 2)
        self.assertEqual(res["verdict"], "benign")


class TestPcapParser(unittest.TestCase):
    """Свой PCAP-парсер."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_parse_ethernet_pcap(self):
        pkts = [
            eth_frame(ipv4_udp_packet("192.0.2.10", "192.0.2.20", 11111, 443,
                                      dg.stun_pkt(56, 76))),
            eth_frame(ipv4_udp_packet("192.0.2.20", "192.0.2.10", 443, 11111,
                                      dg.stun_pkt(56, 76))),
        ]
        p = self.tmp / "eth.pcap"
        write_pcap(p, pkts, dlt=1)
        records = dg.parse_pcap(p)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["dlt"], 1)

    def test_parse_raw_pcap(self):
        pkts = [ipv4_udp_packet("198.51.100.5", "198.51.100.6", 53, 53,
                                b"\x00\x01\x00\x00" + b"\x00" * 8)]
        p = self.tmp / "raw.pcap"
        write_pcap(p, pkts, dlt=101)
        records = dg.parse_pcap(p)
        self.assertEqual(len(records), 1)

    def test_parse_big_endian_pcap(self):
        # BE-файл: магия A1 B2 C3 D4 (число 0xA1B2C3D4 в BE-паке)
        with open(self.tmp / "be.pcap", "wb") as f:
            f.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            pkt = eth_frame(ipv4_udp_packet("203.0.113.1", "203.0.113.2",
                                            1000, 2000, b"hi"))
            f.write(struct.pack(">IIII", 1, 0, len(pkt), len(pkt)))
            f.write(pkt)
        records = dg.parse_pcap(self.tmp / "be.pcap")
        self.assertEqual(len(records), 1)

    def test_parse_rejects_garbage(self):
        p = self.tmp / "garbage.pcap"
        p.write_bytes(b"NOTAPCAP" + b"\x00" * 40)
        with self.assertRaises(ValueError):
            dg.parse_pcap(p)

    def test_udp_flows_from_pcap_port_filter(self):
        """Порт-фильтр: остаётся только поток на порт 443."""
        pkts = [
            eth_frame(ipv4_udp_packet("192.0.2.10", "192.0.2.20", 11111, 443,
                                      dg.stun_pkt(56, 76))),
            eth_frame(ipv4_udp_packet("192.0.2.30", "192.0.2.40", 22222, 8443,
                                      dg.stun_pkt(20, 40))),
        ] * 3
        p = self.tmp / "flows.pcap"
        write_pcap(p, pkts, dlt=1)
        flows = dg.udp_flows_from_pcap(p, port=443)
        self.assertEqual(len(flows), 1)
        key = next(iter(flows))
        self.assertEqual(key[3], 443)
        self.assertEqual(len(flows[key]), 3)
        # без фильтра — оба потока
        flows_all = dg.udp_flows_from_pcap(p)
        self.assertEqual(len(flows_all), 2)

    def test_udp_flows_ignores_tcp(self):
        tcp_ip = bytearray(struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
            bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])))
        p = self.tmp / "tcp.pcap"
        write_pcap(p, [eth_frame(bytes(tcp_ip))], dlt=1)
        flows = dg.udp_flows_from_pcap(p)
        self.assertEqual(len(flows), 0)

    def test_udp_flows_linux_sll(self):
        """DLT 113 (tcpdump -i any, старый SLL): ethertype на offset 14."""
        ip = ipv4_udp_packet("192.0.2.10", "192.0.2.20", 5000, 443,
                             dg.stun_pkt(56, 76))
        sll = (struct.pack(">HHH", 0, 1, 6) + b"\x00" * 8
               + struct.pack(">H", 0x0800) + ip)
        p = self.tmp / "sll.pcap"
        write_pcap(p, [sll], dlt=113)
        flows = dg.udp_flows_from_pcap(p)
        self.assertEqual(len(flows), 1)
        key = next(iter(flows))
        self.assertEqual(key[3], 443)

    def test_udp_flows_linux_sll2(self):
        """DLT 276 (tcpdump -i any, SLL2): protocol на offset 0 (ndpiReader
        4.x этот DLT не читает — наш парсер должен)."""
        ip = ipv4_udp_packet("198.51.100.10", "198.51.100.20", 5000, 8443,
                             dg.stun_pkt(20, 40))
        sll2 = (struct.pack(">HH", 0x0800, 0) + struct.pack(">I", 2)
                + struct.pack(">H", 1) + bytes([0, 6]) + b"\x00" * 8 + ip)
        p = self.tmp / "sll2.pcap"
        write_pcap(p, [sll2], dlt=276)
        flows = dg.udp_flows_from_pcap(p)
        self.assertEqual(len(flows), 1)


class TestEvaluatePcap(unittest.TestCase):
    """Полный прогон evaluate_pcap (модель в tmp)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.model_path = self.tmp / "model.json"
        self.model_path.write_text(json.dumps(_tiny_model()), encoding="utf-8")
        # отчёты — тоже в tmp
        self.report_dir = self.tmp / "reports"

    def _make_pcap(self, tunnel: bool) -> Path:
        payload_maker = (lambda i: dg.rnd_pkt(1200, i)) if tunnel else (
            lambda i: dg.stun_pkt(56, 76))
        pkts = [
            eth_frame(ipv4_udp_packet("192.0.2.10", "192.0.2.20", 5000, 443,
                                      payload_maker(i)))
            for i in range(48)
        ]
        p = self.tmp / ("tunnel.pcap" if tunnel else "benign.pcap")
        write_pcap(p, pkts, dlt=1)
        return p

    def test_evaluate_pcap_no_model(self):
        with patch.object(dg, "MODEL_PATH", self.tmp / "absent.json"):
            res = dg.evaluate_pcap(self._make_pcap(False))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "model_unavailable")

    def test_evaluate_pcap_benign(self):
        model = dg.load_model(self.model_path)
        res = dg.evaluate_pcap(self._make_pcap(False), model=model)
        self.assertTrue(res["ok"])
        self.assertEqual(res["overall"], "benign")
        self.assertEqual(res["flows"], 1)
        self.assertEqual(res["benign_flows"], 1)
        # в отчёте нет IP-адресов (политика обезличивания)
        raw = json.dumps(res)
        self.assertNotIn("192.0.2.10", raw)
        self.assertTrue(res["flow_reports"][0]["flow"].startswith("flow_"))

    def test_evaluate_pcap_tunnel(self):
        model = dg.load_model(self.model_path)
        res = dg.evaluate_pcap(self._make_pcap(True), model=model)
        self.assertTrue(res["ok"])
        self.assertEqual(res["overall"], "tunnel")
        self.assertEqual(res["tunnel_flows"], 1)

    def test_save_and_latest_report(self):
        model = dg.load_model(self.model_path)
        res = dg.evaluate_pcap(self._make_pcap(False), model=model)
        p = dg.save_report(res, directory=self.report_dir)
        self.assertIsNotNone(p)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        latest = dg.latest_report(directory=self.report_dir, max_age_secs=3600)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["overall"], "benign")
        # устаревший отчёт не находится
        old = dg.latest_report(directory=self.report_dir, max_age_secs=-1)
        self.assertIsNone(old)


class TestSyntheticBaseline(unittest.TestCase):
    """Baseline-обучение без зависимостей."""

    def test_train_synthetic_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "model.json"
            m = dg.train_synthetic_baseline(out_path=out)
            self.assertIsNotNone(m)
            self.assertEqual(m["provenance"], "synthetic_baseline")
            loaded = dg.load_model(out)
            self.assertTrue(dg.model_is_usable(loaded))
            # STUN-окно (низкая дисперсия размеров + stun_frac=1) → benign
            r1 = dg.evaluate_udp_packets(
                [dg.stun_pkt(56, 76) for _ in range(dg.WINDOW)], loaded,
                stride=dg.WINDOW)
            # RND-окно с вариативными размерами (высокая дисперсия,
            # stun_frac=0) → tunnel
            rnd_win = [dg.rnd_pkt(800 + k * 20, k) for k in range(dg.WINDOW)]
            r2 = dg.evaluate_udp_packets(rnd_win, loaded, stride=dg.WINDOW)
            self.assertEqual(r1["verdict"], "benign", f"p={r1['p_tunnel_max']}")
            self.assertEqual(r2["verdict"], "tunnel", f"p={r2['p_tunnel_max']}")
            # права 0600
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
