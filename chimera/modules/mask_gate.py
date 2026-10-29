"""
chimera/modules/mask_gate.py
───────────────────────────────────────────────────────────────────────────────
Mask Gate — гейт маскировки Химеры (идея AIVPN make mask-gate, адаптация
под VLESS/REALITY/xHTTP по TCP и Hysteria2 по UDP).

  • Захват трафика: tcpdump (live, порт Xray) или готовый PCAP (offline)
  • Классификация потоков: nDPI (ndpiReader) → вердикт «как выглядит
    трафик снаружи»; tshark → структурные проверки TLS
  • Builtin-фолбэк: свой PCAP-парсер + эвристики TLS-записей
    (без tshark/nDPI — работает везде, включая CI-контейнер)
  • Вердикт гейта: PASS (трафик выглядит как честный TLS к приманке) /
    FAIL (потоки классифицируются как VPN/Unknown-аномалии) /
    SKIP (инструменты недоступны)
  • Отчёт JSON без адресов и payload — только порты, классы, счётчики
    (политика обезличивания, scripts/leak_guard.py)

Критерий PASS для Chimera REALITY/xHTTP: каждый поток на порт Xray
классифицируется nDPI как TLS (это и есть цель — «быть настоящим TLS»),
а не как WireGuard/OpenVPN/Unknown. Для Hysteria2 (UDP): QUIC/STUN.

Точка входа из _core.py:
    from chimera.modules.mask_gate import do_manage_mask_gate
CLI (main.py):
    --mask-gate [port]        — live-захват на порт Xray и вердикт
    --mask-gate-pcap <file>   — offline-оценка готового PCAP
CI: tests/test_mask_gate.py гоняет логику на синтетических PCAP.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Реиспользуем PCAP-парсер и логгер из dpi_gate
from chimera.modules.dpi_gate import (
    parse_pcap, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_LINUX_SLL2,
    _ipv4_from_sll, _log,
)

# ── Пути и константы ──────────────────────────────────────────────────────────
_LIB_DIR    = Path("/var/lib/xray-installer")
STATE_FILE  = _LIB_DIR / "state.json"
XRAY_CONFIG = Path("/etc/xray/config.json")   # реальный порт VLESS живёт тут
REPORT_DIR  = _LIB_DIR / "mask_gate"
CAPTURE_DIR = Path("/tmp/chimera_mask_gate")

# Локальные/служебные inbound Xray: не суть маскировки, скипаем
_SKIP_PROTOCOLS = {"dokodemo-door", "dns", "blackhole", "socks", "http"}
_LOOPBACK_LISTENS = {"127.0.0.1", "localhost", "::1"}

TCPDUMP_BIN = "tcpdump"
TSHARK_BIN  = "tshark"
NDPI_BIN    = "ndpiReader"
CAPTURE_SECS_DEFAULT = 12          # длительность live-захвата
MAX_PCAP_BYTES = 64 * 1024 * 1024  # защита от гигантских захватов

# Классы nDPI, считающиеся «чистыми» для TCP/TLS-маскировки Химеры
NDPI_CLEAN_TCP = {"TLS", "TLSv1", "TLSv1.2", "TLSv1.3", "HTTP",
                  "HTTP2", "HTTP3", "QUIC", "SSL", "HTTPS"}
# Классы nDPI, означающие провал маскировки
NDPI_FAIL_TCP = {"WireGuard", "OpenVPN", "OpenVPN-over-WebSocket-done",
                 "CiscoVPN", "PPTP", "L2TP", "SSTP", "SoftetherVPN",
                 "Tor", "Tor-related", "SSH", "Socks", "SOCKS"}
# UDP: цель Hysteria2 — выглядеть как QUIC/STUN
NDPI_CLEAN_UDP = {"QUIC", "STUN", "DTLS", "HTTP3", "MDNS"}
NDPI_FAIL_UDP = {"WireGuard", "OpenVPN", "L2TP", "IPsec", "IKEv2"}

# Builtin TLS-эвристики (фолбэк без tshark): content-type первой записи
TLS_CONTENT_TYPES = {0x14: "change_cipher_spec", 0x15: "alert",
                     0x16: "handshake", 0x17: "application_data",
                     0x18: "heartbeat"}
TLS_HANDSHAKE_TYPES = {0x01: "client_hello", 0x02: "server_hello",
                       0x0B: "certificate", 0x0F: "cert_verify",
                       0x14: "finished"}


def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
                    CYAN='\033[36m', BLUE='\033[34m', BOLD='\033[1m',
                    DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'NC')}


_C = _detect_colors()


def _shutil_which(name: str) -> Optional[str]:
    return shutil.which(name)


# ══════════════════════════════════════════════════════════════════════════════
# 1. TCP-ПОТОКИ ИЗ PCAP (свой парсер — работает без tshark)
# ══════════════════════════════════════════════════════════════════════════════
def _ipv4_from_link(dlt: int, link: bytes) -> Optional[bytes]:
    if dlt == DLT_EN10MB:
        if len(link) < 14:
            return None
        ethertype = (link[12] << 8) | link[13]
        return link[14:] if ethertype == 0x0800 else None
    if dlt == DLT_RAW:
        return link if link and link[0] >> 4 == 4 else None
    if dlt in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        return _ipv4_from_sll(link, dlt)
    return None


def tcp_streams_from_pcap(path: Path, port: Optional[int] = None) -> dict:
    """TCP-потоки: {(src_ip, sport, dst_ip, dport, direction_idx): [segments]}.

    direction 0 = клиент→сервер (первый пакет потока), 1 = сервер→клиент.
    Сегменты — сырые TCP payload (без заголовка), порядок по ts.
    """
    records = parse_pcap(path)
    # Первый шаг: собрать пакеты по 4-tuple (без направления)
    tuples = {}
    order = []
    for rec in records:
        ip = _ipv4_from_link(rec["dlt"], rec["data"])
        if ip is None or len(ip) < 20 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl + 4:
            continue
        frag = ((ip[6] & 0x1F) << 8) | ip[7]
        if frag & 0x1FFF:
            continue  # не первый фрагмент — пропускаем (редкий случай)
        tcp = ip[ihl:]
        sport = (tcp[0] << 8) | tcp[1]
        dport = (tcp[2] << 8) | tcp[3]
        doff = (tcp[12] >> 4) * 4
        if doff < 20 or len(tcp) < doff:
            continue
        payload = tcp[doff:]
        src_ip = ".".join(str(b) for b in ip[12:16])
        dst_ip = ".".join(str(b) for b in ip[16:20])
        key = (src_ip, sport, dst_ip, dport)
        if key not in tuples:
            order.append(key)
            tuples[key] = []
        if payload:
            tuples[key].append(payload)
    if port is not None:
        tuples = {k: v for k, v in tuples.items()
                  if k[1] == port or k[3] == port}
        order = [k for k in order if k in tuples]
    return {"tuples": tuples, "order": order}


def udp_flows_mask_gate(path: Path, port: Optional[int] = None) -> dict:
    """UDP-потоки для Hysteria2-анализа (реиспользует dpi_gate-парсер)."""
    from chimera.modules.dpi_gate import udp_flows_from_pcap
    return udp_flows_from_pcap(path, port=port)


# ══════════════════════════════════════════════════════════════════════════════
# 2. BUILTIN-ЭВРИСТИКИ TLS (без tshark/nDPI)
# ══════════════════════════════════════════════════════════════════════════════
def _parse_tls_records(data: bytes, limit: int = 16) -> list:
    """Разбирает поток на TLS-записи → [{type, version, length}]."""
    out = []
    off = 0
    while off + 5 <= len(data) and len(out) < limit:
        ctype = data[off]
        version = (data[off + 1] << 8) | data[off + 2]
        length = (data[off + 3] << 8) | data[off + 4]
        if ctype not in TLS_CONTENT_TYPES:
            return out + [{"type": -1, "version": -1, "length": 0}]
        out.append({"type": ctype, "version": version, "length": length})
        if length == 0:
            break
        off += 5 + length
    return out


def tls_heuristics_verdict(segments: list) -> dict:
    """Эвристический вердикт TCP-потока: похож ли на честный TLS.

    Проверки (что видит DPI-коробка):
      1. Первый байт потока — валидный TLS content-type
      2. Version первой записи — 0x0301..0x0304
      3. Есть handshake (0x16) в первых записях
      4. ClientHello → ServerHello/Certificate последовательность
      5. Размеры записей в TLS-норме (≤ 16 KiB + 5)
    """
    if not segments:
        return {"verdict": "insufficient", "checks": {}}
    stream = b"".join(segments[:32])[:65536]
    records = _parse_tls_records(stream)
    checks = {}
    first = records[0] if records else {}
    checks["first_is_tls"] = first.get("type") in (0x14, 0x15, 0x16, 0x17)
    checks["version_ok"] = first.get("version", -1) in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304)
    has_hs = any(r["type"] == 0x16 for r in records)
    checks["has_handshake"] = has_hs
    # ClientHello (первая handshake-запись, байт 5)
    ch = None
    if has_hs and len(stream) > 6:
        for r_i, r in enumerate(records):
            if r["type"] == 0x16:
                # позиции: 5 байт заголовка записи, затем handshake-заголовок
                off = 5
                while off + 4 <= len(stream):
                    if stream[off] in TLS_HANDSHAKE_TYPES:
                        ch = stream[off]
                        break
                    break
                break
    checks["client_hello_seen"] = ch == 0x01 or ch is None  # None = не успели
    rec_lens = [r["length"] for r in records if r["type"] >= 0]
    checks["record_sizes_ok"] = all(0 <= l <= 16640 + 5 for l in rec_lens)
    bad_records = sum(1 for r in records if r["type"] == -1)
    checks["no_garbage_records"] = bad_records == 0
    passed = (checks["first_is_tls"] and checks["version_ok"]
              and checks["no_garbage_records"])
    verdict = "clean_tls" if passed else "suspect"
    return {"verdict": verdict, "checks": checks,
            "records": len(records)}


# ══════════════════════════════════════════════════════════════════════════════
# 3. ВНЕШНИЕ КЛАССИФИКАТОРЫ: ndpiReader и tshark
# ══════════════════════════════════════════════════════════════════════════════
def run_ndpi(pcap_path: Path, ndpi_bin: Optional[str] = None) -> Optional[list]:
    """ndpiReader -i pcap → [{flow, proto, classification}] или None.

    Парсит табличный вывод ndpiReader (колонки: ID, Protocol, Flow duration,
    ...). Возвращает только обезличенные классы + хэш потока.
    """
    ndpi = ndpi_bin or _shutil_which(NDPI_BIN)
    if not ndpi:
        return None
    try:
        proc = subprocess.run(
            [ndpi, "-i", str(pcap_path), "-v", "2"],
            capture_output=True, text=True, timeout=90)
        out = proc.stdout or ""
    except Exception:
        return None
    flows = []
    # Формат ndpiReader 4.x -v 2:
    #   "  1  TCP 192.0.2.10:55993 <-> 192.0.2.20:443 [proto: 91/TLS]..."
    #   протокол = номер/имя; берём ИМЯ после слэша. Fallback — старый
    #   формат "[proto: TLS]" и "Detected protocol: TLS".
    for line in out.splitlines():
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*<->\s*"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if not m:
            continue
        pm = (re.search(r"\[proto:\s*\d+/([A-Za-z0-9_.+-]+)\s*\]", line)
              or re.search(r"\[proto:\s*([A-Za-z0-9_.+-]+)\s*\]", line)
              or re.search(r"Detected protocol:\s*([A-Za-z0-9_.+-]+)", line,
                           re.IGNORECASE))
        if not pm:
            continue
        src, sport = m.group(1), int(m.group(2))
        dst, dport = m.group(3), int(m.group(4))
        proto = pm.group(1).strip()
        from chimera.modules.dpi_gate import _flow_tag
        flows.append({
            "flow": _flow_tag((src, sport, dst, dport)),
            "sport": sport, "dport": dport,
            "classification": proto,
        })
    return flows


def run_tshark_streams(pcap_path: Path, tshark_bin: Optional[str] = None) -> Optional[list]:
    """tshark -T json → потоки с TCP payload (для структурной проверки).

    Возвращает [{flow, sport, dport, first_bytes_b64}] — только первые
    байты каждого направления (для TLS-эвристик), адреса → в хэш-тег.
    """
    tshark = tshark_bin or _shutil_which(TSHARK_BIN)
    if not tshark:
        return None
    try:
        proc = subprocess.run(
            [tshark, "-r", str(pcap_path), "-T", "json",
             "-e", "ip.src", "-e", "tcp.srcport",
             "-e", "ip.dst", "-e", "tcp.dstport",
             "-e", "tcp.payload", "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "udp.payload"],
            capture_output=True, text=True, timeout=120)
        raw = proc.stdout or ""
        data = json.loads(raw) if raw.strip() else None
    except Exception:
        return None
    if not data:
        return []
    import base64
    from chimera.modules.dpi_gate import _flow_tag
    streams = {}
    for pkt in data:
        s = pkt.get("_source", {}).get("layers", {})
        ip_src = (s.get("ip.src") or [""])[0] if s.get("ip.src") else ""
        ip_dst = (s.get("ip.dst") or [""])[0] if s.get("ip.dst") else ""
        tcp_s = s.get("tcp.srcport")
        tcp_d = s.get("tcp.dstport")
        udp_s = s.get("udp.srcport")
        udp_d = s.get("udp.dstport")
        payload = s.get("tcp.payload") or s.get("udp.payload") or []
        payload_hex = payload[0] if payload else ""
        if tcp_s and tcp_d:
            key = (ip_src, int(tcp_s[0]), ip_dst, int(tcp_d[0]), "tcp")
        elif udp_s and udp_d:
            key = (ip_src, int(udp_s[0]), ip_dst, int(udp_d[0]), "udp")
        else:
            continue
        if payload_hex:
            entry = streams.setdefault(key, {"bytes": bytearray()})
            try:
                entry["bytes"].extend(bytes.fromhex(payload_hex.replace(":", "")))
            except ValueError:
                continue
    out = []
    for key, entry in streams.items():
        ip_src, sport, ip_dst, dport, l4 = key
        first = bytes(entry["bytes"][:64])
        out.append({
            "flow": _flow_tag((ip_src, sport, ip_dst, dport)),
            "l4": l4, "sport": sport, "dport": dport,
            "first_bytes_b64": __import__("base64").b64encode(first).decode(),
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
# 4. ГЛАВНЫЙ ПРОГОН
# ══════════════════════════════════════════════════════════════════════════════
def classify_tcp_flow(l4_flow: dict, ndpi_flows: Optional[list]) -> dict:
    """Вердикт одного TCP-потока: nDPI-класс + builtin-эвристики."""
    verdict = {"flow": l4_flow["flow"], "l4": "tcp"}
    ndpi_class = None
    if ndpi_flows:
        for nf in ndpi_flows:
            if nf["flow"] == l4_flow["flow"]:
                ndpi_class = nf["classification"]
                break
    verdict["ndpi"] = ndpi_class or "unavailable"
    if ndpi_class:
        if ndpi_class in NDPI_FAIL_TCP:
            verdict["verdict"] = "fail"
            verdict["reason"] = f"nDPI: {ndpi_class}"
            return verdict
        if ndpi_class in NDPI_CLEAN_TCP:
            verdict["verdict"] = "clean"
            verdict["reason"] = f"nDPI: {ndpi_class}"
            return verdict
        # Unknown/другое → подозрение, но не фейл (DPI-коробки тоже
        # не всё знают; окончательный вердикт по совокупности)
        verdict["verdict"] = "suspect"
        verdict["reason"] = f"nDPI: {ndpi_class} (не в clean-списке)"
        return verdict
    # Фолбэк на builtin TLS-эвристики
    import base64
    first = base64.b64decode(l4_flow.get("first_bytes_b64", ""))
    # Восстанавливаем сегменты приблизительно: builtin смотрит первые байты
    h = tls_heuristics_verdict([first] if first else [])
    verdict["verdict"] = h["verdict"]
    verdict["reason"] = "builtin TLS heuristics"
    verdict["checks"] = h.get("checks", {})
    return verdict


def run_mask_gate(pcap_path: Optional[Path] = None,
                  port: Optional[int] = None,
                  capture_secs: int = CAPTURE_SECS_DEFAULT,
                  live: bool = True,
                  save_report: bool = True) -> dict:
    """Полный гейт. Live-режим: tcpdump → PCAP; затем единый анализ.

    Возвращает отчёт: {ok, mode, tools, flows, verdict, reasons...}.
    verdict: PASS | FAIL | SKIP | INSUFFICIENT.
    """
    tools = {
        "tcpdump": bool(_shutil_which(TCPDUMP_BIN)),
        "tshark": bool(_shutil_which(TSHARK_BIN)),
        "ndpiReader": bool(_shutil_which(NDPI_BIN)),
    }
    mode = "live" if live else "offline"
    report = {
        "ok": True, "mode": mode, "ts": datetime.now().isoformat(timespec="seconds"),
        "tools": tools, "port": port, "verdict": "INSUFFICIENT",
        "flows": 0, "fail_flows": 0, "suspect_flows": 0,
        "clean_flows": 0, "flow_verdicts": [], "reasons": [],
    }

    # ── live-захват ──
    pcap = pcap_path
    if live:
        if not tools["tcpdump"]:
            report["verdict"] = "SKIP"
            report["reasons"].append("tcpdump не найден — live-захват невозможен")
            if save_report:
                save_report_to_disk(report)
            return report
        if port is None:
            report["verdict"] = "SKIP"
            report["reasons"].append("порт не задан (live-режим требует порт Xray)")
            if save_report:
                save_report_to_disk(report)
            return report
        pcap = _live_capture(port, capture_secs)
        if pcap is None:
            report["verdict"] = "SKIP"
            report["reasons"].append("tcpdump-захват не дал PCAP (нет root? интерфейс?)")
            if save_report:
                save_report_to_disk(report)
            return report
        report["pcap"] = str(pcap)
    elif pcap is None:
        report["ok"] = False
        report["verdict"] = "SKIP"
        report["reasons"].append("offline-режим требует pcap_path")
        return report

    try:
        if Path(pcap).stat().st_size > MAX_PCAP_BYTES:
            report["verdict"] = "SKIP"
            report["reasons"].append("PCAP слишком большой")
            if save_report:
                save_report_to_disk(report)
            return report
    except OSError:
        report["ok"] = False
        report["verdict"] = "SKIP"
        report["reasons"].append("PCAP недоступен")
        return report

    # ── nDPI-классификация ──
    ndpi_flows = None
    if tools["ndpiReader"]:
        ndpi_flows = run_ndpi(pcap)
        if ndpi_flows is None:
            report["reasons"].append("ndpiReader упал — вердикт по builtin/tshark")

    # ── потоки ──
    streams = run_tshark_streams(pcap) if tools["tshark"] else None
    flow_verdicts = []
    if streams is not None:
        for st in streams:
            if port is not None and st["sport"] != port and st["dport"] != port:
                continue
            if st["l4"] == "tcp":
                fv = classify_tcp_flow(st, ndpi_flows)
            else:
                fv = classify_udp_flow(st, ndpi_flows)
            flow_verdicts.append(fv)
    else:
        # builtin: свой парсер TCP-потоков
        parsed = tcp_streams_from_pcap(pcap, port=port)
        from chimera.modules.dpi_gate import _flow_tag
        for key in parsed["order"]:
            segs = parsed["tuples"][key]
            tag = _flow_tag(key)
            h = tls_heuristics_verdict(segs)
            fv = {"flow": tag, "l4": "tcp", "ndpi": "unavailable",
                  "verdict": h["verdict"], "reason": "builtin TLS heuristics"}
            flow_verdicts.append(fv)
        # UDP (Hysteria2): builtin — по распределению размеров/энтропии
        for key, pkts in udp_flows_mask_gate(pcap, port=port).items():
            if len(pkts) < 8:
                continue
            tag = _flow_tag(key)
            fv = _builtin_udp_verdict(pkts, ndpi_flows, tag)
            flow_verdicts.append(fv)

    # ── агрегированный вердикт ──
    report["flows"] = len(flow_verdicts)
    report["fail_flows"] = sum(1 for f in flow_verdicts if f["verdict"] == "fail")
    report["suspect_flows"] = sum(1 for f in flow_verdicts if f["verdict"] in ("suspect",))
    report["clean_flows"] = sum(1 for f in flow_verdicts
                                if f["verdict"] in ("clean", "clean_tls"))
    report["insufficient_flows"] = sum(1 for f in flow_verdicts if f["verdict"] == "insufficient")
    report["flow_verdicts"] = flow_verdicts[:64]
    analyzed = report["fail_flows"] + report["suspect_flows"] + report["clean_flows"]
    if analyzed == 0:
        report["verdict"] = "INSUFFICIENT"
        report["reasons"].append("нет анализируемых потоков (трафик не шёл во время захвата?)")
    elif report["fail_flows"] > 0:
        report["verdict"] = "FAIL"
        report["reasons"].append(
            f"{report['fail_flows']} поток(ов) классифицированы как VPN/аномалия")
    elif report["suspect_flows"] > 0:
        # Подозрительные потоки — не PASS, даже если nDPI недоступен:
        # builtin-эвристики не нашли валидной TLS-структуры
        report["verdict"] = "SUSPECT"
        report["reasons"].append(
            f"{report['suspect_flows']} поток(ов) не похожи на чистый TLS/QUIC"
            + ("" if tools["ndpiReader"] and ndpi_flows
               else " (nDPI недоступен — builtin-вердикт)"))
    else:
        report["verdict"] = "PASS"
        report["reasons"].append(
            f"все потоки ({report['clean_flows']}) выглядят как легитимный TLS/QUIC")

    _log("INFO", f"mask_gate {mode}: verdict={report['verdict']} "
                 f"flows={report['flows']} fail={report['fail_flows']} "
                 f"suspect={report['suspect_flows']}")
    if save_report:
        p = save_report_to_disk(report)
        if p:
            report["report_path"] = str(p)
    return report


def classify_udp_flow(l4_flow: dict, ndpi_flows: Optional[list]) -> dict:
    verdict = {"flow": l4_flow["flow"], "l4": "udp"}
    ndpi_class = None
    if ndpi_flows:
        for nf in ndpi_flows:
            if nf["flow"] == l4_flow["flow"]:
                ndpi_class = nf["classification"]
                break
    verdict["ndpi"] = ndpi_class or "unavailable"
    if ndpi_class:
        if ndpi_class in NDPI_FAIL_UDP:
            verdict["verdict"] = "fail"
        elif ndpi_class in NDPI_CLEAN_UDP:
            verdict["verdict"] = "clean"
        else:
            verdict["verdict"] = "suspect"
        verdict["reason"] = f"nDPI: {ndpi_class}"
    else:
        import base64
        first = base64.b64decode(l4_flow.get("first_bytes_b64", ""))
        verdict["verdict"] = _quick_udp_shape(first)
        verdict["reason"] = "builtin quick-shape"
    return verdict


def _builtin_udp_verdict(packets: list, ndpi_flows: Optional[list], tag: str) -> dict:
    """Builtin-вердикт UDP-потока без tshark: форма первых пакетов."""
    first = packets[0] if packets else b""
    verdict = {"flow": tag, "l4": "udp", "ndpi": "unavailable"}
    verdict["verdict"] = _quick_udp_shape(first)
    verdict["reason"] = "builtin quick-shape"
    return verdict


def _quick_udp_shape(pkt: bytes) -> str:
    """Быстрая форма UDP-пакета: QUIC long/short header или STUN."""
    if not pkt:
        return "insufficient"
    b0 = pkt[0]
    if b0 & 0xC0 == 0xC0 and len(pkt) >= 8:
        return "clean"       # QUIC long header
    if b0 & 0xC0 == 0x40:
        return "clean"       # QUIC short header
    if (b0 & 0xC0) == 0 and len(pkt) >= 20 and pkt[:2] in (
            b"\x00\x01", b"\x01\x01", b"\x00\x03", b"\x01\x11"):
        return "clean"       # STUN
    return "suspect"         # сырой UDP — не похож ни на QUIC, ни на STUN


def _default_capture_interface() -> str:
    """Интерфейс default-route для live-захвата.

    ВАЖНО: НЕ «any» — tcpdump -i any пишет Linux SLL/SLL2 (DLT 113/276),
    которые ndpiReader 4.x не читает («Unsupported datalink 276»). Конкретный
    интерфейс даёт DLT_EN10MB, который понимают все инструменты.
    """
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10).stdout
        for word in out.split():
            if word.startswith("dev"):
                continue
        # формат: "default via X dev eth0 proto ..."
        parts = out.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _live_capture(port: int, capture_secs: int,
                  interface: Optional[str] = None) -> Optional[Path]:
    """tcpdump-захват на порт → /tmp/chimera_mask_gate/*.pcap.

    interface=None → интерфейс default route (см. _default_capture_interface).
    """
    try:
        iface = interface or _default_capture_interface()
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        pcap = CAPTURE_DIR / f"mg_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        cmd = ["timeout", str(int(capture_secs)), _shutil_which(TCPDUMP_BIN),
               "-i", iface, "-U", "-w", str(pcap),
               f"port {int(port)}", "-c", "40000"]
        subprocess.run(cmd, capture_output=True, timeout=int(capture_secs) + 10)
        if pcap.exists() and pcap.stat().st_size > 24:
            return pcap
        pcap.unlink(missing_ok=True)
        return None
    except Exception:
        return None


def save_report_to_disk(report: dict, directory: Path = REPORT_DIR) -> Optional[Path]:
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        p = Path(directory) / f"mask_gate_{ts}.json"
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        p.chmod(0o600)
        return p
    except Exception:
        return None


def latest_report(directory: Path = REPORT_DIR, max_age_secs: int = 3600) -> Optional[dict]:
    d = Path(directory)
    if not d.is_dir():
        return None
    best = None
    now = datetime.now().timestamp()
    for p in sorted(d.glob("mask_gate_*.json")):
        try:
            if now - p.stat().st_mtime <= max_age_secs:
                best = p
        except OSError:
            continue
    if best is None:
        return None
    try:
        return json.loads(best.read_text(encoding="utf-8"))
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 5. LIVE-ТЕСТ-ЗОНД: генерируем трафик сами (TCP TLS к порту Xray)
# ══════════════════════════════════════════════════════════════════════════════
def generate_probe_traffic(host: str, port: int, count: int = 6) -> int:
    """Несколько TCP-коннектов + ClientHello-подобные байты → живой трафик
    для захвата. Возвращает число успешных коннектов."""
    ok = 0
    import socket
    for _ in range(max(1, int(count))):
        try:
            s = socket.create_connection((host, port), timeout=4)
            # TLS ClientHello-заглушка: handshake 0x16, TLS 1.2, малый размер.
            # REALITY сам ответит валидным TLS приманки — что и нужно гейту.
            s.sendall(bytes.fromhex("160301001001" + "000d0303" + "00" * 12))
            try:
                s.recv(512)
            except Exception:
                pass
            s.close()
            ok += 1
        except Exception:
            continue
    return ok


def get_xray_port_from_state(state_path: Optional[Path] = None) -> Optional[int]:
    """Порт Xray из state.json (PARAM_PORT / port / listen).

    Путь резолвится в runtime (не дефолт-аргумент) — иначе патч STATE_FILE
    в тестах не действует на прод-путь (урок cb461fa из dpi_gate.load_model).
    """
    state_path = Path(state_path) if state_path else STATE_FILE
    try:
        st = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    for key in ("PARAM_PORT", "port", "listen_port", "xray_port"):
        v = st.get(key)
        if isinstance(v, int) and 1 <= v <= 65535:
            return v
        if isinstance(v, str) and v.isdigit() and 1 <= int(v) <= 65535:
            return int(v)
    # вложенные места
    for sub in ("xray", "network", "params"):
        d = st.get(sub)
        if isinstance(d, dict):
            for key in ("port", "listen_port", "PARAM_PORT"):
                v = d.get(key)
                if isinstance(v, int) and 1 <= v <= 65535:
                    return v
                if isinstance(v, str) and v.isdigit() and 1 <= int(v) <= 65535:
                    return int(v)
    return None


def get_xray_port_from_config(config_path: Optional[Path] = None) -> Optional[int]:
    """Порт основного inbound Xray из /etc/xray/config.json.

    На установках Mode B chain (вся текущая линейка) state.json не содержит
    порта Xray вовсе — там только ключи awg_*/chain_*. Реальный VLESS-порт
    живёт в конфиге Xray: первый inbound с протоколом vless (или любой
    не-служебный), слушающий не на loopback.
    """
    config_path = Path(config_path) if config_path else XRAY_CONFIG
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    inbounds = cfg.get("inbounds")
    if not isinstance(inbounds, list):
        return None

    def _port_of(inb: dict) -> Optional[int]:
        v = inb.get("port")
        if isinstance(v, int) and 1 <= v <= 65535:
            return v
        if isinstance(v, str) and v.isdigit() and 1 <= int(v) <= 65535:
            return int(v)
        return None  # диапазоны "1000-2000" и мусор не берём

    fallback = None
    for inb in inbounds:
        if not isinstance(inb, dict):
            continue
        proto = str(inb.get("protocol") or "").lower()
        listen = str(inb.get("listen") or "").lower()
        port = _port_of(inb)
        if port is None:
            continue
        if proto in _SKIP_PROTOCOLS or listen in _LOOPBACK_LISTENS:
            continue  # dokodemo-door на 127.0.0.1 — не то, что ищем
        if proto == "vless":
            return port  # основной кандидат — сразу
        if fallback is None:
            fallback = port  # не-vless внешний inbound (trojan/…) — запомнить
    return fallback


def get_xray_port() -> Optional[int]:
    """Композитный резолвер порта: state.json → /etc/xray/config.json.

    Порядок: legacy-инсталлы писали порт в state.json (PARAM_PORT и пр.),
    Mode B chain — только в конфиге Xray.
    """
    return (get_xray_port_from_state()
            or get_xray_port_from_config())


def get_server_ip_from_state(state_path: Optional[Path] = None) -> Optional[str]:
    state_path = Path(state_path) if state_path else STATE_FILE
    try:
        st = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    for key in ("PARAM_SERVER_IP", "server_ip", "public_ip", "ip"):
        v = st.get(key)
        if isinstance(v, str) and v:
            return v
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 6. TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_manage_mask_gate() -> None:
    """Интерактивное меню Mask Gate."""
    GREEN, CYAN, DIM, NC, BOLD, BLUE, YELLOW, RED = (
        _C['GREEN'], _C['CYAN'], _C['DIM'], _C['NC'],
        _C['BOLD'], _C['BLUE'], _C['YELLOW'], _C['RED'])
    while True:
        os.system("clear")
        tools = {
            "tcpdump": _shutil_which(TCPDUMP_BIN),
            "tshark": _shutil_which(TSHARK_BIN),
            "ndpiReader": _shutil_which(NDPI_BIN),
        }
        detected_port = get_xray_port()
        rp = latest_report(max_age_secs=86400)
        print()
        print(f"  {BOLD}🎭  MASK GATE — гейт маскировки (идея AIVPN make mask-gate){NC}")
        print(f"  {DIM}Захватывает трафик на порт Xray и проверяет, как он выглядит{NC}")
        print(f"  {DIM}снаружи: nDPI/tshark должны видеть чистый TLS/QUIC, не VPN.{NC}")
        print()
        print(f"  tcpdump:     {GREEN}да{NC} {DIM}({tools['tcpdump']}){NC}" if tools['tcpdump']
              else f"  tcpdump:     {RED}нет{NC} {DIM}(apt install tcpdump){NC}")
        print(f"  tshark:      {GREEN}да{NC} {DIM}({tools['tshark']}){NC}" if tools['tshark']
              else f"  tshark:      {YELLOW}нет{NC} {DIM}(фолбэк: builtin-парсер){NC}")
        print(f"  ndpiReader:  {GREEN}да{NC} {DIM}({tools['ndpiReader']}){NC}" if tools['ndpiReader']
              else f"  ndpiReader:  {YELLOW}нет{NC} {DIM}(apt install ndpi; иначе builtin-эвристики){NC}")
        print(f"  Порт Xray:   {CYAN}{detected_port or 'не найден в state.json'}{NC}")
        if rp:
            v = rp.get("verdict", "?")
            color = GREEN if v == "PASS" else (RED if v == "FAIL" else YELLOW)
            print(f"  Отчёт:       {color}{v}{NC} {DIM}({rp.get('flows', 0)} потоков, {rp.get('ts', '?')}){NC}")
        print()
        print(f"  {BOLD}1.{NC} Live-гейт: захват + анализ (нужен root + порт)")
        print(f"  {BOLD}2.{NC} Offline-гейт: оценить готовый PCAP")
        print(f"  {BOLD}3.{NC} Показать последний отчёт")
        print(f"  {BOLD}0.{NC} ← Назад")
        print()
        try:
            ch = input(f"  {CYAN}Выбор:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if ch == "1":
            print()
            port = detected_port
            default_hint = str(port) if port else "443"
            raw_p = input(f"  {BLUE}Порт Xray [{default_hint}]:{NC} ").strip()
            if raw_p.isdigit() and 1 <= int(raw_p) <= 65535:
                port = int(raw_p)
            elif not raw_p and not port:
                # Enter на пустом детекте = приняли подсказку [443]
                port = 443
            if not port:
                print(f"  {RED}Порт не определён{NC}")
                input(f"  {BLUE}Enter...{NC}")
                continue
            # Тест-зонд в фоне не нужен — на живой ноде трафик уже идёт;
            # но при тишине генерируем пару коннектов сами
            ip = get_server_ip_from_state()
            if ip:
                n = generate_probe_traffic(ip, port, count=3)
                if n:
                    print(f"  {DIM}тест-зонд: {n} коннект(ов) отправлено{NC}")
            print(f"  {CYAN}Захват {CAPTURE_SECS_DEFAULT}s на порт {port}...{NC}")
            report = run_mask_gate(port=port, live=True,
                                   capture_secs=CAPTURE_SECS_DEFAULT)
            _print_report(report)
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "2":
            print()
            raw = input(f"  {BLUE}Путь к .pcap:{NC} ").strip()
            if not raw:
                continue
            p = Path(raw).expanduser()
            if not p.is_file():
                print(f"  {RED}Файл не найден{NC}")
                input(f"  {BLUE}Enter...{NC}")
                continue
            raw_port = input(f"  {BLUE}Порт фильтра (Enter = все):{NC} ").strip()
            port = int(raw_port) if raw_port.isdigit() else None
            report = run_mask_gate(pcap_path=p, port=port, live=False)
            _print_report(report)
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "3":
            rp_data = latest_report(max_age_secs=86400 * 7)
            if rp_data:
                print(json.dumps(rp_data, ensure_ascii=False, indent=2)[:3000])
            else:
                print(f"  {DIM}Отчётов нет{NC}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "0":
            break


def _print_report(report: dict) -> None:
    GREEN, CYAN, DIM, NC, BOLD, YELLOW, RED = (
        _C['GREEN'], _C['CYAN'], _C['DIM'], _C['NC'],
        _C['BOLD'], _C['YELLOW'], _C['RED'])
    v = report.get("verdict", "?")
    color = GREEN if v == "PASS" else (RED if v == "FAIL" else YELLOW)
    print(f"\n  Вердикт гейта: {color}{BOLD}{v}{NC}")
    for r in report.get("reasons", []):
        print(f"    {DIM}•{NC} {r}")
    print(f"  Потоков: {report.get('flows', 0)} "
          f"(clean: {report.get('clean_flows', 0)}, "
          f"suspect: {report.get('suspect_flows', 0)}, "
          f"fail: {report.get('fail_flows', 0)}, "
          f"мало данных: {report.get('insufficient_flows', 0)})")
    for fv in report.get("flow_verdicts", [])[:12]:
        mark = {"clean": GREEN + "✓" + NC, "clean_tls": GREEN + "✓" + NC,
                "fail": RED + "✗" + NC, "suspect": YELLOW + "?" + NC,
                "insufficient": DIM + "·" + NC}.get(fv["verdict"], DIM + "?" + NC)
        print(f"    {mark} {DIM}{fv['flow']}{NC} {fv['l4']}:{fv['verdict']:<8} "
              f"ndpi={fv.get('ndpi', '-')}")
    if report.get("report_path"):
        print(f"\n  {DIM}Отчёт: {report['report_path']}{NC}")
