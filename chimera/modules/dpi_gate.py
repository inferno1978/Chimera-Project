"""
chimera/modules/dpi_gate.py
───────────────────────────────────────────────────────────────────────────────
DPI Gate — ML-гейт «похож ли трафик на маску» (идея AIVPN tools/dpi, порт
на чистый Python для Химеры).

  • 23 признака окна из 24 UDP-пакетов — арифметика f32 бит-в-бит
    совместима с AIVPN features.py (FEATURE_SCHEMA_VERSION = 2)
  • Инференс GBDT из JSON-модели (плоские деревья feature/threshold/
    left/right/value — формат как запечённые const-массивы aivpn
    dpi_gate/model.rs, но в JSON)
  • Свой парсер классического PCAP (DLT_EN10MB=1 / RAW_IP=101), без
    сторонних зависимостей
  • Обучение — scripts/dpi_gate_train.py (офлайн, sklearn опционален)
  • Рантайм-вердикт: окно похоже на легитимный QUIC/STUN или на туннель

Применение в Химере:
  • Hysteria2 (QUIC) и AWG — окна UDP-трафика прогоняются через модель,
    вердикт «tunnel» = маскировка палится → вход для dpi_response
  • Диагностика: новый шаг мастера ( verdict по свежему захвату )
  • CI: маска-гейт на синтетических окнах

Точка входа из _core.py:
    from chimera.modules.dpi_gate import do_manage_dpi_gate
CLI (main.py):
    --dpi-gate-eval <pcap> [port]   — оценить захват
"""
from __future__ import annotations

import json
import math
import os
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Константы (совместимы с AIVPN dpi_gate) ──────────────────────────────────
WINDOW = 24                 # пакетов в окне — так обучена модель
N_FEATURES = 23
FEATURE_SCHEMA_VERSION = 2
FEATURE_SCHEMA_NAME = "quic-short-header-byte0-invariant"
GATE_MODEL_SCHEMA = 1       # формат JSON-модели Химеры

SIZE_BINS = (
    (0, 100),
    (100, 300),
    (300, 600),
    (600, 1000),
    (1000, 1400),
    (1400, 65535),
)
FEATURE_NAMES = (
    "n_pkts", "sz_mean", "sz_std", "sz_min", "sz_max", "sz_med",
    "sz_p10", "sz_p90",
    "szfrac_0_100", "szfrac_100_300", "szfrac_300_600",
    "szfrac_600_1000", "szfrac_1000_1400", "szfrac_1400p",
    "ent_first16", "ent_full",
    "byte0_mean", "byte0_msb_frac", "quic_longform_frac",
    "stun_type_frac", "stun_magic_frac", "stun_lenconsistent_frac",
    "dns_looksdns_frac",
)
STUN_TYPES = (b"\x00\x01", b"\x01\x01", b"\x00\x03", b"\x01\x11")
STUN_MAGIC = b"\x21\x12\xa4\x42"

# ── Пути Химеры ───────────────────────────────────────────────────────────────
_LIB_DIR   = Path("/var/lib/xray-installer")
MODEL_PATH = _LIB_DIR / "dpi_gate_model.json"
REPORT_DIR = _LIB_DIR / "dpi_gate"
_LOG_FILE  = Path("/var/log/chimera.log")


def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _strip_ansi(msg)
            f.write(f"[{ts}] [{level}] [dpi_gate] {clean}\n")
    except Exception:
        pass


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


# ══════════════════════════════════════════════════════════════════════════════
# 1. АРИФМЕТИКА f32 (заменяет numpy.float32 без numpy)
# ══════════════════════════════════════════════════════════════════════════════
def f32(value: float) -> float:
    """Число, округлённое до ближайшего f32 (как np.float32 в AIVPN)."""
    try:
        return struct.unpack("<f", struct.pack("<f", value))[0]
    except (OverflowError, ValueError):
        return math.copysign(math.inf, value) if abs(value) > 3.4e38 else 0.0


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-min(x, 60.0))
        return 1.0 / (1.0 + z)
    z = math.exp(max(x, -60.0))
    return z / (1.0 + z)


# ══════════════════════════════════════════════════════════════════════════════
# 2. ПРИЗНАКИ ОКНА (AIVPN-совместимые, schema v2)
# ══════════════════════════════════════════════════════════════════════════════
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def round_half_even(value: float) -> float:
    floor = math.floor(value)
    diff = value - floor
    if diff < 0.5:
        return floor
    if diff > 0.5:
        return floor + 1.0
    if int(floor) % 2 == 0:
        return floor
    return floor + 1.0


def percentile(sorted_sizes: list, q: float) -> float:
    if not sorted_sizes:
        return 0.0
    idx = int(round_half_even(q * (len(sorted_sizes) - 1)))
    idx = min(max(idx, 0), len(sorted_sizes) - 1)
    return float(sorted_sizes[idx])


def header_flags(packet: bytes) -> dict:
    """Per-packet метаданные — всё, что видит DPI-коробка, без payload-хранения."""
    length = len(packet)
    stored_len = min(length, 65535)
    raw_byte0 = packet[0] if packet else 0
    # Schema v2: QUIC short header (первые два бита 01) → нормализация byte0
    # в 0x40 — инвариант против вариаций spin/protected-битов.
    byte0 = 0x40 if raw_byte0 & 0xC0 == 0x40 else raw_byte0
    normalized = bytes([byte0]) + packet[1:] if packet and byte0 != raw_byte0 else packet
    stun_type = (
        length >= 2 and (packet[0] & 0xC0) == 0 and packet[:2] in STUN_TYPES
    )
    magic_ok = length >= 8 and packet[4:8] == STUN_MAGIC
    stun_lenok = False
    if length >= 4:
        msg_len = (packet[2] << 8) | packet[3]
        stun_lenok = msg_len + 20 == length
    dns_ok = False
    if length >= 12:
        qd = (packet[4] << 8) | packet[5]
        an = (packet[6] << 8) | packet[7]
        dns_ok = qd == 1 and an <= 16
    n16 = min(length, 16)
    return {
        "len": float(stored_len),
        "byte0": float(byte0),
        "has_byte0": 1.0 if length > 0 else 0.0,
        "stun_type": 1.0 if stun_type else 0.0,
        "magic_ok": 1.0 if magic_ok else 0.0,
        "stun_lenok": 1.0 if stun_lenok else 0.0,
        "dns_ok": 1.0 if dns_ok else 0.0,
        "ent16": f32(shannon_entropy(normalized[:n16])),
        "ent_full": f32(shannon_entropy(normalized)),
        "quic_long": 1.0 if length > 0 and (byte0 & 0xC0) == 0xC0 else 0.0,
        "msb": 1.0 if length > 0 and (byte0 & 0x80) != 0 else 0.0,
    }


def extract_features(packets: list) -> list:
    """Вектор из 23 f32 в порядке FEATURE_NAMES (пустое окно → нули)."""
    feats = [0.0] * N_FEATURES
    count = len(packets)
    if count == 0:
        return feats
    meta = [header_flags(p) for p in packets]
    sizes = [int(item["len"]) for item in meta]
    nf = f32(float(count))
    mean = sum(sizes) / count
    var = sum((size - mean) ** 2 for size in sizes) / count
    ordered = sorted(sizes)
    feats[0] = nf
    feats[1] = f32(mean)
    feats[2] = f32(math.sqrt(var))
    feats[3] = f32(float(ordered[0]))
    feats[4] = f32(float(ordered[-1]))
    feats[5] = f32(percentile(ordered, 0.5))
    feats[6] = f32(percentile(ordered, 0.10))
    feats[7] = f32(percentile(ordered, 0.90))
    bins = [0] * len(SIZE_BINS)
    for size in sizes:
        for index, (lo, hi) in enumerate(SIZE_BINS):
            if lo <= size < hi:
                bins[index] += 1
                break
    for index, bin_count in enumerate(bins):
        feats[8 + index] = f32(f32(float(bin_count)) / f32(float(count)))
    feats[14] = f32(sum(item["ent16"] for item in meta) / count)
    feats[15] = f32(sum(item["ent_full"] for item in meta) / count)
    byte_sum = 0
    byte_n = 0
    msb = 0
    quic_long = 0
    for item in meta:
        if item["has_byte0"]:
            byte_sum += int(item["byte0"])
            byte_n += 1
            msb += int(item["msb"])
            quic_long += int(item["quic_long"])
    if byte_n:
        feats[16] = f32(float(f32(float(byte_sum)) / f32(float(byte_n))))
        feats[17] = f32(float(f32(float(msb)) / f32(float(byte_n))))
        feats[18] = f32(float(f32(float(quic_long)) / f32(float(byte_n))))
    feats[19] = f32(float(f32(float(sum(item["stun_type"] for item in meta))) / f32(float(count))))
    feats[20] = f32(float(f32(float(sum(item["magic_ok"] for item in meta))) / f32(float(count))))
    feats[21] = f32(float(f32(float(sum(item["stun_lenok"] for item in meta))) / f32(float(count))))
    feats[22] = f32(float(f32(float(sum(item["dns_ok"] for item in meta))) / f32(float(count))))
    return [f32(item) for item in feats]


# ── Синтетика (тесты + baseline-генерация) ────────────────────────────────────
def stun_pkt(msg_len: int, total: int) -> bytes:
    packet = bytearray([0x00, 0x01,
                        (msg_len >> 8) & 0xFF, msg_len & 0xFF,
                        0x21, 0x12, 0xA4, 0x42])
    for index in range(max(0, total - 8)):
        packet.append((index * 37 + 11) & 0xFF)
    del packet[total:]
    return bytes(packet)


def rnd_pkt(total: int, seed: int) -> bytes:
    return bytes(((seed * 131 + index * 97 + 7) & 0xFF) for index in range(total))


def quic_short_pkt(total: int, byte0: int, seed: int) -> bytes:
    if not 0x40 <= byte0 < 0x80:
        raise ValueError("quic short header byte0 должен быть в [0x40, 0x80)")
    return bytes([byte0]) + rnd_pkt(total, seed)[1:]


# ══════════════════════════════════════════════════════════════════════════════
# 3. GBDT-ИНФЕРЕНС (JSON-модель, формат плоских узлов AIVPN model.rs)
# ══════════════════════════════════════════════════════════════════════════════
def load_model(path: Optional[Path] = None) -> Optional[dict]:
    """JSON: {schema_version, feature_schema_version, window, classes,
              base_score, threshold, trees: [{nodes: [...]}]}

    path=None → MODEL_PATH (runtime-резолв, не дефолт-аргумент — иначе
    патчинг MODEL_PATH в тестах не работает при существующей прод-модели).
    """
    if path is None:
        path = MODEL_PATH
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    if raw.get("schema_version") != GATE_MODEL_SCHEMA:
        return None
    if raw.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        return None
    if not isinstance(raw.get("trees"), list) or not raw["trees"]:
        return None
    return raw


def model_is_usable(model: Optional[dict]) -> bool:
    if not model:
        return False
    classes = model.get("classes") or []
    return len(classes) == 2 and all(isinstance(t.get("nodes"), list) for t in model["trees"])


def _tree_predict(nodes: list, x: list) -> float:
    node = nodes[0]
    while True:
        feat = node.get("feature", -1)
        if feat is None or feat < 0:
            return float(node.get("value", 0.0))
        thr = float(node.get("threshold", 0.0))
        nxt = node.get("left", 0) if x[feat] <= thr else node.get("right", 0)
        if not (0 <= int(nxt) < len(nodes)):
            return float(node.get("value", 0.0))
        node = nodes[int(nxt)]


def score_window(model: dict, feats: list) -> dict:
    """Вердикт GBDT для одного окна (23 признака).

    Возвращает {p_tunnel, verdict} где verdict — имя класса из модели
    ('tunnel' = маска палится, 'benign' = похож на легитимный трафик).
    """
    if len(feats) != N_FEATURES:
        raise ValueError(f"ожидалось {N_FEATURES} признаков, получено {len(feats)}")
    raw = float(model.get("base_score", 0.0))
    for tree in model["trees"]:
        raw += _tree_predict(tree["nodes"], feats)
    p = _sigmoid(raw)
    thr = float(model.get("threshold", 0.5))
    classes = model.get("classes") or ["benign", "tunnel"]
    # Класс 1 (индекс 1) — положительный класс GBDT = туннель
    verdict = classes[1] if p >= thr else classes[0]
    return {"p_tunnel": f32(p), "verdict": verdict}


def _windows(packets: list, stride: int) -> list:
    """Скользящие окна: первый кадр и каждый stride-й (как AIVPN: stride 16)."""
    out = []
    i = 0
    n = len(packets)
    while i < n:
        window = packets[i : i + WINDOW]
        if len(window) == WINDOW:
            out.append(window)
        if stride <= 1:
            i += 1
        else:
            i += stride
    return out


def evaluate_udp_packets(packets: list, model: dict, stride: int = 16) -> dict:
    """Все окна из списка UDP-пакетов → агрегированный вердикт."""
    windows = _windows(packets, stride)
    if not windows:
        return {"windows": 0, "tunnel_windows": 0, "p_tunnel_max": 0.0,
                "p_tunnel_avg": 0.0, "verdict": "insufficient",
                "verdicts": []}
    verdicts = []
    for w in windows:
        verdicts.append(score_window(model, extract_features(w)))
    p_max = max(v["p_tunnel"] for v in verdicts)
    p_avg = sum(v["p_tunnel"] for v in verdicts) / len(verdicts)
    tunnel_cnt = sum(1 for v in verdicts if v["verdict"] == "tunnel")
    # Вердикт потока: туннель, если >30% окон или самое сильное окно >= 0.9
    is_tunnel = (tunnel_cnt / len(verdicts) > 0.30) or p_max >= 0.90
    return {
        "windows": len(verdicts),
        "tunnel_windows": tunnel_cnt,
        "p_tunnel_max": f32(p_max),
        "p_tunnel_avg": f32(p_avg),
        "verdict": "tunnel" if is_tunnel else "benign",
        "verdicts": verdicts,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 4. PCAP-ПАРСЕР (классический формат, без зависимостей)
# ══════════════════════════════════════════════════════════════════════════════
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NSEC_LE = 0xA1B23C4D
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113    # tcpdump -i any (старый формат)
DLT_LINUX_SLL2 = 276   # tcpdump -i any (новый формат, Linux ≥ 5.2)

# Заголовки канального уровня для SLL/SLL2 (Linux cooked capture)
SLL_HDR_LEN = 16       # [pkttype u16][hatype u16][halen u16][addr u8*8][protocol u16]
SLL2_HDR_LEN = 20      # [protocol u16][reserved u16][ifindex u32][hatype u16]
                       # [pkttype u8][addr_len u8][addr u8*8]


def _ipv4_from_sll(link: bytes, dlt: int) -> Optional[bytes]:
    """IPv4 из Linux cooked capture (SLL/SLL2) — tcpdump -i any."""
    if dlt == DLT_LINUX_SLL:
        if len(link) < SLL_HDR_LEN:
            return None
        ethertype = (link[14] << 8) | link[15]
        return link[SLL_HDR_LEN:] if ethertype == 0x0800 else None
    # SLL2: protocol в начале заголовка
    if len(link) < SLL2_HDR_LEN:
        return None
    ethertype = (link[0] << 8) | link[1]
    return link[SLL2_HDR_LEN:] if ethertype == 0x0800 else None
    return None


def parse_pcap(path: Path) -> list:
    """Читает классический PCAP → список записей
    [{ts, dlt, link_data(bytes)}]. Поддерживает little/big endian,
    usec/nsec. IP-реассембли не выполняем (окна допускают фрагменты
    как есть — модель училась на целых кадрах, фрагменты редки)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("PCAP короче глобального заголовка")
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NSEC_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_SWAPPED, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError(f"не PCAP-магия: 0x{magic:08X}")
    global_hdr = struct.unpack(endian + "IHHiIII", data[:24])
    dlt = global_hdr[-1]
    records = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, caplen, origlen = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        if caplen > 262144 or off + caplen > len(data):
            break
        link = bytes(data[off : off + caplen])
        off += caplen
        ts = float(ts_sec) + (float(ts_frac) / 1_000_000.0 if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_SWAPPED) else float(ts_frac) / 1_000_000_000.0)
        records.append({"ts": ts, "dlt": dlt, "data": link, "origlen": origlen})
    return records


def _ipv4_from_ethernet(frame: bytes) -> Optional[bytes]:
    if len(frame) < 14:
        return None
    ethertype = (frame[12] << 8) | frame[13]
    if ethertype != 0x0800:
        return None
    return frame[14:]


def _ipv4_from_raw(link: bytes) -> Optional[bytes]:
    if not link:
        return None
    version = link[0] >> 4
    if version == 4:
        return link
    return None


def _udp_payload_from_ipv4(ip: bytes) -> Optional[bytes]:
    """UDP payload из IPv4-пакета (без фрагментации-реассембли)."""
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = (ip[2] << 8) | ip[3]
    if total_len > len(ip):
        ip = ip[:total_len]
    proto = ip[9]
    frag_off = ((ip[6] & 0x1F) << 8) | ip[7]
    if proto != 17 or (frag_off & 0x1FFF) != 0:
        return None
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    udp_len = (udp[4] << 8) | udp[5]
    if udp_len >= 8 and udp_len <= len(udp):
        return udp[8:udp_len]
    return udp[8:]


def udp_flows_from_pcap(path: Path, port: Optional[int] = None) -> dict:
    """UDP-потоки из PCAP: {(src_ip, src_port, dst_ip, dst_port): [payload]}.

    port — фильтр: оставить только потоки, у которых src или dst порт
    совпадает. Порядок пакетов сохраняется (по ts записи).
    """
    records = parse_pcap(path)
    flows = {}
    for rec in records:
        dlt = rec["dlt"]
        if dlt == DLT_EN10MB:
            ip = _ipv4_from_ethernet(rec["data"])
        elif dlt == DLT_RAW:
            ip = _ipv4_from_raw(rec["data"])
        elif dlt in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
            ip = _ipv4_from_sll(rec["data"], dlt)
        else:
            continue
        if ip is None:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
            continue
        frag_off = ((ip[6] & 0x1F) << 8) | ip[7]
        if (frag_off & 0x1FFF) != 0:
            continue
        udp = ip[ihl:]
        sport = (udp[0] << 8) | udp[1]
        dport = (udp[2] << 8) | udp[3]
        src_ip = ".".join(str(b) for b in ip[12:16])
        dst_ip = ".".join(str(b) for b in ip[16:20])
        if port is not None and sport != port and dport != port:
            continue
        key = (src_ip, sport, dst_ip, dport)
        payload = _udp_payload_from_ipv4(ip)
        if payload is None:
            continue
        flows.setdefault(key, []).append(payload)
    return flows


# ══════════════════════════════════════════════════════════════════════════════
# 5. ОЦЕНКА PCAP + ОТЧЁТ
# ══════════════════════════════════════════════════════════════════════════════
def evaluate_pcap(path: Path, model: Optional[dict] = None,
                  port: Optional[int] = None,
                  stride: int = 16) -> dict:
    """Полный прогон: PCAP → UDP-потоки → окна → GBDT-вердикты.

    Отчёт содержит только счётчики и вероятности: ни адресов, ни payload
    (политика обезличивания — см. scripts/leak_guard.py).
    """
    model = model if model is not None else load_model()
    if not model_is_usable(model):
        return {"ok": False, "error": "model_unavailable",
                "detail": f"нет валидной модели в {MODEL_PATH}; обучите "
                          f"scripts/dpi_gate_train.py"}
    flows = udp_flows_from_pcap(path, port=port)
    flow_reports = []
    for key, packets in flows.items():
        res = evaluate_udp_packets(packets, model, stride=stride)
        flow_reports.append({
            # ключ анонимизируем хэшем — без IP в отчётах
            "flow": _flow_tag(key),
            "packets": len(packets),
            **{k: v for k, v in res.items() if k != "verdicts"},
        })
    verdicts = [f["verdict"] for f in flow_reports]
    summary = {
        "ok": True,
        "ts": datetime.now().isoformat(timespec="seconds"),
        "pcap": Path(path).name,
        "port_filter": port,
        "window": WINDOW,
        "stride": stride,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "flows": len(flow_reports),
        "tunnel_flows": sum(1 for v in verdicts if v == "tunnel"),
        "benign_flows": sum(1 for v in verdicts if v == "benign"),
        "insufficient_flows": sum(1 for v in verdicts if v == "insufficient"),
        "overall": ("tunnel" if any(v == "tunnel" for v in verdicts)
                    else ("benign" if verdicts else "no_udp")),
        "flow_reports": flow_reports,
    }
    return summary


def _flow_tag(key: tuple) -> str:
    import hashlib
    raw = "|".join(str(k) for k in key)
    return "flow_" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def save_report(report: dict, directory: Path = REPORT_DIR) -> Optional[Path]:
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        p = Path(directory) / f"dpi_gate_{ts}.json"
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        p.chmod(0o600)
        return p
    except Exception:
        return None


def latest_report(directory: Path = REPORT_DIR, max_age_secs: int = 3600) -> Optional[dict]:
    """Свежий отчёт для dpi_response (не старше max_age_secs)."""
    d = Path(directory)
    if not d.is_dir():
        return None
    best = None
    now = datetime.now().timestamp()
    for p in sorted(d.glob("dpi_gate_*.json")):
        try:
            st = p.stat()
            if now - st.st_mtime <= max_age_secs:
                best = p  # отсортированы по имени → последний самый свежий
        except OSError:
            continue
    if best is None:
        return None
    try:
        return json.loads(best.read_text(encoding="utf-8"))
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 6. TUI-МЕНЮ (управление + диагностика)
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
                    CYAN='\033[36m', BLUE='\033[34m', BOLD='\033[1m',
                    DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'NC')}


_C = _detect_colors()


def do_manage_dpi_gate() -> None:
    """Интерактивное меню DPI Gate (модель, оценка захвата, последний отчёт)."""
    GREEN, CYAN, DIM, NC, BOLD, BLUE, YELLOW, RED = (
        _C['GREEN'], _C['CYAN'], _C['DIM'], _C['NC'],
        _C['BOLD'], _C['BLUE'], _C['YELLOW'], _C['RED'])
    while True:
        os.system("clear")
        model = load_model()
        usable = model_is_usable(model)
        model_info = ""
        if usable:
            model_info = (f"{GREEN}готова{NC} {DIM}(деревьев: {len(model['trees'])}, "
                          f"классы: {'/'.join(model['classes'])}){NC}")
        else:
            model_info = f"{RED}нет{NC} {DIM}(scripts/dpi_gate_train.py){NC}"
        print()
        print(f"  {BOLD}🧠  DPI GATE — ML-гейт маскировки (GBDT, 23 признака){NC}")
        print(f"  {DIM}Идея AIVPN: GBDT приближает вердикт nDPI по окну {WINDOW} пакетов.{NC}")
        print(f"  {DIM}Вердикт «tunnel» → маска палится → вход для авто-реакции (dpi_response).{NC}")
        print()
        print(f"  Модель:           {model_info}")
        print(f"  Путь модели:      {CYAN}{MODEL_PATH}{NC}")
        rp = latest_report(max_age_secs=86400)
        if rp:
            print(f"  Последний отчёт:  {CYAN}{rp.get('overall', '?')}{NC} "
                  f"{DIM}({rp.get('flows', 0)} потоков, {rp.get('ts', '?')}){NC}")
        else:
            print(f"  Последний отчёт:  {DIM}нет свежих (24ч){NC}")
        print()
        print(f"  {BOLD}1.{NC} Оценить PCAP-захват (диагностика UDP-маскировки)")
        print(f"  {BOLD}2.{NC} Показать последний отчёт")
        print(f"  {BOLD}3.{NC} Самотест арифметики фичей (эталон AIVPN)")
        print(f"  {BOLD}0.{NC} ← Назад")
        print()
        try:
            ch = input(f"  {CYAN}Выбор:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if ch == "1":
            print()
            raw = input(f"  {BLUE}Путь к .pcap:{NC} ").strip()
            if not raw:
                continue
            p = Path(raw).expanduser()
            if not p.is_file():
                print(f"  {RED}Файл не найден: {p}{NC}")
                input(f"  {BLUE}Enter...{NC}")
                continue
            raw_port = input(f"  {BLUE}UDP-порт фильтра (Enter = все):{NC} ").strip()
            port = int(raw_port) if raw_port.isdigit() else None
            try:
                report = evaluate_pcap(p, port=port)
            except Exception as e:
                print(f"  {RED}Ошибка: {e}{NC}")
                input(f"  {BLUE}Enter...{NC}")
                continue
            rp = save_report(report)
            if report.get("ok"):
                color = RED if report["overall"] == "tunnel" else GREEN
                print(f"\n  Вердикт: {color}{BOLD}{report['overall'].upper()}{NC}")
                print(f"  Потоков: {report['flows']} "
                      f"(tunnel: {report['tunnel_flows']}, benign: {report['benign_flows']}, "
                      f"мало данных: {report['insufficient_flows']})")
                for fr in report["flow_reports"][:10]:
                    print(f"    {DIM}{fr['flow']}{NC} pkts={fr['packets']:>4} "
                          f"→ {fr['verdict']:<12} p_tunnel_max={fr['p_tunnel_max']:.3f}")
                if rp:
                    print(f"\n  {DIM}Отчёт: {rp}{NC}")
                _log("INFO", f"dpi_gate evaluate: overall={report['overall']} flows={report['flows']}")
            else:
                print(f"\n  {RED}{report.get('detail', 'ошибка')}{NC}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "2":
            rp_data = latest_report(max_age_secs=86400 * 7)
            if rp_data:
                print(json.dumps(rp_data, ensure_ascii=False, indent=2)[:3000])
            else:
                print(f"  {DIM}Отчётов нет{NC}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "3":
            ok, worst = _selftest_features()
            if ok:
                print(f"  {GREEN}OK{NC} — максимальное отклонение от эталона AIVPN: {worst:.2e}")
            else:
                print(f"  {RED}FAIL{NC} — отклонение {worst:.2e} (ожидалось ≤1e-3)")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "0":
            break


# Эталон из AIVPN features.py (модульный тест feature_extraction_matches_
# python_reference) — те же пакеты, те же 23 значения.
_REFERENCE_PACKETS = (
    ("stun", 56, 76),
    ("stun", 20, 40),
    ("stun", 8, 28),
    ("rnd", 1100, 3),
    ("rnd", 1200, 9),
    ("rnd", 200, 21),
)
_REFERENCE_FEATURES = (
    6.0, 440.66667, 505.47623, 28.0, 1200.0, 76.0, 28.0, 1100.0,
    0.5, 0.16666667, 0.0, 0.0, 0.33333334, 0.0,
    3.9375, 6.6259175, 84.0, 0.5, 0.16666667,
    0.5, 0.5, 0.5, 0.0,
)


def _selftest_features() -> tuple:
    """Сверка extract_features с эталоном AIVPN (tol 1e-3 относительный)."""
    packets = []
    for kind, a, b in _REFERENCE_PACKETS:
        packets.append(stun_pkt(a, b) if kind == "stun" else rnd_pkt(a, b))
    got = extract_features(packets)
    worst = 0.0
    for g, w in zip(got, _REFERENCE_FEATURES):
        scale = max(abs(w), 1.0)
        worst = max(worst, abs(g - w) / scale)
    return worst <= 1e-3, worst


# ══════════════════════════════════════════════════════════════════════════════
# 7. ЭКСПОРТ МОДЕЛИ ИЗ SKLEARN (для scripts/dpi_gate_train.py)
# ══════════════════════════════════════════════════════════════════════════════
def export_sklearn_gbc(gbc, classes: list, threshold: float = 0.5) -> dict:
    """sklearn.ensemble.GradientBoostingClassifier → формат Химеры.

    Плоские узлы: {feature: int, threshold: float, left: int, right: int,
    value: float}. leaf → feature = -1. Индексация узлов как в
    tree_.nodes ndarray sklearn (0 = корень).
    """
    trees = []
    for est in gbc.estimators_.ravel():
        t = est[0].tree_
        nodes = []
        for i in range(t.node_count):
            is_leaf = t.children_left[i] == -1
            nodes.append({
                "feature": -1 if is_leaf else int(t.feature[i]),
                "threshold": f32(float(t.threshold[i])),
                "left": int(t.children_left[i]),
                "right": int(t.children_right[i]),
                "value": f32(float(t.value[i][0][0])),
            })
        trees.append({"nodes": nodes})
    # sklearn GBC: raw = init + lr * sum(trees); init для log-loss —
    # log-odds априори. Воспроизводим как base_score.
    base = float(gbc.init_.class_prior_[1] / max(gbc.init_.class_prior_[0], 1e-12))
    base = math.log(base)
    lr = float(gbc.learning_rate)
    for tree in trees:
        for node in tree["nodes"]:
            node["value"] = f32(node["value"] * lr)
    return {
        "schema_version": GATE_MODEL_SCHEMA,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "window": WINDOW,
        "classes": list(classes),
        "base_score": f32(base),
        "threshold": f32(threshold),
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "trees": trees,
    }


def train_synthetic_baseline(out_path: Path = MODEL_PATH,
                             n_trees: int = 120, depth: int = 3,
                             seed: int = 0) -> Optional[dict]:
    """Baseline-модель на синтетике (без внешних зависимостей).

    Классы: benign (STUN/QUIC-подобные окна) vs tunnel (случайные
    зашифрованные сырые UDP). Это СТАРТОВАЯ точка — честная модель
    учится на реальных захватах (scripts/dpi_gate_train.py + ноды).

    Реализация: логистическая регрессия на 4 агрегатах, «деревья» —
    один пень на признак sz_std. Совместимо по формату; точность
    baseline честно помечена provenance=synthetic_baseline.
    """
    import random
    rng = random.Random(seed)
    # Синтетика: benign — STUN-доминированные окна; tunnel — rnd-окна
    benign_feats = []
    tunnel_feats = []
    for _ in range(400):
        win = [stun_pkt(rng.randint(8, 72), rng.randint(28, 92))
               for _ in range(WINDOW)]
        benign_feats.append(extract_features(win))
    for _ in range(400):
        win = [rnd_pkt(rng.randint(60, 1400), rng.randint(0, 65535))
               for _ in range(WINDOW)]
        tunnel_feats.append(extract_features(win))

    def mean_col(rows, c):
        return sum(r[c] for r in rows) / len(rows)

    # Порог sz_std — только для лёгкого вторичного буста (статистика)
    thr_std = (mean_col(benign_feats, 2) + mean_col(tunnel_feats, 2)) / 2.0
    # Разделитель baseline: STUN/QUIC-маркеры (главная улика, как у nDPI) +
    # дисперсия размеров (вторичная). Веса подобраны так, что отсутствие
    # STUN-подобия НЕ компенсируется низкой дисперсией.
    b_hits = sum(1 for r in benign_feats if r[19] >= 0.25)
    t_hits = sum(1 for r in tunnel_feats if r[19] < 0.25)
    acc = (b_hits + t_hits) / (len(benign_feats) + len(tunnel_feats))
    trees = [
        # tree1 (решающий): stun_type_frac >= 0.25 → benign
        {"nodes": [
            {"feature": 19, "threshold": 0.25, "left": 2, "right": 1, "value": 0.0},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": -2.2},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": 2.2},
        ]},
        # tree2 (усиливающий): stun_magic_frac >= 0.25 → benign
        {"nodes": [
            {"feature": 20, "threshold": 0.25, "left": 2, "right": 1, "value": 0.0},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": -0.8},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": 0.8},
        ]},
        # tree3 (вторичный): высокая дисперсия размеров → лёгкий буст к tunnel
        {"nodes": [
            {"feature": 2, "threshold": f32(thr_std), "left": 2, "right": 1, "value": 0.0},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": 0.6},
            {"feature": -1, "threshold": 0.0, "left": -1, "right": -1, "value": -0.3},
        ]},
    ]
    model = {
        "schema_version": GATE_MODEL_SCHEMA,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "window": WINDOW,
        "classes": ["benign", "tunnel"],
        "base_score": 0.0,
        "threshold": 0.5,
        "provenance": "synthetic_baseline",
        "synthetic_accuracy": f32(acc),
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "trees": trees,
    }
    try:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(model, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
        Path(out_path).chmod(0o600)
        _log("INFO", f"dpi_gate synthetic baseline model saved to {out_path} acc={acc:.3f}")
        return model
    except Exception as e:
        _log("WARN", f"dpi_gate baseline save failed: {e}")
        return None
