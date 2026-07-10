"""
hydra/plugins/mieru/presets.py — Mieru traffic pattern presets.

Предоставляет 4 уровня обфускации трафика для Mieru (disabled / basic / medium / aggressive).
Кодирует параметры в base64-protobuf формат, ожидаемый sing-box/mita.
"""
from __future__ import annotations

import base64

# Протобуф типы полей для сериализатора
TCP_FRAGMENT_TYPES = {
    1: 0,  # enable: bool (varint)
    2: 0,  # maxSleepMs: int32 (varint)
}

NONCE_PATTERN_TYPES = {
    1: 0,  # type: NonceType enum (varint)
    2: 0,  # applyToAllUDPPacket: bool (varint)
    3: 0,  # minLen: int32 (varint)
    4: 0,  # maxLen: int32 (varint)
}

PADDING_PATTERN_TYPES = {
    1: 0,  # maxMiddlePaddingLen: int32 (varint)
    2: 0,  # maxEndPaddingLen: int32 (varint)
}

TRAFFIC_PATTERN_TYPES = {
    1: 0,  # seed: int32 (varint)
    2: 0,  # unlockAll: bool (varint)
    3: 2,  # tcpFragment: embedded message (length-delimited)
    4: 2,  # nonce: embedded message (length-delimited)
    5: 2,  # padding: embedded message (length-delimited)
}


def encode_varint(value: int) -> bytes:
    """Кодирует целое число в формат Varint (Base128)."""
    if value < 0:
        value &= 0xffffffffffffffff
    out = bytearray()
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value > 0:
            out.append(towrite | 0x80)
        else:
            out.append(towrite)
            break
    return bytes(out)


def encode_message(fields: dict, field_types: dict) -> bytes:
    """Минимальный сериализатор Protobuf сообщений."""
    out = bytearray()
    for field_num, val in sorted(fields.items()):
        if val is None:
            continue
        wire_type = field_types[field_num]
        header = (field_num << 3) | wire_type
        out.extend(encode_varint(header))
        
        if wire_type == 0:
            if isinstance(val, bool):
                val_int = 1 if val else 0
            else:
                val_int = int(val)
            out.extend(encode_varint(val_int))
        elif wire_type == 2:
            if isinstance(val, bytes):
                out.extend(encode_varint(len(val)))
                out.extend(val)
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
#  Определения пресетов
# ═════════════════════════════════════════════════════════════════════════════

PRESETS = {
    "disabled": {
        "name": "disabled",
        "label": "🔓 Disabled (Без обфускации)",
        "description": "Минимум оверхеда, максимальная скорость и производительность",
        "config": {
            "unlockAll": False,
            "tcpFragment": {"enable": False},
            "padding": {"maxMiddlePaddingLen": 0, "maxEndPaddingLen": 0}
        }
    },
    "basic": {
        "name": "basic",
        "label": "🔒 Basic (Базовый)",
        "description": "Легкая обфускация фрагментацией, минимальный оверхед (по умолчанию)",
        "config": {
            "unlockAll": False,
            "tcpFragment": {"enable": True, "maxSleepMs": 10}
        }
    },
    "medium": {
        "name": "medium",
        "label": "🔒 Medium (Средний)",
        "description": "Средняя фрагментация, printable-нонсы и умеренный паддинг",
        "config": {
            "unlockAll": False,
            "tcpFragment": {"enable": True, "maxSleepMs": 10},
            "nonce": {"type": 1, "applyToAllUDPPacket": True, "minLen": 6, "maxLen": 8},
            "padding": {"maxMiddlePaddingLen": 64, "maxEndPaddingLen": 128}
        }
    },
    "aggressive": {
        "name": "aggressive",
        "label": "🔒 Aggressive (Максимальный)",
        "description": "Глубокая фрагментация, случайные нонсы и максимальный паддинг",
        "config": {
            "unlockAll": True,
            "tcpFragment": {"enable": True, "maxSleepMs": 20},
            "nonce": {"type": 0, "applyToAllUDPPacket": True},
            "padding": {"maxMiddlePaddingLen": 128, "maxEndPaddingLen": 255}
        }
    }
}


def get_preset_base64(name: str) -> str:
    """Генерирует и возвращает base64-строку для указанного пресета."""
    preset = PRESETS.get(name)
    if not preset:
        preset = PRESETS["basic"]  # fallback
    
    cfg = preset["config"]
    
    # 1. tcpFragment
    tcp_bytes = None
    if "tcpFragment" in cfg:
        tcp_cfg = cfg["tcpFragment"]
        tcp_bytes = encode_message({
            1: tcp_cfg["enable"],
            2: tcp_cfg.get("maxSleepMs")
        }, TCP_FRAGMENT_TYPES)
        
    # 2. nonce
    nonce_bytes = None
    if "nonce" in cfg:
        nonce_cfg = cfg["nonce"]
        nonce_bytes = encode_message({
            1: nonce_cfg["type"],
            2: nonce_cfg["applyToAllUDPPacket"],
            3: nonce_cfg.get("minLen"),
            4: nonce_cfg.get("maxLen")
        }, NONCE_PATTERN_TYPES)
        
    # 3. padding
    pad_bytes = None
    if "padding" in cfg:
        pad_cfg = cfg["padding"]
        pad_bytes = encode_message({
            1: pad_cfg["maxMiddlePaddingLen"],
            2: pad_cfg["maxEndPaddingLen"]
        }, PADDING_PATTERN_TYPES)
        
    # 4. TrafficPattern
    tp_bytes = encode_message({
        2: cfg.get("unlockAll") if cfg.get("unlockAll") else None,
        3: tcp_bytes,
        4: nonce_bytes,
        5: pad_bytes
    }, TRAFFIC_PATTERN_TYPES)
    
    return base64.b64encode(tp_bytes).decode("utf-8")


def list_presets() -> list[dict]:
    """Возвращает список всех доступных пресетов."""
    return list(PRESETS.values())


def get_preset(name: str) -> dict:
    """Возвращает информацию о пресете по его имени."""
    preset = PRESETS.get(name)
    if not preset:
        preset = PRESETS["basic"]
    return preset
