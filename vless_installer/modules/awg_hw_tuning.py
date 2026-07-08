"""
vless_installer/modules/awg_hw_tuning.py
───────────────────────────────────────────────────────────────────────────────
Hardware-aware tuning для AmneziaWG 2.0 standalone.

Применяет idempotent-настройки:
  • sysctl (ip_forward, BBR, fq, сетевые буферы)
  • swap (подгон под RAM)
  • NIC offloads (по возможности)

ВАЖНО: проверяет текущие значения через `sysctl -n` — применяет только если
значение не оптимально. Не перезаписывает настройки, сделанные VLESS-установщиком
или пользователем вручную.
"""
from __future__ import annotations

import re
from pathlib import Path

from .awg_constants import AWGS_SYSCTL_TARGETS


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# ── sysctl ──────────────────────────────────────────────────────────────────

def awgs_sysctl_get(key: str) -> str:
    """Читает текущее значение sysctl-параметра."""
    core = _core_module()
    r = core._run(["sysctl", "-n", key], capture=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def awgs_sysctl_set(key: str, value) -> bool:
    """Применяет значение sysctl (одновременно в runtime и в /etc/sysctl.d/)."""
    core = _core_module()
    # Runtime
    r = core._run(["sysctl", "-w", f"{key}={value}"], capture=True, check=False, quiet=True)
    if r.returncode != 0:
        core.log_to_file("WARN", f"awgs_sysctl_set runtime: {key}={value}: {r.stderr}")
        return False
    # Persistent: дописываем в /etc/sysctl.d/99-awg-standalone.conf
    conf = Path("/etc/sysctl.d/99-awg-standalone.conf")
    try:
        existing = conf.read_text() if conf.exists() else ""
        # Удаляем старую строку с этим ключом
        new_lines = [l for l in existing.splitlines() if not l.startswith(f"{key}=")]
        new_lines.append(f"{key} = {value}")
        conf.write_text("\n".join(new_lines) + "\n")
    except Exception as e:
        core.log_to_file("WARN", f"awgs_sysctl_set persistent: {e}")
    return True


def awgs_sysctl_apply_idempotent() -> dict:
    """
    Применяет все целевые sysctl-настройки idempotent-методом.
    Возвращает dict: {key: {"old": "...", "new": "...", "changed": bool}}
    """
    core = _core_module()
    results = {}
    for key, target in AWGS_SYSCTL_TARGETS.items():
        current = awgs_sysctl_get(key)
        # IPv6 forwarding — пропускаем если IPv6 выключен на хосте
        if key == "net.ipv6.conf.all.forwarding":
            ipv6_check = core._run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
                                   capture=True, check=False)
            if ipv6_check.stdout.strip() == "1":
                results[key] = {"old": current, "new": current, "changed": False,
                                "skipped": "IPv6 disabled on host"}
                continue
        if str(current) == str(target):
            results[key] = {"old": current, "new": current, "changed": False}
            continue
        ok = awgs_sysctl_set(key, target)
        results[key] = {
            "old": current,
            "new": str(target) if ok else current,
            "changed": ok,
        }
        if ok:
            core.log_to_file("INFO", f"awgs_sysctl: {key} {current} → {target}")
    return results


# ── Swap optimization ───────────────────────────────────────────────────────

def awgs_detect_ram_mb() -> int:
    """Возвращает размер RAM в МБ."""
    try:
        meminfo = Path("/proc/meminfo").read_text()
        m = re.search(r"^MemTotal:\s+(\d+)\s+kB", meminfo, re.MULTILINE)
        if m:
            return int(m.group(1)) // 1024
    except Exception:
        pass
    return 0


def awgs_optimize_swap() -> dict:
    """
    Подгоняет swap под размер RAM (как в bivlked).
    Правило: swap = max(1G, RAM/2) если RAM < 4G; иначе swap = RAM/4.
    Ничего не делает если swap уже корректного размера.
    """
    core = _core_module()
    result = {"ram_mb": 0, "current_swap_mb": 0, "target_swap_mb": 0, "changed": False}

    ram = awgs_detect_ram_mb()
    result["ram_mb"] = ram
    if ram == 0:
        return result

    # Текущий swap
    r = core._run(["swapon", "--show=SIZE", "--bytes", "--noheadings"],
                  capture=True, check=False)
    current_swap_bytes = 0
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    current_swap_bytes += int(line)
                except ValueError:
                    pass
    current_swap_mb = current_swap_bytes // (1024 * 1024)
    result["current_swap_mb"] = current_swap_mb

    # Целевой swap
    if ram < 4096:
        target_swap_mb = max(1024, ram // 2)
    else:
        target_swap_mb = ram // 4
    result["target_swap_mb"] = target_swap_mb

    # Если текущий swap уже >= target — не трогаем
    if current_swap_mb >= target_swap_mb:
        return result

    # Создаём/расширяем swap-файл (только если /swapfile не существует
    # или меньше target). Не трогаем существующие swap-разделы.
    swapfile = Path("/swapfile")
    try:
        # Проверяем, есть ли уже swap-файл
        if swapfile.exists():
            current_size = swapfile.stat().st_size // (1024 * 1024)
            if current_size >= target_swap_mb:
                return result
            # Удаляем старый swap-файл
            core._run(["swapoff", str(swapfile)], check=False, quiet=True)
            swapfile.unlink()

        # Создаём новый
        core._run(["fallocate", "-l", f"{target_swap_mb}M", str(swapfile)],
                  check=False, quiet=True)
        core._run(["chmod", "600", str(swapfile)], check=False, quiet=True)
        core._run(["mkswap", str(swapfile)], check=False, quiet=True)
        core._run(["swapon", str(swapfile)], check=False, quiet=True)

        # Добавляем в /etc/fstab если ещё нет
        fstab = Path("/etc/fstab")
        if fstab.exists():
            fstab_content = fstab.read_text()
            if "/swapfile" not in fstab_content:
                fstab.write_text(fstab_content.rstrip() + f"\n/swapfile none swap sw 0 0\n")

        result["changed"] = True
        core.log_to_file("INFO", f"awgs_swap: создан /swapfile {target_swap_mb}M")
    except Exception as e:
        core.log_to_file("WARN", f"awgs_optimize_swap: {e}")

    return result


# ── NIC offloads ────────────────────────────────────────────────────────────

def awgs_detect_default_iface() -> str:
    """Возвращает имя интерфейса по умолчанию (через который идёт default route)."""
    core = _core_module()
    r = core._run(["ip", "route", "show", "default"], capture=True, check=False)
    if r.returncode == 0:
        # default via X.X.X.X dev eth0 ...
        m = re.search(r"\bdev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    return ""


def awgs_optimize_nic() -> dict:
    """
    Включает NIC offloads (GRO/GSO/TSO) если они выключены.
    Не делает ничего если ethtool не установлен или offload уже включён.
    """
    core = _core_module()
    result = {"iface": "", "changed": [], "skipped": ""}

    iface = awgs_detect_default_iface()
    if not iface:
        result["skipped"] = "Не удалось определить default interface"
        return result
    result["iface"] = iface

    # Проверяем ethtool
    r = core._run(["which", "ethtool"], capture=True, check=False)
    if r.returncode != 0:
        result["skipped"] = "ethtool не установлен — пропускаем NIC offloads"
        return result

    # Проверяем текущие offloads
    for offload in ("gro", "gso", "tso"):
        r = core._run(["ethtool", "-k", iface], capture=True, check=False)
        if r.returncode != 0:
            result["skipped"] = f"ethtool -k {iface} failed"
            return result
        # Ищем строку вида "generic-receive-offload: on"
        m = re.search(rf"^{offload.replace('gro', 'generic-receive-offload').replace('gso', 'generic-segmentation-offload').replace('tso', 'tcp-segmentation-offload')}:\s+(\w+)",
                      r.stdout, re.MULTILINE | re.IGNORECASE)
        if m and m.group(1).lower() == "on":
            continue
        # Включаем
        core._run(["ethtool", "-K", iface, offload, "on"],
                  check=False, quiet=True)
        result["changed"].append(offload)

    if result["changed"]:
        core.log_to_file("INFO", f"awgs_nic: включены offloads {result['changed']} на {iface}")
    return result


# ── Полный hardware-tuning ──────────────────────────────────────────────────

def awgs_hw_tune_all() -> dict:
    """
    Применяет все hardware-оптимизации (sysctl + swap + NIC).
    Возвращает суммарный отчёт.
    """
    core = _core_module()
    core.info("Применение hardware-оптимизаций (idempotent)...")

    report = {
        "sysctl": awgs_sysctl_apply_idempotent(),
        "swap":   awgs_optimize_swap(),
        "nic":    awgs_optimize_nic(),
    }

    # Краткий вывод
    sysctl_changed = sum(1 for v in report["sysctl"].values() if v.get("changed"))
    if sysctl_changed:
        core.success(f"sysctl: применено {sysctl_changed} новых значений")
    else:
        core.info("sysctl: всё уже оптимально")

    if report["swap"]["changed"]:
        core.success(f"swap: создан /swapfile {report['swap']['target_swap_mb']}M")
    else:
        core.info(f"swap: уже {report['swap']['current_swap_mb']}M (достаточно)")

    if report["nic"]["changed"]:
        core.success(f"NIC: включены offloads {report['nic']['changed']} на {report['nic']['iface']}")
    elif report["nic"]["skipped"]:
        core.info(f"NIC: {report['nic']['skipped']}")

    return report
