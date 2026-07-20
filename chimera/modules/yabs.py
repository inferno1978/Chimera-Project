"""
chimera/modules/yabs.py
───────────────────────────────────────────────────────────────────────────────
Yet Another Bench Script (YABS) — Python port.

Original: https://github.com/masonr/yet-another-bench-script by Mason Rowe
MIT License — attribution preserved.

Порт на Python для интеграции в Chimera Project. Три теста:
  1. fio Disk Speed Tests (4k/64k/512k/1m random R+W) + dd fallback
  2. iperf3 Network Speed Tests (IPv4/IPv6, до 7 публичных серверов)
  3. Geekbench 6 (CPU single-core / multi-core)

Не требует pip-зависимостей — только stdlib. Внешние бинарники
(fio, iperf3, geekbench6) скачиваются автоматически если не установлены.

Точка входа: do_yabs_menu() — вызывается из _menu_diagnostics().
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Colors (from _core if available, fallback to empty) ─────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

YABS_VERSION = "v2026-07-03"

# ── Constants ────────────────────────────────────────────────────────────────
_BOX_W = 66

# iperf3 public servers — format: (host, port_range, name, location, modes)
_IPERF_SERVERS = [
    ("lon.speedtest.clouvider.net", "5200-5209", "Clouvider", "London, UK (10G)", "IPv4|IPv6"),
    ("iperf-ams-nl.eranium.net", "5201-5210", "Eranium", "Amsterdam, NL (100G)", "IPv4|IPv6"),
    ("speedtest.uztelecom.uz", "5200-5209", "Uztelecom", "Tashkent, UZ (10G)", "IPv4|IPv6"),
    ("speedtest.sin1.sg.leaseweb.net", "5201-5210", "Leaseweb", "Singapore, SG (10G)", "IPv4|IPv6"),
    ("la.speedtest.clouvider.net", "5200-5209", "Clouvider", "Los Angeles, CA, US (10G)", "IPv4|IPv6"),
    ("speedtest.nyc1.us.leaseweb.net", "5201-5210", "Leaseweb", "NYC, NY, US (10G)", "IPv4|IPv6"),
    ("speedtest.sao1.edgoo.net", "9204-9240", "Edgoo", "Sao Paulo, BR (1G)", "IPv4|IPv6"),
]

# Reduced set for -r flag
_IPERF_SERVERS_REDUCED = [
    ("lon.speedtest.clouvider.net", "5200-5209", "Clouvider", "London, UK (10G)", "IPv4|IPv6"),
    ("speedtest.sin1.sg.leaseweb.net", "5201-5210", "Leaseweb", "Singapore, SG (10G)", "IPv4|IPv6"),
    ("speedtest.nyc1.us.leaseweb.net", "5201-5210", "Leaseweb", "NYC, NY, US (10G)", "IPv4|IPv6"),
]

GEEKBENCH_URLS = {
    "x64":  "https://cdn.geekbench.com/Geekbench-6.7.1-Linux.tar.gz",
    "aarch64": "https://cdn.geekbench.com/Geekbench-6.7.1-LinuxARMPreview.tar.gz",
}

FIO_URLS = {
    "x64":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_x64",
    "x86":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_x86",
    "aarch64": "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_aarch64",
    "arm":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_arm",
}

IPERF3_URLS = {
    "x64":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_x64",
    "x86":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_x86",
    "aarch64": "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_aarch64",
    "arm":  "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_arm",
}


# ── Helpers ─────────────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         timeout: Optional[int] = None):
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if timeout:
        kw["timeout"] = timeout
    return subprocess.run(cmd, **kw)


def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _http_get(url: str, timeout: float = 15) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Chimera-YABS/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _http_download(url: str, dest: Path, timeout: float = 30) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Chimera-YABS/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dest.write_bytes(resp.read())
        dest.chmod(0o755)
        return True
    except Exception:
        return False


def _get_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("i386", "i686"):
        return "x86"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m in ("armv7l", "armv6l"):
        return "arm"
    return "unknown"


# ── Box rendering ───────────────────────────────────────────────────────────
def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - len(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = len(text)
    if w > _BOX_W:
        text = text[:_BOX_W-1] + "…"; w = len(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    _box_row(f"  {CYAN}{key}{NC}{' ' * max(0, kw - len(key))}  {val}")

def _box_ok(msg: str) -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_err(msg: str) -> None: _box_row(f"  {RED}✗{NC}  {msg}")


# ── Format helpers ──────────────────────────────────────────────────────────
def format_size(raw_kib: int) -> str:
    """Formats KiB → TiB/GiB/MiB/KiB."""
    if not isinstance(raw_kib, (int, float)) or raw_kib < 0:
        return ""
    if raw_kib >= 1073741824:
        return f"{raw_kib / 1073741824:.1f} TiB"
    if raw_kib >= 1048576:
        return f"{raw_kib / 1048576:.1f} GiB"
    if raw_kib >= 1024:
        return f"{raw_kib / 1024:.1f} MiB"
    return f"{raw_kib:.0f} KiB"


def format_speed(raw_kibs: float) -> str:
    """Formats KiB/s → GB/s/MB/s/KB/s (decimal, as in YABS)."""
    if raw_kibs is None or raw_kibs == "":
        return ""
    try:
        raw = float(raw_kibs)
    except (ValueError, TypeError):
        return ""
    if raw >= 976563:
        return f"{raw * 1024 / 1_000_000_000:.2f} GB/s"
    if raw >= 977:
        return f"{raw * 1024 / 1_000_000:.2f} MB/s"
    return f"{raw * 1024 / 1000:.2f} KB/s"


def format_iops(raw: float) -> str:
    """Formats IOPS: 8, 123, 1.7k, 275.9k."""
    if raw is None or raw == "":
        return ""
    try:
        val = float(raw)
    except (ValueError, TypeError):
        return ""
    if val >= 1000:
        return f"{val / 1000:.1f}k"
    return f"{int(val)}"


# ── System Info ─────────────────────────────────────────────────────────────
@dataclass
class SystemInfo:
    uptime: str = ""
    cpu_model: str = ""
    cpu_cores: str = ""
    cpu_freq: str = ""
    aes_ni: str = ""
    virt_ext: str = ""
    total_ram: str = ""
    total_swap: str = ""
    total_disk: str = ""
    distro: str = ""
    kernel: str = ""
    vm_type: str = ""
    ipv4: str = ""
    ipv6: str = ""


def _check_connectivity() -> tuple[bool, bool]:
    """Returns (ipv4_ok, ipv6_ok)."""
    ipv4_ok = _which("ping") is not None
    ipv6_ok = False
    if ipv4_ok:
        r4 = _run(["ping", "-4", "-c1", "-W2", "ipv4.google.com"],
                  capture=True, check=False, timeout=5)
        ipv4_ok = r4.returncode == 0
        r6 = _run(["ping", "-6", "-c1", "-W2", "ipv6.google.com"],
                  capture=True, check=False, timeout=5)
        ipv6_ok = r6.returncode == 0
    else:
        # fallback: try curl
        r4 = _http_get("https://ipv4.icanhazip.com", timeout=5)
        ipv4_ok = r4 is not None
        r6 = _http_get("https://ipv6.icanhazip.com", timeout=5)
        ipv6_ok = r6 is not None
    return ipv4_ok, ipv6_ok


def _read_uptime() -> str:
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        d = int(secs // 86400)
        h = int((secs % 86400) // 3600)
        m = int((secs % 3600) // 60)
        return f"{d} days, {h} hours, {m} minutes"
    except Exception:
        return "unknown"


def gather_system_info() -> SystemInfo:
    """Gather basic system information."""
    info = SystemInfo()
    info.uptime = _read_uptime()

    # CPU model
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        m = re.search(r'model name\s*:\s*(.+)', cpuinfo)
        if m:
            info.cpu_model = m.group(1).strip()
        else:
            # ARM: try lscpu
            if _which("lscpu"):
                r = _run(["lscpu"], capture=True, check=False)
                if r.stdout:
                    m2 = re.search(r'Model name:\s*(.+)', r.stdout)
                    if m2:
                        info.cpu_model = m2.group(1).strip()
    except Exception:
        info.cpu_model = "unknown"

    # CPU cores + freq
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        cores = len(re.findall(r'^processor\s*:', cpuinfo, re.MULTILINE))
        info.cpu_cores = str(cores)
        m = re.search(r'cpu MHz\s*:\s*(.+)', cpuinfo)
        if m:
            info.cpu_freq = f"{float(m.group(1).strip()):.0f} MHz"
        else:
            info.cpu_freq = "??? MHz"
    except Exception:
        info.cpu_cores = "?"
        info.cpu_freq = "??? MHz"

    # AES-NI
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        info.aes_ni = f"{GREEN}✓ Enabled{NC}" if "aes" in cpuinfo.lower() else f"{RED}✗ Disabled{NC}"
        info.virt_ext = f"{GREEN}✓ Enabled{NC}" if ("vmx" in cpuinfo.lower() or "svm" in cpuinfo.lower()) else f"{RED}✗ Disabled{NC}"
    except Exception:
        info.aes_ni = "unknown"
        info.virt_ext = "unknown"

    # RAM + Swap
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.strip().split()[0])
        info.total_ram = format_size(mem.get("MemTotal", 0))
        info.total_swap = format_size(mem.get("SwapTotal", 0))
    except Exception:
        info.total_ram = "unknown"
        info.total_swap = "unknown"

    # Disk
    try:
        r = _run(["df", "-t", "simfs", "-t", "ext2", "-t", "ext3", "-t", "ext4",
                  "-t", "btrfs", "-t", "xfs", "--total"], capture=True, check=False)
        if r.stdout:
            for line in r.stdout.splitlines():
                if "total" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        info.total_disk = format_size(int(parts[1]))
                        break
    except Exception:
        info.total_disk = "unknown"

    # Distro
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    info.distro = line.split('"')[1]
                    break
    except Exception:
        info.distro = "unknown"

    # Kernel
    info.kernel = platform.release()

    # VM type
    if _which("systemd-detect-virt"):
        r = _run(["systemd-detect-virt"], capture=True, check=False)
        info.vm_type = r.stdout.strip().upper() if r.stdout else "UNKNOWN"
    else:
        info.vm_type = "UNKNOWN"

    # Connectivity
    ipv4_ok, ipv6_ok = _check_connectivity()
    ipv4_str = f"{GREEN}✓ Online{NC}" if ipv4_ok else f"{RED}✗ Offline{NC}"
    ipv6_str = f"{GREEN}✓ Online{NC}" if ipv6_ok else f"{RED}✗ Offline{NC}"
    info.ipv4 = ipv4_str
    info.ipv6 = ipv6_str

    return info


def print_system_info(info: SystemInfo) -> None:
    print()
    print(f"{BOLD}Basic System Information:{NC}")
    print(f"{DIM}---------------------------------{NC}")
    print(f"Uptime     : {info.uptime}")
    print(f"Processor  : {info.cpu_model}")
    print(f"CPU cores  : {info.cpu_cores} @ {info.cpu_freq}")
    print(f"AES-NI     : {info.aes_ni}")
    print(f"VM-x/AMD-V : {info.virt_ext}")
    print(f"RAM        : {info.total_ram}")
    print(f"Swap       : {info.total_swap}")
    print(f"Disk       : {info.total_disk}")
    print(f"Distro     : {info.distro}")
    print(f"Kernel     : {info.kernel}")
    print(f"VM Type    : {info.vm_type}")
    print(f"IPv4/IPv6  : {info.ipv4} / {info.ipv6}")


# ── IP Info ─────────────────────────────────────────────────────────────────
def print_ip_info() -> None:
    """Get IP info from ip-api.com."""
    resp = _http_get("http://ip6.me/api/", timeout=10)
    if not resp:
        return
    parts = resp.strip().split(",")
    if len(parts) < 2:
        return
    net_type, net_ip = parts[0], parts[1]
    json_resp = _http_get(f"http://ip-api.com/json/{net_ip}", timeout=10)
    if not json_resp:
        return
    try:
        data = json.loads(json_resp)
    except Exception:
        return
    print()
    print(f"{net_type} Network Information:")
    print(f"---------------------------------")
    print(f"ISP        : {data.get('isp', 'Unknown')}")
    print(f"ASN        : {data.get('as', 'Unknown')}")
    if data.get('org'):
        print(f"Host       : {data['org']}")
    city = data.get('city', '')
    region = data.get('regionName', '')
    region_code = data.get('region', '')
    if city and region:
        print(f"Location   : {city}, {region} ({region_code})")
    if data.get('country'):
        print(f"Country    : {data['country']}")


# ── Disk Test ───────────────────────────────────────────────────────────────
BLOCK_SIZES = ["4k", "64k", "512k", "1m"]


def _get_fio_cmd(work_dir: Path, arch: str) -> Optional[str]:
    """Returns fio command path — local or downloaded."""
    local = _which("fio")
    if local:
        return local
    # Download fio binary
    url = FIO_URLS.get(arch)
    if not url:
        return None
    dest = work_dir / "fio"
    print(f"  {DIM}Скачиваю fio binary...{NC}", end="", flush=True)
    if _http_download(url, dest):
        print(f"\r  {GREEN}✓{NC}  fio скачан                    ")
        return str(dest)
    print(f"\r  {RED}✗{NC}  fio не скачался                ")
    return None


def run_fio_test(fio_cmd: str, work_dir: Path, arch: str) -> Optional[list]:
    """Run fio disk tests. Returns list of (bs, speed_r, iops_r, speed_w, iops_w, speed_rw, iops_rw) or None."""
    fio_size = "512M" if arch in ("aarch64", "arm") else "2G"
    test_file = work_dir / "test.fio"

    # Generate test file
    print(f"  {DIM}Generating fio test file...{NC}", end="", flush=True)
    _run([fio_cmd, f"--name=setup", "--ioengine=libaio", "--rw=read",
          "--bs=64k", "--iodepth=64", "--numjobs=2", f"--size={fio_size}",
          "--runtime=1", "--gtod_reduce=1", f"--filename={test_file}",
          "--direct=1", "--minimal"], capture=True, check=False, timeout=60)
    print(f"\r  {DIM}{'':40}{NC}")

    results = []
    for bs in BLOCK_SIZES:
        print(f"  {DIM}fio random R+W {bs}...{NC}", end="", flush=True)
        r = _run([fio_cmd, f"--name=rand_rw_{bs}", "--ioengine=libaio",
                  "--rw=randrw", "--rwmixread=50", f"--bs={bs}",
                  "--iodepth=64", "--numjobs=2", f"--size={fio_size}",
                  "--runtime=30", "--gtod_reduce=1", "--direct=1",
                  f"--filename={test_file}", "--group_reporting", "--minimal"],
                 capture=True, check=False, timeout=40)
        print(f"\r  {DIM}{'':40}{NC}")
        if r.stdout and f"rand_rw_{bs}" in r.stdout:
            line = r.stdout.strip()
            parts = line.split(";")
            if len(parts) >= 49:
                speed_r = float(parts[6]) if parts[6] else 0
                iops_r = float(parts[7]) if parts[7] else 0
                speed_w = float(parts[47]) if parts[47] else 0
                iops_w = float(parts[48]) if parts[48] else 0
                speed_rw = speed_r + speed_w
                iops_rw = iops_r + iops_w
                results.append((bs, speed_r, iops_r, speed_w, iops_w, speed_rw, iops_rw))
    return results if results else None


def run_dd_test(work_dir: Path) -> Optional[tuple]:
    """Fallback dd test. Returns (write_avg, read_avg) in MB/s or None."""
    test_file = work_dir / "dd.test"
    write_speeds = []
    read_speeds = []
    for _ in range(3):
        r = _run(["dd", "if=/dev/zero", f"of={test_file}", "bs=64k",
                  "count=16k", "oflag=direct"], capture=True, check=False, timeout=60)
        if r.stderr:
            m = re.search(r'(\d+\.?\d*)\s+(\w+)/s', r.stderr)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                if unit == "GB/s":
                    val *= 1000
                write_speeds.append(val)
        r = _run(["dd", f"if={test_file}", "of=/dev/null", "bs=8k"],
                 capture=True, check=False, timeout=60)
        if r.stderr:
            m = re.search(r'(\d+\.?\d*)\s+(\w+)/s', r.stderr)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                if unit == "GB/s":
                    val *= 1000
                read_speeds.append(val)
    try:
        test_file.unlink(missing_ok=True)
    except Exception:
        pass
    if write_speeds and read_speeds:
        return (sum(write_speeds) / len(write_speeds), sum(read_speeds) / len(read_speeds))
    return None


def print_disk_results(fio_results: Optional[list], partition: str) -> None:
    print()
    if fio_results:
        print(f"{BOLD}fio Disk Speed Tests (Mixed R/W 50/50){NC}")
        print(f"{BOLD}Partition: {partition}{NC}")
        print(f"{DIM}---------------------------------{NC}")
        print(f"{'Block Size':<12} | {'Read':>12} {'(IOPS)':>10} | {'Write':>12} {'(IOPS)':>10} | {'Total':>12} {'(IOPS)':>10}")
        print(f"{'-'*12} | {'-'*12} {'-'*10} | {'-'*12} {'-'*10} | {'-'*12} {'-'*10}")
        for bs, sr, ir, sw, iw, srw, irw in fio_results:
            print(f"{bs:<12} | {format_speed(sr):>12} {format_iops(ir):>10} | "
                  f"{format_speed(sw):>12} {format_iops(iw):>10} | "
                  f"{format_speed(srw):>12} {format_iops(irw):>10}")
    else:
        print(f"{BOLD}dd Sequential Disk Speed Tests:{NC}")
        print(f"{DIM}---------------------------------{NC}")


def disk_test_section(arch: str, work_dir: Path) -> None:
    """Run disk test section."""
    # Check disk space
    try:
        r = _run(["df", "-k", "."], capture=True, check=False)
        avail = 0
        if r.stdout:
            lines = r.stdout.strip().splitlines()
            if len(lines) >= 2:
                avail = int(lines[1].split()[3])
    except Exception:
        avail = 0

    min_space = 524288 if arch in ("aarch64", "arm") else 2097152
    if avail < min_space:
        print(f"\n{YELLOW}⚠  Недостаточно места на диске ({avail}KB). Пропускаю disk test.{NC}")
        return

    disk_dir = work_dir / "disk"
    disk_dir.mkdir(parents=True, exist_ok=True)

    fio_cmd = _get_fio_cmd(disk_dir, arch)
    fio_results = None
    if fio_cmd:
        fio_results = run_fio_test(fio_cmd, disk_dir, arch)

    if not fio_results:
        print(f"\n{YELLOW}⚠  fio недоступен. Запускаю dd fallback...{NC}")
        dd_result = run_dd_test(disk_dir)
        if dd_result:
            write_avg, read_avg = dd_result
            w_unit = "GB/s" if write_avg >= 1000 else "MB/s"
            w_val = write_avg / 1000 if write_avg >= 1000 else write_avg
            r_unit = "GB/s" if read_avg >= 1000 else "MB/s"
            r_val = read_avg / 1000 if read_avg >= 1000 else read_avg
            print(f"\n{BOLD}dd Sequential Disk Speed Tests:{NC}")
            print(f"{DIM}---------------------------------{NC}")
            print(f"Write : {w_val:.2f} {w_unit}")
            print(f"Read  : {r_val:.2f} {r_unit}")
        else:
            print(f"\n{RED}✗  Disk test failed.{NC}")
        return

    # Get partition
    partition = "unknown"
    try:
        r = _run(["df", "-P", "."], capture=True, check=False)
        if r.stdout:
            lines = r.stdout.strip().splitlines()
            if len(lines) >= 2:
                partition = lines[-1].split()[0]
    except Exception:
        pass

    print_disk_results(fio_results, partition)


# ── iperf3 Network Test ────────────────────────────────────────────────────
def _get_iperf3_cmd(work_dir: Path, arch: str) -> Optional[str]:
    local = _which("iperf3")
    if local:
        return local
    url = IPERF3_URLS.get(arch)
    if not url:
        return None
    dest = work_dir / "iperf3"
    print(f"  {DIM}Скачиваю iperf3 binary...{NC}", end="", flush=True)
    if _http_download(url, dest):
        print(f"\r  {GREEN}✓{NC}  iperf3 скачан                ")
        return str(dest)
    print(f"\r  {RED}✗{NC}  iperf3 не скачался            ")
    return None


def _iperf_one_server(iperf_cmd: str, server: tuple, mode: str) -> tuple:
    """Run iperf test to one server. Returns (send_speed, recv_speed, latency)."""
    host, ports_str, name, location, modes = server
    if mode not in modes:
        return ("", "", "")
    port_lo, port_hi = map(int, ports_str.split("-"))
    flags = ["-6"] if "IPv6" in mode else ["-4"]
    send_speed = ""
    recv_speed = ""
    latency = "--"

    # Send test (3 attempts)
    for attempt in range(3):
        port = __import__("random").randint(port_lo, port_hi)
        r = _run([iperf_cmd] + flags + ["-c", host, "-p", str(port), "-P", "8"],
                 capture=True, check=False, timeout=20)
        if r.stdout and "receiver" in r.stdout and "error" not in r.stdout:
            for line in r.stdout.splitlines():
                if "SUM" in line and "receiver" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        val = parts[6]
                        if val and val != "0.00":
                            send_speed = f"{val} {parts[7]}"
                            break
            if send_speed:
                break
        if r.stdout and "unable to connect" in r.stdout:
            break
        time.sleep(2)

    time.sleep(1)

    # Receive test (3 attempts)
    for attempt in range(3):
        port = __import__("random").randint(port_lo, port_hi)
        r = _run([iperf_cmd] + flags + ["-c", host, "-p", str(port), "-P", "8", "-R"],
                 capture=True, check=False, timeout=20)
        if r.stdout and "receiver" in r.stdout and "error" not in r.stdout:
            for line in r.stdout.splitlines():
                if "SUM" in line and "receiver" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        val = parts[6]
                        if val and val != "0.00":
                            recv_speed = f"{val} {parts[7]}"
                            break
            if recv_speed:
                break
        if r.stdout and "unable to connect" in r.stdout:
            break
        time.sleep(2)

    # Latency
    if _which("ping"):
        r = _run(["ping"] + flags + ["-c1", "-W2", host],
                 capture=True, check=False, timeout=5)
        if r.stdout:
            m = re.search(r'time=([\d.]+)', r.stdout)
            if m:
                latency = f"{m.group(1)} ms"

    return (send_speed or "busy", recv_speed or "busy", latency)


def network_test_section(arch: str, work_dir: Path, ipv4_ok: bool, ipv6_ok: bool,
                         reduced: bool = False) -> None:
    """Run iperf3 network speed tests."""
    iperf_cmd = _get_iperf3_cmd(work_dir, arch)
    if not iperf_cmd:
        print(f"\n{RED}✗  iperf3 недоступен. Пропускаю network test.{NC}")
        return

    servers = _IPERF_SERVERS_REDUCED if reduced else _IPERF_SERVERS

    for mode in (["IPv4"] if ipv4_ok else []) + (["IPv6"] if ipv6_ok else []):
        print()
        print(f"{BOLD}iperf3 Network Speed Tests ({mode}):{NC}")
        print(f"{DIM}---------------------------------{NC}")
        print(f"{'Provider':<15} | {'Location (Link)':<25} | {'Send Speed':<15} | {'Recv Speed':<15} | {'Ping':<15}")
        print(f"{'-'*15} | {'-'*25} | {'-'*15} | {'-'*15} | {'-'*15}")
        for server in servers:
            send, recv, lat = _iperf_one_server(iperf_cmd, server, mode)
            print(f"{server[2]:<15} | {server[3]:<25} | {send:<15} | {recv:<15} | {lat:<15}")


# ── Geekbench ──────────────────────────────────────────────────────────────
def geekbench_section(arch: str, work_dir: Path, total_ram_kib: int) -> None:
    """Run Geekbench 6 benchmark."""
    if arch == "x86":
        print(f"\n{YELLOW}⚠  Geekbench 6 не поддерживает 32-bit архитектуры. Пропускаю.{NC}")
        return
    if arch not in GEEKBENCH_URLS:
        print(f"\n{YELLOW}⚠  Архитектура {arch} не поддерживается Geekbench. Пропускаю.{NC}")
        return

    gb_dir = work_dir / "geekbench6"
    gb_dir.mkdir(parents=True, exist_ok=True)
    gb_cmd_name = "geekbench6"

    # Check for local install
    local_gb = _which(gb_cmd_name)
    if local_gb:
        gb_path = local_gb
    else:
        url = GEEKBENCH_URLS[arch]
        print(f"  {DIM}Скачиваю Geekbench 6 (~100MB)...{NC}", end="", flush=True)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Chimera-YABS/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                tmp_tar = work_dir / "gb.tar.gz"
                tmp_tar.write_bytes(resp.read())
            with tarfile.open(tmp_tar, "r:gz") as tar:
                tar.extractall(path=gb_dir)
            gb_path = str(gb_dir / gb_cmd_name)
            os.chmod(gb_path, 0o755)
            tmp_tar.unlink(missing_ok=True)
            print(f"\r  {GREEN}✓{NC}  Geekbench 6 скачан            ")
        except Exception as e:
            print(f"\r  {RED}✗{NC}  Geekbench не скачан: {e}    ")
            return

    # Check RAM
    if total_ram_kib <= 1048576:
        print(f"\n{YELLOW}⚠  Недостаточно RAM (≤1GB). Geekbench может не запуститься.{NC}")

    print(f"\n  {DIM}Running Geekbench 6... *cue elevator music*{NC}", end="", flush=True)
    r = _run([gb_path, "--upload"], capture=True, check=False, timeout=600)
    print(f"\r  {DIM}{'':50}{NC}")

    gb_url = ""
    if r.stdout:
        for line in r.stdout.splitlines():
            if "https://browser" in line:
                gb_url = line.split()[0]
                break

    if not gb_url:
        print(f"{RED}✗  Geekbench test failed.{NC}")
        if total_ram_kib <= 1048576:
            print(f"  {DIM}Возможная причина: мало RAM. Добавьте swap ≥1GB.{NC}")
        return

    # Wait for results to be available
    time.sleep(10)

    # Parse scores from browser page
    page = _http_get(gb_url, timeout=15)
    single = "?"
    multi = "?"
    if page:
        scores = re.findall(r"class='score'>(\d+)<", page)
        if not scores:
            scores = re.findall(r'class="score"[^>]*>(\d+)<', page)
        if len(scores) >= 2:
            single = scores[0]
            multi = scores[1]

    print()
    print(f"{BOLD}Geekbench 6 Benchmark Test:{NC}")
    print(f"{DIM}---------------------------------{NC}")
    print(f"{'Single Core':<15} : {single}")
    print(f"{'Multi Core':<15} : {multi}")
    print(f"{'Full Test':<15} : {gb_url}")


# ── Main entry point ────────────────────────────────────────────────────────
def run_yabs(skip_disk: bool = False, skip_network: bool = False,
             skip_geekbench: bool = False, reduced_net: bool = False) -> None:
    """Run YABS benchmark."""
    os.system("clear")
    print(f"{CYAN}# ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## #{NC}")
    print(f"{CYAN}#              Yet-Another-Bench-Script              #{NC}")
    print(f"{CYAN}#                     {YABS_VERSION}                    #{NC}")
    print(f"{CYAN}# https://github.com/masonr/yet-another-bench-script #{NC}")
    print(f"{CYAN}# ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## #{NC}")
    print()

    start_time = time.time()
    arch = _get_arch()
    if arch == "unknown":
        print(f"{RED}Architecture not supported.{NC}")
        _pause()
        return

    print(f"Architecture: {arch}")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # System info
    info = gather_system_info()
    print_system_info(info)

    # Get RAM in KiB for Geekbench check
    total_ram_kib = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total_ram_kib = int(line.split()[1])
                    break
    except Exception:
        pass

    # IP info
    if not skip_network:
        print_ip_info()

    # Create temp directory
    work_dir = Path(tempfile.mkdtemp(prefix="yabs_"))
    try:
        # Disk test
        if not skip_disk:
            print()
            disk_test_section(arch, work_dir)

        # Network test
        if not skip_network:
            network_test_section(arch, work_dir, "IPv4" in str(info.ipv4),
                                 "IPv6" in str(info.ipv6), reduced_net)

        # Geekbench
        if not skip_geekbench:
            geekbench_section(arch, work_dir, total_ram_kib)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠  Прервано пользователем.{NC}")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    elapsed = int(time.time() - start_time)
    if elapsed > 60:
        print(f"\nYABS completed in {elapsed // 60} min {elapsed % 60} sec")
    else:
        print(f"\nYABS completed in {elapsed} sec")


def do_yabs_menu() -> None:
    """TUI menu for YABS — called from _menu_diagnostics()."""
    while True:
        os.system("clear")
        _box_top("🚀  YABS — YET ANOTHER BENCH SCRIPT")
        _box_row()
        _box_kv("Версия:", YABS_VERSION)
        _box_kv("Источник:", "github.com/masonr/yet-another-bench-script")
        _box_kv("Автор:", "Mason Rowe (MIT License)")
        _box_row()
        _box_row(f"  {DIM}Три теста производительности сервера:{NC}")
        _box_row(f"  {DIM}  • fio Disk Speed (4k/64k/512k/1m R+W){NC}")
        _box_row(f"  {DIM}  • iperf3 Network (7 серверов, IPv4/IPv6){NC}")
        _box_row(f"  {DIM}  • Geekbench 6 (CPU single/multi core){NC}")
        _box_row()
        _box_sep()
        _box_item("1", "🚀  Полный бенчмарк (все 3 теста)")
        _box_item("2", "💾  Только disk test (fio)")
        _box_item("3", "🌐  Только network test (iperf3)")
        _box_item("4", "🧠  Только Geekbench 6 (CPU)")
        _box_item("5", "⚡  Быстрый network (3 сервера вместо 7)")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot()
        print()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            run_yabs()
            _pause()
        elif ch == "2":
            run_yabs(skip_network=True, skip_geekbench=True)
            _pause()
        elif ch == "3":
            run_yabs(skip_disk=True, skip_geekbench=True)
            _pause()
        elif ch == "4":
            run_yabs(skip_disk=True, skip_network=True)
            _pause()
        elif ch == "5":
            run_yabs(skip_disk=True, skip_geekbench=True, reduced_net=True)
            _pause()
        elif ch in ("q", ""):
            break


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        sys.exit(1)
    do_yabs_menu()
