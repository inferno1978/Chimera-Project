"""
vless_installer/modules/trusttunnel_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec for TrustTunnel prebuilt binaries (TrustTunnel/TrustTunnel GitHub releases).

Used by trusttunnel.py::_download_and_install_binary() to download the Linux
release tarball containing:
  - trusttunnel_endpoint   (the server binary)
  - trusttunnel_endpoint.sig (GPG detached signature)
  - setup_wizard           (config generator)
  - setup_wizard.sig
  - LICENSE
  - trusttunnel.service.template

Naming convention (verified via GitHub API against v1.0.33):
  https://github.com/TrustTunnel/TrustTunnel/releases/download/v${VERSION}/trusttunnel-v${VERSION}-linux-${ARCH}.tar.gz

post_install does:
  1. tar xzf {src} {tmpdir}
  2. Find trusttunnel_endpoint + setup_wizard + trusttunnel_endpoint.sig + setup_wizard.sig
  3. copy2 to /opt/trusttunnel/ (chmod 0o755 for binaries, 0o644 for .sig)
  4. cleanup tmpdir

install_dests = [/opt/trusttunnel] — the install directory.
manual_incoming_dir = /root/ — not equal to install_dests (PackageSpec invariant).

Tones of entry:
    from vless_installer.modules.trusttunnel_packages import TRUSTTUNNEL_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.trusttunnel_mirrors import get_trusttunnel_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================
_TRUSTTUNNEL_INSTALL_DESTS: list[Path] = [Path("/opt/trusttunnel")]
_MANUAL_DIR = Path("/root")

# Minimum tarball size: real v1.0.33 x86_64 = ~10.7 MB. 1 MB threshold
# catches HTML 404 pages.
_MIN_TARBALL_SIZE = 1_000_000

# Files we extract from the tarball.
_BINARIES_TO_COPY = ["trusttunnel_endpoint", "setup_wizard"]
_SIGS_TO_COPY = ["trusttunnel_endpoint.sig", "setup_wizard.sig"]
_OTHER_FILES = ["LICENSE", "trusttunnel.service.template"]


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _trusttunnel_mirror_urls(filename: str, tag: str = "v1.0.33", **kw) -> list[str]:
    """Build mirror URLs for the TrustTunnel release tarball.

    filename — passed by download_manager (built by filename_builder).
    tag — release tag including the leading 'v' (e.g. 'v1.0.33').
    """
    if not filename:
        return []
    return get_trusttunnel_mirrors(tag=tag, filename=filename)


# ============================================================================
#  post_install — tar xzf + copy binaries + sigs to /opt/trusttunnel
# ============================================================================
def _post_install_trusttunnel(src: Path, install_dests: list[Path]) -> bool:
    """Extract the tarball and copy binaries + sigs to install_dests[0]/.

    Returns True if BOTH binaries (trusttunnel_endpoint + setup_wizard) are
    found and copied. False on any failure — gives fetch_package a chance to
    try the next mirror.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="trusttunnel-extract-"))
    try:
        # 1. tar xzf
        r = subprocess.run(
            ["tar", "xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Find the extracted directory (trusttunnel-v{ver}-linux-{arch}/)
        # Walk and locate the binaries by name.
        found_endpoint = False
        found_wizard = False
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)

        for name in _BINARIES_TO_COPY + _SIGS_TO_COPY + _OTHER_FILES:
            # Find first match anywhere under tmp/
            matches = list(tmp.rglob(name))
            if not matches:
                continue
            src_file = matches[0]
            dest_file = dest_dir / name
            shutil.copy2(str(src_file), str(dest_file))
            if name in _BINARIES_TO_COPY:
                dest_file.chmod(0o755)
                if name == "trusttunnel_endpoint":
                    found_endpoint = True
                elif name == "setup_wizard":
                    found_wizard = True
            else:
                try:
                    dest_file.chmod(0o644)
                except Exception:
                    pass

        return found_endpoint and found_wizard

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec
# ============================================================================
TRUSTTUNNEL_SPEC = PackageSpec(
    name="trusttunnel prebuilt binaries",
    filename_builder=lambda tag, **kw: _build_filename(tag),
    mirror_urls_builder=_trusttunnel_mirror_urls,
    install_dests=_TRUSTTUNNEL_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_TARBALL_SIZE,
    post_install=_post_install_trusttunnel,
)


def _build_filename(tag: str = "v1.0.33", **kw) -> str:
    """Build the tarball filename based on tag + current architecture.

    Naming convention (verified against v1.0.33 release assets):
      trusttunnel-v${VERSION}-linux-x86_64.tar.gz
      trusttunnel-v${VERSION}-linux-aarch64.tar.gz

    where VERSION is the tag without the leading 'v'.
    """
    import platform
    version = tag.lstrip("v")
    arch = platform.machine().lower()
    # Normalize arch names to match upstream's convention
    if arch in ("x86_64", "amd64"):
        arch = "x86_64"
    elif arch in ("aarch64", "arm64"):
        arch = "aarch64"
    else:
        arch = "x86_64"  # safe default
    return f"trusttunnel-v{version}-linux-{arch}.tar.gz"
