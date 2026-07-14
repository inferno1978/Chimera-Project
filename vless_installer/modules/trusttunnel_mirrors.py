"""
vless_installer/modules/trusttunnel_mirrors.py
───────────────────────────────────────────────────────────────────────────────
URL builders for TrustTunnel release tarballs.

Single source (GitHub Releases) — no mirror CDN exists for this project.
If GitHub becomes unreachable, the user can manually place the tarball in
/root/ (manual_incoming_dir in trusttunnel_packages.py) and fetch_package
will pick it up.

Naming convention (verified via GitHub API in Phase 0):
  https://github.com/TrustTunnel/TrustTunnel/releases/download/v${VERSION}/trusttunnel-v${VERSION}-linux-${ARCH}.tar.gz

Public API:
    get_trusttunnel_mirrors(tag="v1.0.33", filename="trusttunnel-v1.0.33-linux-x86_64.tar.gz")
        -> list[str]
"""
from __future__ import annotations


def get_trusttunnel_mirrors(tag: str = "v1.0.33", filename: str = "") -> list[str]:
    """Return the list of download URLs for the TrustTunnel release tarball.

    Parameters:
      tag:      Release tag WITH leading 'v' (e.g. 'v1.0.33').
      filename: The tarball filename (e.g. 'trusttunnel-v1.0.33-linux-x86_64.tar.gz').
                If empty, returns [] (caller must provide it via filename_builder).

    Returns:
      List of URLs. Currently only the official GitHub Releases URL — no
      mirrors exist. If GitHub is blocked from the user's server, they can
      pre-place the tarball at /root/{filename} and fetch_package will use
      it without hitting the network.
    """
    if not filename:
        return []
    if not tag:
        tag = "v1.0.33"
    if not tag.startswith("v"):
        tag = "v" + tag
    return [
        f"https://github.com/TrustTunnel/TrustTunnel/releases/download/{tag}/{filename}",
    ]
