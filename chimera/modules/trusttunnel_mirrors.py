"""
chimera/modules/trusttunnel_mirrors.py
───────────────────────────────────────────────────────────────────────────────
URL-builder для скачивания TrustTunnel release tarball'а.

Один источник — GitHub Releases. У TrustTunnel нет mirror-CDN (как,
например, у jsDelivr для fptn/mieru). Если GitHub недоступен с сервера
пользователя, остаётся ручное размещение tarball'а в /root/ —
download_manager.fetch_package проверяет /root/ до обращения в сеть.

Naming convention (подтверждён через GitHub API в Phase 0, v1.0.33):
  https://github.com/TrustTunnel/TrustTunnel/releases/download/v${VERSION}/trusttunnel-v${VERSION}-linux-${ARCH}.tar.gz

Точка входа:
    from chimera.modules.trusttunnel_mirrors import get_trusttunnel_mirrors
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations


def get_trusttunnel_mirrors(tag: str = "v1.0.33", filename: str = "") -> list[str]:
    """Вернуть список download URLs для TrustTunnel release tarball'а.

    Параметры:
      tag:      Release tag С ведущей 'v' (например 'v1.0.33').
      filename: Имя tarball'а (например
                'trusttunnel-v1.0.33-linux-x86_64.tar.gz').
                Если пусто — возвращает [] (caller должен передать через
                filename_builder).

    Возвращает:
      Список URL. Сейчас один — официальный GitHub Releases. Зеркал нет:
      если GitHub заблокирован, пользователь кладёт tarball в /root/
      вручную, и fetch_package подхватывает его без сети.
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
