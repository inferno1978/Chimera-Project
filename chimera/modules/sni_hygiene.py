"""
chimera/modules/sni_hygiene.py
───────────────────────────────────────────────────────────────────────────────
SNI/dest-гигиена: свой домен вместо доменов известных ресурсов.

ПРОБЛЕМА (2026): хостинги РФ стали вносить в ToS пункты о блокировке/удалении
серверов, у которых в SNI/dest обнаруживаются домены известных ресурсов
(Microsoft/Google/Cloudflare и т.п.) — сервер «маскируется» под чужой сайт,
хотя IP не принадлежит этому ресурсу. РКН likewise палит несоответствие
«SNI = известный домен, а IP = VPS-подсесь хостинга».

ПОЛИТИКА Chimera (v5.5.1, требование владельца проекта):
  • ПРИОРИТЕТ — собственный домен пользователя (Self-SNI паттерн,
    wiki.amnezia.host «Self-SNI для VLESS + Reality»): IP↔домен↔сертификат
    совпадают, наблюдатель видит домен, который реально живёт на этом IP.
    REALITY dest при этом — ЛОКАЛЬНЫЙ nginx-сокет с LE-сертификатом своего
    домена (петли не возникает: dest = сокет, а не домен:443).
  • Известные домены — ТОЛЬКО явный выбор пользователя для кастомизации
    (справочник KNOWN_SNI_DOMAINS + предупреждение warn_known_domain).
  • Нигде в дефолтах/фолбэках домены известных ресурсов не фигурируют.

Используется: install_prompts (Mode B dest), xray_install (self-SNI),
fragment_* (канонический SNI-рул), singbox (ShadowTLS handshake), naiveproxy
(fake_url), mtproto/Telemt (fake TLS домен), diagnostics.
"""
from __future__ import annotations

from typing import Optional


# ── Справочник известных ресурсов (ТОЛЬКО для явной кастомизации) ────────────
# Формат: (домен, категория, примечание). Список курируемый — не для дефолтов!
# Требования к домену-донору REALITY (wiki/ARCHITECT): TLS 1.3 + H2, ответ
# без редиректа, Certificate record ≤ 8192 байт (лимит TLS-парсера REALITY),
# не на том же CDN, что и ваш сервер.
KNOWN_SNI_DOMAINS: tuple = (
    ("www.cloudflare.com",  "Международный · Cloudflare",
     "ECDSA-цепочка компактная, Certificate ≤ 8192 — технически надёжный донор"),
    ("www.amazon.com",      "Международный · Amazon",      "Требует проверки TLS 1.3"),
    ("www.samsung.com",     "Международный · Samsung",     "Требует проверки TLS 1.3"),
    ("www.adobe.com",       "Международный · Adobe",       "Требует проверки TLS 1.3"),
    ("ya.ru",               "Россия · Яндекс",             "Для ру-эgress нод; РКН-хостинги не любит"),
    ("vk.com",              "Россия · ВКонтакте",          "Для ру-эgress нод"),
    ("discordapp.com",      "Международный · Discord",     "Часто блокируется сам"),
    ("www.icloud.com",      "Международный · Apple",       "Certificate может превышать лимит REALITY"),
    ("www.bing.com",        "Международный · Microsoft",   "См. предупреждение о microsoft.com"),
)

# Домены, известные техническими проблемами как REALITY dest.
# www.microsoft.com: баг TLS-парсера REALITY (Xray-core) — жёсткий лимит
# 8192 байт на Certificate record; у microsoft.com (Akamai) — 8273 байта,
# handshake падает для ЛЮБОГО клиента (воспроизведено на Xray 26.3.27).
REALITY_DEST_BROKEN: tuple = ("microsoft.com", "www.microsoft.com")

# Подсказка про бесплатный домен (wiki.amnezia.host, Self-SNI, шаг 1)
FREE_DOMAIN_HINT: str = (
    "Нет домена? duckdns.org даёт бесплатный (mysite.duckdns.org): войдите "
    "через GitHub/Google, укажите IP этого сервера — и используйте его как "
    "свой SNI/dest"
)


def _host_of(value: str) -> str:
    """Выделяет hostname из 'host:port' / URL / голого домена."""
    if not isinstance(value, str):
        return ""
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    if ":" in v:
        v = v.rsplit(":", 1)[0]
    return v.strip(".")


def is_known_resource_domain(host: str) -> bool:
    """True если host — домен известного ресурса (маскировка под него
    триггерит ToS РФ-хостингов и РКН-эвристики)."""
    h = _host_of(host)
    if not h:
        return False
    for dom, _, _ in KNOWN_SNI_DOMAINS + tuple(
            (d, "", "") for d in REALITY_DEST_BROKEN):
        d = _host_of(dom)
        if h == d or h.endswith("." + d):
            return True
    # Широкие суффиксы популярных экосистем (вкл. поддомены CDN)
    for suffix in ("microsoft.com", "google.com", "cloudflare.com",
                   "apple.com", "icloud.com", "amazon.com", "bing.com",
                   "yandex.ru", "yandex.com", "ya.ru", "vk.com",
                   "googletagmanager.com"):
        if h == suffix or h.endswith("." + suffix):
            return True
    return False


def is_broken_reality_dest(host: str) -> bool:
    """True если домен заведомо ломает REALITY (Certificate > 8192 байт)."""
    h = _host_of(host)
    return any(h == _host_of(d) or h.endswith("." + _host_of(d))
               for d in REALITY_DEST_BROKEN)


def own_masking_domain(state: Optional[dict]) -> str:
    """Свой домен из state (domain) — приоритетный кандидат SNI/dest.

    Возвращает '' если домена нет. Никогда не фолбэчится на известные
    домены — пустой результат означает «спросить пользователя».
    """
    if not isinstance(state, dict):
        return ""
    d = _host_of(str(state.get("domain") or ""))
    return d


def warn_known_domain_text(host: str) -> str:
    """Текст предупреждения для явного выбора известного домена."""
    base = (f"⚠️  {host} — домен известного ресурса. РФ-хостинги вносят в "
            f"ToS блокировку серверов, маскирующихся под чужие популярные "
            f"сайты (SNI не совпадает с владельцем IP), РКН фиксирует это "
            f"же несоответствие. Рекомендуется СВОЙ домен.")
    if is_broken_reality_dest(host):
        base += (f" КРОМЕ ТОГО: {host} как REALITY dest технически сломан — "
                 f"Certificate record не укладывается в лимит 8192 байт "
                 f"TLS-парсера REALITY, handshake падает у всех клиентов.")
    return base


# ── Каноническое SNI-правило (клиентская сторона) ────────────────────────────
def client_sni_for_state(state: Optional[dict]) -> str:
    """SNI для клиентского подключения по state (канон Chimera).

    Режим B + AWG-exit + reality_dest → reality_dest (host-часть) —
    совпадает с serverNames сервера. Иначе — domain (свой домен; в
    режимах A REALITY serverNames сервера = domain). Никогда не
    фолбэчится на известные домены: нет данных → ''.
    """
    if not isinstance(state, dict):
        return ""
    rd = str(state.get("reality_dest") or "")
    if (state.get("awg_exit_enabled")
            and str(state.get("install_mode") or "") == "B" and rd):
        return _host_of(rd)
    return _host_of(str(state.get("domain") or ""))


# ── Self-SNI (Mode B): свой домен + локальный nginx-сокет ────────────────────
def reality_self_sni(dest: str, own_domain: str) -> bool:
    """True если REALITY dest в Mode B указывает на СВОЙ домен.

    В этом случае xray обязан брать dest = ЛОКАЛЬНЫЙ nginx-сокет с
    LE-сертификатом этого домена (как в Mode A), а НЕ domain:443 —
    иначе возникает петля (xray коннектится сам к себе на 443, где его
    собственный REALITY-inbound с тем же dest — бесконечный цикл).
    IP↔домен↔сертификат совпадают; SNI на проводе = свой домен.
    """
    return bool(own_domain) and _host_of(dest) == _host_of(own_domain)


def reality_server_settings(awg_exit_enabled: bool, reality_dest: str,
                            own_domain: str, socket_path: str) -> dict:
    """dest/xver/serverNames для REALITY-inbound (единая точка правды).

    Три случая:
      • Mode A (AWG выкл): dest = nginx-сокет, xver=1 (Proxy Protocol для
        nginx), serverNames = [свой домен];
      • Mode B + ЧУЖОЙ dest (явный выбор): dest = domain:443 (заём
        TLS-хендшейка у внешнего сайта), xver=0 (PP некому читать),
        serverNames = [reality_dest];
      • Mode B + Self-SNI (dest = свой домен): dest = nginx-сокет с
        LE-сертификатом своего домена (петли нет), xver=1,
        serverNames = [свой домен] — SNI на проводе = свой домен,
        известных ресурсов нет нигде.
    """
    if awg_exit_enabled and not reality_self_sni(reality_dest, own_domain):
        return {"dest": reality_dest + ":443", "xver": 0,
                "serverNames": [reality_dest]}
    return {"dest": socket_path, "xver": 1, "serverNames": [own_domain]}
