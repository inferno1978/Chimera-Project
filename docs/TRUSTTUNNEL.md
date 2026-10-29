# TrustTunnel (AdGuard VPN protocol)

> Секция README.md, вынесенная миграцией 2026-10-29 (в README — краткое резюме).
> Текст не менялся.

## 🔐 TrustTunnel (AdGuard VPN protocol)

**Меню:** главное → `18` · **Upstream:** https://github.com/TrustTunnel/TrustTunnel

Референсная реализация протокола AdGuard VPN на Rust (Apache 2.0, open-source с января 2026). Интеграция использует **официальный upstream-бинарник** `trusttunnel_endpoint` + `setup_wizard` (prebuilt, GPG-подписан ключом AdGuard `28645AC9...`) — НЕ форк и НЕ реимплементация. Транспорт: HTTP/2-over-TLS (TCP) и HTTP/3-over-QUIC (UDP) с мультиплексированием TCP/UDP/ICMP. Выдача доступа пользователю — через deep-link `tt://?<base64url>` (upstream TLV-формат), который встраивается в существующий self-service Telegram-бот наравне с `vless://`, `vpn://`, `hysteria2://`.

**Порт по умолчанию: `8443` (TCP + UDP).** Это отдельный порт, не 443 — порт 443 уже занят VLESS (TCP, REALITY или xHTTP) и Hysteria2 (UDP), а TrustTunnel слушает одновременно TCP и UDP на одном номере порта, не имеет SNI-dispatch и не умеет fallback. При установке конфликт проверяется через `core.check_port_used_by_other_protocol`.

Сертификаты — через существующий конвейер `ssl_certbot.obtain_ssl_cert()`. `setup_wizard` запускается БЕЗ `--cert-type` (обход upstream-дедлока ≤ v1.0.33 — ветки provided/letsencrypt гарантированно виснут в non-interactive, см. TROUBLESHOOTING.md §3), после чего `hosts.toml` перегенерируется на LE-пути. Авто-renewal — через certbot cron + deploy-hook `systemctl reload trusttunnel` (SIGHUP перезагружает `hosts.toml` без рестарта, без разрыва активных сессий).

Управление пользователями — общий `user_lifecycle.TrustTunnelAdapter`, credentials в `/opt/trusttunnel/credentials.toml` (TOML, массив `[[client]]`). Известные ограничения — см. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) (агрегированный трафик, рестарт при смене пользователей).
