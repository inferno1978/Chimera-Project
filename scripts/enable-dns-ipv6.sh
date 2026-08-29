#!/usr/bin/env bash
# ============================================================================
#  Chimera Project — enable-dns-ipv6.sh (v72)
# ============================================================================
#  Включает IPv6 в DNS-стеке на ЖИВОМ сервере (AGH + dnscrypt):
#
#    1. dnscrypt-proxy.toml: listen_addresses += '[::1]:PORT'
#       (127.0.0.1 всегда первый — на него ориентируются остальные модули)
#    2. AdGuardHome.yaml: bind_hosts += <публичный IPv6 сервера>
#       (конкретный адрес, не '::' — wildcard конфликтует с 127.0.0.1)
#    3. UFW: проверяет DoT :853/DoH :30443 (уже публичны по дизайну,
#       ufw-правило покрывает v4+v6 автоматически).
#
#  ЧЕГО СКРИПТ НЕ ДЕЛАЕТ (осознанно, дизайн проекта v65):
#    НЕ открывает :53 наружу в UFW — иначе получится open resolver
#    (усиление DDoS). Публичный IPv6-доступ к DNS — через DoT :853 и
#    DoH :30443, которые уже открыты. IPv6-клиенты появляются в
#    статистике AGH («Частые клиенты») при подключении по DoT/DoH.
#
#  Идемпотентен: повторный запуск ничего не ломает (пропускает готовое).
#  Безопасен: бэкап каждого файла перед правкой + проверка сервиса +
#  DNS-ALIVE проверка + авточтобыоткат при падении.
#
#  Запуск:  sudo bash scripts/enable-dns-ipv6.sh
# ============================================================================
set -uo pipefail

B="\033[1m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; C="\033[36m"; N="\033[0m"
ok()   { echo -e "  ${G}[OK]${N} $*"; }
skip() { echo -e "  ${C}[..]${N} $*"; }
bad()  { echo -e "  ${R}[!!]${N} $*"; }
hdr()  { echo -e "\n${B}── $* ──${N}"; }

TS="$(date +%Y%m%d%H%M%S)"

# ── 0. root + пути ──────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "Запусти от root: sudo bash $0"; exit 1; }

DNSTOML="/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
AGHYAML="/opt/AdGuardHome/AdGuardHome.yaml"
DNS_SVC="dnscrypt-proxy"
AGH_SVC="AdGuardHome"

# Авто-детект путей из systemd-юнитов (если дефолтные не нашлись)
if [ ! -f "$DNSTOML" ]; then
    p="$(systemctl cat "$DNS_SVC" 2>/dev/null | grep -oP '(?<=-config )\S+' | head -1)"
    [ -n "$p" ] && [ -f "$p" ] && DNSTOML="$p"
fi
if [ ! -f "$AGHYAML" ]; then
    p="$(systemctl cat "$AGH_SVC" 2>/dev/null | grep -oP '(?<=-c |--config )\S+' | head -1)"
    [ -n "$p" ] && [ -f "$p" ] && AGHYAML="$p"
    [ ! -f "$AGHYAML" ] && p="$(systemctl cat "$AGH_SVC" 2>/dev/null | grep -oP '(?<=-w |--workdir )\S+' | head -1)/AdGuardHome.yaml" && [ -f "$p" ] && AGHYAML="$p"
fi

wait_svc() {  # wait_svc <имя> <сек>
    local i
    for ((i=1; i<=$2; i++)); do
        systemctl is-active --quiet "$1" && return 0
        sleep 1
    done
    return 1
}

dns_alive() {  # системный DNS реально отвечает
    timeout 8 getent hosts ya.ru >/dev/null 2>&1
}

# ── 1. Публичный IPv6 ───────────────────────────────────────────────────────
hdr "1/4  Поиск публичного IPv6"
V6="$(python3 - << 'PYEOF'
import re, subprocess
try:
    r = subprocess.run(["ip", "-6", "addr", "show", "scope", "global"],
                       capture_output=True, text=True, check=False, timeout=10)
    cands = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*inet6\s+([0-9a-fA-F:]+)/(\d+)\s+scope\s+global\s*(.*)", line)
        if not m:
            continue
        addr, flags = m.group(1), (m.group(3) or "")
        if addr.startswith("fe80") or "." in addr:
            continue
        cands.append((addr.lower(), "temporary" in flags or "deprecated" in flags))
    stable = [a for a, f in cands if not f]
    pool = stable or [a for a, _ in cands]
    print(pool[0] if pool else "")
except Exception:
    print("")
PYEOF
)"
if [ -z "$V6" ]; then
    bad "Глобальный IPv6 не найден (нет адреса/маршрута). Нечего включать."
    exit 1
fi
ok "IPv6: $V6"

# ── 2. dnscrypt-proxy: [::1]:PORT ───────────────────────────────────────────
hdr "2/4  dnscrypt-proxy — слушатель [::1]"
if [ ! -f "$DNSTOML" ]; then
    skip "TOML не найден ($DNSTOML) — dnscrypt не установлен, пропускаю"
elif grep -q "\[::1\]" "$DNSTOML" 2>/dev/null && systemctl is-active --quiet "$DNS_SVC"; then
    skip "'[::1]' уже в конфиге, сервис активен — готово"
else
    BAK="$DNSTOML.$TS.preIPv6.bak"
    cp -a "$DNSTOML" "$BAK"
    ok "бэкап: $BAK"
    OUT="$(python3 - "$DNSTOML" 2>&1 << 'PYEOF'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
m = re.search(r"^listen_addresses\s*=\s*\[([^\n]*)\][^\n]*$", text, re.MULTILINE)
if not m:
    sys.exit("listen_addresses не найден в TOML")
inner = m.group(1)
if "[::1]" in inner:
    sys.exit(0)  # уже есть
port = None
for e in re.findall(r"['\"]([^'\"]+)['\"]", inner):
    parts = e.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        port = parts[1]
        break
if port is None:
    sys.exit("не удалось определить порт в listen_addresses")
new = "listen_addresses = [%s, '[::1]:%s']" % (inner, port)
open(path, "w", encoding="utf-8").write(
    text[:m.start()] + new + text[m.end():])
print("     listen_addresses += [::1]:%s" % port)
PYEOF
)"; RC=$?
    if [ $RC -eq 0 ]; then
        [ -n "$OUT" ] && echo -e "  $OUT"
        systemctl restart "$DNS_SVC"
        if wait_svc "$DNS_SVC" 15 && ss -tulnp 2>/dev/null | grep "$DNS_SVC" | grep -q "\[::1\]"; then
            ok "dnscrypt-proxy слушает 127.0.0.1 + [::1]"
        else
            bad "dnscrypt-proxy не поднялся с [::1] — откат"
            cp -a "$BAK" "$DNSTOML"
            systemctl restart "$DNS_SVC"; wait_svc "$DNS_SVC" 15 || true
            exit 1
        fi
    else
        bad "правка TOML не удалась: $OUT"
        cp -a "$BAK" "$DNSTOML" 2>/dev/null || true
    fi
fi

# ── 3. AdGuard Home: bind_hosts += IPv6 ─────────────────────────────────────
hdr "3/4  AdGuard Home — bind_hosts += $V6"
if [ ! -f "$AGHYAML" ]; then
    skip "AdGuardHome.yaml не найден ($AGHYAML) — AGH не установлен, пропускаю"
elif grep -qF -- "$V6" "$AGHYAML"; then
    skip "IPv6 уже в конфиге AGH — готово"
else
    BAK="$AGHYAML.$TS.preIPv6.bak"
    cp -a "$AGHYAML" "$BAK"
    ok "бэкап: $BAK"
    OUT="$(python3 - "$AGHYAML" "$V6" 2>&1 << 'PYEOF'
import re, sys
path, v6 = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
m = re.search(r"^([ \t]*)bind_hosts:\n((?:[ \t]+-[ \t].*\n?)+)", text, re.MULTILINE)
if not m:
    sys.exit("блок bind_hosts не найден в yaml")
items = m.group(2)
if v6 in items:
    sys.exit(0)  # уже есть
indent = re.match(r"[ \t]+", items.splitlines()[0]).group(0)
new_items = items.rstrip("\n") + '\n%s- "%s"\n' % (indent, v6)
open(path, "w", encoding="utf-8").write(
    text[:m.start()] + m.group(1) + "bind_hosts:\n" + new_items + text[m.end():])
print("     bind_hosts += %s" % v6)
PYEOF
)"; RC=$?
    if [ $RC -eq 0 ]; then
        [ -n "$OUT" ] && echo -e "  $OUT"
        systemctl restart "$AGH_SVC"
        if wait_svc "$AGH_SVC" 25 && dns_alive; then
            ok "AGH активен, DNS жив (getent OK)"
            if ss -tuln 2>/dev/null | grep -qF "[$V6]:"; then
                ok "AGH биндит $V6 (:53/DoT/DoH/Web по IPv6)"
            else
                skip "AGH активен, но $V6 в ss не виден — проверь: ss -tuln | grep $V6"
            fi
        else
            bad "AGH упал или DNS мёртв — ОТКАТ конфига"
            cp -a "$BAK" "$AGHYAML"
            systemctl restart "$AGH_SVC"; wait_svc "$AGH_SVC" 20 || true
            if dns_alive; then
                ok "откат прошёл, DNS жив (IPv6 выключен)"
            else
                bad "DNS мёртв даже после отката! Смотри: journalctl -u AdGuardHome -n 30"
            fi
            exit 1
        fi
    else
        bad "правка yaml не удалась: $OUT"
        cp -a "$BAK" "$AGHYAML" 2>/dev/null || true
    fi
fi

# ── 4. UFW: публичные TLS-порты DNS (v4+v6 одним правилом) ──────────────────
hdr "4/4  UFW — публичные DoT/DoH (без :53!)"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    for rule in "853/tcp" "30443/tcp"; do
        if ufw status | grep -q "$rule"; then
            skip "$rule уже разрешён (v4+v6)"
        else
            ufw allow "$rule" comment "AGH DoT/DoH IPv6-ready" >/dev/null 2>&1 \
                && ok "$rule открыт (v4+v6)" || bad "не удалось открыть $rule"
        fi
    done
    if ufw status | grep -qE "^\s*53[/ ]"; then
        echo -e "  ${Y}[i]${N} :53 открыт в UFW вручную — open resolver! Проверь, твоё ли это правило."
    else
        ok ":53 наружу закрыт (дизайн v65 — нет open resolver; IPv6-клиенты ходят через DoT/DoH)"
    fi
else
    skip "UFW неактивен — порты не трогаю"
fi

# ── Итог ────────────────────────────────────────────────────────────────────
hdr "Итог"
echo -e "  DNS-слушатели сейчас:"
ss -tuln 2>/dev/null | grep -E ":(53|5300)\s" | sed 's/^/    /'
echo
echo -e "  ${G}IPv6 включён в DNS-стек.${N} IPv6-клиенты появятся в дашборде AGH"
echo -e "  («Частые клиенты») при подключении по DoT :853 / DoH :30443."
echo -e "  Тест с IPv6-клиента:"
echo -e "    kdig -6 +tls @[$V6] ya.ru                    # DoT :853"
echo -e "    curl -6 -ksI https://[$V6]:30443/ | head -1   # DoH/Web :30443"
