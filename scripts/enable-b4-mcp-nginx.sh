#!/usr/bin/env bash
# ============================================================================
#  Chimera Project — enable-b4-mcp-nginx.sh (v72.2)
# ============================================================================
#  Добавляет location /api/mcp в существующий nginx front b4 Web UI
#  (порт 9743) — чтобы MCP-клиенты (Claude, Cursor и др.) могли ходить
#  на https://<домен>:9743/api/mcp.
#
#  ЗАЧЕМ: MCP go-sdk (StreamableHTTPHandler) включает DNS-rebinding
#  защиту: при loopback-бэкенде (nginx → 127.0.0.1:9700) Host-заголовок
#  обязан быть loopback. Домен в Host → 403 «invalid Host header».
#  Локация подменяет Host на 127.0.0.1:9700 только для /api/mcp,
#  стриппает Origin (mcpGate сверяет его с Host) и включает
#  SSE-стриминг (proxy_buffering off, read-timeout 1ч — discovery
#  в b4_find_bypass_strategy идёт минутами).
#
#  ВАЖНО: MCP-сервер b4 должен быть включён в самом b4:
#    b4 Web UI → Settings → API → MCP → Enable (+ сгенерировать токен).
#
#  Идемпотентен: повторный запуск ничего не меняет (если локация есть).
#  Безопасен: бэкап конфига + nginx -t + авточтобыоткат.
#
#  Запуск:  sudo bash scripts/enable-b4-mcp-nginx.sh
# ============================================================================
set -uo pipefail

B="\033[1m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; C="\033[36m"; N="\033[0m"
ok()   { echo -e "  ${G}[OK]${N} $*"; }
skip() { echo -e "  ${C}[..]${N} $*"; }
bad()  { echo -e "  ${R}[!!]${N} $*"; }
hdr()  { echo -e "\n${B}── $* ──${N}"; }

TS="$(date +%Y%m%d%H%M%S)"

[ "$(id -u)" -eq 0 ] || { echo "Запусти от root: sudo bash $0"; exit 1; }

SITES_DIRS="/etc/nginx/sites-enabled /etc/nginx/conf.d"
B4_SITE_DEFAULT="/etc/nginx/sites-enabled/chimera-b4-nginx"

# ── 1. Поиск nginx-сайта b4 ─────────────────────────────────────────────────
hdr "1/4  Поиск nginx front для b4"
SITE=""
if [ -f "$B4_SITE_DEFAULT" ]; then
    SITE="$B4_SITE_DEFAULT"
else
    for d in $SITES_DIRS; do
        [ -d "$d" ] || continue
        for f in "$d"/*.conf "$d"/*; do
            [ -f "$f" ] || continue
            if grep -q "127.0.0.1:9700" "$f" 2>/dev/null && grep -q "proxy_pass" "$f" 2>/dev/null; then
                SITE="$f"; break 2
            fi
        done
    done
fi
if [ -z "$SITE" ]; then
    bad "nginx front для b4 не найден (нет $(basename "$B4_SITE_DEFAULT") и ни одного"
    bad "сайта с proxy_pass на 127.0.0.1:9700 в $SITES_DIRS)."
    bad "Сначала установи nginx front: TUI → DPI Bypass (или B4+YouTube) → nginx front."
    exit 1
fi
ok "сайт: $SITE"

# ── 2. Проверки состояния ───────────────────────────────────────────────────
hdr "2/4  Проверка текущего состояния"
if grep -q "location /api/mcp {" "$SITE"; then
    skip "location /api/mcp уже есть — готово"
    exit 0
fi
if ! grep -q "proxy_pass http://127.0.0.1:9700" "$SITE"; then
    bad "в сайте нет ожидаемого proxy_pass http://127.0.0.1:9700 —"
    bad "конфиг сгенерирован не chimera или порт Web UI изменён. Пришли файл:"
    echo "    cat $SITE"
    exit 1
fi
ok "фронт найден, MCP-локации нет — добавляю"

# ── 3. Вставка location /api/mcp ────────────────────────────────────────────
hdr "3/4  Вставка location /api/mcp"
BAK="$SITE.$TS.preMCP.bak"
cp -a "$SITE" "$BAK"
ok "бэкап: $BAK"

OUT="$(python3 - "$SITE" 2>&1 << 'PYEOF'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
if "location /api/mcp {" in text:
    sys.exit(0)  # уже есть (гонка с повторным запуском)
m = re.search(r"^(\s*)location / \{", text, re.MULTILINE)
if not m:
    sys.exit("location / { не найден в конфиге")
indent = m.group(1)          # отступ блока location /
block = f"""{indent}# MCP (Model Context Protocol) — b4 control plane. Host обязан быть
{indent}# loopback (go-sdk DNS-rebinding protection). НЕ редактировать вручную.
{indent}# Добавлено scripts/enable-b4-mcp-nginx.sh (v72.2).
{indent}location /api/mcp {{
{indent}    proxy_pass http://127.0.0.1:9700;
{indent}    proxy_http_version 1.1;
{indent}    proxy_set_header Host 127.0.0.1:9700;
{indent}    proxy_set_header Origin "";
{indent}    proxy_set_header X-Real-IP $remote_addr;
{indent}    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
{indent}    proxy_set_header X-Forwarded-Proto $scheme;
{indent}    proxy_set_header Connection "";
{indent}    proxy_buffering off;
{indent}    proxy_cache off;
{indent}    proxy_read_timeout 3600s;
{indent}    proxy_send_timeout 3600s;
{indent}}}

"""
# Вставляем ПЕРЕД location / (prefix-локация длиннее / выигрывает
# независимо от порядка — но так конфиг читабельнее).
text = text[:m.start()] + block + text[m.start():]
open(path, "w", encoding="utf-8").write(text)
print("     location /api/mcp вставлен перед location /")
PYEOF
)"; RC=$?
if [ $RC -ne 0 ]; then
    bad "правка конфига не удалась: $OUT"
    cp -a "$BAK" "$SITE" 2>/dev/null || true
    exit 1
fi
[ -n "$OUT" ] && echo -e "  $OUT"

# ── 4. nginx -t + reload + проверка ─────────────────────────────────────────
hdr "4/4  Проверка конфига и reload"
if ! nginx -t 2>&1; then
    bad "nginx -t FAILED — откат конфига"
    cp -a "$BAK" "$SITE"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx && ok "откат применён, nginx перезагружен"
    exit 1
fi
ok "nginx -t прошёл"
if ! nginx -s reload 2>/dev/null && ! systemctl reload nginx; then
    bad "reload не удался — откат конфига"
    cp -a "$BAK" "$SITE"
    nginx -t >/dev/null 2>&1 && nginx -s reload 2>/dev/null
    exit 1
fi
ok "nginx перезагружен"

sleep 1

# Финальная проба: локальный запрос через nginx front на /api/mcp.
# Ожидаем ЛЮБОЙ ответ MCP-протокола (SSE-строка event:/data: или
# JSON-RPC). 403 «invalid Host» = не сработало; 404 «disabled» = MCP
# выключен в настройках b4 (см. шапку скрипта).
PORT="$(grep -oP '^\s*listen\s+\K\d+' "$SITE" | head -1)"
PORT="${PORT:-9743}"
RESP="$(curl -sk -m 10 -X POST "https://127.0.0.1:$PORT/api/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' 2>&1 | head -c 300)"
if echo "$RESP" | grep -q "invalid Host"; then
    bad "всё ещё 403 invalid Host — пришли вывод скрипта целиком"
    exit 1
elif echo "$RESP" | grep -q "mcp server is disabled"; then
    echo -e "  ${Y}[i]${N} Проксирование работает, но MCP выключен в b4:"
    echo -e "      b4 Web UI → Settings → API → MCP → Enable + токен"
elif echo "$RESP" | grep -qE "event:|data:|jsonrpc|invalid or missing MCP token"; then
    ok "MCP-эндпоинт отвечает через nginx (Host проходит)"
else
    skip "неожиданный ответ от /api/mcp: $(echo "$RESP" | head -c 120)"
    skip "проверь вручную: curl -sk -X POST https://127.0.0.1:$PORT/api/mcp ..."
fi

hdr "Итог"
echo -e "  ${G}MCP-прокси настроен.${N} Конфиг MCP-клиента:"
echo -e '    {'
echo -e '      "b4": {'
echo -e '        "url": "https://<твой-домен>:'"$PORT"'/api/mcp",'
echo -e '        "headers": { "Authorization": "Bearer <MCP-токен из b4>" }'
echo -e '      }'
echo -e '    }'
echo -e "  После переустановки nginx front через TUI локация сохранится"
echo -e "  (v72.2 генерирует её сам — обнови /opt/chimera: git pull)."
