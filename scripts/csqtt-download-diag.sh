#!/usr/bin/env bash
# Diagnostic script: почему Chimera не может скачать CSQTT source.
# Запустить на VPS юзера: bash chimera-download-diag.sh
# Прислать весь вывод.

echo "============================================================"
echo "Chimera download diagnostic"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Host: $(hostname)"
echo "============================================================"
echo

echo "=== 1. Публичный IP VPS ==="
curl -s --max-time 10 https://api.ipify.org && echo || echo "FAILED: cannot reach ipify"
echo

echo "=== 2. DNS resolution: github.com ==="
getent hosts github.com || nslookup github.com 2>&1 | head -10
echo

echo "=== 3. DNS resolution: codeload.github.com ==="
getent hosts codeload.github.com || nslookup codeload.github.com 2>&1 | head -10
echo

echo "=== 4. DNS resolution: ghproxy.net ==="
getent hosts ghproxy.net || nslookup ghproxy.net 2>&1 | head -10
echo

echo "=== 5. TCP connectivity to github.com:443 ==="
timeout 10 bash -c '</dev/tcp/github.com/443' 2>&1 && echo "OK: TCP 443 github.com reachable" || echo "FAILED: TCP 443 github.com unreachable"
echo

echo "=== 6. TCP connectivity to codeload.github.com:443 ==="
timeout 10 bash -c '</dev/tcp/codeload.github.com/443' 2>&1 && echo "OK: TCP 443 codeload reachable" || echo "FAILED: TCP 443 codeload unreachable"
echo

echo "=== 7. TCP connectivity to ghproxy.net:443 ==="
timeout 10 bash -c '</dev/tcp/ghproxy.net/443' 2>&1 && echo "OK: TCP 443 ghproxy.net reachable" || echo "FAILED: TCP 443 ghproxy.net unreachable"
echo

echo "=== 8. HTTP HEAD: github.com (CSQTT tarball) ==="
curl -sI -L --max-time 15 -A "Mozilla/5.0" "https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>&1 | head -10
echo

echo "=== 9. HTTP HEAD: codeload.github.com ==="
curl -sI --max-time 15 -A "Mozilla/5.0" "https://codeload.github.com/amurcanov/csqtt/tar.gz/refs/heads/main" 2>&1 | head -10
echo

echo "=== 10. HTTP HEAD: ghproxy.net ==="
curl -sI --max-time 15 -A "Mozilla/5.0" "https://ghproxy.net/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>&1 | head -10
echo

echo "=== 11. HTTP HEAD: gh-proxy.com ==="
curl -sI --max-time 15 -A "Mozilla/5.0" "https://gh-proxy.com/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>&1 | head -10
echo

echo "=== 12. HTTP HEAD: gh.llkk.cc ==="
curl -sI --max-time 15 -A "Mozilla/5.0" "https://gh.llkk.cc/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>&1 | head -10
echo

echo "=== 13. Real download test: github.com (4 bytes, gzip magic) ==="
bytes=$(curl -sL --max-time 30 -r 0-3 -A "Mozilla/5.0" "https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>/dev/null | od -A n -t x1 | tr -d ' \n')
echo "Bytes: $bytes"
[[ "${bytes:0:4}" == "1f8b" ]] && echo "OK: gzip magic detected" || echo "BAD: not gzip (probably HTML error page)"
echo

echo "=== 14. Real download test: ghproxy.net ==="
bytes=$(curl -sL --max-time 30 -r 0-3 -A "Mozilla/5.0" "https://ghproxy.net/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>/dev/null | od -A n -t x1 | tr -d ' \n')
echo "Bytes: $bytes"
[[ "${bytes:0:4}" == "1f8b" ]] && echo "OK: gzip magic detected" || echo "BAD: not gzip (probably HTML error page)"
echo

echo "=== 15. Real download test: gh-proxy.com ==="
bytes=$(curl -sL --max-time 30 -r 0-3 -A "Mozilla/5.0" "https://gh-proxy.com/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>/dev/null | od -A n -t x1 | tr -d ' \n')
echo "Bytes: $bytes"
[[ "${bytes:0:4}" == "1f8b" ]] && echo "OK: gzip magic detected" || echo "BAD: not gzip (probably HTML error page)"
echo

echo "=== 16. Real download test: gh.llkk.cc ==="
bytes=$(curl -sL --max-time 30 -r 0-3 -A "Mozilla/5.0" "https://gh.llkk.cc/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz" 2>/dev/null | od -A n -t x1 | tr -d ' \n')
echo "Bytes: $bytes"
[[ "${bytes:0:4}" == "1f8b" ]] && echo "OK: gzip magic detected" || echo "BAD: not gzip (probably HTML error page)"
echo

echo "=== 17. /etc/resolv.conf ==="
cat /etc/resolv.conf 2>&1 | head -10
echo

echo "=== 18. /etc/hosts (всякие подмены) ==="
cat /etc/hosts 2>&1 | head -20
echo

echo "=== 19. iptables OUTPUT chain (что блокирует) ==="
iptables -L OUTPUT -n -v 2>&1 | head -20
echo

echo "=== 20. ufw status (если есть) ==="
which ufw >/dev/null 2>&1 && ufw status 2>&1 | head -20 || echo "ufw not installed"
echo

echo "=== 21. curl version ==="
curl --version | head -2
echo

echo "============================================================"
echo "Diagnostic complete. Send this whole output for analysis."
echo "============================================================"
