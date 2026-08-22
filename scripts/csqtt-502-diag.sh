#!/usr/bin/env bash
# Диагностика 502 Bad Gateway для CSQTT Web Panel.
# Запуск: bash csqtt-502-diag.sh
# Прислать весь вывод.

echo "============================================================"
echo "CSQTT 502 Bad Gateway — диагностика"
echo "Date: $(date)"
echo "Host: $(hostname)"
echo "============================================================"
echo

echo "=== 1. systemctl status csqtt ==="
systemctl status csqtt --no-pager -l 2>&1 | head -30
echo

echo "=== 2. systemctl is-active csqtt ==="
systemctl is-active csqtt
echo

echo "=== 3. ss -tlnp | grep csqtt ==="
ss -tlnp | grep -i csqtt
echo

echo "=== 4. ss -tlnp | grep 40500 ==="
ss -tlnp | grep 40500
echo

echo "=== 5. ss -ulnp | grep 40000 (UDP data-plane) ==="
ss -ulnp | grep 40000
echo

echo "=== 6. curl https://127.0.0.1:40500 -k (web panel напрямую) ==="
curl -sI --max-time 10 -k https://127.0.0.1:40500 2>&1 | head -10
echo

echo "=== 7. curl https://127.0.0.1:40500 -k -v (verbose) ==="
curl -k --max-time 10 -v https://127.0.0.1:40500 2>&1 | head -25
echo

echo "=== 8. ps aux | grep csqtt ==="
ps aux | grep -i csqtt | grep -v grep
echo

echo "=== 9. journalctl -u csqtt -n 50 (последние 50 строк логов) ==="
journalctl -u csqtt -n 50 --no-pager 2>&1
echo

echo "=== 10. /etc/csqtt/ — конфиги ==="
ls -la /etc/csqtt/ 2>&1
echo

echo "=== 11. cat /etc/csqtt/config.json ==="
cat /etc/csqtt/config.json 2>&1 | head -30
echo

echo "=== 12. cat /etc/csqtt/passwords.json (без паролей) ==="
# Покажем структуру без значений паролей
python3 -c "
import json
try:
    with open('/etc/csqtt/passwords.json') as f:
        d = json.load(f)
    print('main_password: ***' + str(d.get('main_password',''))[-4:] if d.get('main_password') else 'main_password: (empty)')
    print('passwords count:', len(d.get('passwords', {})))
    print('devices count:', len(d.get('devices', {})))
except Exception as e:
    print(f'Error: {e}')
"
echo

echo "=== 13. nginx vhost для csqtt ==="
ls /etc/nginx/sites-enabled/ 2>&1 | grep -i csqtt
echo "---"
cat /etc/nginx/sites-enabled/*csqtt* 2>&1
echo

echo "=== 14. nginx -t ==="
nginx -t 2>&1
echo

echo "=== 15. tail /var/log/nginx/error.log ==="
tail -30 /var/log/nginx/error.log 2>&1
echo

echo "=== 16. curl https://chimeravpn.online:41000 -k -v (через nginx front) ==="
curl -k --max-time 10 -v https://chimeravpn.online:41000 2>&1 | head -30
echo

echo "=== 17. /var/lib/xray-installer/csqtt.json (state) ==="
cat /var/lib/xray-installer/csqtt.json 2>&1
echo

echo "=== 18. /var/lib/xray-installer/csqtt_nginx_front.json ==="
cat /var/lib/xray-installer/csqtt_nginx_front.json 2>&1
echo

echo "=== 19. csqtt-server --version (если возможно) ==="
/usr/local/bin/csqtt-server --version 2>&1 | head -5
echo

echo "=== 20. free -m (RAM) ==="
free -m
echo

echo "=== 21. df -h / (disk) ==="
df -h /
echo

echo "============================================================"
echo "Diagnostic complete. Send this whole output for analysis."
echo "============================================================"
