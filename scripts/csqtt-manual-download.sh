#!/usr/bin/env bash
# Ручное скачивание CSQTT source, если автоматически не получается.
# Запустить на VPS: bash chimera-csqtt-manual-download.sh
# Скрипт пробует 6 способов:
#   1. Прямой curl с github.com
#   2. Через ghproxy.net
#   3. Через gh-proxy.com
#   4. Через gh.llkk.cc
#   5. Через GitLab mirror (если есть)
#   6. Через wget с подменой User-Agent
# При успехе кладёт файл в /root/csqtt-main.tar.gz
# После этого повторить установку CSQTT в Chimera — она найдёт файл в /root/.

set -u
DEST="/root/csqtt-main.tar.gz"
URLS=(
  "https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz"
  "https://codeload.github.com/amurcanov/csqtt/tar.gz/refs/heads/main"
  "https://ghproxy.net/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz"
  "https://gh-proxy.com/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz"
  "https://gh.llkk.cc/https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz"
)

echo "=== Ручное скачивание CSQTT source ==="
echo "Целевой файл: $DEST"
echo

# Сначала проверим — может уже есть валидный файл
if [[ -f "$DEST" ]]; then
  size=$(stat -c%s "$DEST")
  magic=$(od -A n -t x1 -N 2 "$DEST" | tr -d ' ')
  if [[ "$magic" == "1f8b" && $size -gt 100000 ]]; then
    echo "✓ Файл уже существует и валиден: $DEST ($size байт)"
    echo "  Повторите установку CSQTT в Chimera — она найдёт этот файл."
    exit 0
  else
    echo "⚠ Существующий файл невалиден ($size байт, magic=$magic) — удаляю"
    rm -f "$DEST"
  fi
fi
echo

i=0
for url in "${URLS[@]}"; do
  i=$((i+1))
  echo "--- Попытка $i/${#URLS[@]}: $url ---"
  
  # Try curl with custom UA and DNS-over-HTTPS fallback
  if curl -fL --max-time 60 --retry 2 \
       -A "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" \
       --connect-timeout 15 \
       -o "$DEST" "$url" 2>&1; then
    
    if [[ -f "$DEST" ]]; then
      size=$(stat -c%s "$DEST")
      magic=$(od -A n -t x1 -N 2 "$DEST" | tr -d ' ')
      
      if [[ "$magic" == "1f8b" && $size -gt 100000 ]]; then
        echo
        echo "✓ УСПЕХ! Файл скачан: $DEST"
        echo "  Размер: $size байт"
        echo "  Gzip magic: $magic ✓"
        echo
        echo "Теперь повторите установку CSQTT в Chimera:"
        echo "  Главное меню → 8 (VK Whitelist Bypass) → 4 (CSQTT) → 1 (Установить)"
        echo "  Chimera найдёт файл в /root/ и не пойдёт по зеркалам."
        exit 0
      else
        echo "✗ Файл скачался, но невалиден: size=$size magic=$magic"
        echo "  (вероятно HTML-страница с ошибкой вместо tarball)"
        rm -f "$DEST"
      fi
    fi
  fi
  echo
done

# Last resort: wget
echo "--- Попытка 6 (wget): codeload.github.com ---"
if wget --timeout=60 --tries=2 \
     --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" \
     -O "$DEST" \
     "https://codeload.github.com/amurcanov/csqtt/tar.gz/refs/heads/main" 2>&1; then
  
  if [[ -f "$DEST" ]]; then
    size=$(stat -c%s "$DEST")
    magic=$(od -A n -t x1 -N 2 "$DEST" | tr -d ' ')
    
    if [[ "$magic" == "1f8b" && $size -gt 100000 ]]; then
      echo
      echo "✓ УСПЕХ через wget! Файл: $DEST ($size байт)"
      exit 0
    else
      echo "✗ wget скачал, но невалидно: size=$size magic=$magic"
      rm -f "$DEST"
    fi
  fi
fi

echo
echo "✗ ВСЕ ПОПЫТКИ НЕУДАЧНЫ."
echo
echo "Что делать дальше:"
echo "  1. Запустите диагностический скрипт: bash chimera-download-diag.sh"
echo "     и пришлите вывод — посмотрим, что именно блокирует."
echo "  2. Попробуйте скачать файл вручную на вашем ПК:"
echo "     https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz"
echo "     и закачать на VPS через SCP:"
echo "     scp csqtt-main.tar.gz root@<VPS-IP>:/root/"
echo "  3. Если на вашем ПК тоже не качает — попробуйте через VPN/прокси."
echo "  4. Сообщите провайдеру VPS — возможно, они блокируют github.com."
exit 1
