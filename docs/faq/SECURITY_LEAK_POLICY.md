# SECURITY: политика репозитория — никаких чувствительных данных

Этот репозиторий зеркалируется и предназначен для публикации.
Любые чувствительные данные о **боевой инфраструктуре** запрещены
в коммитах, сообщениях коммитов, ветках и тегах.

## Что запрещено (LEAK — коммит/пуш блокируется)

- **IP-адреса наших нод** (entry/exit/хоп/relay/monitoring) — в коде,
  тестах, комментариях, changelog, docstring, сообщениях коммитов.
- **Домены нашей инфраструктуры** — VPS-домены, панельные домены,
  DDNS-имена, SNI наших REALITY-сертификатов.
- **Токены и креды** — gitlab (`glpat-`), github (`ghp_`), токены
  TG-ботов (`\d{8,12}:...`), chat_id, SSH-пароли, приватные ключи,
  UUID реальных пользователей VLESS, API-ключи.
- **Косвенные признаки инфраструктуры** — имя хостера ноды, город/
  организация сети ноды (geoip), страна каскада (`RU→XX→XX`),
  поведенческие детали конкретной ноды (закреплённые нестандартные
  порты, имена её конфигов, если это не кодовые константы проекта).

## Что допустимо

- `127.0.0.1`, private-диапазоны (10/8, 172.16/12, 192.168/16,
  100.64/10), link-local, multicast.
- TEST-NET для примеров и фикстур: `192.0.2.x`, `198.51.100.x`,
  `203.0.113.x`, канонические `1.2.3.4` / `5.6.7.8`.
- Публичные DNS (1.1.1.1, 8.8.8.8, 9.9.9.9, AdGuard DNS),
  Cloudflare/WARP endpoints (162.159.0.0/16), Telegram DC
  (149.154.160.0/20, 91.108.0.0/16) — это суть публичных сервисов.
- Публичные сервисы в DPI-листах и зеркалах (github.com,
  npmjs.org, youtube.com и т.п.) — это данные ПО, не наша инфра.
- `example.com`/`*.example.com` в фикстурах, кодовые константы
  проекта (порты-дефолты, теги inbound/outbound, имена юнитов).

## Машинная проверка: scripts/leak_guard.py

```bash
python3 scripts/leak_guard.py --staged        # добавленные строки индекса
python3 scripts/leak_guard.py --diff HEAD     # всё незакоммиченное
python3 scripts/leak_guard.py --msg-file "$(git dir)/COMMIT_EDITMSG"
python3 scripts/leak_guard.py                 # полный аудит дерева
```

- **LEAK** (код возврата 1): публичный IP вне allowlist, токены/
  ключи/креды. Коммит запрещён — обезличь и перечитай диф.
- **WARN** (код возврата 0, печатается для ревью): UUID (фикстура
  или прод-ключ — проверь глазами) и домены вне публичного списка
  (новое зеркало? или твой VPS?). Читай WARN перед пушем.

Полный аудит без аргументов шумит на исторических датасетах
(vendor/, тесты) — рабочие режимы для коммитов: `--staged` и
`--msg-file`.

### Хуки (рекомендуется)

```bash
ln -sf ../../scripts/leak_guard.py .git/hooks/pre-commit    # не сработает:
```
хукам нужен запускчик; вместо симлинка положи в `.git/hooks/`:

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
exec python3 "$(git rev-parse --show-toplevel)/scripts/leak_guard.py" --staged
EOF
cat > .git/hooks/commit-msg <<'EOF'
#!/bin/sh
exec python3 "$(git rev-parse --show-toplevel)/scripts/leak_guard.py" --msg-file "$1"
EOF
chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
```

## Если утечка уже ушла в репозиторий

1. Не правь вручную поверх — данные остаются в истории.
2. `git filter-branch --tree-filter/--msg-filter` по диапазону +
   `push --force-with-lease` в оба зеркала (GitLab chimera-v5,
   GitHub main) — см. changelog-запись 08.10.2026.
3. После force-push: на нодах с `/opt/chimera` выполнить
   `git fetch && git reset --hard origin/chimera-v5` (pull после
   переписывания истории расходится).
4. Сообщить владельцу: старые (до-фильтровые) копии могут оставаться
   в reflog/зеркалах до GC.
