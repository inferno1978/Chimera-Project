# Mirror Sync — GitHub / GitLab

Источник истины проекта — self-hosted Forgejo. GitHub и GitLab — зеркала
только для чтения по конвенции: коммитить в них напрямую не следует.

## Маппинг веток

| Forgejo (источник) | GitHub | GitLab |
| --- | --- | --- |
| `main` | `main` | `chimera-v5` |
| прочие ветки | та же ветка | та же ветка |

GitLab-зеркало живёт в канонической ветке **`chimera-v5`** — именно на неё
ссылается команда установки (bootstrap-зеркало №2:
`…/-/raw/chimera-v5/bootstrap.sh`), README и тесты
(`tests/test_bootstrap_mirrors.py`). Ветки `main` на GitLab нет, синк её
не создаёт; дефолтная ветка проекта — `chimera-v5`.

## Механизм

- `chimera-mirror-sync.timer` — systemd-таймер на выделенном хосте, где
  лежат сохранённые креды зеркал (git credential store).
- Расписание: ежечасно (`OnCalendar=hourly`, `Persistent=true`,
  `RandomizedDelaySec=300`) — пропущенные во время даунтайма прогоны
  навёрстываются при загрузке.
- Каждый прогон: `git fetch origin` → push каждой ветки origin на оба
  зеркала с учётом маппинга (таблица выше); ветка-симлинк `HEAD`
  не пушится.
- Пуш **без force** и **без prune**: защита веток на зеркалах не
  нарушается, легаси-ветки и теги зеркал (`dev`, delivery-ветки, старые
  релизные теги) намеренно сохраняются.
- При неудаче любого пуша — TG-алерт `[mirror-sync] FAIL`
  (автономно через state.json), лог: `/var/log/chimera-mirror-sync.log`
  (ротация — logrotate).

## Управление

```bash
systemctl start chimera-mirror-sync.service   # синкнуть сейчас
systemctl status chimera-mirror-sync.timer    # расписание
tail -f /var/log/chimera-mirror-sync.log     # живой лог
```

## Если зеркала разошлись

Основная причина — прямой коммит в зеркало в обход Forgejo. Решение:
закоммитить то же самое в Forgejo (источник истины) и выровнять зеркало
force-push'ем. Учтение: на зеркалах включена защита веток — force-push
требует временного снятия защиты через настройки зеркала (API админа),
после пуша защиту вернуть 1:1.
