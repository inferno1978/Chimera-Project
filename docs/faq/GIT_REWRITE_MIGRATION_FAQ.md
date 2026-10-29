# GIT REWRITE MIGRATION — миграция старых клонов после rewrite истории (29.10.2026)

> Документ отвечает на вопросы пользователей, у которых `git pull` в `/opt/chimera`
> после 29.10.2026 начал падать с ошибками divergent branches / unmerged files,
> а `python3 main.py` — с SyntaxError. Команда миграции — в
> [INSTALL.md → «Миграция старых клонов»](../../INSTALL.md#миграция-старых-клонов-после-rewrite-истории-29102026).

## 1. Симптомы

Любая комбинация из перечисленного:

```
hint: You have divergent branches and need to specify how to reconcile them.
fatal: Need to specify how to reconcile divergent branches.
```
```
error: Pulling is not possible because you have unmerged files.
fatal: Exiting because of an unresolved conflict.
```
```
File "/opt/chimera/main.py", line 219
    >>>>>>> 8c9baf2...
            ^
SyntaxError: invalid decimal literal
```

На клонах с gitlab-зеркала дополнительно:

```
error: pathspec 'main' did not match any file(s) known to git
fatal: ambiguous argument 'origin/main': unknown revision or path not in the
working tree.
```

## 2. Причина

29.10.2026 история репозитория Chimera была **переписана** (зачистка утёкших
секретов) и force-push во все зеркала: каноничный Forgejo
(`git.chimeraprodvpn.online`) и зеркала GitLab / GitHub. Старые и новые ветки
не имеют общих коммитов — git видит две независимые истории:

- `git pull` не может fast-forward → предлагает merge → конфликты во **всех**
  изменённых с момента клона файлах;
- если merge был начат и не завершён (`git merge --abort` не выполнен) — в
  рабочих файлах остаются маркеры `<<<<<<<` / `=======` / `>>>>>>>`, и Python
  падает на первом же маркере с `SyntaxError: invalid decimal literal`;
- у gitlab-зеркала ветка называется `chimera-v5`, у Forgejo — `main`, поэтому
  `checkout main` и `reset --hard origin/main` на старом клоне не находят цель.

Сами зеркала живы и синхронны с каноничным репозиторием. Проблема — только на
стороне старых клонов и решается на каждой машине один раз.

## 3. Лечение

Команда миграции — [INSTALL.md → «Миграция старых клонов (после rewrite
истории 29.10.2026)»](../../INSTALL.md#миграция-старых-клонов-после-rewrite-истории-29102026).
Суть: отменить зависший merge → переключить origin на каноничный Forgejo →
пересоздать локальную ветку `main` поверх `origin/main` → проверить, что в
`main.py` не осталось маркеров конфликтов и код компилируется.

Локальные правки (если что-то меняли руками в файлах репозитория) перед
миграцией сохраните тарболом — команда в том же блоке INSTALL.md.

## 4. Это повторится?

Нет. Миграция переводит клон на новую историю; дальше `git pull` работает
как обычный fast-forward. Rewrite такого масштаба — разовое событие
(инцидент утечки секретов), регулярных переписываний истории не планируется.

## 5. Не помогло?

- `git fetch origin` падает с таймаутом с вашего сервера — проверьте
  доступность `git.chimeraprodvpn.online` (`curl -sI https://git.chimeraprodvpn.online`)
  и при необходимости временно используйте gitlab-зеркало
  (`git remote set-url origin https://gitlab.com/netwalker071778/chimera-project.git`,
  ветка `chimera-v5`);
- после миграции кроны Chimera (autoban, dpi-response и т.п.) пишут в лог
  ошибки — пришлите хвост лога (`tail -20 /var/log/chimera.log`) в поддержку.
