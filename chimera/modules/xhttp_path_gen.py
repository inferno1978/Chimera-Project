"""
chimera/modules/xhttp_path_gen.py
───────────────────────────────────────────────────────────────────────────────
Генератор случайного пути-обманки для профиля «CDN masking» (XHTTP).

Порт логики gen_path() из install-caddy-node.sh:
  • Списки WORDS / VERSIONS / EXTS идентичны bash-оригиналу
  • 1-3 сегмента пути (директория/файл) — соответствует regex
    ^/[\\w-]+(/[\\w-]+){0,2}\\.(php|ts)$
  • Опциональная замена одного из сегментов на «версию» (v1/v2/.../latest)
    с вероятностью 2/3 — как в bash `if (( RANDOM % 3 != 0 ))`
  • Случайное расширение из {php, ts}
  • Безопасный RNG через secrets module (crypto-strength, не bash $RANDOM)

ВАЖНО: bash-оригинал использовал `dirs = RANDOM % 3 + 1` (1..3 директорий
+ 1 filename = 2..4 сегмента). Здесь диапазон уменьшен до 0..2 (1..3 сегмента
всего), чтобы путь гарантированно соответствовал формату, заданному в ТЗ:
    ^/[\\w-]+(/[\\w-]+){0,2}\\.(php|ts)$
Это единственное сознательное отклонение от bash-логики — всё остальное
(списки, shuffle, версия, расширение, вероятности) перенесено 1:1.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import secrets

# ── Списки из install-caddy-node.sh (строки 33-35) ───────────────────────────
# Порядок и состав — идентичны bash-оригиналу. Любая опечатка ломает
# совместимость с уже развёрнутыми клиентскими конфигами.
WORDS: tuple[str, ...] = (
    "api", "cdn", "static", "media", "stream", "assets", "data", "content",
    "core", "edge", "node", "live", "cache", "gateway", "service", "push",
    "pull", "sync", "fetch", "upload", "chunk", "segment", "frame", "track",
    "session", "blob", "object", "store", "queue", "relay", "proxy", "hub",
    "channel", "feed", "source", "origin", "mirror", "vault", "bucket",
    "shard", "packet", "tile", "manifest", "playlist", "thumb", "preview",
    "render", "worker", "signal", "beacon", "pixel", "event", "report",
    "metric",
)

VERSIONS: tuple[str, ...] = (
    "v1", "v2", "v3", "v4", "v5", "v6", "api2", "r2", "g2",
    "beta", "stable", "latest",
)

EXTS: tuple[str, ...] = ("php", "ts")


def _shuffle_seq(seq: list[str]) -> list[str]:
    """Fisher–Yates shuffle через secrets.randbelow — crypto-strength аналог
    bash `shuf`. Возвращает новую перемешанную копию.
    """
    out = list(seq)
    for i in range(len(out) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def generate_decoy_path() -> str:
    """Генерирует случайный path для XHTTP-туннеля в профиле «CDN masking».

    Возвращает строку вида:
        /api/v2/static.ts
        /cdn/stream.php
        /v3/cache.php
        /edge.php

    Формат всегда соответствует regex:
        ^/[\\w-]+(/[\\w-]+){0,2}\\.(php|ts)$

    Алгоритм (порт gen_path() из install-caddy-node.sh):
      1. Перемешать WORDS → pool
      2. dirs = случайное 0..2 (число директорий перед именем файла)
      3. parts = pool[:dirs]  — первые `dirs` слов из pool
      4. С вероятностью 2/3 заменить один из parts на случайную версию
      5. filename = pool[dirs] — следующее слово из pool (НЕ из parts)
      6. ext = случайный из {php, ts}
      7. Склеить: /{parts_joined}/{filename}.{ext}
         (если parts пуст — /{filename}.{ext})
    """
    pool = _shuffle_seq(list(WORDS))

    # 1..3 сегмента всего: dirs=0..2 директорий + 1 filename
    dirs = secrets.randbelow(3)            # 0..2 — адаптация под regex ТЗ
    parts = pool[:dirs]
    idx = dirs

    # Опциональная замена одного сегмента на версию (вероятность 2/3).
    # bash: `if (( RANDOM % 3 != 0 ))` → эквивалент `secrets.randbelow(3) != 0`.
    # bash-оригинал выбирает позицию через `RANDOM % ${#parts[@]}` — если parts
    # пуст, замена пропускается (в bash это бы упало на делении на 0, но цикл
    # выполняется только при dirs≥1 в оригинале; здесь мы явно проверяем).
    if parts and secrets.randbelow(3) != 0:
        replace_pos = secrets.randbelow(len(parts))
        parts[replace_pos] = secrets.choice(VERSIONS)

    # filename — следующий элемент pool после parts (как `pool[idx]` в bash)
    filename = pool[idx]
    ext = secrets.choice(EXTS)

    if parts:
        return "/" + "/".join(parts) + "/" + filename + "." + ext
    return "/" + filename + "." + ext


# ── Минимальный self-test для ручной проверки ────────────────────────────────
if __name__ == "__main__":  # pragma: no cover
    import re
    _RE = re.compile(r"^/[\w-]+(/[\w-]+){0,2}\.(php|ts)$")
    for _ in range(20):
        p = generate_decoy_path()
        ok = bool(_RE.match(p))
        print(f"{'OK' if ok else 'FAIL'}  {p}")
