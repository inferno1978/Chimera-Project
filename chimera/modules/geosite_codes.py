"""
chimera/modules/geosite_codes.py
───────────────────────────────────────────────────────────────────────────────
Теги категорий установленного geosite.dat — точный protobuf-парсер
(без зависимостей) + mtime-кэш.

ЗАЧЕМ: routing-правило с geosite:<код>, которого нет в geosite.dat,
валит Xray при старте («code not found in geosite.dat» → exit 23 →
RestartPreventExitStatus=23 → служба мертва → i/o timeout у ВСЕХ
клиентов — прецеденты legacy-v3-v5 и youtube_route FIX).
Существующая проверка split_tunnel._geosite_has_category ищет
подстроку grep'ом — для коротких кодов (vk, ok, x, ea, gog) даёт
ложные срабатывания: подстрока «ok» влетает в ok.ru внутри ЛЮБОЙ
категории 80-МБ файла. Этот модуль читает protobuf-структуру и
возвращает ТОЧНОЕ множество тегов.

ФОРМАТ (v2fly/runetfreedom geosite.dat):
    GeositeList { repeated Geosite entry = 1 }
    Geosite     { string tag = 1; repeated Domain domain = 2 }
    Domain      { Type type = 1 (varint); string value = 2 }
Внутрь Domain не заходим — на теги и счётчики флейвор полей Domain
не влияет (в иных сборках поля Domain перевернуты).

API:
    geosite_dat_path()            — первый существующий .dat (Path | None)
    geosite_tags(refresh=False)   — set нижнего регистра тегов | None (~0.02 с)
    geosite_codes(refresh=False)  — {тег: число доменов} | None (~2 с, кэш)

None = файла нет / ни один не распарсился → «не проверяем»: финальный
гвард остаётся `xray run -test` в момент применения правила
(routing_rules._rr_apply_to_xray(validate=True) с откатом).

КЭШ: по (path, mtime_ns, size) каждого кандидата — cron-обновление
geo-файлов (воскресенье 03:00, setup_geo_autoupdate) меняет mtime →
кэш сбрасывается сам, рестарт процесса не нужен.

КАНДИДАТЫ (канон split_tunnel._geosite_has_category /
geo_packages._GEO_INSTALL_DESTS): /etc/xray, /usr/local/share/xray,
/usr/local/etc/xray. Если несколько копий живы и парсятся — тег
считается доступным только при наличии ВО ВСЕХ копиях
(консервативно: Xray может загрузить любую из них — зеркало-инцидент
legacy-v3-v5, когда /etc/xray и share/ расходились; счётчики — max
по копиям, это только для подписей в UI).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

# ── Кандидаты geosite.dat (порядок = канон split_tunnel) ──────────────────────
GEOSITE_DAT_CANDIDATES: tuple = (
    Path("/etc/xray/geosite.dat"),
    Path("/usr/local/share/xray/geosite.dat"),
    Path("/usr/local/etc/xray/geosite.dat"),
)

# кэш: path → {"mtime_ns": int, "size": int, "codes": dict[str, int] | None}
# codes=None в кэше = файл был, но не распарсился (не ретраим до смены mtime).
_CACHE: dict = {}


# ── Protobuf-примитивы ────────────────────────────────────────────────────────

def _read_varint(buf: bytes, pos: int) -> "tuple[int, int]":
    """Varint (protobuf wire type 0). ValueError при усечении/переполнении."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("усечённый varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint длиннее 9 байт")


def _skip_field(wt: int, buf: bytes, pos: int) -> int:
    """Пропуск значения поля по wire type. ValueError при усечении."""
    if wt == 0:
        _, pos = _read_varint(buf, pos)
        return pos
    if wt == 1:
        if pos + 8 > len(buf):
            raise ValueError("усечённый fixed64")
        return pos + 8
    if wt == 5:
        if pos + 4 > len(buf):
            raise ValueError("усечённый fixed32")
        return pos + 4
    raise ValueError(f"неподдерживаемый wire type {wt}")


def _parse_tags_only(data: bytes) -> "dict[str, int]":
    """Теги + нулевые счётчики: читаем ПЕРВОЕ поле каждого entry
    (tag), остальной блоб пропускаем срезом — O(числа категорий),
    ~0.02 с на 80-МБ файле. Счётчики доменов НЕ считаются."""
    tags: dict = {}
    pos, n = 0, len(data)
    while pos < n:
        key, pos = _read_varint(data, pos)
        field, wt = key >> 3, key & 7
        if wt == 2:
            ln, pos = _read_varint(data, pos)
            if pos + ln > n:
                raise ValueError("усечённый entry")
            blob = data[pos:pos + ln]
            pos += ln
            if field == 1:
                tag = _entry_tag(blob)
                if tag:
                    low = tag.lower()
                    tags.setdefault(low, 0)
        else:
            pos = _skip_field(wt, data, pos)
    if not tags:
        raise ValueError("ни одного тега — не geosite.dat?")
    return tags


def _parse_tags_counts(data: bytes) -> "dict[str, int]":
    """Теги + число доменов в каждой категории: полный проход полей
    каждого entry (внутрь Domain не заходим — только заголовки).
    ~2 с на 80-МБ файле (3.7 млн доменов)."""
    tags: dict = {}
    pos, n = 0, len(data)
    while pos < n:
        key, pos = _read_varint(data, pos)
        field, wt = key >> 3, key & 7
        if wt == 2:
            ln, pos = _read_varint(data, pos)
            if pos + ln > n:
                raise ValueError("усечённый entry")
            blob = data[pos:pos + ln]
            pos += ln
            if field == 1:
                tag, count = _entry_tag_and_count(blob)
                if tag:
                    low = tag.lower()
                    tags[low] = tags.get(low, 0) + count
        else:
            pos = _skip_field(wt, data, pos)
    if not tags:
        raise ValueError("ни одного тега — не geosite.dat?")
    return tags


def _entry_tag(blob: bytes) -> "str | None":
    """Первое поле entry = тег (string). None если entry пуст."""
    try:
        key, j = _read_varint(blob, 0)
        if (key >> 3) == 1 and (key & 7) == 2:
            ln, j = _read_varint(blob, j)
            if j + ln > len(blob):
                raise ValueError("усечённый tag")
            return blob[j:j + ln].decode("utf-8", "replace")
    except ValueError:
        return None
    return None


def _entry_tag_and_count(blob: bytes) -> "tuple[str | None, int]":
    """Тег + число полей domain=2 внутри entry."""
    tag: "str | None" = None
    count = 0
    pos, n = 0, len(blob)
    while pos < n:
        key, pos = _read_varint(blob, pos)
        field, wt = key >> 3, key & 7
        if wt != 2:
            pos = _skip_field(wt, blob, pos)
            continue
        ln, pos = _read_varint(blob, pos)
        if pos + ln > n:
            raise ValueError("усечённое поле entry")
        val = blob[pos:pos + ln]
        pos += ln
        if field == 1:
            tag = val.decode("utf-8", "replace")
        elif field == 2:
            count += 1          # Domain-сообщения: 1 поле = 1 домен
    return tag, count


# ── Публичный API ─────────────────────────────────────────────────────────────

def geosite_dat_path() -> "Path | None":
    """Первый существующий geosite.dat из кандидатов (или None)."""
    for p in GEOSITE_DAT_CANDIDATES:
        if p.exists():
            return p
    return None


def _parsed_candidates(refresh: bool, parser) -> "list[dict[str, int]]":
    """Парсит все существующие кандидаты (с кэшем), возвращает список
    распарсенных словарей {тег: ...}. Пустой список = проверять нечем."""
    out: list = []
    for p in GEOSITE_DAT_CANDIDATES:
        if not p.exists():
            continue
        try:
            st = p.stat()
            key = str(p)
            cached = _CACHE.get(key)
            if (not refresh and cached
                    and cached["mtime_ns"] == st.st_mtime_ns
                    and cached["size"] == st.st_size
                    and cached.get("counts") is not None):
                out.append(cached["counts"])
                continue
            data = p.read_bytes()
            codes = parser(data)
            _CACHE[key] = {"mtime_ns": st.st_mtime_ns,
                           "size": st.st_size,
                           "counts": codes}
            out.append(codes)
        except (OSError, ValueError):
            # битый/усечённый файл (скачивается?) — пропускаем кандидата;
            # кэш не пишем: следующий вызов попробует снова
            continue
    return out


def geosite_tags(refresh: bool = False) -> "set[str] | None":
    """Множество тегов (нижний регистр) из живого geosite.dat | None.

    Быстро (~0.02 с): полные счётчики не считаются — '0' у всех.
    При нескольких распарсенных копиях — пересечение (консервативно).
    """
    parsed = _parsed_candidates(refresh, _parse_tags_only)
    if not parsed:
        return None
    result = set(parsed[0])
    for other in parsed[1:]:
        result &= set(other)
    return result


def geosite_codes(refresh: bool = False) -> "dict[str, int] | None":
    """{тег (нижний регистр): число доменов} из живого geosite.dat | None.

    Медленнее (~2 с на 80 МБ при первом обращении, дальше mtime-кэш).
    Пересечение тегов по копиям; счётчики — max по копиям (для подписей).
    """
    parsed = _parsed_candidates(refresh, _parse_tags_counts)
    if not parsed:
        return None
    result: dict = dict(parsed[0])
    for other in parsed[1:]:
        keys = set(result) & set(other)
        result = {k: max(result[k], other[k]) for k in keys}
    return result
