"""tests/test_mieru_cascade_lb_exits.py

Состав балансировки Exit-ов (lb_exits) в mieru-каскаде — порт выбора
состава из awg_cascade_lb (06.10): балансировать можно между ВЫБРАННЫМИ
Exit-ами (пара/тройка/сколько угодно — из всего флота), а не только
между всеми зарегистрированными.

Живой мотив (октябрь 2026, тот же что у AWG): во флоте есть чистые
Exit-ы (de/pl1, steal 0.00%) и проблемные (nl1 — steal до 22%);
гнать трафик на плохие потому, что они «просто зарегистрированы», —
вредно.

Покрывает:
 1. _normalize_lb_selection — ids/метки/дубли/неоднозначные метки/
    порядок st['exits']
 2. _lb_effective_exits — дефолт все/подмножество/протухшие ids/
    <2 валидных → фолбэк/выключенный в составе/мёртвый в составе
 3. _rule_specs — rr/random/prio только по выбранным; пиннинг
    ортогонален составу (закреплён вне состава — работает)
 4. _rule_specs_all_variants — зачистка по-прежнему покрывает ВСЕ
    Exit-ы (superset; невыбранные не должны оставлять хвостов)
 5. set_lb_exits — отклонение <2/сохранение/чистка EMA/сброс долей/
    role!=entry/пустой флот
 6. health_tick — доли считаются только по выбранным
 7. state_load — дефолт lb_exits=[] (обратная совместимость)
"""

from __future__ import annotations

import contextlib
import types

import pytest

from chimera.modules import mieru_cascade as mc


# ── фикстуры ────────────────────────────────────────────────────────────

def _exit(i, label, *, enabled=True, healthy=True, rp=None):
    return {"id": f"e{i}", "label": label, "host": f"10.0.0.{i}",
            "port": 2012, "enabled": enabled, "healthy": healthy,
            "fail_streak": 0, "redsocks_port": rp if rp is not None
            else 23080 + i}


def _st(**kw):
    st = {
        "role": "entry",
        "matcher": "cgroup",
        "strategy": "rr",
        "strict_udp_block": False,
        "exits": [_exit(1, "de"), _exit(2, "fi1"),
                  _exit(3, "nl1"), _exit(4, "pl1")],
        "lb_exits": [],
    }
    st.update(kw)
    return st


# ── 1. _normalize_lb_selection ─────────────────────────────────────────

def test_normalize_none_and_empty_mean_all():
    assert mc._normalize_lb_selection(None, _st()["exits"]) == []
    assert mc._normalize_lb_selection([], _st()["exits"]) == []


def test_normalize_by_ids_in_st_order():
    # ввод в обратном порядке → результат в порядке st['exits']
    assert mc._normalize_lb_selection(
        ["e4", "e1", "e4", "", "xx", None], _st()["exits"]) == ["e1", "e4"]


def test_normalize_by_labels():
    assert mc._normalize_lb_selection(
        ["pl1", "de"], _st()["exits"]) == ["e1", "e4"]


def test_normalize_ambiguous_label_dropped():
    # две ноды с одинаковой меткой — неоднозначно, токен игнорируется
    exits = [_exit(1, "de"), _exit(2, "de"), _exit(3, "pl1")]
    assert mc._normalize_lb_selection(["de", "pl1"], exits) == ["e3"]


def test_normalize_mixed_ids_and_labels():
    assert mc._normalize_lb_selection(
        ["e1", "pl1", "fi1"], _st()["exits"]) == ["e1", "e2", "e4"]


# ── 2. _lb_effective_exits ─────────────────────────────────────────────

def test_effective_all_by_default():
    st = _st()
    assert len(mc._lb_effective_exits(st)) == 4
    st["lb_exits"] = []
    assert len(mc._lb_effective_exits(st)) == 4


def test_effective_subset_pair():
    st = _st(lb_exits=["e4", "e1"])
    eff = mc._lb_effective_exits(st)
    assert [e["id"] for e in eff] == ["e1", "e4"]


def test_effective_subset_three():
    # N-способность: тройка, не только пара
    st = _st(lb_exits=["e2", "e4", "e1"])
    eff = mc._lb_effective_exits(st)
    assert [e["id"] for e in eff] == ["e1", "e2", "e4"]


def test_effective_stale_ids_fallback_all():
    st = _st(lb_exits=["e1", "gone-1", "gone-2"])
    assert len(mc._lb_effective_exits(st)) == 4


def test_effective_single_valid_fallback_all():
    st = _st(lb_exits=["e1"])
    assert len(mc._lb_effective_exits(st)) == 4


def test_effective_disabled_in_selection_fallback_all():
    # валидность = известный И включённый; один из двух выключен —
    # молчаливая одиночная нода запрещена, фолбэк на все
    st = _st(lb_exits=["e1", "e4"])
    st["exits"][3]["enabled"] = False          # pl1 выключен
    assert len(mc._lb_effective_exits(st)) == 3  # de, fi1, nl1


def test_effective_dead_selected_degrades_not_fallback():
    # выбранный, но недоступный выпадает из ротации (естественная
    # деградация) — фолбэка на все НЕТ: выбор валиден (2 включённых)
    st = _st(lb_exits=["e1", "e4"])
    st["exits"][0]["healthy"] = False          # de мёртв
    eff = mc._lb_effective_exits(st)
    assert [e["id"] for e in eff] == ["e4"]


def test_effective_respects_act_argument():
    # внешний активный список тоже фильтруется составом
    st = _st(lb_exits=["e1", "e4"])
    act = [_exit(1, "de"), _exit(9, "xx")]
    eff = mc._lb_effective_exits(st, act)
    assert [e["id"] for e in eff] == ["e1"]


# ── 3. _rule_specs — только выбранные ──────────────────────────────────

def _redirect_ports(specs):
    out = []
    for sp in specs:
        rest = sp["rest"]
        if "REDIRECT" in rest and "--to-ports" in rest:
            out.append(int(rest[rest.index("--to-ports") + 1]))
    return out


def test_rule_specs_rr_only_selected():
    st = _st(lb_exits=["e1", "e4"], strategy="rr")
    specs = mc._rule_specs(st)
    ports = _redirect_ports(specs)
    assert sorted(ports) == [23081, 23084]      # de + pl1 только
    # rr на паре: nth every=2 у первого, второй — catch-all
    redirs = [sp["rest"] for sp in specs if "REDIRECT" in sp["rest"]]
    assert "--every" in redirs[0] and "2" in redirs[0]
    assert "--every" not in redirs[1]


def test_rule_specs_rr_all_when_no_selection():
    st = _st(strategy="rr")
    ports = _redirect_ports(mc._rule_specs(st))
    assert sorted(ports) == [23081, 23082, 23083, 23084]


def test_rule_specs_random_pair():
    st = _st(lb_exits=["e1", "e4"], strategy="random")
    specs = mc._rule_specs(st)
    assert sorted(_redirect_ports(specs)) == [23081, 23084]
    redirs = [sp["rest"] for sp in specs if "REDIRECT" in sp["rest"]]
    assert "--probability" in " ".join(redirs[0])
    assert "--probability" not in " ".join(redirs[1])


def test_rule_specs_prio_first_in_st_order():
    # порядок ротации = порядок st['exits'] (ввод состава порядок не
    # меняет — «поднять в списке» в [3]-меню управляет приоритетом)
    st = _st(lb_exits=["e4", "e1"], strategy="prio")
    specs = mc._rule_specs(st)
    assert _redirect_ports(specs) == [23081]           # только de


def test_rule_specs_pinned_outside_selection_still_works():
    # пиннинг ортогонален составу: закреплён nl1 (вне состава de+pl1)
    # → весь трафик на nl1, стратегии не действуют
    st = _st(lb_exits=["e1", "e4"], strategy="smart",
             pinned_exit="e3")
    specs = mc._rule_specs(st)
    assert _redirect_ports(specs) == [23083]           # nl1


def test_rule_specs_guard_comes_first():
    st = _st(lb_exits=["e1", "e4"], strategy="rr")
    specs = mc._rule_specs(st)
    assert "RETURN" in specs[0]["rest"]                # loopback guard
    assert "127.0.0.0/8" in specs[0]["rest"]


# ── 4. зачистка покрывает ВСЕ Exit-ы (superset) ────────────────────────

def test_all_variants_cover_unselected_exits():
    st = _st(lb_exits=["e1", "e4"], strategy="rr")
    specs = mc._rule_specs_all_variants(st)
    ports = _redirect_ports(specs)
    # все четыре порта — включая невыбранных fi1/nl1
    assert sorted(set(ports)) == [23081, 23082, 23083, 23084]


# ── 5. set_lb_exits ────────────────────────────────────────────────────

def _mock_set(monkeypatch, tmp_path, st, *, apply_ok=True):
    saved = {}
    applied = []

    def fake_apply(s):
        applied.append(True)
        mc.state_save(s)          # как реальный _rules_apply (шаг 4)
        return apply_ok

    monkeypatch.setattr(mc, "state_load", lambda: st)
    monkeypatch.setattr(mc, "state_save", lambda s: saved.update(s))
    monkeypatch.setattr(mc, "_rules_apply", fake_apply)
    monkeypatch.setattr(mc, "_routing_sh_text", lambda s: "# test")
    monkeypatch.setattr(mc, "_ROUTING_SH", tmp_path / "routing.sh")
    monkeypatch.setattr(mc, "_cascade_lock",
                        lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(
        mc, "_mieru",
        lambda: types.SimpleNamespace(GREEN="", NC="", YELLOW=""))
    return saved, applied


def test_set_rejects_lt2(monkeypatch, tmp_path):
    st = _st()
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["de"]) is False
    assert applied == []                    # правила не трогали
    assert "lb_exits" not in saved          # state не сохраняли


def test_set_rejects_all_unknown(monkeypatch, tmp_path):
    st = _st()
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["xx", "yy"]) is False


def test_set_rejects_non_entry_role(monkeypatch, tmp_path):
    st = _st(role="exit")
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["de", "pl1"]) is False


def test_set_updates_state_and_clears_ema(monkeypatch, tmp_path):
    st = _st(lb_exits=[], metrics_ema={
        "de": {"lat_ms": 10}, "fi1": {"lat_ms": 20},
        "nl1": {"lat_ms": 30}, "pl1": {"lat_ms": 40}},
        balance={"shares": {"de": .25, "fi1": .25, "nl1": .25, "pl1": .25}})
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["pl1", "de"]) is True
    assert applied == [True]
    assert saved["lb_exits"] == ["e1", "e4"]           # порядок st['exits']
    assert sorted(saved["metrics_ema"]) == ["de", "pl1"]
    assert saved["balance"] is None                    # форс-ребаланс
    assert (tmp_path / "routing.sh").read_text() == "# test"


def test_set_none_resets_to_all(monkeypatch, tmp_path):
    st = _st(lb_exits=["e1", "e4"])
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(None) is True
    assert saved["lb_exits"] == []
    assert applied == [True]


def test_set_three_of_four(monkeypatch, tmp_path):
    st = _st()
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["de", "fi1", "pl1"]) is True
    assert saved["lb_exits"] == ["e1", "e2", "e4"]


def test_set_rejects_when_fleet_empty(monkeypatch, tmp_path):
    # флот пуст: имена не резолвятся → явный выбор отклонён
    st = _st(role="entry", exits=[])
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["de", "pl1"]) is False
    assert applied == []
    # сброс на «все» — применяется (запоминается, применять нечего)
    assert mc.set_lb_exits(None) is True
    assert saved["lb_exits"] == []
    assert applied == []


def test_set_pinned_untouched(monkeypatch, tmp_path):
    # пин ортогонален составу: set_lb_exits не снимает закрепление
    st = _st(pinned_exit="e3")
    saved, applied = _mock_set(monkeypatch, tmp_path, st)
    assert mc.set_lb_exits(["de", "pl1"]) is True
    assert saved.get("pinned_exit") == "e3"


# ── 6. health_tick: доли только по выбранным ───────────────────────────

def test_health_tick_balance_over_selected(monkeypatch, tmp_path):
    st = _st(lb_exits=["e1", "e4"], strategy="leastping",
             balance={"shares": {"de": .5, "pl1": .5}},
             applied_rules=[{"spec": "applied"}])
    captured = {}

    def fake_balance_shares(s, act):
        captured["act"] = [e["id"] for e in act]
        return {"shares": {"de": .5, "pl1": .5}}

    monkeypatch.setattr(mc, "state_load", lambda: st)
    monkeypatch.setattr(mc, "state_save", lambda s: None)
    monkeypatch.setattr(
        mc, "_mieru",
        lambda: types.SimpleNamespace(YELLOW="", NC="", GREEN="", RED=""))
    monkeypatch.setattr(mc, "_ensure_local_services", lambda s: [])
    monkeypatch.setattr(mc, "_probe_exit_tcp", lambda e: 12.0)
    monkeypatch.setattr(mc, "_probe_exit_e2e", lambda e: True)
    monkeypatch.setattr(mc, "_balance_shares", fake_balance_shares)
    monkeypatch.setattr(mc, "_rule_specs",
                        lambda s, bal=None: [{"spec": "fresh"}])
    monkeypatch.setattr(mc, "_rules_in_sync", lambda s: True)
    monkeypatch.setattr(mc, "_rules_apply", lambda s: True)
    monkeypatch.setattr(mc, "_routing_sh_text", lambda s: "# routing.sh")
    monkeypatch.setattr(mc, "_b4_exempt_active", lambda s: False)
    monkeypatch.setattr(mc, "_ROUTING_SH", tmp_path / "routing.sh")

    result = mc._health_tick_locked(verbose=False)
    # доли считались ТОЛЬКО по выбранным de+pl1
    assert captured["act"] == ["e1", "e4"]
    assert result["balance"]["shares"] == {"de": .5, "pl1": .5}
    assert result["rebalanced"] is False       # доли не дрейфанули


# ── 7. дефолт state + сводка ───────────────────────────────────────────

def test_state_default_lb_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(mc, "_MODULE_STATE",
                        tmp_path / "mieru_cascade.json")
    st = mc.state_load()
    assert st["lb_exits"] == []
    assert st["strategy"] == "rr"


def test_state_default_backfills_existing_file(monkeypatch, tmp_path):
    # живой state без lb_exits (до обновления модуля) → ключ добавится
    p = tmp_path / "mieru_cascade.json"
    p.write_text('{"role": "entry", "strategy": "smart"}',
                 encoding="utf-8")
    monkeypatch.setattr(mc, "_MODULE_STATE", p)
    st = mc.state_load()
    assert st["role"] == "entry"
    assert st["lb_exits"] == []


def test_summary_all_and_subset():
    assert mc._lb_exits_summary(_st()) == "все (4)"
    assert mc._lb_exits_summary(_st(lb_exits=["e4", "e1"])) == \
        "de, pl1 (2 из 4)"
    # мёртвый в составе: эффективных меньше выбранных
    st = _st(lb_exits=["e1", "e4"])
    st["exits"][0]["healthy"] = False
    assert mc._lb_exits_summary(st) == "de, pl1 (1 из 4)"
