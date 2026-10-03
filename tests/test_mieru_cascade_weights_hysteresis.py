"""tests/test_mieru_cascade_weights_hysteresis.py

Гистерезис дрейфа весов в health-тике mieru-каскада (v5.5.4).

Живой кейс (октябрь 2026, entry-нода с leastping): без порога джиттер
метрик каждый тик давал «новые» вероятности → weights_drift=True →
полная пересборка правил (~90 вызовов iptables) + persist
/etc/iptables/rules.v4 каждую минуту. Фикс: ребаланс только при
материальном дрейфе долей (>WEIGHTS_HYSTERESIS или смена состава
Exit-ов).
"""

import types

from chimera.modules import mieru_cascade as mc


def _bal(shares):
    return {"shares": dict(shares)}


BASE = {"A": 0.30, "B": 0.35, "C": 0.35}


# ── _shares_materially_changed: юнит ──────────────────────────────────────

def test_jitter_within_threshold_is_not_material():
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.29, "B": 0.36, "C": 0.35})) is False


def test_material_drift_over_threshold():
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.40, "B": 0.30, "C": 0.30})) is True


def test_boundary_exactly_threshold_is_not_material():
    # строго больше порога: ровно 5 п.п. — ещё джиттер
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.35, "B": 0.35, "C": 0.30})) is False
    # 5.1 п.п. — уже материально
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.351, "B": 0.35, "C": 0.299})) is True


def test_exit_set_change_is_material():
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.5, "B": 0.5})) is True
    assert mc._shares_materially_changed(
        _bal(BASE), _bal({"A": 0.25, "B": 0.25, "C": 0.25, "D": 0.25})) is True


def test_old_balance_none_is_material():
    # никогда не применяли (stale state) — ребаланс, самовыправится
    assert mc._shares_materially_changed(None, _bal(BASE)) is True
    assert mc._shares_materially_changed({}, _bal(BASE)) is True


def test_both_empty_is_not_material():
    assert mc._shares_materially_changed(_bal({}), _bal({})) is False
    assert mc._shares_materially_changed(None, None) is False


# ── _health_tick_locked: интеграционные (пробы замоканы) ─────────────────

def _st():
    return {
        "role": "entry",
        "strategy": "leastping",
        "exits": [
            {"id": "e1", "label": "A", "enabled": True, "healthy": True,
             "fail_streak": 0, "redsocks_port": 23081},
            {"id": "e2", "label": "B", "enabled": True, "healthy": True,
             "fail_streak": 0, "redsocks_port": 23082},
            {"id": "e3", "label": "C", "enabled": True, "healthy": True,
             "fail_streak": 0, "redsocks_port": 23084},
        ],
        "applied_rules": [{"spec": "applied"}],
        "balance": _bal(BASE),
    }


def _mock_tick(monkeypatch, tmp_path, *, bal):
    applied = []

    def fake_apply(st):
        applied.append(True)
        return True

    monkeypatch.setattr(mc, "state_load", lambda: _st())
    monkeypatch.setattr(mc, "state_save", lambda st: None)
    monkeypatch.setattr(
        mc, "_mieru",
        lambda: types.SimpleNamespace(YELLOW="", NC="", GREEN="", RED=""))
    monkeypatch.setattr(mc, "_ensure_local_services", lambda st: [])
    monkeypatch.setattr(mc, "_probe_exit_tcp", lambda e: 12.0)
    monkeypatch.setattr(mc, "_probe_exit_e2e", lambda e: True)
    monkeypatch.setattr(mc, "_active_exits", lambda st: st["exits"])
    monkeypatch.setattr(mc, "_balance_shares", lambda st, act: bal)
    monkeypatch.setattr(mc, "_rule_specs",
                        lambda st, bal=None: [{"spec": "fresh"}])
    monkeypatch.setattr(mc, "_rules_in_sync", lambda st: True)
    monkeypatch.setattr(mc, "_rules_apply", fake_apply)
    monkeypatch.setattr(mc, "_routing_sh_text", lambda st: "# routing.sh (test)")
    monkeypatch.setattr(mc, "_b4_exempt_active", lambda st: False)
    monkeypatch.setattr(mc, "_ROUTING_SH", tmp_path / "routing.sh")
    return applied


def test_tick_jitter_does_not_rebuild(monkeypatch, tmp_path):
    applied = _mock_tick(
        monkeypatch, tmp_path,
        bal=_bal({"A": 0.29, "B": 0.36, "C": 0.35}))   # джиттер 1 п.п.
    result = mc._health_tick_locked(verbose=False)
    assert applied == []                       # ни одной пересборки
    assert result["rebalanced"] is False
    assert result["balance"]["shares"]["A"] == 0.29   # свежие доли видны


def test_tick_material_drift_rebuilds(monkeypatch, tmp_path):
    applied = _mock_tick(
        monkeypatch, tmp_path,
        bal=_bal({"A": 0.40, "B": 0.30, "C": 0.30}))   # уход на 10 п.п.
    result = mc._health_tick_locked(verbose=False)
    assert applied == [True]                   # ребаланс выполнен
    assert result["rebalanced"] is True
