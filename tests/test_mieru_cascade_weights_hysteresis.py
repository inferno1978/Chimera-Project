"""tests/test_mieru_cascade_weights_hysteresis.py

Гистерезис дрейфа весов в health-тике mieru-каскада.

Живой кейс (октябрь 2026, entry-нода с leastping): без порога джиттер
метрик каждый тик давал «новые» вероятности → weights_drift=True →
полная пересборка правил (~90 вызовов iptables) + persist
/etc/iptables/rules.v4 каждую минуту. Фикс: ребаланс только при
материальном дрейфе долей (>WEIGHTS_HYSTERESIS или смена состава
Exit-ов).
"""

import time
import types

import pytest

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


# ── EMA-сглаживание метрик ───────────────────────────────────────────────

def test_ema_no_history_returns_fresh():
    st = {}
    out = mc._ema_metrics(st, "A", {"lat_ms": 30.0, "ttfb_ms": 200.0})
    assert out == {"lat_ms": 30.0, "ttfb_ms": 200.0}
    assert "A" in st["metrics_ema"]              # история посеяна


def test_ema_blends_with_history():
    st = {"metrics_ema": {"A": {"lat_ms": 100.0, "ttfb_ms": 300.0,
                                "ts": time.time()}}}
    out = mc._ema_metrics(st, "A", {"lat_ms": 200.0, "ttfb_ms": 300.0})
    exp = mc._B_EMA_ALPHA * 200.0 + (1 - mc._B_EMA_ALPHA) * 100.0
    assert out["lat_ms"] == pytest.approx(exp)
    assert out["ttfb_ms"] == pytest.approx(300.0)


def test_ema_stale_history_forgotten():
    st = {"metrics_ema": {"A": {"lat_ms": 100.0, "ts": time.time() - 3600}}}
    out = mc._ema_metrics(st, "A", {"lat_ms": 200.0})
    assert out["lat_ms"] == 200.0               # протухла — берём fresh


def test_ema_non_numeric_passthrough():
    st = {"metrics_ema": {"A": {"lat_ms": 100.0, "ts": time.time()}}}
    out = mc._ema_metrics(st, "A", {"lat_ms": None})
    assert out["lat_ms"] is None                # провал пробы не сглаживаем


def test_balance_shares_smart_uses_smoothed_metrics(monkeypatch):
    monkeypatch.setattr(mc, "_count_exit_load", lambda e: 0)
    monkeypatch.setattr(mc, "_probe_exit_ttfb", lambda e: 480.0)
    st = {
        "strategy": "smart",
        "metrics_ema": {"A": {"lat_ms": 30.0, "ttfb_ms": 160.0,
                              "load": 0, "ts": time.time()}},
    }
    act = [{"id": "e1", "label": "A", "latency_ms": 30.0,
            "redsocks_port": 23081}]
    bal = mc._balance_shares(st, act)
    # всплеск TTFB 480 при истории 160 → сглажено между ними, не 480
    assert 160.0 < bal["metrics"]["A"]["ttfb_ms"] < 480.0
    assert bal["shares"]["A"] == pytest.approx(1.0)


# ── Cooldown весовых ребалансов ───────────────────────────────────────────

def test_cooldown_blocks_weights_rebuild(monkeypatch, tmp_path):
    applied = _mock_tick(
        monkeypatch, tmp_path,
        bal=_bal({"A": 0.40, "B": 0.30, "C": 0.30}))   # материальный дрейф

    def _st_now():
        s = _st()
        s["weights_applied_ts"] = time.time()          # только что применяли
        return s

    monkeypatch.setattr(mc, "state_load", _st_now)
    result = mc._health_tick_locked(verbose=False)
    assert applied == []                       # cooldown подавил ребаланс
    assert result["rebalanced"] is False


def test_cooldown_expiry_allows_rebuild(monkeypatch, tmp_path):
    applied = _mock_tick(
        monkeypatch, tmp_path,
        bal=_bal({"A": 0.40, "B": 0.30, "C": 0.30}))

    def _st_old():
        s = _st()
        s["weights_applied_ts"] = (
            time.time() - (mc.WEIGHTS_REBUILD_COOLDOWN_S + 1))
        return s

    monkeypatch.setattr(mc, "state_load", _st_old)
    result = mc._health_tick_locked(verbose=False)
    assert applied == [True]                   # cooldown истёк — ребаланс
    assert result["rebalanced"] is True


def test_rules_apply_records_weights_ts(monkeypatch, tmp_path):
    st = _st()
    monkeypatch.setattr(mc, "_active_exits", lambda st: st["exits"])
    monkeypatch.setattr(mc, "_balance_shares",
                        lambda st, act: _bal({"A": 1.0}))
    monkeypatch.setattr(mc, "_rule_specs",
                        lambda st, bal=None: [{"spec": "x"}])
    monkeypatch.setattr(mc, "_spec_argv",
                        lambda sp, add: ["true"] if add else ["false"])
    monkeypatch.setattr(mc, "_purge_orphan_rules", lambda st: None)
    monkeypatch.setattr(
        mc, "_run",
        lambda cmd, capture=False: types.SimpleNamespace(
            returncode=0 if cmd[0] == "true" else 1, stderr=""))
    monkeypatch.setattr(mc, "proto_ipt_persist", lambda: None)
    monkeypatch.setattr(mc, "state_save", lambda st: None)
    mc._rules_apply(st)
    assert st.get("weights_applied_ts", 0) > 0  # clock для cooldown
