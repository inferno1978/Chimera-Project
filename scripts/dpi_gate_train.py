#!/usr/bin/env python3
"""
scripts/dpi_gate_train.py — обучение GBDT-модели DPI Gate на PCAP-захватах.

Пайплайн (идея AIVPN tools/dpi, адаптация под Химеру):
  1. Читает PCAP-захваты из директорий benign/ (легитимный QUIC/STUN,
     например живой HTTPS/3-трафик) и tunnel/ (трафик Hysteria2/AWG
     с нод Химеры)
  2. Извлекает окна по 24 пакета (23 признака, schema v2 — совместима
     с AIVPN features.py)
  3. Учит GradientBoostingClassifier (sklearn; 120 деревьев, depth 3 —
     гиперпараметры AIVPN, зафиксированы, не подбираются)
  4. Экспортирует плоские деревья в /var/lib/xray-installer/dpi_gate_model.json
  5. Пишет отчёт: train/val accuracy, происхождение данных (SHA-256
     файлов), НИКАКИХ адресов и payload в модель/отчёт не попадает

Использование:
    python3 scripts/dpi_gate_train.py --benign-dir ./captures/benign \
                                      --tunnel-dir ./captures/tunnel
    python3 scripts/dpi_gate_train.py --synthetic   # baseline без захватов

Захваты на ноде (пример, порты подставить свои):
    tcpdump -i any -w benign.pcap udp port 443 and not host <node_ip>
    tcpdump -i any -w tunnel.pcap udp port <hysteria2_port>

Требования для обучения: scikit-learn (pip install scikit-learn).
Инференс на нодах sklearn НЕ требует (чистый Python).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from chimera.modules.dpi_gate import (  # noqa: E402
    WINDOW, FEATURE_SCHEMA_VERSION, extract_features, export_sklearn_gbc,
    load_model, model_is_usable, evaluate_udp_packets, stun_pkt, rnd_pkt,
    train_synthetic_baseline, MODEL_PATH,
)

SEED = 0
N_TREES = 120
MAX_DEPTH = 3
LEARNING_RATE = 0.15
STRIDE = 16  # выбор окон: первый кадр и каждый stride-й


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def windows_from_dir(directory: Path, label: str) -> tuple:
    """Все окна из всех PCAP директории → (X, y, provenance)."""
    from chimera.modules.dpi_gate import udp_flows_from_pcap
    X, provenance = [], []
    pcaps = sorted(directory.glob("*.pcap")) + sorted(directory.glob("*.cap"))
    if not pcaps:
        raise SystemExit(f"нет .pcap в {directory}")
    for pcap in pcaps:
        flows = udp_flows_from_pcap(pcap)
        n_windows = 0
        for key, packets in flows.items():
            i = 0
            while i < len(packets):
                w = packets[i : i + WINDOW]
                if len(w) == WINDOW:
                    X.append(extract_features(w))
                    n_windows += 1
                i += STRIDE
        provenance.append({"file": pcap.name, "sha256": sha256_file(pcap),
                           "label": label, "windows": n_windows})
    y = [1 if label == "tunnel" else 0] * len(X)
    return X, y, provenance


def train_real(benign_dir: Path, tunnel_dir: Path, out: Path,
               val_frac: float = 0.2) -> dict:
    try:
        from sklearn.ensemble import GradientBoostingClassifier
    except ImportError:
        raise SystemExit("scikit-learn не установлен: pip install scikit-learn")

    Xb, yb, prov_b = windows_from_dir(benign_dir, "benign")
    Xt, yt, prov_t = windows_from_dir(tunnel_dir, "tunnel")
    X, y = Xb + Xt, yb + yt
    if len(Xb) < 50 or len(Xt) < 50:
        raise SystemExit(
            f"мало окон: benign={len(Xb)}, tunnel={len(Xt)}; нужно ≥50 на класс "
            f"(увеличьте захват или уменьшите stride)")

    # Разделение train/val со стратификацией по классу (session-holdout
    # на уровне файлов — честнее, но требует структуры директорий; для
    # простоты держим оконный split с фикс. seed)
    rng = random.Random(SEED)
    idx = list(range(len(X)))
    rng.shuffle(idx)
    n_val = max(1, int(len(idx) * val_frac))
    val_idx = set(idx[:n_val])

    X_train = [X[i] for i in range(len(X)) if i not in val_idx]
    y_train = [y[i] for i in range(len(X)) if i not in val_idx]
    X_val = [X[i] for i in sorted(val_idx)]
    y_val = [y[i] for i in sorted(val_idx)]

    clf = GradientBoostingClassifier(
        n_estimators=N_TREES, max_depth=MAX_DEPTH,
        learning_rate=LEARNING_RATE, random_state=SEED)
    clf.fit(X_train, y_train)

    acc_train = clf.score(X_train, y_train)
    acc_val = clf.score(X_val, y_val) if X_val else 0.0

    model = export_sklearn_gbc(clf, classes=["benign", "tunnel"])
    model["provenance"] = "real_captures"
    model["training_report"] = {
        "n_train": len(X_train), "n_val": len(X_val),
        "acc_train": round(acc_train, 4), "acc_val": round(acc_val, 4),
        "benign_windows": len(Xb), "tunnel_windows": len(Xt),
        "sources": prov_b + prov_t,
        "params": {"n_trees": N_TREES, "max_depth": MAX_DEPTH,
                   "lr": LEARNING_RATE, "stride": STRIDE, "seed": SEED},
        "trained_at": datetime.now().isoformat(timespec="seconds"),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(model, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    out.chmod(0o600)
    return model["training_report"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benign-dir", type=Path, help="PCAP легитимного QUIC/STUN")
    ap.add_argument("--tunnel-dir", type=Path, help="PCAP трафика Hysteria2/AWG")
    ap.add_argument("--synthetic", action="store_true",
                    help="baseline-модель на синтетике (без sklearn/захватов)")
    ap.add_argument("--out", type=Path, default=MODEL_PATH,
                    help=f"путь модели (по умолчанию {MODEL_PATH})")
    ap.add_argument("--self-check", action="store_true",
                    help="проверить модель после обучения на контрольных окнах")
    args = ap.parse_args()

    if args.synthetic:
        print("[dpi_gate_train] синтетический baseline...")
        m = train_synthetic_baseline(out_path=args.out)
        if m:
            print(f"  OK: {args.out} (деревьев: {len(m['trees'])}, "
                  f"synthetic_accuracy={m['synthetic_accuracy']})")
        else:
            raise SystemExit("не удалось сохранить baseline")
    elif args.benign_dir and args.tunnel_dir:
        print("[dpi_gate_train] обучение на реальных захватах...")
        report = train_real(args.benign_dir, args.tunnel_dir, args.out)
        print(f"  OK: {args.out}")
        print(f"  train: {report['n_train']} окон, acc={report['acc_train']}")
        print(f"  val:   {report['n_val']} окон, acc={report['acc_val']}")
        print(f"  benign окон: {report['benign_windows']}, "
              f"tunnel окон: {report['tunnel_windows']}")
    else:
        ap.error("укажите --benign-dir и --tunnel-dir, либо --synthetic")

    if args.self_check:
        model = load_model(args.out)
        assert model_is_usable(model), "модель не прошла валидацию"
        # Контроль: синтетический STUN → benign, случайный UDP → tunnel
        from chimera.modules.dpi_gate import quic_short_pkt
        benign_win = [stun_pkt(56, 76) for _ in range(WINDOW)]
        tunnel_win = [rnd_pkt(1200, k) for k in range(WINDOW)]
        r1 = evaluate_udp_packets(benign_win, model, stride=WINDOW)
        r2 = evaluate_udp_packets(tunnel_win, model, stride=WINDOW)
        print(f"  self-check: STUN-окно → {r1['verdict']} "
              f"(p_tunnel={r1['p_tunnel_max']:.3f})")
        print(f"  self-check: RND-окно  → {r2['verdict']} "
              f"(p_tunnel={r2['p_tunnel_max']:.3f})")


if __name__ == "__main__":
    main()
