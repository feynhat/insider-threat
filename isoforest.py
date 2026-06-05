"""
Isolation Forest scoring for security alert subgraphs.
Uses hand-crafted features. Works with graph.py.

Usage:
    python isoforest.py security_data.json
"""

import json
import sys
from collections import Counter
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

MITRE_MAP = {
    "Authentication":      ("Initial Access",      "TA0001", 0),
    "Privilege Operation": ("Privilege Escalation", "TA0004", 1),
    "Defense Evasion":     ("Defense Evasion",      "TA0005", 2),
    "Data Access":         ("Collection",           "TA0009", 3),
    "Exfiltration":        ("Exfiltration",         "TA0010", 4),
}

FEATURE_NAMES = [
    "weight_mean", "sev_mean", "sev_max",
    "n_event_types", "span_hours", "n_events", "n_entities",
]


def load_and_score(file):
    from graph import load_bipartite_graph_from_json, connected_components_sorted

    # Build graph and find components
    G, event_ids, entity_ids = load_bipartite_graph_from_json(file)
    comps = connected_components_sorted(G)

    # Load metadata
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)
    events_by_id = {e["id"]: e for e in data["events"]}
    entities_by_id = {e["id"]: e for e in data["entities"]}
    gt = data.get("ground_truth", {})
    tp_event_ids = set(gt.get("true_positive_events", []))
    fp_tp_ratio = gt.get("fp_tp_ratio", data.get("metadata", {}).get("fp_tp_ratio", 20))

    # Extract features per component
    results = []
    for comp in comps:
        ev_ids = {n for n in comp if G.nodes[n].get("kind") == "event"}
        en_ids = {n for n in comp if G.nodes[n].get("kind") == "entity"}

        # Skip components with no events (isolated entity nodes)
        if not ev_ids:
            continue

        evts = [events_by_id[eid] for eid in ev_ids if eid in events_by_id]
        if not evts:
            continue

        sevs = [e["severity"] for e in evts]
        times = sorted(datetime.fromisoformat(e["timestamp"]) for e in evts)
        span = (times[-1] - times[0]).total_seconds() / 3600
        weights = [G.edges[u, v].get("weight", 0)
                   for u, v in G.edges if u in comp and v in comp]
        event_types = Counter(e["type"] for e in evts)

        features = [
            np.mean(weights) if weights else 0,
            np.mean(sevs),
            max(sevs),
            len(event_types),
            span,
            len(ev_ids),
            len(en_ids),
        ]

        results.append({
            "event_ids": ev_ids,
            "entity_ids": en_ids,
            "features": features,
            "is_tp": bool(ev_ids & tp_event_ids),
            "events": evts,
            "event_types": event_types,
        })

    # Run Isolation Forest
    X = np.array([r["features"] for r in results])
    n_tp_estimate = max(1, len(results) // (fp_tp_ratio + 1))
    iso = IsolationForest(
        n_estimators=200,
        contamination=n_tp_estimate / len(results),
        random_state=42,
    )
    preds = iso.fit_predict(X)
    scores = iso.decision_function(X)

    for i, r in enumerate(results):
        r["anomaly_score"] = scores[i]
        r["flagged"] = preds[i] == -1

    # Sort by anomaly score (most anomalous first)
    results.sort(key=lambda r: r["anomaly_score"])
    return results


if __name__ == "__main__":
    file = sys.argv[1] if len(sys.argv) > 1 else "security_data.json"
    results = load_and_score(file)

    labels_true = [r["is_tp"] for r in results]
    flagged = [r["flagged"] for r in results]
    tp_caught = sum(f and t for f, t in zip(flagged, labels_true))
    fp_flagged = sum(f and not t for f, t in zip(flagged, labels_true))
    n_tp = sum(labels_true)

    print(f"Components scored: {len(results)}")
    print(f"Flagged: {sum(flagged)}")
    print(f"TP caught: {tp_caught}/{n_tp}")
    print(f"FP flagged: {fp_flagged}")
    print(f"Precision: {tp_caught / max(sum(flagged), 1):.0%}")
    print(f"Recall:    {tp_caught / max(n_tp, 1):.0%}")

    print(f"\nTOP 10 MOST ANOMALOUS:")
    for i, r in enumerate(results[:10]):
        label = "TP" if r["is_tp"] else "FP"
        f = r["features"]
        print(f"  #{i+1} [{label}] events={f[5]:.0f}, sev={f[1]:.1f}, "
              f"wt={f[0]:.3f}, stages={f[3]:.0f}/5, "
              f"score={r['anomaly_score']:.3f}")