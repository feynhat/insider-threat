"""
Visualization for security alert subgraphs.
Usage: import after running the graph builder, or run standalone:
    python visualize_graphs.py security_data.json
"""

import json
import sys
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import Patch

# --- Constants ---

MITRE_MAP = {
    "Authentication":      ("Initial Access",      "TA0001", 0),
    "Privilege Operation": ("Privilege Escalation", "TA0004", 1),
    "Defense Evasion":     ("Defense Evasion",      "TA0005", 2),
    "Data Access":         ("Collection",           "TA0009", 3),
    "Exfiltration":        ("Exfiltration",         "TA0010", 4),
}
TACTIC_NAMES = {k: v[0] for k, v in MITRE_MAP.items()}

EVENT_COLORS = {
    "Authentication": "#e63946", "Privilege Operation": "#f4a261",
    "Defense Evasion": "#e9c46a", "Data Access": "#2a9d8f",
    "Exfiltration": "#264653",
}
ENTITY_COLORS = {
    "User": "#457b9d", "Host": "#a8dadc", "File": "#f4a261",
    "Process": "#6d6875", "Domain": "#b5838d",
    "NetworkConnection": "#ffb4a2", "Database": "#e5989b",
}


def load_metadata(file):
    """Load JSON and index events/entities by ID."""
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)
    events_by_id = {e["id"]: e for e in data["events"]}
    entities_by_id = {e["id"]: e for e in data["entities"]}
    gt = data.get("ground_truth", {})
    tp_event_ids = set(gt.get("true_positive_events", []))
    return events_by_id, entities_by_id, tp_event_ids, gt


def classify_components(G, components, tp_event_ids):
    """Split components into TP and FP based on ground truth."""
    tp_comps, fp_comps = [], []
    for comp in components:
        event_ids = {n for n in comp if G.nodes[n].get("kind") == "event"}
        if event_ids & tp_event_ids:
            tp_comps.append(comp)
        else:
            fp_comps.append(comp)
    return tp_comps, fp_comps


def comp_stats(G, comp, events_by_id):
    """Compute summary stats for a component."""
    event_ids = {n for n in comp if G.nodes[n].get("kind") == "event"}
    entity_ids = {n for n in comp if G.nodes[n].get("kind") == "entity"}
    evts = [events_by_id[eid] for eid in event_ids if eid in events_by_id]
    if not evts:
        return {}
    sevs = [e["severity"] for e in evts]
    weights = [G.edges[u, v].get("weight", 0) for u, v in G.edges if u in comp and v in comp]
    event_types = Counter(e["type"] for e in evts)
    return {
        "n_events": len(event_ids),
        "n_entities": len(entity_ids),
        "sev_mean": sum(sevs) / len(sevs),
        "weight_mean": sum(weights) / len(weights) if weights else 0,
        "n_event_types": len(event_types),
        "event_types": event_types,
    }


def draw_subgraph(ax, G, comp, events_by_id, entities_by_id, title=None):
    """Draw a single component as a bipartite graph."""
    sub = G.subgraph(comp).copy()
    ev_nodes = [n for n in sub if sub.nodes[n].get("kind") == "event"]
    en_nodes = [n for n in sub if sub.nodes[n].get("kind") == "entity"]

    pos = {}
    for i, n in enumerate(ev_nodes):
        pos[n] = (0, -i * 1.2)
    for i, n in enumerate(en_nodes):
        pos[n] = (2, -i * len(ev_nodes) * 1.2 / max(len(en_nodes), 1))

    colors, sizes, labels = [], [], {}
    for n in sub:
        if sub.nodes[n].get("kind") == "event" and n in events_by_id:
            e = events_by_id[n]
            colors.append(EVENT_COLORS.get(e["type"], "#999"))
            sizes.append(300)
            labels[n] = TACTIC_NAMES.get(e["type"], e["type"])[:8]
        elif n in entities_by_id:
            e = entities_by_id[n]
            colors.append(ENTITY_COLORS.get(e["type"], "#999"))
            sizes.append(180)
            labels[n] = e["name"][:10]
        else:
            colors.append("#999")
            sizes.append(100)
            labels[n] = ""

    edge_widths = [sub.edges[u, v].get("weight", 0.5) * 3 for u, v in sub.edges]
    nx.draw(sub, pos, ax=ax, node_color=colors, node_size=sizes,
            width=edge_widths, edge_color="#cccccc", labels=labels, font_size=6)
    if title:
        ax.set_title(title, fontsize=9)


def plot_tp_vs_fp(G, tp_comps, fp_comps, events_by_id, entities_by_id):
    """Side-by-side grid: all TP components + sample FP components."""
    n_tp = len(tp_comps)
    n_show = max(n_tp, 3)
    fig, axes = plt.subplots(2, n_show, figsize=(6 * n_show, 10))
    if n_show == 1:
        axes = axes.reshape(2, 1)

    for i in range(n_show):
        # TP row
        if i < n_tp:
            stats = comp_stats(G, tp_comps[i], events_by_id)
            draw_subgraph(axes[0, i], G, tp_comps[i], events_by_id, entities_by_id,
                          f"TP: {stats['n_events']}ev, sev={stats['sev_mean']:.1f}, "
                          f"wt={stats['weight_mean']:.2f}, {stats['n_event_types']}/5")
        else:
            axes[0, i].axis("off")

        # FP row — sample from different sizes
        if i < len(fp_comps):
            idx = i * len(fp_comps) // n_show
            stats = comp_stats(G, fp_comps[idx], events_by_id)
            draw_subgraph(axes[1, i], G, fp_comps[idx], events_by_id, entities_by_id,
                          f"FP: {stats['n_events']}ev, sev={stats['sev_mean']:.1f}, "
                          f"wt={stats['weight_mean']:.2f}, {stats['n_event_types']}/5")
        else:
            axes[1, i].axis("off")

    patches = [Patch(color=c, label=f"Event: {TACTIC_NAMES[k]}") for k, c in EVENT_COLORS.items()]
    patches += [Patch(color=c, label=f"Entity: {k}") for k, c in ENTITY_COLORS.items()]
    fig.legend(handles=patches, loc="lower center", ncol=4, fontsize=8,
               bbox_to_anchor=(0.5, -0.02))
    fig.suptitle("Subgraph Comparison: True Positives (top) vs False Positives (bottom)", fontsize=13)
    fig.tight_layout()
    return fig


def plot_kill_chains(G, tp_comps, events_by_id):
    """Kill chain timeline for each TP component."""
    n = len(tp_comps)
    cols = min(n, 3)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
    if n == 1:
        axes = [axes]
    else:
        axes = axes.flat

    stage_order = sorted(MITRE_MAP.keys(), key=lambda k: MITRE_MAP[k][2])

    for ax, comp in zip(axes, tp_comps):
        event_ids = [n for n in comp if G.nodes[n].get("kind") == "event"]
        evts = sorted([events_by_id[eid] for eid in event_ids if eid in events_by_id],
                      key=lambda e: e["timestamp"])
        t0 = datetime.fromisoformat(evts[0]["timestamp"])
        for e in evts:
            dt = (datetime.fromisoformat(e["timestamp"]) - t0).total_seconds() / 3600
            stage = MITRE_MAP[e["type"]][2]
            ax.scatter(dt, stage, color=EVENT_COLORS[e["type"]], s=120,
                       zorder=3, edgecolors="black", linewidth=0.5)
        ax.set_yticks(range(5))
        ax.set_yticklabels([TACTIC_NAMES[s] for s in stage_order], fontsize=7)
        ax.set_xlabel("Hours from first event", fontsize=8)
        ax.set_title(f"{len(evts)} events", fontsize=9)
        ax.grid(axis="x", alpha=0.3)

    # hide unused axes
    for i in range(n, rows * cols):
        axes[i].axis("off")

    fig.suptitle("Kill Chain Progression in True Positive Subgraphs", fontsize=13)
    fig.tight_layout()
    return fig


def plot_feature_distributions(G, tp_comps, fp_comps, events_by_id):
    """Histograms of key features, TP highlighted."""
    tp_stats = [comp_stats(G, c, events_by_id) for c in tp_comps]
    fp_stats = [comp_stats(G, c, events_by_id) for c in fp_comps]

    features = [
        ("weight_mean",   "Mean Edge Weight"),
        ("sev_mean",      "Mean Severity"),
        ("n_event_types", "Kill Chain Coverage (distinct stages)"),
    ]
    fig, axes = plt.subplots(1, len(features), figsize=(5 * len(features), 4))
    for ax, (key, label) in zip(axes, features):
        fp_vals = [s[key] for s in fp_stats if key in s]
        tp_vals = [s[key] for s in tp_stats if key in s]
        ax.hist(fp_vals, bins=15, alpha=0.6, color="#b0b0b0", label=f"FP (n={len(fp_vals)})")
        for v in tp_vals:
            ax.axvline(v, color="#e63946", linewidth=2, alpha=0.8)
        ax.plot([], [], color="#e63946", linewidth=2, label=f"TP (n={len(tp_vals)})")
        ax.set_xlabel(label)
        ax.set_ylabel("Count")
        ax.legend(fontsize=8)

    fig.suptitle("Feature Distributions: TP vs FP", fontsize=13)
    fig.tight_layout()
    return fig


# --- Standalone entry point ---
if __name__ == "__main__":
    from graph import load_bipartite_graph_from_json, connected_components_sorted

    file = sys.argv[1] if len(sys.argv) > 1 else "security_data.json"
    G, event_ids, entity_ids = load_bipartite_graph_from_json(file)
    comps = connected_components_sorted(G)
    events_by_id, entities_by_id, tp_event_ids, gt = load_metadata(file)
    tp_comps, fp_comps = classify_components(G, comps, tp_event_ids)

    print(f"Components: {len(comps)} total ({len(tp_comps)} TP, {len(fp_comps)} FP)")

    plot_tp_vs_fp(G, tp_comps, fp_comps, events_by_id, entities_by_id)
    plot_kill_chains(G, tp_comps, events_by_id)
    plot_feature_distributions(G, tp_comps, fp_comps, events_by_id)
    plt.show()
