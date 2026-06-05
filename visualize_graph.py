from graph import load_bipartite_graph_from_json, connected_components_sorted
from visualize_graphs import *

G, event_ids, entity_ids = load_bipartite_graph_from_json("security_data.json")
comps = connected_components_sorted(G)
events_by_id, entities_by_id, tp_event_ids, gt = load_metadata("security_data.json")
tp_comps, fp_comps = classify_components(G, comps, tp_event_ids)

plot_tp_vs_fp(G, tp_comps, fp_comps, events_by_id, entities_by_id)
plot_kill_chains(G, tp_comps, events_by_id)
plot_feature_distributions(G, tp_comps, fp_comps, events_by_id)
plt.show()