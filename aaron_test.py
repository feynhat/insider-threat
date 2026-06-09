#I want to check whether the event id's in each of the true positive attack scenarios all belong to the same connected component in the graph
import json
import networkx as nx
from graph import load_bipartite_graph_from_json, connected_components_sorted

file = "security_data.json"
with open(file, "r", encoding="utf-8") as f:
    data = json.load(f)

G, event_ids, entity_ids = load_bipartite_graph_from_json(file)
comps = connected_components_sorted(G)

for scenario in data.get("ground_truth", {}).get("attack_scenarios", []):
    scenario_event_ids = set(scenario.get("event_ids", []))
    found_component = None
    for comp in comps:
        if scenario_event_ids.issubset(comp):
            found_component = comp
            break
    if found_component is not None:
        print(f"Scenario {scenario['id']} is contained in component with {len(found_component)} nodes.")
    else:
        print(f"Scenario {scenario['id']} is NOT contained in any single component.")