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
    scenario_entity_ids = set(scenario.get("entity_ids", []))
    scenario_node_ids = scenario_event_ids.union(scenario_entity_ids)
    found_component = None
    for comp in comps:
        if scenario_node_ids.issubset(comp):
            found_component = comp
            break
    if found_component is not None:
        print(f"Scenario {scenario['id']} is contained in component with {len(found_component)} nodes.")
    else:
        print(f"Scenario {scenario['id']} is NOT contained in any single component.")

# I want to draw a graph of one of true positive attack scenarios, showing the events and entities involved, and the relationships between them. I want to label the nodes with their ids and types (event or entity), and color the event nodes by their severity level.
import matplotlib.pyplot as plt

def draw_scenario_graph(scenario_id):
    scenario = next((s for s in data.get("ground_truth", {}).get("attack_scenarios", []) if s["id"] == scenario_id), None)
    if scenario is None:
        print(f"Scenario {scenario_id} not found.")
        return

    scenario_event_ids = set(scenario.get("event_ids", []))
    scenario_entity_ids = set(scenario.get("entity_ids", []))
    scenario_node_ids = scenario_event_ids.union(scenario_entity_ids)

    subgraph = G.subgraph(scenario_node_ids).copy()

    pos = nx.spring_layout(subgraph)
    node_colors = []
    for n in subgraph.nodes():
        if n in scenario_event_ids:
            event = next((e for e in data["events"] if e["id"] == n), None)
            severity = event.get("severity", 0) if event else 0
            node_colors.append(severity)
        else:
            node_colors.append(0)

    plt.figure(figsize=(10, 8))
    nx.draw(subgraph, pos, with_labels=True, node_color=node_colors, cmap=plt.cm.Reds, edge_color='gray')
    plt.title(f"Attack Scenario {scenario_id}")
    plt.show()

# Example usage:
draw_scenario_graph("425eeea0-76a9-460c-ae37-b66bfbaa2045")