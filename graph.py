import json
from typing import Tuple, Set

import networkx as nx


def load_bipartite_graph_from_json(file: str) -> Tuple[nx.Graph, Set[str], Set[str]]:
	"""Load json file and return a bipartite weighted graph.

	Nodes are the `id` values from `events` and `entities`.
	Edges are created from `relationships` with the edge attribute `weight` set
	from the relationship's `weight` field. Each node gets attributes:
	- `kind`: either 'event' or 'entity'
	- `bipartite`: 0 for events, 1 for entities

	Returns:
	  (G, event_ids, entity_ids)
	"""
	with open(file, "r", encoding="utf-8") as f:
		data = json.load(f)

	events = data.get("events", [])
	entities = data.get("entities", [])
	relationships = data.get("relationships", [])

	G = nx.Graph()

	event_ids = {e["id"] for e in events}
	entity_ids = {e["id"] for e in entities}

	for eid in event_ids:
		G.add_node(eid, kind="event", bipartite=0)
	for nid in entity_ids:
		G.add_node(nid, kind="entity", bipartite=1)

	for rel in relationships:
		src = rel.get("source")
		tgt = rel.get("target")
		weight = rel.get("weight", 1.0)
		rtype = rel.get("type")

		if src is None or tgt is None:
			continue

		# Ensure nodes exist in graph (in case relationships reference missing ids)
		if src not in G:
			G.add_node(src, kind=("event" if src in event_ids else "entity"), bipartite=(0 if src in event_ids else 1))
		if tgt not in G:
			G.add_node(tgt, kind=("event" if tgt in event_ids else "entity"), bipartite=(0 if tgt in event_ids else 1))

		G.add_edge(src, tgt, weight=weight, type=rtype)

	return G, event_ids, entity_ids




def connected_components_sorted(G: nx.Graph):
	"""Return connected components sorted by size (descending)."""
	comps = list(nx.connected_components(G))
	comps.sort(key=len, reverse=True)
	return comps


if __name__ == "__main__":
	G, events, entities = load_bipartite_graph_from_json("security_data.json")
	print(f"Loaded graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
	print(f"Events: {len(events)}, Entities: {len(entities)}")

	# show a few sample edges
	for u, v, d in list(G.edges(data=True))[:10]:
		print(u, "-", v, ":", d)

	comps = connected_components_sorted(G)
	print(f"Connected components: {len(comps)}")
	# print sizes of the 5 largest components
	for i, comp in enumerate(comps[:5], start=1):
		print(f"Component {i}: size={len(comp)}")

