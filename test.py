def create_bipartite_graph(part1, part2, edges) -> nx.Graph:
    """Load json file and return a bipartite weighted graph.

    Nodes are the `id` values from `events` and `entities`.
    Edges are created from `relationships` with the edge attribute `weight` set
    from the relationship's `weight` field. Each node gets attributes:
    - `kind`: either 'event' or 'entity'
    - `bipartite`: 0 for events, 1 for entities
    """
    G = nx.Graph()

    part1_ids = {n["id"] for n in part1}
    part2_ids = {n["id"] for n in part2}

    for nid in part1_ids:
        G.add_node(nid, bipartite=0)
    for nid in part2_ids:
        G.add_node(nid, bipartite=1)

    for e in edges:
        print(e)
        src = e.get("source")
        tgt = e.get("target")
        weight = e.get("weight", 1.0)
        rtype = e.get("type")

        if src is None or tgt is None:
            continue

        # Ensure nodes exist in graph (in case relationships reference missing ids)
        if src not in G:
            print("source node not in G")
            G.add_node(src, kind=("event" if src in event_ids else "entity"), bipartite=(0 if src in event_ids else 1))

        if tgt not in G:
            print("target node not in G")
            G.add_node(tgt, kind=("event" if tgt in event_ids else "entity"), bipartite=(0 if tgt in event_ids else 1))

        G.add_edge(src, tgt, weight=weight, type=rtype)

    return G

def connected_components_sorted(G: nx.Graph):
    """Return connected components sorted by size (descending)."""
    comps = list(nx.connected_components(G))
    comps.sort(key=len, reverse=True)
    return comps
