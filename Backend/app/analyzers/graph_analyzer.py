import networkx as nx
from typing import List, Dict, Any, Optional, Set, Tuple


class GraphAnalyzer:
    """
    In-memory graph analytics using NetworkX.
    Provides graph algorithms:
    - k-hop neighborhood expansion
    - shortest path between entities
    - circular fund flow detection (directed cycles)
    - connected components & campaign clusters
    - high-connectivity degree anomaly detection
    - shared infrastructure identification
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_records(
        self,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        transactions: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Populates graph from entities, relationships, and optional transactions."""
        self.graph.clear()

        # Add entity nodes
        for ent in entities:
            node_id = f"e-{ent['id']}"
            self.graph.add_node(
                node_id,
                numeric_id=ent["id"],
                label=ent.get("value", ""),
                normalized_value=ent.get("normalized_value", ""),
                entity_type=ent.get("entity_type", "UNKNOWN"),
                risk_score=ent.get("risk_score", 0.0),
                meta_data=ent.get("metadata", ent.get("meta_data", {})),
                node_type="ENTITY"
            )

        # Add relationships
        for rel in relationships:
            src = f"e-{rel['source_entity_id']}"
            tgt = f"e-{rel['target_entity_id']}"
            if self.graph.has_node(src) and self.graph.has_node(tgt):
                self.graph.add_edge(
                    src,
                    tgt,
                    id=f"r-{rel.get('id', 0)}",
                    relationship_type=rel.get("relationship_type", "RELATED_TO"),
                    confidence=rel.get("confidence", 1.0),
                    meta_data=rel.get("metadata", rel.get("meta_data", {}))
                )

        # Add transactions as edges
        if transactions:
            for tx in transactions:
                src = f"e-{tx['sender_entity_id']}"
                tgt = f"e-{tx['receiver_entity_id']}"
                if self.graph.has_node(src) and self.graph.has_node(tgt):
                    edge_key = f"tx-{tx.get('id', tx.get('transaction_ref'))}"
                    self.graph.add_edge(
                        src,
                        tgt,
                        id=edge_key,
                        relationship_type="TRANSFERRED_TO",
                        amount=tx.get("amount", 0.0),
                        currency=tx.get("currency", "INR"),
                        channel=tx.get("channel", "UPI"),
                        timestamp=str(tx.get("timestamp", "")),
                        transaction_ref=tx.get("transaction_ref", ""),
                        status=tx.get("status", "SUCCESS")
                    )

    def get_neighborhood(self, center_id: str, max_hops: int = 2, max_nodes: int = 150) -> Dict[str, Any]:
        """
        Extracts subgraph centered on a specific entity up to max_hops.
        Handles both in-edges and out-edges (undirected view for neighborhood discovery).
        """
        if not self.graph.has_node(center_id):
            return {"nodes": [], "edges": []}

        # Use undirected view for finding hops
        undirected = self.graph.to_undirected(as_view=True)
        lengths = nx.single_source_shortest_path_length(undirected, center_id, cutoff=max_hops)
        
        # Limit to max_nodes sorted by hop distance
        sorted_nodes = sorted(lengths.keys(), key=lambda n: lengths[n])[:max_nodes]
        subgraph = self.graph.subgraph(sorted_nodes)

        nodes_list = []
        for n, data in subgraph.nodes(data=True):
            nodes_list.append({
                "id": n,
                "numeric_id": data.get("numeric_id", 0),
                "label": data.get("label", n),
                "entity_type": data.get("entity_type", "UNKNOWN"),
                "risk_score": data.get("risk_score", 0.0),
                "hop_distance": lengths.get(n, 0),
                "metadata": data.get("meta_data", {})
            })

        edges_list = []
        for u, v, data in subgraph.edges(data=True):
            edges_list.append({
                "id": data.get("id", f"{u}_{v}"),
                "source": u,
                "target": v,
                "relationship_type": data.get("relationship_type", "CONNECTED_TO"),
                "confidence": data.get("confidence", 1.0),
                "amount": data.get("amount"),
                "metadata": data.get("meta_data", {})
            })

        return {"nodes": nodes_list, "edges": edges_list}

    def find_shortest_path(self, source_id: str, target_id: str) -> Optional[List[Dict[str, Any]]]:
        """Finds shortest path between two nodes (direction-agnostic for investigation)."""
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            return None

        undirected = self.graph.to_undirected(as_view=True)
        try:
            path_nodes = nx.shortest_path(undirected, source=source_id, target=target_id)
            result = []
            for n in path_nodes:
                data = self.graph.nodes[n]
                result.append({
                    "id": n,
                    "numeric_id": data.get("numeric_id", 0),
                    "label": data.get("label", n),
                    "entity_type": data.get("entity_type", "UNKNOWN"),
                    "risk_score": data.get("risk_score", 0.0)
                })
            return result
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def detect_circular_flows(self, max_cycle_length: int = 5) -> List[Dict[str, Any]]:
        """
        Detects directed cycles in money transfers: A -> B -> C -> A.
        Focuses only on 'TRANSFERRED_TO' or transfer-type edges.
        """
        tx_graph = nx.DiGraph()
        for u, v, data in self.graph.edges(data=True):
            if data.get("relationship_type") in ("TRANSFERRED_TO", "SENT"):
                tx_graph.add_edge(u, v, **data)

        detected_cycles = []
        try:
            simple_cycles = nx.simple_cycles(tx_graph)
            for cycle in simple_cycles:
                if 2 <= len(cycle) <= max_cycle_length:
                    cycle_nodes = []
                    for n in cycle:
                        data = self.graph.nodes.get(n, {})
                        cycle_nodes.append({
                            "id": n,
                            "numeric_id": data.get("numeric_id", 0),
                            "label": data.get("label", n),
                            "entity_type": data.get("entity_type", "UNKNOWN")
                        })
                    detected_cycles.append({
                        "length": len(cycle),
                        "cycle": cycle,
                        "nodes": cycle_nodes,
                        "explanation": f"Circular fund movement detected across {len(cycle)} entities: {' -> '.join([c['label'] for c in cycle_nodes])} -> {cycle_nodes[0]['label']}"
                    })
                    if len(detected_cycles) >= 10:
                        break
        except Exception:
            pass

        return detected_cycles

    def find_connected_components(self) -> List[List[str]]:
        """Finds weakly connected clusters of entities."""
        undirected = self.graph.to_undirected(as_view=True)
        components = [list(c) for c in nx.connected_components(undirected)]
        return sorted(components, key=len, reverse=True)

    def calculate_centrality_anomalies(self, top_k: int = 10) -> List[Dict[str, Any]]:
        """Calculates degree centrality and flags unusually high-connectivity entities."""
        if not self.graph.nodes():
            return []

        degree_dict = dict(self.graph.degree())
        sorted_nodes = sorted(degree_dict.items(), key=lambda x: x[1], reverse=True)[:top_k]

        results = []
        for node_id, deg in sorted_nodes:
            if deg >= 4:  # Threshold for interesting connectivity
                data = self.graph.nodes[node_id]
                results.append({
                    "node_id": node_id,
                    "numeric_id": data.get("numeric_id", 0),
                    "label": data.get("label", ""),
                    "entity_type": data.get("entity_type", ""),
                    "degree": deg,
                    "risk_score": data.get("risk_score", 0.0),
                    "explanation": f"High connectivity node ({deg} relationships). Frequently acts as an operational nexus or mule hub."
                })
        return results
