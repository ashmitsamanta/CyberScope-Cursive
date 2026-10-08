import abc
import networkx as nx
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.models.case import Case
from app.analyzers.graph_analyzer import GraphAnalyzer


class IGraphService(abc.ABC):
    """Abstract interface for graph storage and analytics engine."""

    @abc.abstractmethod
    def sync_from_db(self, db: Session, force: bool = False) -> None:
        pass

    @abc.abstractmethod
    def get_full_graph(
        self,
        db: Session,
        limit: int = 150,
        entity_type: Optional[str] = None,
        search: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> Dict[str, Any]:
        pass

    @abc.abstractmethod
    def get_case_graph(
        self,
        db: Session,
        case_identifier: Any,
        hops: int = 2,
        case_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        pass

    @abc.abstractmethod
    def get_neighborhood(
        self,
        db: Session,
        entity_identifier: Any,
        hops: int = 2,
        entity_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        pass

    @abc.abstractmethod
    def find_shortest_path(self, db: Session, source_id: Any, target_id: Any) -> Optional[List[Dict[str, Any]]]:
        pass

    @abc.abstractmethod
    def detect_circular_flows(self, db: Session) -> List[Dict[str, Any]]:
        pass


class NetworkXGraphService(IGraphService):
    """
    In-memory graph implementation using NetworkX.
    Provides fast, deterministic execution without external daemon dependency.
    """

    def __init__(self):
        self.analyzer = GraphAnalyzer()
        self._is_synced = False

    def sync_from_db(self, db: Session, force: bool = False) -> None:
        """Loads all entities, relationships, and transactions into graph."""
        if self._is_synced and not force:
            return

        entities = db.query(Entity).all()
        relationships = db.query(Relationship).all()
        transactions = db.query(Transaction).all()

        ent_dicts = [e.to_dict() for e in entities]
        rel_dicts = [r.to_dict() for r in relationships]
        tx_dicts = [t.to_dict() for t in transactions]

        self.analyzer.build_from_records(ent_dicts, rel_dicts, tx_dicts)
        self._is_synced = True

    def resolve_entity(self, db: Session, entity_identifier: Any) -> Optional[Entity]:
        """
        Resolves an entity record by integer ID, numeric string ID, node ID ('e-12'),
        or normalized value (e.g. phone '+919686579303', domain 'secure-kyc-update.com', upi, url).
        """
        if entity_identifier is None:
            return None

        # 1. Direct integer ID
        if isinstance(entity_identifier, int):
            return db.query(Entity).filter(Entity.id == entity_identifier).first()

        clean_id = str(entity_identifier).strip()
        if not clean_id:
            return None

        # 2. Node id format e-10
        if clean_id.startswith("e-") and clean_id[2:].isdigit():
            ent = db.query(Entity).filter(Entity.id == int(clean_id[2:])).first()
            if ent:
                return ent

        # 3. Numeric string id
        if clean_id.isdigit():
            ent = db.query(Entity).filter(Entity.id == int(clean_id)).first()
            if ent:
                return ent

        # 4. Exact match or case-insensitive match on normalized_value or value
        ent = db.query(Entity).filter(
            (Entity.normalized_value.ilike(clean_id)) |
            (Entity.value.ilike(clean_id))
        ).first()
        if ent:
            return ent

        # 5. Domain / phone / upi / url normalizations
        from app.utils.normalization import (
            normalize_phone, normalize_domain, normalize_upi, normalize_url
        )
        for norm_fn in (normalize_phone, normalize_domain, normalize_upi, normalize_url):
            try:
                candidate = norm_fn(clean_id)
                if candidate and candidate != clean_id:
                    ent = db.query(Entity).filter(
                        (Entity.normalized_value.ilike(candidate)) |
                        (Entity.value.ilike(candidate))
                    ).first()
                    if ent:
                        return ent
            except Exception:
                pass

        return None

    def _compute_node_metrics(self, db: Optional[Session] = None) -> Dict[str, Dict[str, Any]]:
        """
        Computes degree, connected case count, and connected case names/IDs
        for all nodes in the NetworkX graph so the frontend knows node prominence.
        """
        G = self.analyzer.graph
        undirected = G.to_undirected(as_view=True)
        case_nodes = {
            n: data.get("label")
            for n, data in G.nodes(data=True)
            if data.get("entity_type") == "CASE"
        }

        # Case number to ID mapping
        case_num_to_id: Dict[str, int] = {}
        if db is not None:
            try:
                rows = db.query(Case.id, Case.case_number).all()
                case_num_to_id = {r[1]: r[0] for r in rows if r[1]}
            except Exception:
                pass

        metrics: Dict[str, Dict[str, Any]] = {}
        for n in G.nodes():
            deg = G.degree(n)
            connected_cases = set()
            if case_nodes:
                try:
                    lengths = nx.single_source_shortest_path_length(undirected, n, cutoff=2)
                    for neighbor in lengths:
                        if neighbor in case_nodes and case_nodes[neighbor]:
                            connected_cases.add(case_nodes[neighbor])
                except Exception:
                    pass

            c_list = sorted(list(connected_cases))
            c_ids = [case_num_to_id[c] for c in c_list if c in case_num_to_id]
            metrics[n] = {
                "degree": deg,
                "connected_case_count": len(connected_cases),
                "connected_cases": c_list,
                "case_ids": c_ids
            }
        return metrics

    def get_full_graph(
        self,
        db: Session,
        limit: int = 150,
        entity_type: Optional[str] = None,
        search: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Returns overview graph with top nodes and active edges.
        Supports filtering by entity_type, search text, and min_risk.
        Returns matching nodes and the edges connecting between them.
        Nodes include degree and connected_case_count prominence metrics in metadata.
        """
        self.sync_from_db(db)
        node_metrics = self._compute_node_metrics(db=db)

        clean_search = search.strip().lower() if search and search.strip() else None
        clean_type = entity_type.strip().upper() if entity_type and entity_type.strip() else None

        matched_nodes = []
        for n, data in self.analyzer.graph.nodes(data=True):
            # Check entity_type filter
            if clean_type:
                node_type = str(data.get("entity_type", "")).strip().upper()
                if node_type != clean_type:
                    continue

            # Check min_risk filter
            if min_risk is not None:
                risk = float(data.get("risk_score", 0.0))
                if risk < float(min_risk):
                    continue

            # Check search filter
            if clean_search:
                label = str(data.get("label", "")).lower()
                norm_val = str(data.get("normalized_value", "")).lower()
                node_id = str(n).lower()
                num_id = str(data.get("numeric_id", ""))
                meta_str = str(data.get("meta_data", {})).lower()
                if (
                    clean_search not in label
                    and clean_search not in norm_val
                    and clean_search not in node_id
                    and clean_search not in num_id
                    and clean_search not in meta_str
                ):
                    continue

            matched_nodes.append((n, data))

        # Sort matching nodes by risk score descending, then degree descending
        matched_nodes.sort(
            key=lambda item: (
                float(item[1].get("risk_score", 0.0)),
                node_metrics.get(item[0], {}).get("degree", 0)
            ),
            reverse=True
        )

        selected_nodes = matched_nodes[:limit]
        nodes = []
        for n, data in selected_nodes:
            meta = dict(data.get("meta_data", {}))
            m = node_metrics.get(n, {})
            meta["degree"] = m.get("degree", self.analyzer.graph.degree(n))
            meta["connected_case_count"] = m.get("connected_case_count", 0)
            if "connected_cases" in m:
                meta["connected_cases"] = m["connected_cases"]

            nodes.append({
                "id": n,
                "numeric_id": data.get("numeric_id", 0),
                "label": data.get("label", n),
                "entity_type": data.get("entity_type", "UNKNOWN"),
                "risk_score": round(float(data.get("risk_score", 0.0)), 1),
                "metadata": meta,
                "case_ids": m.get("case_ids", [])
            })

        node_ids = set(n["id"] for n in nodes)
        edges = []
        for u, v, data in self.analyzer.graph.edges(data=True):
            if u in node_ids and v in node_ids:
                edge_meta = dict(data.get("meta_data", {}))
                amount = data.get("amount")
                channel = data.get("channel")
                if amount is not None:
                    edge_meta["amount"] = amount
                if channel is not None:
                    edge_meta["channel"] = channel

                edges.append({
                    "id": data.get("id", f"{u}_{v}"),
                    "source": u,
                    "target": v,
                    "relationship_type": data.get("relationship_type", "CONNECTED_TO"),
                    "confidence": float(data.get("confidence", 1.0)),
                    "amount": amount,
                    "channel": channel,
                    "metadata": edge_meta
                })

        filters_applied = {}
        if clean_type:
            filters_applied["entity_type"] = clean_type
        if clean_search:
            filters_applied["search"] = clean_search
        if min_risk is not None:
            filters_applied["min_risk"] = min_risk

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": self.analyzer.graph.number_of_nodes(),
                "total_edges": self.analyzer.graph.number_of_edges(),
                "nodes_count": len(nodes),
                "edges_count": len(edges),
                "filtered_nodes": len(nodes),
                "filtered_edges": len(edges),
                "total_matched": len(matched_nodes),
                "filters": filters_applied
            }
        }

    def get_case_graph(
        self,
        db: Session,
        case_identifier: Optional[Any] = None,
        hops: int = 2,
        case_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Retrieves graph associated with a case by integer ID or case number string (e.g. CS-1024).
        Finds the CASE entity for this case and returns its neighborhood up to `hops`.
        Returns rich nodes, edges, and stats for frontend investigation.
        """
        self.sync_from_db(db)
        target_identifier = case_identifier if case_identifier is not None else case_id
        if target_identifier is None:
            return {"nodes": [], "edges": [], "stats": {"nodes_count": 0, "edges_count": 0, "hops": hops}}

        case_rec = None
        if isinstance(target_identifier, int):
            case_rec = db.query(Case).filter(Case.id == target_identifier).first()
        elif isinstance(target_identifier, str):
            clean_ident = target_identifier.strip()
            if clean_ident.isdigit():
                case_rec = db.query(Case).filter(Case.id == int(clean_ident)).first()
            if not case_rec:
                case_rec = db.query(Case).filter(Case.case_number.ilike(clean_ident)).first()

        if not case_rec:
            return {
                "nodes": [],
                "edges": [],
                "stats": {
                    "nodes_count": 0,
                    "edges_count": 0,
                    "hops": hops,
                    "total_nodes": 0,
                    "total_edges": 0,
                    "case_identifier": str(target_identifier)
                }
            }

        node_metrics = self._compute_node_metrics(db=db)

        # Find entity representing this case
        case_ent = db.query(Entity).filter(
            Entity.entity_type == "CASE",
            (Entity.normalized_value.ilike(case_rec.case_number) | Entity.value.ilike(case_rec.case_number))
        ).first()

        center_node = f"e-{case_ent.id}" if case_ent else None

        # If no explicit case entity or disconnected, gather entities directly linked via relationships or transactions
        if not center_node or not self.analyzer.graph.has_node(center_node):
            from app.models.indicator import Indicator
            tx_entities = db.query(Transaction).filter(Transaction.case_id == case_rec.id).all()
            ent_ids = set()
            for tx in tx_entities:
                if tx.sender_entity_id:
                    ent_ids.add(tx.sender_entity_id)
                if tx.receiver_entity_id:
                    ent_ids.add(tx.receiver_entity_id)

            indicators = db.query(Indicator).filter(Indicator.case_id == case_rec.id).all()
            for ind in indicators:
                if ind.entity_id:
                    ent_ids.add(ind.entity_id)

            if not ent_ids:
                return {
                    "nodes": [],
                    "edges": [],
                    "stats": {
                        "case_id": case_rec.id,
                        "case_number": case_rec.case_number,
                        "case_title": case_rec.title,
                        "severity": case_rec.severity,
                        "risk_score": case_rec.risk_score,
                        "nodes_count": 0,
                        "edges_count": 0,
                        "hops": hops,
                        "total_nodes": 0,
                        "total_edges": 0
                    }
                }
            first_ent = list(ent_ids)[0]
            center_node = f"e-{first_ent}"

        subgraph_data = self.analyzer.get_neighborhood(center_node, max_hops=hops, max_nodes=150)

        enriched_nodes = []
        for n_data in subgraph_data["nodes"]:
            nid = n_data["id"]
            meta = dict(n_data.get("metadata", {}))
            m = node_metrics.get(nid, {})
            meta["degree"] = m.get("degree", self.analyzer.graph.degree(nid) if self.analyzer.graph.has_node(nid) else 0)
            meta["connected_case_count"] = m.get("connected_case_count", 0)
            if "connected_cases" in m:
                meta["connected_cases"] = m["connected_cases"]
            n_data["metadata"] = meta
            n_data["case_ids"] = m.get("case_ids", [])
            enriched_nodes.append(n_data)

        enriched_edges = []
        for e_data in subgraph_data["edges"]:
            e_meta = dict(e_data.get("metadata", {}))
            if "amount" in e_data and e_data["amount"] is not None:
                e_meta["amount"] = e_data["amount"]
            if "channel" in e_data and e_data["channel"] is not None:
                e_meta["channel"] = e_data["channel"]
            e_data["metadata"] = e_meta
            enriched_edges.append(e_data)

        return {
            "nodes": enriched_nodes,
            "edges": enriched_edges,
            "stats": {
                "case_id": case_rec.id,
                "case_number": case_rec.case_number,
                "case_title": case_rec.title,
                "severity": case_rec.severity,
                "risk_score": case_rec.risk_score,
                "center_node": center_node,
                "nodes_count": len(enriched_nodes),
                "edges_count": len(enriched_edges),
                "hops": hops,
                "total_nodes": len(enriched_nodes),
                "total_edges": len(enriched_edges),
            }
        }

    def get_neighborhood(
        self,
        db: Session,
        entity_identifier: Optional[Any] = None,
        hops: int = 2,
        entity_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Retrieves graph neighborhood around an entity by integer ID or normalized value (e.g. phone, domain).
        Enriches nodes with prominence metrics in metadata.
        """
        self.sync_from_db(db)
        target_identifier = entity_identifier if entity_identifier is not None else entity_id
        if target_identifier is None:
            return {"nodes": [], "edges": [], "stats": {"nodes_count": 0, "edges_count": 0, "hops": hops}}

        ent = self.resolve_entity(db, target_identifier)
        if ent:
            center_node = f"e-{ent.id}"
        elif isinstance(target_identifier, str) and self.analyzer.graph.has_node(target_identifier.strip()):
            center_node = target_identifier.strip()
        else:
            return {
                "nodes": [],
                "edges": [],
                "stats": {
                    "nodes_count": 0,
                    "edges_count": 0,
                    "hops": hops,
                    "total_nodes": 0,
                    "total_edges": 0,
                    "entity_identifier": str(target_identifier)
                }
            }

        node_metrics = self._compute_node_metrics(db=db)
        subgraph_data = self.analyzer.get_neighborhood(center_node, max_hops=hops)

        enriched_nodes = []
        for n_data in subgraph_data["nodes"]:
            nid = n_data["id"]
            meta = dict(n_data.get("metadata", {}))
            m = node_metrics.get(nid, {})
            meta["degree"] = m.get("degree", self.analyzer.graph.degree(nid) if self.analyzer.graph.has_node(nid) else 0)
            meta["connected_case_count"] = m.get("connected_case_count", 0)
            if "connected_cases" in m:
                meta["connected_cases"] = m["connected_cases"]
            n_data["metadata"] = meta
            n_data["case_ids"] = m.get("case_ids", [])
            enriched_nodes.append(n_data)

        enriched_edges = []
        for e_data in subgraph_data["edges"]:
            e_meta = dict(e_data.get("metadata", {}))
            if "amount" in e_data and e_data["amount"] is not None:
                e_meta["amount"] = e_data["amount"]
            if "channel" in e_data and e_data["channel"] is not None:
                e_meta["channel"] = e_data["channel"]
            e_data["metadata"] = e_meta
            enriched_edges.append(e_data)

        return {
            "nodes": enriched_nodes,
            "edges": enriched_edges,
            "stats": {
                "center_node": center_node,
                "center_entity_id": ent.id if ent else None,
                "center_label": ent.value if ent else str(target_identifier),
                "nodes_count": len(enriched_nodes),
                "edges_count": len(enriched_edges),
                "hops": hops,
                "total_nodes": len(enriched_nodes),
                "total_edges": len(enriched_edges),
            }
        }

    def find_shortest_path(self, db: Session, source_id: Any, target_id: Any) -> Optional[List[Dict[str, Any]]]:
        self.sync_from_db(db)
        src_ent = self.resolve_entity(db, source_id)
        tgt_ent = self.resolve_entity(db, target_id)
        src_node = f"e-{src_ent.id}" if src_ent else (f"e-{source_id}" if isinstance(source_id, int) or str(source_id).isdigit() else str(source_id))
        tgt_node = f"e-{tgt_ent.id}" if tgt_ent else (f"e-{target_id}" if isinstance(target_id, int) or str(target_id).isdigit() else str(target_id))
        return self.analyzer.find_shortest_path(src_node, tgt_node)

    def detect_circular_flows(self, db: Session) -> List[Dict[str, Any]]:
        self.sync_from_db(db)
        return self.analyzer.detect_circular_flows()


    def find_shared_infrastructure(self, db: Session) -> List[Dict[str, Any]]:
        """
        Finds infrastructure entities (PHONE, DOMAIN, UPI_ID, DEVICE, IP_ADDRESS)
        that are connected to 2 or more distinct cases.
        """
        self.sync_from_db(db)
        infra_types = ("PHONE", "DOMAIN", "UPI_ID", "DEVICE", "IP_ADDRESS")
        shared_list = []

        # Find all CASE entities
        case_nodes = {
            n: data.get("label")
            for n, data in self.analyzer.graph.nodes(data=True)
            if data.get("entity_type") == "CASE"
        }

        undirected = self.analyzer.graph.to_undirected(as_view=True)
        for n, data in self.analyzer.graph.nodes(data=True):
            if data.get("entity_type") in infra_types:
                # Find connected cases within 2 hops
                connected_cases = set()
                neighbors = nx.single_source_shortest_path_length(undirected, n, cutoff=2)
                for neighbor_id in neighbors:
                    if neighbor_id in case_nodes:
                        connected_cases.add(case_nodes[neighbor_id])

                if len(connected_cases) >= 2:
                    shared_list.append({
                        "node_id": n,
                        "numeric_id": data.get("numeric_id", 0),
                        "entity_type": data.get("entity_type"),
                        "value": data.get("label"),
                        "label": data.get("label"),
                        "connected_case_count": len(connected_cases),
                        "connected_cases": list(connected_cases),
                        "risk_score": data.get("risk_score", 0.0),
                    })

        return sorted(shared_list, key=lambda x: x["connected_case_count"], reverse=True)


# Global singleton instance
graph_service = NetworkXGraphService()
