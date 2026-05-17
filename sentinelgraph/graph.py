"""Security knowledge graph operations."""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional

from .models import Edge, Entity
from .storage import Store
from .utils import stable_id


class SecurityGraph:
    def __init__(self, store: Store):
        self.store = store

    def entity(self, entity_type: str, name: str, **attributes: Any) -> Entity:
        entity_id = attributes.pop("id", stable_id(entity_type, name))
        entity = Entity(id=entity_id, type=entity_type, name=name, attributes=attributes)
        return self.store.upsert_entity(entity)

    def link(self, source: str, target: str, relation: str, **attributes: Any) -> Edge:
        return self.store.upsert_edge(
            Edge(source=source, target=target, relation=relation, attributes=attributes)
        )

    def upsert_repo(self, name: str, **attributes: Any) -> Entity:
        return self.entity("repo", name, id=stable_id("repo", name), **attributes)

    def upsert_service(self, repo: str, service: str, **attributes: Any) -> Entity:
        repo_entity = self.upsert_repo(repo)
        service_entity = self.entity("service", service, id=stable_id("service", repo, service), **attributes)
        self.link(repo_entity.id, service_entity.id, "contains")
        return service_entity

    def traverse(self, start_id: str, depth: int = 3) -> Dict[str, Any]:
        seen = {start_id}
        nodes: Dict[str, Entity] = {}
        edges: List[Edge] = []
        start = self.store.get_entity(start_id)
        if not start:
            return {"nodes": [], "edges": []}
        nodes[start.id] = start
        queue = deque([(start_id, 0)])
        while queue:
            current, level = queue.popleft()
            if level >= depth:
                continue
            for edge, neighbor in self.store.neighbors(current):
                edges.append(edge)
                if neighbor.id not in seen:
                    seen.add(neighbor.id)
                    nodes[neighbor.id] = neighbor
                    queue.append((neighbor.id, level + 1))
        return {
            "nodes": [node.model_dump() for node in nodes.values()],
            "edges": [edge.model_dump() for edge in edges],
        }

    def causal_search(
        self,
        keywords: List[str],
        entity_types: Optional[List[str]] = None,
        depth: int = 2,
    ) -> Dict[str, Any]:
        matches: Dict[str, Entity] = {}
        lowered = [kw.lower() for kw in keywords if kw]
        candidates: List[Entity] = []
        if entity_types:
            for entity_type in entity_types:
                candidates.extend(self.store.list_entities(entity_type))
        else:
            candidates = self.store.list_entities()
        for entity in candidates:
            haystack = f"{entity.name} {entity.attributes}".lower()
            if all(keyword in haystack for keyword in lowered):
                matches[entity.id] = entity
        traversals = [self.traverse(entity_id, depth=depth) for entity_id in matches]
        node_map: Dict[str, Dict[str, Any]] = {}
        edge_map: Dict[str, Dict[str, Any]] = {}
        for traversal in traversals:
            for node in traversal["nodes"]:
                node_map[node["id"]] = node
            for edge in traversal["edges"]:
                edge_map[f"{edge['source']}:{edge['target']}:{edge['relation']}"] = edge
        return {"matches": [e.model_dump() for e in matches.values()], "nodes": list(node_map.values()), "edges": list(edge_map.values())}

    def service_from_file(self, repo: str, path: str) -> Entity:
        parts = [p for p in path.split("/") if p]
        if not parts:
            return self.upsert_service(repo, "unknown")
        if parts[0] in {"services", "apps"} and len(parts) > 1:
            service = parts[1]
        elif parts[0] in {"src", "app"} and len(parts) > 1:
            service = parts[1]
        else:
            service = parts[0]
        return self.upsert_service(repo, service, file_prefix="/".join(parts[:2]))
