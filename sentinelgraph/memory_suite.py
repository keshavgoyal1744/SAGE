"""Memory management, dashboard, onboarding, and health reporting."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

from .graph import SecurityGraph
from .models import MemoryAskRequest, MemorySyncRequest, MergeRequestInput, ReplyCommandInput
from .provider_ops import ProviderOps
from .utils import stable_id


class MemorySuite:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def validate(self) -> Dict[str, object]:
        decisions = self.graph.store.list_entities("decision")
        errors = []
        seen = set()
        for decision in decisions:
            attrs = decision.attributes
            decision_key = attrs.get("decision_id") or decision.id
            if decision_key in seen:
                errors.append(f"Duplicate decision id: {decision_key}")
            seen.add(decision_key)
            for field in ["text", "status", "governs"]:
                if field not in attrs:
                    errors.append(f"{decision.id} missing {field}")
            for dep in attrs.get("depends_on", []):
                if not self.graph.store.get_entity(dep):
                    errors.append(f"{decision.id} depends on missing decision {dep}")
        cycles = self._dependency_cycles(decisions)
        errors.extend(cycles)
        return {"valid": not errors, "decision_count": len(decisions), "errors": errors}

    def sync(self, request: MemorySyncRequest) -> Dict[str, object]:
        decisions = self.graph.store.list_entities("decision")
        pages = {f"SENTINELGRAPH-MEMORY-{idx:03d}.md": self._decision_page(decision) for idx, decision in enumerate(decisions, 1)}
        index = "# SentinelGraph Memory Index\n\n" + "\n".join(
            f"- [{name}](./{name})" for name in pages
        )
        pages["SENTINELGRAPH-INDEX.md"] = index
        actions = []
        if request.mode in {"push", "both"}:
            ops = ProviderOps(request)
            if request.external_target in {"repo", "both"}:
                branch = request.branch
                actions.extend(
                    [
                        ops.create_branch(branch),
                        ops.commit_files(branch, "docs: sync SentinelGraph security memory", pages),
                        ops.create_change_request(branch, "main", "SentinelGraph memory sync", "Publishes current security memory pages."),
                    ]
                )
            if request.external_target in {"wiki", "both"}:
                actions.append(ops.sync_wiki_pages(pages))
        return {"pages": pages, "actions": [action.model_dump() for action in actions]}

    def ask(self, request: MemoryAskRequest) -> Dict[str, object]:
        keywords = [part.lower() for part in request.question.split() if len(part) > 2]
        matches = []
        for entity_type in ["decision", "finding", "incident", "service"]:
            for entity in self.graph.store.list_entities(entity_type):
                if request.repo and entity.attributes.get("repo") not in {None, request.repo}:
                    continue
                text = f"{entity.name} {entity.attributes}".lower()
                score = sum(1 for keyword in keywords if keyword in text)
                if score:
                    matches.append((score, entity))
        matches.sort(key=lambda item: item[0], reverse=True)
        selected = [entity.model_dump() for _, entity in matches[: request.limit]]
        answer = "No matching security memory found."
        if selected:
            answer = "Relevant security memory:\n" + "\n".join(
                f"- {item['type']} {item['name']}: {item['attributes'].get('text') or item['attributes'].get('title') or item['id']}"
                for item in selected
            )
        return {"question": request.question, "answer": answer, "matches": selected}

    def dashboard_html(self) -> str:
        counts = self.graph.store.counts()
        decisions = self.graph.store.list_entities("decision")
        findings = self.graph.store.list_findings()
        incidents = self.graph.store.list_incidents()
        rows = "\n".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in counts.items()
        )
        decision_items = "\n".join(f"<li>{d.name}</li>" for d in decisions[:20])
        finding_items = "\n".join(f"<li>{f['severity']}: {f['title']}</li>" for f in findings[:20])
        incident_items = "\n".join(f"<li>{i['severity']}: {i['title']}</li>" for i in incidents[:20])
        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SentinelGraph Dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 32px; color: #172033; }}
    table {{ border-collapse: collapse; }}
    td {{ border-bottom: 1px solid #d6dbe6; padding: 8px 14px; }}
    section {{ margin-block: 24px; }}
  </style>
</head>
<body>
  <h1>SentinelGraph Dashboard</h1>
  <section><h2>Inventory</h2><table>{rows}</table></section>
  <section><h2>Decisions</h2><ul>{decision_items}</ul></section>
  <section><h2>Findings</h2><ul>{finding_items}</ul></section>
  <section><h2>Incidents</h2><ul>{incident_items}</ul></section>
</body>
</html>"""

    def onboarding(self, repo: str) -> Dict[str, object]:
        security = [d for d in self.graph.store.list_entities("decision") if d.attributes.get("security_relevant")]
        findings = [f for f in self.graph.store.list_findings(repo) if f["severity"] in {"high", "critical"}]
        incidents = self.graph.store.list_incidents(repo)
        services = self.graph.store.list_entities("service")
        return {
            "repo": repo,
            "security_decisions": [d.model_dump() for d in security[:10]],
            "top_findings": findings[:10],
            "recent_incidents": incidents[:5],
            "services": [s.model_dump() for s in services[:20]],
            "briefing": [
                "Review security decisions before touching governed services.",
                "High and critical findings require explicit remediation evidence.",
                "Runtime-linked services should get focused negative tests.",
            ],
        }

    def health(self, repo: str | None = None) -> Dict[str, object]:
        decisions = self.graph.store.list_entities("decision")
        findings = self.graph.store.list_findings(repo)
        incidents = self.graph.store.list_incidents(repo)
        active = [d for d in decisions if d.attributes.get("status") == "active"]
        governed_files = sorted({path for d in active for path in d.attributes.get("governs", [])})
        stale = [d.model_dump() for d in active if not d.attributes.get("governs")]
        carbon = self.carbon_report()
        return {
            "active_decisions": len(active),
            "governed_files": governed_files,
            "coverage_gaps": stale,
            "open_findings": len([f for f in findings if f["status"] == "open"]),
            "incidents": len(incidents),
            "carbon": carbon,
            "validation": self.validate(),
        }

    def carbon_report(self) -> Dict[str, object]:
        decisions = self.graph.store.list_entities("decision")
        saved = 0.0
        cost = 0.0
        for decision in decisions:
            text = f"{decision.name} {decision.attributes}".lower()
            if "cache" in text or "batch" in text or "optimize" in text:
                saved += 150.0
            if "retry" in text or "scan" in text:
                cost += 20.0
        co2 = (saved - cost) * 0.4
        return {"estimated_kwh_saved_month": saved, "estimated_kwh_cost_month": cost, "estimated_kg_co2_delta": round(co2, 2)}

    def reply(self, item: ReplyCommandInput) -> Dict[str, object]:
        decision = self.graph.store.get_entity(item.decision_id)
        if not decision:
            return {"status": "not-found", "decision_id": item.decision_id}
        attrs = dict(decision.attributes)
        if item.command == "intentional":
            attrs["status"] = "superseded"
            attrs["override_reason"] = item.reasoning
        elif item.command == "accidental":
            attrs["status"] = "active"
            attrs["last_accidental_ack"] = item.reasoning
        else:
            attrs["discussion_requested_by"] = item.actor
            attrs["discussion_reason"] = item.reasoning
        updated = decision.model_copy(update={"attributes": attrs})
        self.graph.store.upsert_entity(updated)
        return {"status": "updated", "decision": updated.model_dump()}

    def pattern_rules(self) -> Dict[str, object]:
        comments = []
        for entity in self.graph.store.list_entities("merge_request"):
            comments.extend(entity.attributes.get("comments", []))
        counter = Counter()
        for comment in comments:
            body = str(comment.get("body", "")).lower()
            for marker in ["do not use md5", "use parameterized queries", "add negative tests", "avoid bypass"]:
                if marker in body:
                    counter[marker] += 1
        rules = [
            {"rule": rule, "support": count, "status": "candidate" if count < 3 else "active"}
            for rule, count in counter.items()
        ]
        return {"rules": rules}

    def enforce_patterns(self, item: MergeRequestInput) -> Dict[str, object]:
        rules = self.pattern_rules()["rules"]
        text = f"{item.title} {item.description} {item.diff_summary} {' '.join(item.files_changed)}".lower()
        violations = []
        for rule in rules:
            marker = rule["rule"]
            if marker == "do not use md5" and "md5" in text:
                violations.append({"rule": marker, "severity": "high", "message": "MR appears to use MD5 despite review memory."})
            if marker == "use parameterized queries" and any(term in text for term in ["select *", " + ", "format("]):
                violations.append({"rule": marker, "severity": "high", "message": "MR contains query-building signals that need parameterization review."})
            if marker == "add negative tests" and not any(path.startswith("tests/") or "/test" in path for path in item.files_changed):
                violations.append({"rule": marker, "severity": "medium", "message": "Review memory asks for negative tests, but no test file changed."})
            if marker == "avoid bypass" and "bypass" in text:
                violations.append({"rule": marker, "severity": "high", "message": "MR uses bypass language against review memory."})
        return {
            "repo": item.repo,
            "mr_id": item.mr_id,
            "rules_evaluated": len(rules),
            "violations": violations,
            "status": "fail" if any(v["severity"] == "high" for v in violations) else "warn" if violations else "pass",
        }

    def _decision_page(self, decision) -> str:
        attrs = decision.attributes
        return f"""# {decision.name}

- ID: {attrs.get('decision_id', decision.id)}
- Status: {attrs.get('status')}
- Security relevant: {attrs.get('security_relevant')}
- Governs: {', '.join(attrs.get('governs', []))}

{attrs.get('text', '')}
"""

    def _dependency_cycles(self, decisions) -> List[str]:
        graph = defaultdict(list)
        ids = {decision.id for decision in decisions}
        for decision in decisions:
            for dep in decision.attributes.get("depends_on", []):
                if dep in ids:
                    graph[decision.id].append(dep)
        errors = []
        visiting = set()
        visited = set()

        def visit(node, stack):
            if node in visiting:
                errors.append("Decision dependency cycle: " + " -> ".join(stack + [node]))
                return
            if node in visited:
                return
            visiting.add(node)
            for nxt in graph[node]:
                visit(nxt, stack + [node])
            visiting.remove(node)
            visited.add(node)

        for node in ids:
            visit(node, [])
        return errors
