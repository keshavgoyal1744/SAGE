"""Security scan artifact parsing."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any, Dict, Iterable, List


def parse_security_artifacts(artifacts: Dict[str, bytes | str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for filename, raw in artifacts.items():
        if isinstance(raw, bytes) and filename.endswith(".zip"):
            findings.extend(parse_zip(raw))
            continue
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        findings.extend(parse_security_report(filename, text))
    return findings


def parse_zip(raw: bytes) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        for name in archive.namelist():
            if name.endswith((".json", ".sarif")):
                findings.extend(parse_security_report(name, archive.read(name).decode("utf-8", errors="replace")))
    return findings


def parse_security_report(filename: str, text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    lower = filename.lower()
    if "sarif" in lower or data.get("version") == "2.1.0":
        return parse_sarif(data, filename)
    if "dependency" in lower or data.get("scan", {}).get("type") == "dependency_scanning":
        return parse_gitlab_vulnerabilities(data, "dependency-scanning", filename)
    if "container" in lower or data.get("scan", {}).get("type") == "container_scanning":
        return parse_gitlab_vulnerabilities(data, "container-scanning", filename)
    if "secret" in lower or data.get("scan", {}).get("type") == "secret_detection":
        return parse_gitlab_vulnerabilities(data, "secret-detection", filename)
    if "sast" in lower or "vulnerabilities" in data:
        return parse_gitlab_vulnerabilities(data, "sast", filename)
    return []


def parse_gitlab_vulnerabilities(data: Dict[str, Any], report_type: str, filename: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        location = vuln.get("location", {}) or {}
        identifiers = vuln.get("identifiers", []) or []
        finding = {
            "source": "artifact",
            "report_type": report_type,
            "artifact": filename,
            "id": vuln.get("id") or vuln.get("uuid") or vuln.get("fingerprint"),
            "title": vuln.get("name") or vuln.get("message") or vuln.get("description") or "Security finding",
            "severity": normalize_severity(vuln.get("severity")),
            "category": report_type,
            "file": location.get("file") or location.get("dependency", {}).get("package", {}).get("name") or location.get("image"),
            "line": location.get("start_line") or location.get("line"),
            "cve": first_identifier(identifiers, "cve"),
            "cwe": first_identifier(identifiers, "cwe"),
            "evidence": {"raw_location": location, "scanner": data.get("scan", {}).get("scanner", {})},
        }
        findings.append(finding)
    return findings


def parse_sarif(data: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for run in data.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id, {})
            location = first_location(result)
            findings.append(
                {
                    "source": "artifact",
                    "report_type": "sarif",
                    "artifact": filename,
                    "id": result.get("guid") or result.get("fingerprints", {}).get("primaryLocationLineHash") or rule_id,
                    "title": result.get("message", {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id,
                    "severity": sarif_level_to_severity(result.get("level")),
                    "category": rule_id or "sarif",
                    "file": location.get("uri"),
                    "line": location.get("line"),
                    "cve": rule.get("properties", {}).get("cve"),
                    "cwe": rule_id if str(rule_id).startswith("CWE-") else None,
                    "evidence": {"rule": rule, "properties": result.get("properties", {})},
                }
            )
    return findings


def first_identifier(identifiers: Iterable[Dict[str, Any]], kind: str) -> str | None:
    for identifier in identifiers:
        value = str(identifier.get("value") or identifier.get("name") or "")
        if value.lower().startswith(kind):
            return value
    return None


def first_location(result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        physical = result["locations"][0]["physicalLocation"]
        return {
            "uri": physical.get("artifactLocation", {}).get("uri"),
            "line": physical.get("region", {}).get("startLine"),
        }
    except (KeyError, IndexError, TypeError):
        return {}


def normalize_severity(value: Any) -> str:
    text = str(value or "medium").lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text == "error":
        return "high"
    if text == "warning":
        return "medium"
    if text == "note":
        return "low"
    return "medium"


def sarif_level_to_severity(level: Any) -> str:
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(str(level or "").lower(), "medium")
