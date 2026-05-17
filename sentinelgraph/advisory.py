"""External vulnerability advisory enrichment."""

from __future__ import annotations

from typing import Any, Dict, List

import httpx

from .models import AdvisoryEnrichmentRequest
from .source_control import request_with_retry


OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "javascript": "npm",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "java": "Maven",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "ruby": "RubyGems",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "packagist": "Packagist",
}


class AdvisoryEngine:
    def enrich(self, request: AdvisoryEnrichmentRequest) -> Dict[str, object]:
        advisories: List[Dict[str, object]] = []
        errors: List[str] = []
        for identifier in [request.cve, request.ghsa]:
            if identifier:
                result = fetch_osv_by_id(identifier)
                if result.get("error"):
                    errors.append(str(result["error"]))
                elif result.get("id"):
                    advisories.append(result)
        if request.package or request.purl:
            result = fetch_osv_package(request)
            if result.get("error"):
                errors.append(str(result["error"]))
            advisories.extend(result.get("advisories", []))
        if request.include_nvd and request.cve:
            nvd = fetch_nvd_cve(request.cve)
            if nvd.get("error"):
                errors.append(str(nvd["error"]))
            elif nvd.get("id"):
                advisories.append(nvd)
        advisories = dedupe_advisories(advisories)
        return {
            "query": request.model_dump(),
            "count": len(advisories),
            "advisories": advisories,
            "errors": errors,
            "risk": advisory_risk(advisories),
        }


def fetch_osv_package(request: AdvisoryEnrichmentRequest) -> Dict[str, object]:
    payload: Dict[str, Any] = {}
    if request.purl:
        payload["package"] = {"purl": request.purl}
    elif request.package:
        ecosystem = OSV_ECOSYSTEMS.get(str(request.ecosystem or "").lower(), request.ecosystem or "")
        payload["package"] = {"name": request.package, "ecosystem": ecosystem}
    if request.version:
        payload["version"] = request.version
    if not payload.get("package"):
        return {"advisories": []}
    try:
        with httpx.Client(timeout=10.0) as client:
            response = request_with_retry(client, "POST", "https://api.osv.dev/v1/query", json=payload)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        return {"advisories": [], "error": f"OSV package query failed: {exc}"}
    return {"advisories": [normalize_osv(item) for item in data.get("vulns", []) if isinstance(item, dict)]}


def fetch_osv_by_id(identifier: str) -> Dict[str, object]:
    try:
        with httpx.Client(timeout=10.0) as client:
            response = request_with_retry(client, "GET", f"https://api.osv.dev/v1/vulns/{identifier}")
            if response.status_code == 404:
                return {}
            response.raise_for_status()
            return normalize_osv(response.json())
    except Exception as exc:
        return {"error": f"OSV id query failed for {identifier}: {exc}"}


def fetch_nvd_cve(cve: str) -> Dict[str, object]:
    if not str(cve).upper().startswith("CVE-"):
        return {}
    try:
        with httpx.Client(timeout=10.0) as client:
            response = request_with_retry(
                client,
                "GET",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve},
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        return {"error": f"NVD query failed for {cve}: {exc}"}
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if not vulnerabilities:
        return {}
    cve_data = vulnerabilities[0].get("cve", {})
    descriptions = cve_data.get("descriptions", [])
    metrics = cve_data.get("metrics", {})
    severity = nvd_severity(metrics)
    return {
        "id": cve_data.get("id") or cve,
        "source": "nvd",
        "summary": first_english_description(descriptions),
        "aliases": [cve],
        "severity": severity,
        "published": cve_data.get("published"),
        "modified": cve_data.get("lastModified"),
        "references": [ref.get("url") for ref in cve_data.get("references", {}).get("referenceData", []) if ref.get("url")][:10],
        "raw": {"metrics": metrics},
    }


def normalize_osv(item: Dict[str, Any]) -> Dict[str, object]:
    severity = ""
    severities = item.get("severity") or []
    if severities and isinstance(severities, list):
        severity = str(severities[0].get("score") or severities[0].get("type") or "")
    affected = item.get("affected") or []
    packages = []
    for entry in affected if isinstance(affected, list) else []:
        package = entry.get("package") or {}
        if package:
            packages.append(package)
    return {
        "id": item.get("id"),
        "source": "osv",
        "summary": item.get("summary") or item.get("details", "")[:300],
        "details": item.get("details", "")[:2000],
        "aliases": item.get("aliases") or [],
        "severity": severity,
        "published": item.get("published"),
        "modified": item.get("modified"),
        "packages": packages,
        "references": [ref.get("url") for ref in item.get("references", []) if isinstance(ref, dict) and ref.get("url")][:10],
    }


def nvd_severity(metrics: Dict[str, Any]) -> str:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)
        if values:
            metric = values[0].get("cvssData", {})
            return str(metric.get("baseSeverity") or metric.get("baseScore") or "").lower()
    return ""


def first_english_description(descriptions: List[Dict[str, Any]]) -> str:
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value") or ""
    return descriptions[0].get("value", "") if descriptions else ""


def advisory_risk(advisories: List[Dict[str, object]]) -> Dict[str, object]:
    critical = 0
    high = 0
    for item in advisories:
        text = f"{item.get('severity')} {item.get('summary')}".lower()
        if "critical" in text or "9." in text or "10." in text:
            critical += 1
        elif "high" in text or "8." in text or "7." in text:
            high += 1
    if critical:
        level = "critical"
    elif high:
        level = "high"
    elif advisories:
        level = "medium"
    else:
        level = "low"
    return {"level": level, "critical": critical, "high": high}


def dedupe_advisories(advisories: List[Dict[str, object]]) -> List[Dict[str, object]]:
    result = []
    seen = set()
    for advisory in advisories:
        key = advisory.get("id") or tuple(advisory.get("aliases") or [])
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(advisory)
    return result
