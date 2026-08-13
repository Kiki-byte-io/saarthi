import json


def _incident_key(finding):
    """
    Create a stable incident group from scanner evidence.

    Prefer vulnerability class, then CWE, then scanner rule title.
    This keeps incident grouping deterministic and prevents the LLM
    from accidentally dropping findings.
    """

    vulnerability_class = finding.get("vulnerability_class") or []

    if isinstance(vulnerability_class, list):
        for value in vulnerability_class:
            if isinstance(value, str) and value.strip():
                return value.strip()

    cwe = finding.get("cwe") or []

    if isinstance(cwe, list):
        for value in cwe:
            if isinstance(value, str) and value.strip():
                return value.strip()

    title = finding.get("title", "Unknown Finding")

    return title.strip()


def _build_incidents(findings):
    """
    Build the canonical incident set from ALL findings.

    The scanner evidence remains authoritative.
    """

    grouped = {}

    for finding in findings:

        key = _incident_key(finding)

        if key not in grouped:
            grouped[key] = {
                "incident": key,
                "findings": []
            }

        grouped[key]["findings"].append({
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "severity": finding.get("severity"),
            "priority": finding.get("priority"),
            "confidence": finding.get("confidence"),
            "tool": finding.get("tool"),
            "category": finding.get("category"),
            "cwe": finding.get("cwe", []),
            "owasp": finding.get("owasp", []),
            "vulnerability_class": finding.get(
                "vulnerability_class",
                []
            )
        })

    return list(grouped.values())


def _sort_incidents(incidents):

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }

    def score(incident):

        severities = [
            severity_order.get(
                finding.get("severity", "LOW"),
                0
            )
            for finding in incident["findings"]
        ]

        return (
            max(severities) if severities else 0,
            len(incident["findings"])
        )

    incidents.sort(
        key=score,
        reverse=True
    )

    return incidents


def run(state):

    findings = state.get("findings", [])

    if not findings:
        state["incidents"] = []
        return state

    # ---------------------------------------------------------
    # Canonical incident grouping
    # ---------------------------------------------------------

    incidents = _build_incidents(findings)
    incidents = _sort_incidents(incidents)

    print(
        f"[CorrelationAgent] Correlated "
        f"{len(findings)} findings into "
        f"{len(incidents)} incidents"
    )

    # ---------------------------------------------------------
    # Preserve LLM context separately.
    #
    # Qwen can still reason over the richer context later,
    # but it cannot delete or redefine scanner findings.
    # ---------------------------------------------------------

    state["incidents"] = incidents

    state["correlation_summary"] = {
        "total_findings": len(findings),
        "total_incidents": len(incidents),
        "llm_contexts_available": len(
            state.get("llm_contexts", [])
        )
    }

    return state