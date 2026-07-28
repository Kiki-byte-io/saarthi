import json
import os
INPUT_FILE = "reports/reachable_findings.json"
OUTPUT_FILE = "reports/final_prioritized_findings.json"
RUNTIME_EVIDENCE_FILE = "reports/runtime_evidence.json"


def load_runtime_evidence():
    """
    Loads runtime evidence and creates a lookup
    using finding_id as the key.
    """

    if not os.path.exists(RUNTIME_EVIDENCE_FILE):
        return {}

    with open(RUNTIME_EVIDENCE_FILE) as f:
        evidence = json.load(f)

    lookup = {}

    for item in evidence:

        finding_id = item.get("finding_id")

        if not finding_id:
            continue

        lookup.setdefault(finding_id, []).append(item)

    return lookup

SEVERITY_SCORES = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 10
}


ATTACK_SURFACE_SCORES = {
    "APPLICATION_CODE": 20,
    "CI_PIPELINE": 15,
    "DEPENDENCY": 10,
    "CONFIGURATION": 10
}


ATTACK_PATH_KEYWORDS = [
    "CWE-78",
    "CWE-89",
    "CWE-502",
    "CWE-918",
    "CWE-434",
    "CWE-321",
    "SQL",
    "Command Injection",
    "Deserialization"
]

RUNTIME_BONUS = {
    "reachability": 15,
    "code_execution": 30,
    "sink_reached": 50
}


def calculate_score(finding):

    score = 0

    score += SEVERITY_SCORES.get(
        finding.get("severity", "LOW"),
        10
    )

    score += finding.get(
        "reachability_score",
        0
    )

    asset_type = finding.get(
        "asset_type",
        ""
    )

    score += ATTACK_SURFACE_SCORES.get(
        asset_type,
        0
    )

    exposure = finding.get(
        "exposure",
        "LOW"
    )

    if exposure == "HIGH":
        score += 30

    elif exposure == "MEDIUM":
        score += 15

    title = finding.get(
        "title",
        ""
    )

    for keyword in ATTACK_PATH_KEYWORDS:

        if keyword.lower() in title.lower():

            score += 25
            break

    return score

def runtime_bonus(finding, runtime_lookup):
    """
    Returns a score bonus based on runtime evidence.
    """

    finding_id = finding.get("finding_id")

    if not finding_id:
        return 0

    evidence = runtime_lookup.get(finding_id)

    if not evidence:
        return 0

    if not evidence.get("confirmed", False):
        return 0

    evidence_type = evidence.get("evidence_type", "")

    return RUNTIME_BONUS.get(evidence_type, 0)

def priority(score):

    if score >= 100:
        return "CRITICAL"

    if score >= 80:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    return "LOW"


def main():
    import os

    if not os.path.exists(INPUT_FILE):
        print(f"[!] {INPUT_FILE} not found. Skipping prioritization.")
        return

    with open(INPUT_FILE) as f:
        findings = json.load(f)

    runtime_lookup = load_runtime_evidence()

    print(
        f"[+] Loaded {len(runtime_lookup)} runtime evidence entries."
    )

    results = []
    for finding in findings:

        final_score = calculate_score(finding)

        final_score += runtime_bonus(
            finding,
            runtime_lookup
        )

        finding[
            "final_score"
        ] = final_score

        finding[
            "priority"
        ] = priority(
            final_score
        )

        results.append(
            finding
        )

    results.sort(
        key=lambda x:
        x["final_score"],
        reverse=True
    )

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            results,
            f,
            indent=2
        )

    print(
        f"[+] Prioritized {len(results)} findings"
    )

    print(
        f"[+] Output: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()

