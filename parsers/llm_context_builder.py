import json

INPUT_FILE = "reports/final_prioritized_findings.json"
OUTPUT_FILE = "reports/llm_contexts.json"


def build_summary(finding):

    endpoints = finding.get(
        "api_endpoints",
        []
    )

    methods = finding.get(
        "methods",
        []
    )

    exposure = finding.get(
        "exposure",
        "LOW"
    )

    asset = finding.get(
        "asset_type",
        "UNKNOWN"
    )

    text = []

    text.append(
        f"Asset Type: {asset}"
    )

    text.append(
        f"Exposure: {exposure}"
    )

    if endpoints:
        text.append(
            "Endpoints: "
            + ", ".join(endpoints[:5])
        )

    if methods:
        text.append(
            "Methods: "
            + ", ".join(methods[:5])
        )

    return ". ".join(text)


def run(state):

    with open(INPUT_FILE) as f:
        findings = json.load(f)

    contexts = []

    for finding in findings:

        contexts.append({

            "finding_id":
                finding["finding_id"],

            "tool":
                finding.get("tool"),

            "category":
                finding.get("category"),

            "title":
                finding["title"],

            "description":
                finding.get("description", ""),

            "severity":
                finding["severity"],

            "priority":
                finding["priority"],

            "final_score":
                finding.get("final_score", 0),

            "confidence":
                finding.get("confidence"),

            "likelihood":
                finding.get("likelihood"),

            "impact":
                finding.get("impact"),

            "vulnerability_class":
                finding.get(
                    "vulnerability_class",
                    []
                ),

            "cwe":
                finding.get(
                    "cwe",
                    []
                ),

            "owasp":
                finding.get(
                    "owasp",
                    []
                ),

            "file":
                finding["file"],

            "asset_type":
                finding["asset_type"],

            "reachability_score":
                finding["reachability_score"],

            "api_endpoints":
                finding.get(
                    "api_endpoints",
                    []
                ),

            "methods":
                finding.get(
                    "methods",
                    []
                ),

            "summary":
                build_summary(
                    finding
                )
        })

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            contexts,
            f,
            indent=2
        )

    state["llm_contexts"] = contexts

    print(
        f"[LLMContextBuilder] Generated "
        f"{len(contexts)} context packs"
    )

    return state


def main():

    state = {}

    run(state)


if __name__ == "__main__":
    main()