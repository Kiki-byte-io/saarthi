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


def main():

    with open(INPUT_FILE) as f:
        findings = json.load(f)

    contexts = []

    for finding in findings:

        contexts.append({

            "finding_id":
                finding["finding_id"],

            "title":
                finding["title"],

            "severity":
                finding["severity"],

            "priority":
                finding["priority"],

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

    print(
        f"[+] Context Packs: "
        f"{len(contexts)}"
    )

    print(
        f"[+] Output: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
