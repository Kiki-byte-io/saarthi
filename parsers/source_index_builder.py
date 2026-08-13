import json
import os
import re


CONTEXT_FILE = "reports/repository_context.json"
OUTPUT_FILE = "reports/source_index.json"


SOURCE_PATTERNS = {

    "php_superglobal": [
        r"\$_GET\s*\[",
        r"\$_POST\s*\[",
        r"\$_REQUEST\s*\[",
        r"\$_COOKIE\s*\[",
        r"\$_FILES\s*\[",
        r"\$_SERVER\s*\[",
    ],

    "nextcloud_request": [
        r"->getParam\s*\(",
        r"->getParams\s*\(",
    ],
}
def load_source_files():

    with open(CONTEXT_FILE) as f:
        context = json.load(f)

    return context.get(
        "source_files",
        []
    )


def build_patterns():

    compiled = {}

    for category, patterns in SOURCE_PATTERNS.items():

        compiled[category] = [
            re.compile(pattern)
            for pattern in patterns
        ]

    return compiled


def scan_file(path, compiled_patterns):

    findings = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            lines = f.readlines()

    except Exception:

        return findings

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        for category, patterns in compiled_patterns.items():

            for pattern in patterns:

                match = pattern.search(line)

                if not match:
                    continue

                findings.append({
                    "file": path,
                    "line": line_number,
                    "category": category,
                    "source": match.group(0).strip(),
                    "code": line.strip()
                })

                break

    return findings


def main():

    source_files = load_source_files()

    compiled_patterns = build_patterns()

    findings = []

    scanned = 0

    for source_file in source_files:

        if not source_file.endswith(".php"):
            continue

        normalized = source_file.replace(
            "\\",
            "/"
        )

        excluded = (
            "/vendor/",
            "/build/",
            "/node_modules/",
            "/.git/",
            "/tests/",
            "/test/",
            "/composer/",
        )

        if any(
            part in normalized
            for part in excluded
        ):
            continue

        if ".php-cs-fixer" in normalized:
            continue

        scanned += 1

        findings.extend(
            scan_file(
                source_file,
                compiled_patterns
            )
        )

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            findings,
            f,
            indent=2
        )

    print(
        f"[+] PHP Files Scanned: {scanned}"
    )

    print(
        f"[+] Sources Found: {len(findings)}"
    )


if __name__ == "__main__":
    main()