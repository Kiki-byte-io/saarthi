import json
import os
import re


CONTEXT_FILE = "reports/repository_context.json"
OUTPUT_FILE = "reports/sink_index.json"


SINK_PATTERNS = {

    "command_injection": [
        r"\bexec\s*\(",
        r"\bsystem\s*\(",
        r"\bshell_exec\s*\(",
        r"\bpassthru\s*\(",
        r"\bproc_open\s*\(",
        r"\bpopen\s*\(",
    ],

    "code_injection": [
        r"\beval\s*\(",
    ],

    "deserialization": [
        r"\bunserialize\s*\(",
    ],

    "file_inclusion": [
        r"\binclude\s*\(",
        r"\brequire\s*\(",
        r"\binclude_once\s*\(",
        r"\brequire_once\s*\(",
    ],

    "file_write": [
        r"\bfile_put_contents\s*\(",
        r"\bfwrite\s*\(",
        r"\bfputs\s*\(",
    ],

    "file_delete": [
        r"\bunlink\s*\(",
    ],

    "file_rename": [
        r"\brename\s*\(",
    ],

    "file_read": [
        r"\bfile_get_contents\s*\(",
        r"\bfread\s*\(",
    ],

    "network": [
        r"\bcurl_exec\s*\(",
        r"\bcurl_multi_exec\s*\(",
    ],

    "redirect": [
        r"\bheader\s*\(",
    ],

    "sql": [
        r"->\s*query\s*\(",
        r"->\s*execute\s*\(",
        r"->\s*exec\s*\(",
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

    for category, patterns in SINK_PATTERNS.items():

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

                    "sink": match.group(0).strip(),

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

        # Avoid generated/vendor/test code
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
        f"[+] Sinks Found: {len(findings)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
