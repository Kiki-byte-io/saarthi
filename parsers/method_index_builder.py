import json
import os
import re

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--repo", default="vulnerable_codebases/WebGoat")
args, _ = parser.parse_known_args()

REPO_ROOT = args.repo

OUTPUT_FILE = "reports/method_index.json"


JAVA_METHOD_PATTERN = re.compile(
    r"(public|private|protected)\s+.*?\s+([a-zA-Z0-9_]+)\s*\(",
    re.MULTILINE
)

PHP_METHOD_PATTERN = re.compile(
    r"(?:public|private|protected|static|\s)+"
    r"function\s+([a-zA-Z0-9_]+)\s*\(",
    re.MULTILINE
)


def extract_java_methods(path):

    methods = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

        matches = JAVA_METHOD_PATTERN.findall(
            content
        )

        for match in matches:

            methods.append(
                match[1]
            )

    except Exception:
        pass

    return methods


def extract_php_methods(path):

    methods = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

        matches = PHP_METHOD_PATTERN.findall(
            content
        )

        for match in matches:

            methods.append(
                match
            )

    except Exception:
        pass

    return methods


def main():

    results = []

    for root, dirs, files in os.walk(
        REPO_ROOT
    ):

        for file in files:

            path = os.path.join(
                root,
                file
            )

            if file.endswith(".java"):

                methods = extract_java_methods(
                    path
                )

                language = "java"

            elif file.endswith(".php"):

                methods = extract_php_methods(
                    path
                )

                language = "php"

            else:

                continue

            if methods:

                results.append({
                    "file": path,
                    "language": language,
                    "methods": methods
                })

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
        f"[+] Files Indexed: "
        f"{len(results)}"
    )

    total_methods = sum(
        len(x["methods"])
        for x in results
    )

    print(
        f"[+] Methods Indexed: "
        f"{total_methods}"
    )

    print(
        f"[+] Saved: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()