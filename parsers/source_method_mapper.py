import json
import os
import re


SOURCE_FILE = "reports/source_index.json"
OUTPUT_FILE = "reports/source_method_map.json"


PHP_METHOD_PATTERN = re.compile(
    r"""
    (?:
        public
        |private
        |protected
        |static
    )*
    \s*
    function
    \s+
    ([a-zA-Z_][a-zA-Z0-9_]*)
    \s*
    \(
    """,
    re.MULTILINE | re.VERBOSE
)


def load_sources():

    with open(SOURCE_FILE) as f:
        return json.load(f)


def load_file(path):

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            return f.read()

    except Exception:

        return None


def find_method(content, line_number):

    lines = content.splitlines()

    if line_number < 1 or line_number > len(lines):
        return None

    # Find method declarations before the source line.
    #
    # We deliberately choose the nearest preceding method.
    # This gives us the method containing the source without
    # attempting full PHP parsing.

    matches = list(
        PHP_METHOD_PATTERN.finditer(content)
    )

    if not matches:
        return None

    target_offset = sum(
        len(line) + 1
        for line in lines[:line_number - 1]
    )

    candidate = None

    for match in matches:

        if match.start() > target_offset:
            break

        candidate = match

    if candidate is None:
        return None

    return candidate.group(1)


def main():

    sources = load_sources()

    results = []

    resolved = 0
    unresolved = 0

    # Cache file contents because several sources can
    # occur in the same PHP file.

    file_cache = {}

    for source in sources:

        file_path = source.get(
            "file",
            ""
        )

        line_number = source.get(
            "line"
        )

        if not file_path or not line_number:
            unresolved += 1
            continue

        if file_path not in file_cache:

            file_cache[file_path] = load_file(
                file_path
            )

        content = file_cache[file_path]

        if content is None:

            unresolved += 1
            continue

        method = find_method(
            content,
            line_number
        )

        result = dict(source)

        if method:
            result["method"] = method
            resolved += 1

        else:
            result["method"] = "__file__"
            result["context"] = "procedural_php"
            resolved += 1

        results.append(result)

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
        f"[+] Sources: {len(sources)}"
    )

    print(
        f"[+] Resolved to methods: {resolved}"
    )

    print(
        f"[+] Unresolved: {unresolved}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
