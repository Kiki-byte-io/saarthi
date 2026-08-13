import json
import re


SINK_FILE = "reports/sink_index.json"
OUTPUT_FILE = "reports/sink_method_map.json"


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


def load_sinks():

    with open(SINK_FILE) as f:
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

    if (
        line_number is None
        or line_number < 1
        or line_number > len(lines)
    ):
        return None

    # Convert the target line into a character offset.
    target_offset = sum(
        len(line) + 1
        for line in lines[:line_number - 1]
    )

    matches = list(
        PHP_METHOD_PATTERN.finditer(content)
    )

    if not matches:
        return None

    candidate = None

    for match in matches:

        if match.start() > target_offset:
            break

        candidate = match

    if candidate is None:
        return None

    return candidate.group(1)


def main():

    sinks = load_sinks()

    results = []

    resolved = 0
    unresolved = 0

    file_cache = {}

    for sink in sinks:

        file_path = sink.get(
            "file",
            ""
        )

        line_number = sink.get(
            "line"
        )

        if not file_path or not line_number:

            result = dict(sink)

            result["method"] = "__file__"
            result["context"] = "unknown"

            results.append(result)

            unresolved += 1

            continue

        if file_path not in file_cache:

            file_cache[file_path] = load_file(
                file_path
            )

        content = file_cache[file_path]

        if content is None:

            result = dict(sink)

            result["method"] = "__file__"
            result["context"] = "missing_file"

            results.append(result)

            unresolved += 1

            continue

        method = find_method(
            content,
            line_number
        )

        result = dict(sink)

        if method:

            result["method"] = method
            result["context"] = "method"

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
        f"[+] Sinks: {len(sinks)}"
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
