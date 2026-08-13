import json
import re
import argparse


parser = argparse.ArgumentParser()
parser.add_argument(
    "--repo",
    default="vulnerable_codebases/WebGoat"
)
args, _ = parser.parse_known_args()

REPO_ROOT = args.repo

CONTEXT_FILE = "reports/repository_context.json"
OUTPUT_FILE = "reports/call_graph.json"


# ---------------------------------------------------------
# Java
# ---------------------------------------------------------

JAVA_METHOD_PATTERN = re.compile(
    r'(?:public|private|protected|static|\s)+'
    r'[\w\<\>\[\], ?]+'
    r'\s+'
    r'(\w+)'
    r'\s*\([^)]*\)'
    r'\s*\{',
    re.MULTILINE
)


# ---------------------------------------------------------
# PHP
# ---------------------------------------------------------

PHP_METHOD_PATTERN = re.compile(
    r'(?:public|private|protected|static|final|abstract|\s)+'
    r'function\s+'
    r'([a-zA-Z_][a-zA-Z0-9_]*)'
    r'\s*\([^)]*\)'
    r'\s*\{',
    re.MULTILINE
)


# ---------------------------------------------------------
# Generic function/method call detection
# ---------------------------------------------------------

CALL_PATTERN = re.compile(
    r'(\w+)\s*\('
)


IGNORE_CALLS = {
    # Java / PHP control structures
    "if",
    "for",
    "foreach",
    "while",
    "switch",
    "catch",
    "return",
    "new",
    "super",
    "this",
    "try",
    "throw",
    "__construct",

    # PHP language constructs
    "isset",
    "empty",
    "unset",
    "echo",
    "print",
    "include",
    "require",
    "include_once",
    "require_once",

    # Common language constructs
    "array",
    "list",

    # PHP syntax
    "function",
    "use",
    "elseif",
    "else",
    "endif",
    "endfor",
    "endforeach",
    "endwhile",
    "endswitch",
}


# ---------------------------------------------------------
# File loading
# ---------------------------------------------------------

def load_source_files():

    with open(CONTEXT_FILE) as f:
        context = json.load(f)

    return context["source_files"]


# ---------------------------------------------------------
# Method extraction
# ---------------------------------------------------------

def extract_methods(content, language):

    if language == "php":
        return list(
            PHP_METHOD_PATTERN.finditer(content)
        )

    return list(
        JAVA_METHOD_PATTERN.finditer(content)
    )


# ---------------------------------------------------------
# Brace-aware method body extraction
# ---------------------------------------------------------

def find_matching_brace(content, opening_brace):

    depth = 0

    i = opening_brace

    in_single_quote = False
    in_double_quote = False
    in_line_comment = False
    in_block_comment = False

    while i < len(content):

        char = content[i]

        next_char = (
            content[i + 1]
            if i + 1 < len(content)
            else ""
        )

        # ---------------------------------------------
        # Line comments
        # ---------------------------------------------

        if in_line_comment:

            if char == "\n":
                in_line_comment = False

            i += 1
            continue

        # ---------------------------------------------
        # Block comments
        # ---------------------------------------------

        if in_block_comment:

            if char == "*" and next_char == "/":
                in_block_comment = False
                i += 2
                continue

            i += 1
            continue

        # ---------------------------------------------
        # Strings
        # ---------------------------------------------

        if in_single_quote:

            if char == "\\":
                i += 2
                continue

            if char == "'":
                in_single_quote = False

            i += 1
            continue

        if in_double_quote:

            if char == "\\":
                i += 2
                continue

            if char == '"':
                in_double_quote = False

            i += 1
            continue

        # ---------------------------------------------
        # Start comments
        # ---------------------------------------------

        if char == "/" and next_char == "/":
            in_line_comment = True
            i += 2
            continue

        if char == "/" and next_char == "*":
            in_block_comment = True
            i += 2
            continue

        # ---------------------------------------------
        # Start strings
        # ---------------------------------------------

        if char == "'":
            in_single_quote = True
            i += 1
            continue

        if char == '"':
            in_double_quote = True
            i += 1
            continue

        # ---------------------------------------------
        # Braces
        # ---------------------------------------------

        if char == "{":

            depth += 1

        elif char == "}":

            depth -= 1

            if depth == 0:
                return i

        i += 1

    return None


def extract_method_body(content, method_match):

    opening_brace = content.find(
        "{",
        method_match.end() - 1
    )

    if opening_brace == -1:
        return None

    closing_brace = find_matching_brace(
        content,
        opening_brace
    )

    if closing_brace is None:
        return None

    return content[
        opening_brace + 1:
        closing_brace
    ]


# ---------------------------------------------------------
# Call extraction
# ---------------------------------------------------------

def extract_calls_from_body(body, caller):

    calls = CALL_PATTERN.findall(body)

    result = []

    seen = set()

    for callee in calls:

        if callee == caller:
            continue

        if callee in IGNORE_CALLS:
            continue

        if len(callee) < 3:
            continue

        if callee in seen:
            continue

        seen.add(callee)

        result.append(callee)

    return result


# ---------------------------------------------------------
# File-level call extraction
# ---------------------------------------------------------

def extract_calls(source_file):

    try:

        with open(
            source_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

    except Exception:

        return []


    if source_file.endswith(".php"):
        language = "php"

    elif source_file.endswith(".java"):
        language = "java"

    else:
        return []


    methods = extract_methods(
        content,
        language
    )

    edges = []


    for method in methods:

        caller = method.group(1)

        # Constructors create huge amounts of noise.
        if caller == "__construct":
            continue

        body = extract_method_body(
            content,
            method
        )

        if body is None:
            continue

        callees = extract_calls_from_body(
            body,
            caller
        )

        for callee in callees:

            edges.append({
                "caller": caller,
                "callee": callee,
                "file": source_file,
                "language": language
            })

    return edges


# ---------------------------------------------------------
# Build graph
# ---------------------------------------------------------

def build_graph():

    files = load_source_files()

    graph = []

    excluded_parts = {
        "/build/",
        "/vendor/",
        "/node_modules/",
        "/.git/",
    }

    for file in files:

        normalized = file.replace(
            "\\",
            "/"
        )

        if any(
            part in normalized
            for part in excluded_parts
        ):
            continue

        if (
            "/tests/" in normalized
            or "/test/" in normalized
        ):
            continue

        graph.extend(
            extract_calls(file)
        )

    return graph


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    graph = build_graph()

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            graph,
            f,
            indent=2
        )

    print(
        f"[+] Call Edges: {len(graph)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()