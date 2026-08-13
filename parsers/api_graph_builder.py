import json
import re

CONTEXT_FILE = "reports/repository_context.json"
OUTPUT_FILE = "reports/api_graph.json"


JAVA_PATTERNS = [
    r'@GetMapping\("([^"]+)"\)',
    r'@PostMapping\("([^"]+)"\)',
    r'@PutMapping\("([^"]+)"\)',
    r'@DeleteMapping\("([^"]+)"\)',
    r'@RequestMapping\("([^"]+)"\)',
]


def extract_java_endpoints(java_file):

    endpoints = []

    try:

        with open(
            java_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

        for pattern in JAVA_PATTERNS:

            matches = re.findall(
                pattern,
                content
            )

            for match in matches:

                endpoints.append({
                    "url": match,
                    "method": "UNKNOWN"
                })

    except Exception:
        pass

    return endpoints


def extract_php_endpoints(php_file):

    endpoints = []

    try:

        with open(
            php_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            content = f.read()

        # Nextcloud registerRoutes() / routes arrays.
        #
        # Example:
        #
        # 'name' => 'Api#getThumbnail',
        # 'url' => '/api/v1/thumbnail/{x}/{y}/{file}',
        # 'verb' => 'GET',

        route_pattern = re.compile(
            r"""
            ['"]name['"]\s*=>\s*['"]([^'"]+)['"]
            .*?
            ['"]url['"]\s*=>\s*['"]([^'"]+)['"]
            .*?
            ['"]verb['"]\s*=>\s*['"]([^'"]+)['"]
            """,
            re.DOTALL | re.VERBOSE
        )

        for match in route_pattern.finditer(content):

            name = match.group(1)
            url = match.group(2)
            method = match.group(3)

            endpoints.append({
                "name": name,
                "url": url,
                "method": method,
                "type": "nextcloud_route"
            })

        # Legacy routes:
        #
        # $this->create('route_name', 'some/path.php')

        legacy_pattern = re.compile(
            r"""
            \$this->create\(
                \s*['"]([^'"]+)['"]
                \s*,\s*['"]([^'"]+)['"]
            """,
            re.VERBOSE
        )

        for match in legacy_pattern.finditer(content):

            endpoints.append({
                "name": match.group(1),
                "url": match.group(2),
                "method": "UNKNOWN",
                "type": "nextcloud_legacy_route"
            })

    except Exception:
        pass

    return endpoints


def main():

    with open(CONTEXT_FILE) as f:
        context = json.load(f)

    api_graph = []

    excluded_parts = {
        "/tests/",
        "/test/",
        "/build/",
        "/vendor/",
        "/node_modules/",
        "/.git/",
    }

    # Java / Spring + PHP / Nextcloud
    for source_file in context.get(
        "source_files",
        []
    ):

        normalized = source_file.replace(
            "\\",
            "/"
        )

        # Skip tests, vendor, build artifacts, etc.
        if any(
            part in normalized
            for part in excluded_parts
        ):
            continue

        if source_file.endswith(
            (".java", ".kt")
        ):

            endpoints = extract_java_endpoints(
                source_file
            )

            if endpoints:

                api_graph.append({
                    "file": source_file,
                    "language": "java",
                    "endpoints": endpoints
                })

        elif source_file.endswith(".php"):

            endpoints = extract_php_endpoints(
                source_file
            )

            if endpoints:

                api_graph.append({
                    "file": source_file,
                    "language": "php",
                    "endpoints": endpoints
                })

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            api_graph,
            f,
            indent=2
        )

    total = sum(
        len(x["endpoints"])
        for x in api_graph
    )

    print(
        f"[+] API Files: {len(api_graph)}"
    )

    print(
        f"[+] Endpoints: {total}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()