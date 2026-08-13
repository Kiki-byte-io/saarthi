import json
import xml.etree.ElementTree as ET

INPUT_FILE = "reports/repository_context.json"
OUTPUT_FILE = "reports/dependency_graph.json"


def parse_pom(pom_file):

    deps = []

    try:

        tree = ET.parse(pom_file)
        root = tree.getroot()

        ns = {
            "m": "http://maven.apache.org/POM/4.0.0"
        }

        for dep in root.findall(
            ".//m:dependency",
            ns
        ):

            group = dep.find(
                "m:groupId",
                ns
            )

            artifact = dep.find(
                "m:artifactId",
                ns
            )

            version = dep.find(
                "m:version",
                ns
            )

            deps.append({
                "ecosystem": "maven",
                "group": (
                    group.text
                    if group is not None
                    else ""
                ),
                "artifact": (
                    artifact.text
                    if artifact is not None
                    else ""
                ),
                "version": (
                    version.text
                    if version is not None
                    else ""
                ),
                "source_file": pom_file
            })

    except Exception as e:

        print(
            f"Error parsing {pom_file}: {e}"
        )

    return deps


def parse_composer(composer_file):

    deps = []

    try:

        with open(
            composer_file,
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        for name, version in data.get(
            "require",
            {}
        ).items():

            deps.append({
                "ecosystem": "composer",
                "group": "",
                "artifact": name,
                "version": version,
                "source_file": composer_file
            })

        for name, version in data.get(
            "require-dev",
            {}
        ).items():

            deps.append({
                "ecosystem": "composer",
                "group": "",
                "artifact": name,
                "version": version,
                "source_file": composer_file,
                "development": True
            })

    except Exception as e:

        print(
            f"Error parsing {composer_file}: {e}"
        )

    return deps


def main():

    with open(INPUT_FILE) as f:

        context = json.load(f)

    all_deps = []

    # Maven dependencies
    for pom in context.get(
        "pom_files",
        []
    ):

        all_deps.extend(
            parse_pom(pom)
        )

    # Composer dependencies
    for composer in context.get(
        "composer_files",
        []
    ):

        all_deps.extend(
            parse_composer(composer)
        )

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            all_deps,
            f,
            indent=2
        )

    print(
        f"[+] Dependencies Found: {len(all_deps)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()