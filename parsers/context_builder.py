import json
import os

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--repo", default="vulnerable_codebases/WebGoat")
args, _ = parser.parse_known_args()

REPO_ROOT = args.repo

OUTPUT_FILE = "reports/repository_context.json"


SOURCE_EXTENSIONS = (
    ".java",
    ".kt",
    ".php",
)

CONFIG_EXTENSIONS = (
    ".yml",
    ".yaml",
    ".properties",
    ".xml",
    ".json",
)

DOC_EXTENSIONS = (
    ".md",
    ".adoc",
    ".txt",
)


def build_context():

    context = {
    "source_files": [],
    "config_files": [],
    "documents": [],
    "pom_files": [],
    "composer_files": [],
}

    for root, dirs, files in os.walk(REPO_ROOT):

        for file in files:

            path = os.path.join(root, file)

            if file == "pom.xml":
                context["pom_files"].append(path)

            elif file == "composer.json":
                context["composer_files"].append(path)

            elif file.endswith(SOURCE_EXTENSIONS):
                context["source_files"].append(path)

            elif file.endswith(CONFIG_EXTENSIONS):
                context["config_files"].append(path)

            elif file.endswith(DOC_EXTENSIONS):
                context["documents"].append(path)

    return context


def main():

    context = build_context()

    with open(OUTPUT_FILE, "w") as f:

        json.dump(
            context,
            f,
            indent=2
        )

    print(
        f"[+] Source Files: "
        f"{len(context['source_files'])}"
    )

    print(
        f"[+] Config Files: "
        f"{len(context['config_files'])}"
    )

    print(
        f"[+] Documents: "
        f"{len(context['documents'])}"
    )

    print(
        f"[+] POM Files: "
        f"{len(context['pom_files'])}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )

    print(
    f"[+] Composer Files: "
    f"{len(context['composer_files'])}"
    )

if __name__ == "__main__":
    main()