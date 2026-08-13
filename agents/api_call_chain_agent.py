import json
import os
import re


API_GRAPH = "reports/api_graph.json"
CALL_GRAPH = "reports/call_graph.json"
OUTPUT_FILE = "reports/api_call_chains.json"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def parse_controller_method(endpoint):
    """
    Convert:

        RequestHandler#addShare

    into:

        controller = RequestHandler
        method = addShare
    """

    if not isinstance(endpoint, dict):
        return None, None

    name = endpoint.get("name", "")

    if "#" not in name:
        return None, None

    controller, method = name.split("#", 1)

    return controller.strip(), method.strip()
def resolve_legacy_route(endpoint, repo_root):
    """
    Resolve a Nextcloud legacy route directly to its PHP target file.

    Example:

        apps/files_versions/download.php
            ->
        ../targets/nextcloud-28/apps/files_versions/download.php
    """

    if not isinstance(endpoint, dict):
        return None

    if endpoint.get("type") != "nextcloud_legacy_route":
        return None

    url = endpoint.get("url", "")

    if not url:
        return None

    # Remove leading slash
    relative_path = url.lstrip("/")

    target = os.path.normpath(
        os.path.join(
            repo_root,
            relative_path
        )
    )

    if os.path.isfile(target):
        return target

    return None

def controller_variants(controller):
    """
    Convert Nextcloud route controller names into possible PHP
    controller class names.

    Examples:

        birthday_calendar -> BirthdayCalendar
        invitation_response -> InvitationResponse
        out_of_office -> OutOfOffice
        Users -> Users
    """

    variants = []

    if not controller:
        return variants

    variants.append(controller)

    if "_" in controller:
        variants.append(
            "".join(
                part.capitalize()
                for part in controller.split("_")
            )
        )

    variants.append(
        controller[:1].upper() + controller[1:]
    )

    return list(dict.fromkeys(variants))


# ---------------------------------------------------------
# PHP symbol extraction
# ---------------------------------------------------------

CLASS_PATTERN = re.compile(
    r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+extends\s+([A-Za-z_\\][A-Za-z0-9_\\]*))?",
    re.MULTILINE
)

TRAIT_PATTERN = re.compile(
    r"\btrait\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE
)

USE_TRAIT_PATTERN = re.compile(
    r"\buse\s+([^;{]+)(?:\{[^}]*\})?\s*;",
    re.MULTILINE
)

FUNCTION_PATTERN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE
)


def build_php_symbol_index(source_files):
    """
    Build a lightweight PHP symbol index.

    Produces:

        classes[class_name] = {
            "file": "...",
            "parent": "...",
            "traits": [...],
            "methods": [...]
        }

        traits[trait_name] = {
            "file": "...",
            "traits": [...],
            "methods": [...]
        }

    This is intentionally lightweight. It is not a PHP parser.
    """

    classes = {}
    traits = {}

    for source_file in source_files:

        if not source_file.endswith(".php"):
            continue

        try:
            with open(
                source_file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:
                content = f.read()

        except Exception:
            continue

        methods = set(
            FUNCTION_PATTERN.findall(content)
        )

        # -------------------------------------------------
        # Classes
        # -------------------------------------------------

        class_matches = list(
            CLASS_PATTERN.finditer(content)
        )

        for match in class_matches:

            class_name = match.group(1)
            parent = match.group(2)

            # Look near the class declaration for traits.
            #
            # This is intentionally limited to the class body
            # region instead of treating every "use" in the file
            # as a trait.
            class_start = match.end()

            next_class = (
                class_matches[class_matches.index(match) + 1].start()
                if class_matches.index(match) + 1 < len(class_matches)
                else len(content)
            )

            class_region = content[
                class_start:next_class
            ]

            trait_names = []

            for trait_match in USE_TRAIT_PATTERN.findall(
                class_region
            ):

                # A use statement may contain multiple traits:
                #
                # use TraitA, TraitB;
                #
                # Strip whitespace and PHP namespace prefixes.
                for trait_name in trait_match.split(","):

                    trait_name = trait_name.strip()

                    if not trait_name:
                        continue

                    trait_name = trait_name.split("\\")[-1]

                    trait_names.append(
                        trait_name
                    )

            classes[class_name] = {
                "file": source_file,
                "parent": (
                    parent.split("\\")[-1]
                    if parent
                    else None
                ),
                "traits": list(
                    dict.fromkeys(trait_names)
                ),
                "methods": methods,
            }

        # -------------------------------------------------
        # Traits
        # -------------------------------------------------

        for match in TRAIT_PATTERN.finditer(content):

            trait_name = match.group(1)

            traits[trait_name] = {
                "file": source_file,
                "traits": [],
                "methods": methods,
            }

    return classes, traits


# ---------------------------------------------------------
# Method resolution
# ---------------------------------------------------------

def resolve_method(
    class_name,
    method,
    classes,
    traits,
    visited=None
):
    """
    Resolve a method through:

        1. class itself
        2. traits used by the class
        3. parent class
        4. parent traits

    Returns the PHP source file containing the resolved method.
    """

    if not class_name or not method:
        return None

    if visited is None:
        visited = set()

    key = (
        class_name.lower(),
        method.lower()
    )

    if key in visited:
        return None

    visited.add(key)

    # -----------------------------------------------------
    # Class
    # -----------------------------------------------------

    class_info = classes.get(class_name)

    if class_info:

        if method in class_info["methods"]:
            return class_info["file"]

        # -------------------------------------------------
        # Traits used by class
        # -------------------------------------------------

        for trait_name in class_info["traits"]:

            result = resolve_trait_method(
                trait_name,
                method,
                classes,
                traits,
                visited
            )

            if result:
                return result

        # -------------------------------------------------
        # Parent class
        # -------------------------------------------------

        parent = class_info.get("parent")

        if parent:

            result = resolve_method(
                parent,
                method,
                classes,
                traits,
                visited
            )

            if result:
                return result

    return None


def resolve_trait_method(
    trait_name,
    method,
    classes,
    traits,
    visited
):
    """
    Resolve a method inside a trait, including nested traits.
    """

    if not trait_name:
        return None

    key = (
        "trait:" + trait_name.lower(),
        method.lower()
    )

    if key in visited:
        return None

    visited.add(key)

    trait_info = traits.get(trait_name)

    if not trait_info:
        return None

    if method in trait_info["methods"]:
        return trait_info["file"]

    for nested_trait in trait_info.get(
        "traits",
        []
    ):

        result = resolve_trait_method(
            nested_trait,
            method,
            classes,
            traits,
            visited
        )

        if result:
            return result

    return None


def find_controller_file(
    source_files,
    controller,
    method,
    classes,
    traits
):
    """
    Resolve a Nextcloud route controller/method.

    Resolution order:

        1. Direct <Controller>Controller.php lookup
        2. PHP class index
        3. Traits
        4. Parent classes
    """

    if not controller or not method:
        return None

    function_pattern = re.compile(
        rf"\bfunction\s+{re.escape(method)}\s*\(",
        re.MULTILINE
    )

    variants = controller_variants(
        controller
    )

    # =====================================================
    # 1. DIRECT CONTROLLER FILE LOOKUP
    # =====================================================
    #
    # This is the old resolver logic that already gave us
    # 349 resolved endpoints.
    #

    for source_file in source_files:

        if not source_file.endswith(".php"):
            continue

        filename = os.path.basename(
            source_file
        )

        if "Controller.php" not in filename:
            continue

        filename_without_ext = filename[:-4]

        controller_match = False

        for variant in variants:

            expected = (
                f"{variant}Controller"
            )

            if (
                filename_without_ext.lower()
                == expected.lower()
            ):
                controller_match = True
                break

        if not controller_match:
            continue

        try:
            with open(
                source_file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:
                content = f.read()

        except Exception:
            continue

        # Direct method exists.
        if function_pattern.search(
            content
        ):
            return source_file

    # =====================================================
    # 2. CLASS INDEX + INHERITANCE / TRAITS
    # =====================================================

    candidate_classes = []

    for variant in variants:

        candidate_classes.append(
            variant
        )

        candidate_classes.append(
            f"{variant}Controller"
        )

    candidate_classes = list(
        dict.fromkeys(
            candidate_classes
        )
    )

    for candidate in candidate_classes:

        # Exact class lookup
        if candidate in classes:

            result = resolve_method(
                candidate,
                method,
                classes,
                traits
            )

            if result:
                return result

        # Case-insensitive lookup
        for class_name in classes:

            if (
                class_name.lower()
                == candidate.lower()
            ):

                result = resolve_method(
                    class_name,
                    method,
                    classes,
                    traits
                )

                if result:
                    return result

    return None


# ---------------------------------------------------------
# Call graph
# ---------------------------------------------------------

def build_method_call_map(calls):
    """
    Build:

        file -> caller -> [callees]

    from the call graph.
    """

    call_map = {}

    for call in calls:

        file_name = call.get(
            "file",
            ""
        )

        caller = call.get(
            "caller",
            ""
        )

        callee = call.get(
            "callee",
            ""
        )

        if (
            not file_name
            or not caller
            or not callee
        ):
            continue

        call_map.setdefault(
            file_name,
            {}
        ).setdefault(
            caller,
            []
        ).append(
            callee
        )

    return call_map


# ---------------------------------------------------------
# Main agent
# ---------------------------------------------------------

def run(state):
    repo_root = os.path.abspath(
    "../targets/nextcloud-28"
    )

    if (
        not os.path.exists(API_GRAPH)
        or not os.path.exists(CALL_GRAPH)
    ):
        print(
            "[APICallChainAgent] "
            "API or Call graph not found. Skipping."
        )

        state["api_call_chains"] = []

        return state

    apis = load_json(
        API_GRAPH
    )

    calls = load_json(
        CALL_GRAPH
    )

    # -----------------------------------------------------
    # Load repository context
    # -----------------------------------------------------

    context_file = (
        "reports/repository_context.json"
    )

    if os.path.exists(
        context_file
    ):

        context = load_json(
            context_file
        )

        source_files = context.get(
            "source_files",
            []
        )

    else:

        source_files = []

    # -----------------------------------------------------
    # Build PHP symbol index
    # -----------------------------------------------------

    print(
        "[APICallChainAgent] "
        "Building PHP class/trait index..."
    )

    classes, traits = build_php_symbol_index(
        source_files
    )

    print(
        f"[APICallChainAgent] "
        f"Indexed {len(classes)} PHP classes "
        f"and {len(traits)} traits"
    )

    # -----------------------------------------------------
    # Build call map
    # -----------------------------------------------------

    call_map = build_method_call_map(
        calls
    )

    chains = []

    resolved = 0
    unresolved = 0
    linked_calls = 0

    # -----------------------------------------------------
    # Resolve endpoints
    # -----------------------------------------------------

    for api in apis:

        endpoints = api.get(
            "endpoints",
            []
        )

        route_file = api.get(
            "file",
            ""
        )

        endpoint_chains = []

        for endpoint in endpoints:

            controller, method = (
                parse_controller_method(
                    endpoint
                )
            )

            controller_file = None
            legacy_file = None
            call_chain = []

            resolved_this_endpoint = False

            # =================================================
            # CONTROLLER ROUTE
            # =================================================

            if controller and method:

                controller_file = (
                    find_controller_file(
                        source_files,
                        controller,
                        method,
                        classes,
                        traits
                    )
                )

                if controller_file:

                    resolved_this_endpoint = True

                    callees = (
                        call_map
                        .get(
                            controller_file,
                            {}
                        )
                        .get(
                            method,
                            []
                        )
                    )

                    call_chain = [
                        {
                            "caller": method,
                            "callee": callee
                        }
                        for callee in callees
                    ]

                    linked_calls += len(
                        call_chain
                    )

            # =================================================
            # LEGACY ROUTE
            # =================================================

            elif endpoint.get(
                "type"
            ) == "nextcloud_legacy_route":

                legacy_file = (
                    resolve_legacy_route(
                        endpoint,
                        repo_root
                    )
                )

                if legacy_file:

                    resolved_this_endpoint = True

                    file_calls = (
                        call_map.get(
                            legacy_file,
                            {}
                        )
                    )

                    for caller, callees in (
                        file_calls.items()
                    ):

                        for callee in callees:

                            call_chain.append({
                                "caller": caller,
                                "callee": callee
                            })

                            linked_calls += 1

            # =================================================
            # RESOLUTION RESULT
            # =================================================

            if resolved_this_endpoint:
                resolved += 1
            else:
                unresolved += 1

            endpoint_chains.append({

                "endpoint": endpoint,

                "controller": controller,

                "method": method,

                "controller_file":
                    controller_file,

                "legacy_file":
                    legacy_file,

                "resolved":
                    resolved_this_endpoint,

                "call_chain":
                    call_chain

            })

        chains.append({

            "file": route_file,

            "endpoints": endpoints,

            "endpoint_chains":
                endpoint_chains

        })

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            chains,
            f,
            indent=2
        )

    state[
        "api_call_chains"
    ] = chains

    print(
        f"[APICallChainAgent] "
        f"{len(chains)} API files"
    )

    print(
        f"[APICallChainAgent] "
        f"Resolved endpoints: {resolved}"
    )

    print(
        f"[APICallChainAgent] "
        f"Unresolved endpoints: {unresolved}"
    )

    print(
        f"[APICallChainAgent] "
        f"Linked call edges: {linked_calls}"
    )

    print(
        f"[APICallChainAgent] "
        f"Saved: {OUTPUT_FILE}"
    )

    return state