import json
import os
from collections import defaultdict, deque


SOURCE_FILE = "reports/source_method_map.json"
CALL_GRAPH_FILE = "reports/call_graph.json"
SINK_FILE = "reports/sink_method_map.json"

OUTPUT_FILE = "reports/taint_flows.json"


MAX_DEPTH = 8
MAX_STATES = 50000
MAX_CROSS_FILE_TARGETS = 20


def load_json(path):

    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------
# CALL GRAPH
# ---------------------------------------------------------

def build_call_graph(calls):

    """
    Build a file-aware call graph.

    Structure:

        caller_file
            caller_method
                -> [(callee_method, resolution)]

    The original call graph only records the file containing
    the caller, so cross-file resolution is necessarily
    name-based for now.
    """

    graph = defaultdict(lambda: defaultdict(set))

    # Keep track of which files contain each caller method.
    method_files = defaultdict(set)

    for call in calls:

        file_name = call.get("file")
        caller = call.get("caller")
        callee = call.get("callee")

        if not file_name or not caller or not callee:
            continue

        graph[file_name][caller].add(callee)

        method_files[caller].add(file_name)

    return graph, method_files


# ---------------------------------------------------------
# SINK MAP
# ---------------------------------------------------------

def build_sink_map(sinks):

    """
    Build:

        file -> method -> [sinks]
    """

    sink_map = defaultdict(
        lambda: defaultdict(list)
    )

    for sink in sinks:

        file_name = sink.get("file")
        method = sink.get("method")

        if not file_name or not method:
            continue

        sink_map[file_name][method].append(
            sink
        )

    return sink_map


# ---------------------------------------------------------
# PATH SEARCH
# ---------------------------------------------------------

def find_paths(
    start_file,
    start_method,
    start_line,
    call_graph,
    method_files,
    sink_map
):
    """
    Find candidate source -> sink paths using file-aware traversal.

    Rules:
    1. Same-method source/sink is allowed only when sink occurs
       after the source.
    2. Same-file method calls are followed directly.
    3. Cross-file calls are followed ONLY when the callee method
       exists in exactly one file.
    4. Ambiguous method names are NOT guessed.
    """

    results = []

    # ---------------------------------------------------------
    # SAME-METHOD / INTRA-PROCEDURAL
    # ---------------------------------------------------------

    current_sinks = sink_map.get(
        start_file,
        {}
    ).get(
        start_method,
        []
    )

    for sink in current_sinks:

        sink_line = sink.get("line")

        if (
            start_line is not None
            and sink_line is not None
            and sink_line >= start_line
        ):

            results.append({
                "path": [
                    {
                        "file": start_file,
                        "method": start_method
                    }
                ],
                "sink": sink,
                "resolution": "same_method"
            })

    # ---------------------------------------------------------
    # PATH SEARCH
    # ---------------------------------------------------------

    queue = deque()

    queue.append(
        (
            start_file,
            start_method,
            [
                {
                    "file": start_file,
                    "method": start_method
                }
            ]
        )
    )

    visited = set()

    states_processed = 0

    while queue:

        if states_processed >= MAX_STATES:
            break

        current_file, current_method, path = queue.popleft()

        states_processed += 1

        state = (
            current_file,
            current_method,
            len(path)
        )

        if state in visited:
            continue

        visited.add(state)

        if len(path) - 1 >= MAX_DEPTH:
            continue

        callees = call_graph.get(
            current_file,
            {}
        ).get(
            current_method,
            set()
        )

        existing_states = {
            (
                item["file"],
                item["method"]
            )
            for item in path
        }

        for callee in callees:

            # -------------------------------------------------
            # SAME-FILE CALL
            # -------------------------------------------------

            if callee in call_graph.get(
                current_file,
                {}
            ):

                next_state = (
                    current_file,
                    callee
                )

                if next_state in existing_states:
                    continue

                next_path = path + [
                    {
                        "file": current_file,
                        "method": callee
                    }
                ]

                # Check sinks in called method
                for sink in sink_map.get(
                    current_file,
                    {}
                ).get(
                    callee,
                    []
                ):

                    results.append({
                        "path": next_path,
                        "sink": sink,
                        "resolution": "file_aware"
                    })

                queue.append(
                    (
                        current_file,
                        callee,
                        next_path
                    )
                )

                continue

            # -------------------------------------------------
            # CROSS-FILE CALL
            # -------------------------------------------------
            #
            # Only follow if the method name exists in exactly
            # ONE file.
            #
            # Example:
            #
            # addShare -> 2 possible files
            #              DON'T GUESS
            #
            # uniqueMethod -> 1 possible file
            #                 SAFE TO FOLLOW
            # -------------------------------------------------

            target_files = list(
                method_files.get(
                    callee,
                    set()
                )
            )

            if len(target_files) != 1:
                continue

            target_file = target_files[0]

            next_state = (
                target_file,
                callee
            )

            if next_state in existing_states:
                continue

            next_path = path + [
                {
                    "file": target_file,
                    "method": callee
                }
            ]

            # Check sinks in cross-file target
            for sink in sink_map.get(
                target_file,
                {}
            ).get(
                callee,
                []
            ):

                results.append({
                    "path": next_path,
                    "sink": sink,
                    "resolution": "unique_cross_file"
                })

            queue.append(
                (
                    target_file,
                    callee,
                    next_path
                )
            )

    return results

# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    if not os.path.exists(SOURCE_FILE):

        print(
            "[TaintFlow] Source method map not found."
        )

        return

    if not os.path.exists(CALL_GRAPH_FILE):

        print(
            "[TaintFlow] Call graph not found."
        )

        return

    if not os.path.exists(SINK_FILE):

        print(
            "[TaintFlow] Sink method map not found."
        )

        return

    sources = load_json(
        SOURCE_FILE
    )

    calls = load_json(
        CALL_GRAPH_FILE
    )

    sinks = load_json(
        SINK_FILE
    )

    print(
        f"[TaintFlow] Sources: {len(sources)}"
    )

    print(
        f"[TaintFlow] Call edges: {len(calls)}"
    )

    print(
        f"[TaintFlow] Sinks: {len(sinks)}"
    )

    # -----------------------------------------------------
    # Build indexes
    # -----------------------------------------------------

    call_graph, method_files = build_call_graph(
        calls
    )

    sink_map = build_sink_map(
        sinks
    )

    sink_method_count = sum(
        len(methods)
        for methods in sink_map.values()
    )

    print(
        f"[TaintFlow] Sink files: "
        f"{len(sink_map)}"
    )

    print(
        f"[TaintFlow] Sink methods: "
        f"{sink_method_count}"
    )

    flows = []

    source_methods = 0
    procedural_sources = 0

    # -----------------------------------------------------
    # Trace every source
    # -----------------------------------------------------

    for source in sources:

        method = source.get(
            "method"
        )

        source_file = source.get(
            "file"
        )

        if not method or not source_file:
            continue

        source_methods += 1

        if method == "__file__":

            procedural_sources += 1

            continue

        paths = find_paths(
            source_file,
            method,
            source.get("line"),
            call_graph,
            method_files,
            sink_map
        )

        for result in paths:

            path = result["path"]

            # Determine whether path crosses files.
            files_in_path = {
                item["file"]
                for item in path
            }

            if len(files_in_path) == 1:

                resolution = "file_aware"

            else:

                resolution = "name_based_cross_file"

            flows.append({

                "source": source,

                "path": path,

                "sink": result["sink"],

                "depth": len(path) - 1,

                "resolution": resolution

            })

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            flows,
            f,
            indent=2
        )

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    file_aware = sum(
        1
        for flow in flows
        if flow["resolution"] == "file_aware"
    )

    cross_file = sum(
        1
        for flow in flows
        if flow["resolution"] == "name_based_cross_file"
    )

    print(
        f"[TaintFlow] Sources with methods: "
        f"{source_methods}"
    )

    print(
        f"[TaintFlow] Procedural sources: "
        f"{procedural_sources}"
    )

    print(
        f"[TaintFlow] Candidate flows: "
        f"{len(flows)}"
    )

    print(
        f"[TaintFlow] File-aware flows: "
        f"{file_aware}"
    )

    print(
        f"[TaintFlow] Cross-file name-based flows: "
        f"{cross_file}"
    )

    print(
        f"[TaintFlow] Saved: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()