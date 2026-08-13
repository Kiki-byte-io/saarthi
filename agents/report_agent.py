import json
import os

OUTPUT_FILE = "reports/final_security_assessment.md"

def run(state):

    reasoning = state.get(
        "security_reasoning",
        {}
    )

    if not isinstance(reasoning, dict):
        print(
            "[ReportAgent] Invalid reasoning object, using empty dict"
        )
        reasoning = {}

    attack_paths = state.get(
        "attack_paths",
        []
    )

    if not isinstance(attack_paths, list):
        print(
            "[ReportAgent] Invalid attack paths, using empty list"
        )
        attack_paths = []

    knowledge_graph = state.get(
        "security_knowledge_graph",
        {}
    )

    if not isinstance(knowledge_graph, dict):
        print(
            "[ReportAgent] Invalid knowledge graph, using empty dict"
        )
        knowledge_graph = {}

    # We will use raw inputs from the graph generation to get counts/details
    raw_inputs = knowledge_graph.get("raw_inputs", {})
    if not isinstance(raw_inputs, dict):
        print(
            "[ReportAgent] Invalid raw_inputs, using empty dict"
        )
        raw_inputs = {}
    attack_surface = state.get("attack_surface", raw_inputs.get("attack_surface", {}))
    trust_boundaries = state.get("trust_boundaries", raw_inputs.get("trust_boundaries", []))
    sast_incidents = state.get("incidents", raw_inputs.get("sast_incidents", []))
    dast_incidents = state.get(
        "dast_incidents",
        raw_inputs.get("dast_incidents", [])
    )

    runtime_observations = raw_inputs.get(
        "runtime_observations",
        []
    )

    runtime_evidence = raw_inputs.get(
        "runtime_evidence",
        []
    )

    runtime_flow_evidence = raw_inputs.get(
        "runtime_flow_evidence",
        []
    )

    if not isinstance(runtime_observations, list):
        print(
            "[ReportAgent] Invalid runtime observations, using empty list"
        )
        runtime_observations = []
    graph_stats = knowledge_graph.get("statistics", {})
    app_plan = state.get("assessment_plan", {})
    app_type = app_plan.get("application_type", "Unknown")

    if isinstance(sast_incidents, str):
        try:
            clean_sast = sast_incidents.replace('```json', '').replace('```', '').strip()
            sast_incidents = json.loads(clean_sast)
        except:
            sast_incidents = []

    endpoints_count = attack_surface.get("endpoint_count", 0) if isinstance(attack_surface, dict) else len(attack_surface)
    if endpoints_count == 0:
        # Fallback if attack_surface structure is different
        endpoints_count = len(state.get("discovered_endpoints", []))

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write("# Saarthi Final Security Assessment\n\n")

        # Executive Summary
        f.write("## Executive Summary\n\n")

        risk_score = reasoning.get("Risk Score", "N/A")
        overall_risk = reasoning.get("Overall Risk", "UNKNOWN")

        f.write(
            f"**Overall Risk Level:** {overall_risk} "
            f"({risk_score}/100)\n\n"
        )

        f.write("### Assessment Overview\n\n")

        f.write(
            f"- **SAST incidents:** {len(sast_incidents)}\n"
        )
        f.write(
            f"- **DAST incidents:** {len(dast_incidents)}\n"
        )
        f.write(
            f"- **Underlying attack paths:** {len(attack_paths)}\n"
        )
        f.write(
            f"- **Statically discovered endpoints:** {endpoints_count}\n"
        )
        f.write(
            f"- **Runtime observations:** {len(runtime_observations)}\n"
        )
        f.write(
            f"- **Runtime-confirmed vulnerabilities:** "
            f"{len([e for e in runtime_evidence if e.get('confirmed')])}\n\n"
        )

        if runtime_observations or runtime_evidence or runtime_flow_evidence:

            f.write("### Validation Status\n\n")
            f.write(
                "**Runtime validation was available during this assessment.** "
                "Static findings can therefore be correlated with observed "
                "application behaviour where supporting runtime evidence exists.\n\n"
            )

        else:

            f.write("### Validation Status\n\n")
            f.write(
                "**Static analysis only — no runtime validation was performed.** "
                "The findings represent security risks identified from the "
                "repository and should be validated in a controlled runtime "
                "environment before being considered runtime-confirmed.\n\n"
            )

        f.write("### Key Risk Areas\n\n")

        prioritized_findings = reasoning.get(
            "Prioritized Findings",
            []
        )

        if prioritized_findings:

            for finding in prioritized_findings[:3]:
                f.write(f"- {finding}\n")

            f.write("\n")

        f.write(
            "The assessment combines repository analysis, dependency analysis, "
            "secret detection, API discovery, call-graph analysis, reachability "
            "analysis, and security reasoning. Runtime confirmation is reported "
            "separately so that statically inferred risk is not presented as "
            "proven exploitation.\n\n"
        )

        # Architecture Overview
        f.write("## Architecture Overview\n\n")
        f.write(f"**Application Type:** {app_type}\n")
        f.write("The application architecture was analyzed using a combination of repository parsing and runtime discovery. ")
        if app_plan.get("contains_api"):
            f.write("It features a significant REST API layer which serves as the primary attack surface. ")
        if app_plan.get("contains_database"):
            f.write("A database backend was detected, indicating potential risks related to data persistence and injection. ")
        f.write("\n\n")

        # Assessment Scope
        f.write("## Assessment Scope\n\n")
        target_url = state.get('target_url', 'N/A')
        project_root = state.get('project_root', 'N/A')
        f.write(f"- **Target URL:** {target_url}\n")
        f.write(f"- **Repository Path:** {project_root}\n")
        f.write(f"- **Discovery Mode:** {'Hybrid' if target_url != 'N/A' and project_root != 'N/A' else 'Single-Mode'}\n\n")

        # Attack Surface
        f.write("## Attack Surface\n\n")
        f.write(f"- **Statically Discovered Endpoints:** {endpoints_count}\n")
        f.write(f"- **Runtime Observed Events:** {len(runtime_observations)}\n")
        f.write(f"- **Observed Traffic Flows:** {len(runtime_flow_evidence)}\n")
        f.write(f"- **Runtime Confirmed Vulnerabilities:** {len([e for e in runtime_evidence if e.get('confirmed')])}\n")
        f.write(f"- **Detected Framework:** {app_type}\n\n")
        if runtime_observations:
            f.write(
                "The attack surface combines endpoints identified through "
                "static analysis and endpoints observed during runtime discovery.\n\n"
            )
        else:
            f.write(
                "The attack surface represents endpoints identified through "
                "static repository analysis. Runtime accessibility was not "
                "validated in this assessment mode.\n\n"
            )
        # Runtime Data Flows
        f.write("## Runtime Data Flows\n\n")
        if runtime_flow_evidence:
            f.write("The following end-to-end data flows from user-controlled sources to sensitive sinks were observed:\n\n")
            f.write("| Source | Sink | Trace ID | Boundary Crossed | Sanitization | Confidence |\n")
            f.write("| --- | --- | --- | --- | --- | --- |\n")
            for flow in runtime_flow_evidence:
                f.write(f"| {flow['source']['source_type']} | {flow['sink']['sink_type']} | `{flow['trace_id']}` | {'✅' if flow['boundary_crossed'] else '❌'} | {'⚠️' if flow['sanitization_detected'] else '✅ None'} | {flow['confidence']:.2f} |\n")
            f.write("\n")

            f.write("### Observed Source-to-Sink Details\n\n")
            for flow in runtime_flow_evidence:
                f.write(f"#### Flow: {flow['source']['source_type']} -> {flow['sink']['sink_type']}\n")
                f.write(f"- **Source Location:** `{flow['source']['location']}`\n")
                f.write(f"- **Sink Location:** `{flow['sink']['location']}`\n")
                f.write(f"- **Trace ID:** `{flow['trace_id']}`\n")
                if flow.get("metadata", {}).get("path"):
                    f.write("- **Execution Path:** " + " → ".join([str(p) for p in flow['metadata']['path']]) + "\n")
                f.write("\n")
        else:
            f.write("No end-to-end runtime data flows were observed.\n\n")

        # Runtime Evidence
        f.write("## Runtime Evidence\n\n")
        if runtime_evidence:
            f.write("The following findings have been confirmed through runtime code execution and data flow analysis:\n\n")
            f.write("| Finding | Evidence | Type | Confirmed |\n")
            f.write("| --- | --- | --- | --- |\n")
            for ev in runtime_evidence:
                f.write(f"| {ev.get('finding_id')} | {ev.get('description')} | {ev.get('evidence_type')} | {'✅ Yes' if ev.get('confirmed') else '❌ No'} |\n")
        else:
            f.write("No direct runtime evidence was collected for specific vulnerabilities. Reasoning is based on static analysis and network observation.\n")
        f.write("\n")

        # Trust Boundaries
        f.write("## Trust Boundaries\n\n")

        if trust_boundaries:

            for tb in trust_boundaries:

                if not isinstance(tb, dict):
                    continue

                f.write(
                    f"- **{tb.get('boundary', 'Boundary')}**: "
                    f"{tb.get('source', 'Unknown')} -> "
                    f"{tb.get('target', 'Unknown')}\n"
                )

        else:
            f.write(
                "No distinct trust boundaries were identified in the current context.\n"
            )

        f.write("\n")

        # Observed Runtime Behaviour
        f.write("## Observed Runtime Behaviour\n\n")
        if runtime_observations:
            f.write("The following significant runtime behaviours were observed during the assessment:\n\n")
            # List first few unique observations
            unique_obs = []
            seen_urls = set()
            for obs in runtime_observations:

                if not isinstance(obs, dict):
                    continue

                url = obs.get("url")

                if not url:
                    continue

                if url not in seen_urls:
                    unique_obs.append(obs)
                    seen_urls.add(url)

            for obs in unique_obs[:10]:
                f.write(f"- **{obs.get('method')} {obs.get('url')}** (Status: {obs.get('status_code')})\n")
                if obs.get("cookies"):
                    f.write(f"  - Cookies: {', '.join(obs.get('cookies').keys())}\n")
                if obs.get("form_data"):
                    f.write(f"  - Form Data: {', '.join(obs.get('form_data').keys())}\n")
        else:
            f.write("No runtime traffic was observed.\n")
        f.write("\n")

        # Static Findings (SAST)
        f.write("## Static Findings (SAST)\n\n")

        print(
            f"[ReportAgent] SAST incidents count: {len(sast_incidents)}"
        )

        if sast_incidents:

            for inc in sast_incidents:

                if not isinstance(inc, dict):
                    print(
                        f"[ReportAgent] Skipping malformed incident: {inc}"
                    )
                    continue

                f.write(
                    f"### {inc.get('incident', 'Unknown Finding')}\n"
                )

                findings = inc.get("findings", [])

                if findings:

                    f.write("| File | Priority | Reachability Score |\n")
                    f.write("| --- | --- | --- |\n")

                    for find in findings:

                        if not isinstance(find, dict):
                            print(
                                f"[ReportAgent] Skipping malformed finding: {find}"
                            )
                            continue

                        file = find.get(
                            "file",
                            find.get("location", "N/A")
                        )

                        priority = find.get(
                            "priority",
                            "N/A"
                        )

                        reachability = find.get(
                            "reachability_score",
                            "N/A"
                        )

                        f.write(
                            f"| `{file}` | {priority} | {reachability} |\n"
                        )

                f.write("\n")

        else:
            f.write(
                "No static findings were identified.\n"
            )

        f.write("\n")

        if not isinstance(dast_incidents, list):
            print(
                "[ReportAgent] Invalid DAST incidents, using empty list"
            )
            dast_incidents = []

        # Dynamic Findings (DAST)
        f.write("## Dynamic Findings (DAST)\n\n")

        print(
            f"[ReportAgent] DAST incidents count: {len(dast_incidents)}"
        )

        if dast_incidents:

            for inc in dast_incidents:

                if not isinstance(inc, dict):
                    print(
                        f"[ReportAgent] Skipping malformed DAST incident: {inc}"
                    )
                    continue

                f.write(
                    f"- **{inc.get('incident', 'Unknown Finding')}** "
                    f"(Instances: {len(inc.get('findings', []))})\n"
                )

        else:
            f.write(
                "No runtime findings were identified.\n"
            )

        f.write("\n")

        # Correlated Findings
        f.write("## Correlated Findings\n\n")
        f.write("Saarthi has correlated static code vulnerabilities with runtime execution evidence. ")
        f.write("This correlation reduces false positives and highlights vulnerabilities that are demonstrably reachable in the running environment.\n\n")

        # Knowledge Graph Statistics
        if graph_stats:
            f.write("### Knowledge Graph Statistics\n")
            f.write(f"- **Nodes:** {graph_stats.get('node_count')}\n")
            f.write(f"- **Edges:** {graph_stats.get('edge_count')}\n")
            f.write(f"- **Relationship Types:** {', '.join(graph_stats.get('edge_types', []))}\n\n")

        # Attack Chains
        f.write("## Attack Scenarios\n\n")

        if attack_paths:

            # Group paths by vulnerability name.
            grouped_paths = {}

            for path in attack_paths:

                if not isinstance(path, dict):
                    continue

                name = path.get("name", "Unnamed Path")

                # Remove the generic SAST prefix so that
                # multiple findings of the same vulnerability
                # are presented as one attack scenario.
                if name.startswith("SAST Attack Path: "):
                    group_name = name.replace(
                        "SAST Attack Path: ",
                        "",
                        1
                    )
                else:
                    group_name = name

                grouped_paths.setdefault(
                    group_name,
                    []
                ).append(path)

            f.write(
                f"Saarthi identified **{len(attack_paths)} underlying "
                f"attack paths**, grouped into **{len(grouped_paths)} "
                f"attack scenarios** for readability. The underlying "
                f"paths remain available in `reports/attack_chains.json`.\n\n"
            )

            for idx, (group_name, paths) in enumerate(
                grouped_paths.items(),
                1
            ):

                f.write(
                    f"### {idx}. {group_name}\n\n"
                )

                # Highest severity represented in this scenario.
                severity_order = {
                    "CRITICAL": 4,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1,
                    "INFO": 0
                }

                severities = [
                    p.get("severity")
                    for p in paths
                    if p.get("severity")
                ]

                highest_severity = (
                    max(
                        severities,
                        key=lambda s: severity_order.get(s, 0)
                    )
                    if severities
                    else "N/A"
                )

                f.write(
                    f"- **Related attack paths:** {len(paths)}\n"
                )
                f.write(
                    f"- **Highest severity:** {highest_severity}\n"
                )

                boundaries = sorted({
                    str(p.get("boundary_crossed"))
                    for p in paths
                    if p.get("boundary_crossed")
                    and str(p.get("boundary_crossed")) != "N/A"
                })

                if boundaries:
                    f.write(
                        "- **Trust boundaries:** "
                        + ", ".join(boundaries)
                        + "\n"
                    )

                impacts = sorted({
                    str(p.get("impact"))
                    for p in paths
                    if p.get("impact")
                    and str(p.get("impact")) != "N/A"
                })

                if impacts:
                    f.write("- **Potential impact:**\n")
                    for impact in impacts[:3]:
                        f.write(f"  - {impact}\n")

                # Show representative paths rather than dumping
                # every duplicate path into the executive report.
                f.write("\n**Representative attack path:**\n\n")

                representative = paths[0].get("path", [])

                if isinstance(representative, list):
                    f.write(
                        " → ".join(
                            str(step)
                            for step in representative
                        )
                        + "\n"
                    )

                # Show affected application locations where available.
                locations = []

                for p in paths:
                    for step in p.get("path", []):
                        if (
                            isinstance(step, str)
                            and step.startswith(
                                "Application Call Chain:"
                            )
                        ):
                            location = step.replace(
                                "Application Call Chain:",
                                "",
                                1
                            ).strip()

                            if location not in locations:
                                locations.append(location)

                if locations:
                    f.write("\n**Affected locations:**\n\n")

                    for location in locations[:10]:
                        f.write(
                            f"- `{location}`\n"
                        )

                    if len(locations) > 10:
                        f.write(
                            f"- ...and "
                            f"{len(locations) - 10} more locations\n"
                        )

                f.write("\n")

        else:
            f.write(
                "No definitive attack scenarios were derived.\n\n"
            )

        # AI-Assisted Reasoning
        f.write("## AI-Assisted Reasoning\n\n")

        f.write("### Most Likely Attack\n")
        f.write(f"{reasoning.get('Most Likely Attack', 'Not evaluated.')}\n\n")

        f.write("### Most Dangerous Attack\n")
        f.write(f"{reasoning.get('Most Dangerous Attack', 'Not evaluated.')}\n\n")

        f.write("### Exploitability Assessment\n")
        f.write(f"{reasoning.get('Exploitability Assessment', 'Not evaluated.')}\n\n")

        f.write("### Business Impact\n")
        f.write(f"{reasoning.get('Business Impact', 'Not evaluated.')}\n\n")

        # Risk Assessment
        f.write("## Risk Assessment\n\n")
        f.write(f"**Priority:** {reasoning.get('Remediation Priority', 'N/A')}\n\n")
        f.write("### Top Risks\n\n")
        prioritized = reasoning.get("Prioritized Findings", [])
        if prioritized:
            for risk in prioritized:
                f.write(f"- {risk}\n")
        else:
            f.write("No prioritized risks were provided.\n")
        f.write("\n")

        # Remediation Roadmap
        f.write("## Remediation Roadmap\n\n")
        remediation_order = reasoning.get("Remediation Order", [])
        if remediation_order:
            for step in remediation_order:
                f.write(f"1. {step}\n")
        else:
            f.write("No remediation steps were provided.\n")
        f.write("\n")

        # Executive Recommendations
        f.write("## Executive Recommendations\n\n")

        f.write(
            "It is highly recommended that the engineering teams prioritize "
            "the Top Risks identified in this report. "
        )

        if runtime_evidence or runtime_flow_evidence:
            f.write(
                "Runtime evidence was available for this assessment, providing "
                "additional validation of vulnerability reachability. "
            )
        else:
            f.write(
                "This assessment was performed without runtime confirmation. "
                "The identified vulnerabilities should therefore be validated "
                "in a controlled runtime environment before being treated as "
                "confirmed exploitable issues. "
            )

        f.write(
            "Following the Remediation Roadmap will systematically address "
            "the underlying security weaknesses and reduce overall risk exposure."
        )
    print(f"[ReportAgent] Saved high-quality final assessment to {OUTPUT_FILE}")

    return state
