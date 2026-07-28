import json
import os
from typing import List, Dict, Any
from runtime.models.runtime_event import RuntimeEvent, RuntimeEvidence, EventType
from runtime.dataflow.taint_tracker import TaintTracker
from dataclasses import asdict

class RuntimeCorrelator:
    def __init__(self):
        self.evidence: List[RuntimeEvidence] = []

    def correlate(self, findings: List[Dict[str, Any]], events: List[RuntimeEvent]) -> List[RuntimeEvidence]:
        """
        Correlates SAST/DAST findings with runtime events.
        """
        new_evidence = []

        # Group events by trace for easier analysis
        traces = {}
        for event in events:
            if event.trace_id:
                if event.trace_id not in traces:
                    traces[event.trace_id] = []
                traces[event.trace_id].append(event)

        for finding in findings:
            finding_id = (
                finding.get("finding_id")
                or finding.get("id")
                or finding.get("title")
                or finding.get("incident")
                or "Unknown"
            )

            # 1. Match by URL/Endpoint (Common for DAST)
            if "file" in finding: # Often used for endpoint in DAST findings in this project
                target_url = finding["file"]
                for trace_id, trace_events in traces.items():
                    for event in trace_events:
                        if event.event_type == EventType.HTTP_REQUEST:
                            if target_url in event.attributes.get("http.url", "") or \
                               target_url in event.attributes.get("http.target", ""):

                                # Check if the same trace reached a sensitive sink (e.g., DB)
                                has_db_sink = any(e.event_type == EventType.DATABASE_QUERY for e in trace_events)

                                desc = f"Finding {finding_id} was executed at runtime."
                                if has_db_sink:
                                    desc += " Trace reached a database sink."

                                evidence = RuntimeEvidence(
                                    evidence_id=f"EV_{finding_id}_{trace_id}",
                                    finding_id=finding_id,
                                    description=desc,
                                    confirmed=True,
                                    evidence_type="sink_reached" if has_db_sink else "reachability",
                                    related_trace_ids=[trace_id]
                                )
                                new_evidence.append(evidence)
                                break # Found evidence in this trace

            # 2. Match by Code Location (Common for SAST)
            # This requires better mapping between SAST file/line and runtime function names
            # For now, use a simple name-based heuristic
            if "name" in finding:
                finding_name = finding["name"].lower()
                for trace_id, trace_events in traces.items():
                    for event in trace_events:
                        if event.event_type == EventType.FUNCTION_CALL:
                            method_name = event.metadata.get("name", "").lower()
                            if method_name and (method_name in finding_name or finding_name in method_name):
                                evidence = RuntimeEvidence(
                                    evidence_id=f"EV_SAST_{finding_id}_{trace_id}",
                                    finding_id=finding_id,
                                    description=f"SAST finding {finding_id} matches runtime function call: {method_name}",
                                    confirmed=True,
                                    evidence_type="code_execution",
                                    related_trace_ids=[trace_id]
                                )
                                new_evidence.append(evidence)

        self.evidence.extend(new_evidence)
        return new_evidence

    def save_evidence(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data = [
            {
                "evidence_id": e.evidence_id,
                "finding_id": e.finding_id,
                "description": e.description,
                "confirmed": e.confirmed,
                "evidence_type": e.evidence_type,
                "timestamp": e.timestamp,
                "related_trace_ids": e.related_trace_ids,
                "metadata": e.metadata
            } for e in self.evidence
        ]
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

def run_correlation(state):
    print("[RuntimeCorrelator] Running correlation...")

    # Collect all incidents
    sast_incidents = state.get("incidents", [])
    if isinstance(sast_incidents, str):
        try:
            sast_incidents = json.loads(sast_incidents)
        except:
            sast_incidents = []

    dast_incidents = state.get("dast_incidents", [])

    all_findings = []
    for inc in sast_incidents:
        for f in inc.get("findings", []):
            if isinstance(f, dict):
                f["incident"] = inc.get("incident")
                all_findings.append(f)

    for inc in dast_incidents:
        for f in inc.get("findings", []):
            if isinstance(f, dict):
                f["incident"] = inc.get("incident")
                all_findings.append(f)

    # Normalized Events from state (populated by mode 4 orchestrator)
    events = state.get("runtime_events", [])

    # If no incidents in state, try to load from reachable_findings.json
    if not all_findings and os.path.exists("reports/reachable_findings.json"):
        try:
            with open("reports/reachable_findings.json", "r") as f:
                reachable = json.load(f)
                all_findings.extend(reachable)
        except:
            pass

    correlator = RuntimeCorrelator()
    evidence = correlator.correlate(all_findings, events)

    # 3. Run Data Flow Analysis
    print("[RuntimeCorrelator] Running Runtime Data Flow Analysis...")
    taint_tracker = TaintTracker()
    flow_evidence = taint_tracker.track_traces(events)

    # Save Flow Evidence
    flow_data = [asdict(e) for e in flow_evidence]
    os.makedirs("reports", exist_ok=True)
    with open("reports/runtime_flow_evidence.json", "w") as f:
        json.dump(flow_data, f, indent=2)

    state["runtime_flow_evidence"] = flow_data
    print(f"[RuntimeCorrelator] Generated {len(flow_evidence)} pieces of runtime flow evidence.")

    correlator.save_evidence("reports/runtime_evidence.json")
    state["runtime_evidence"] = [
        {
            "evidence_id": e.evidence_id,
            "finding_id": e.finding_id,
            "description": e.description,
            "confirmed": e.confirmed,
            "evidence_type": e.evidence_type,
            "related_trace_ids": e.related_trace_ids
        } for e in evidence
    ]

    print(f"[RuntimeCorrelator] Generated {len(evidence)} pieces of runtime evidence.")
    return state
