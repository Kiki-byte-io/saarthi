import argparse
import os
import subprocess

# Agents
from agents.planning_agent import run as planning_agent
from agents.runtime_observer_agent import start as start_runtime_observer
from agents.runtime_observer_agent import stop as stop_runtime_observer
from agents.recon_agent import run as recon_agent
from agents.discovery_agent import run as discovery_agent
from agents.trust_boundary_agent import run as trust_boundary_agent
from agents.api_call_chain_agent import run as api_call_chain_agent
from agents.attack_surface_agent import run as attack_surface_agent
from agents.pipeline_agent import run as pipeline_agent
from agents.context_agent import run as context_agent
from agents.correlation_agent import run as correlation_agent
from agents.zap_agent import run as zap_agent
from agents.zap_parser_agent import run as zap_parser_agent
from agents.dast_correlation_agent import run as dast_correlation_agent
from agents.security_knowledge_graph_agent import run as security_knowledge_graph_agent
from agents.attack_path_agent import run as attack_path_agent
from agents.security_reasoning_agent import run as security_reasoning_agent
from agents.remediation_agent import run as remediation_agent
from agents.report_agent import run as report_agent
from parsers.llm_context_builder import run as llm_context_builder


# Runtime Intelligence
from runtime.collector.otel_collector import OTelFileCollector
from runtime.correlation.runtime_correlator import run_correlation as runtime_correlation

def print_stage(stage, status="✓"):
    print(f"[{status}] {stage}")

def main():
    parser = argparse.ArgumentParser(description="Saarthi Security Orchestrator")
    parser.add_argument("--url", type=str, help="Target URL for DAST/Discovery")
    parser.add_argument("--repo", type=str, help="Target Repository Path for SAST")
    parser.add_argument("--runtime", type=str, help="Path to runtime intelligence feed")
    args = parser.parse_args()

    state = {}
    if args.url:
        state["target_url"] = args.url
    if args.repo:
        state["project_root"] = args.repo
    else:
        state["project_root"] = os.getcwd()

    run_url = args.url is not None
    run_repo = args.repo is not None
    run_runtime = args.runtime is not None

    mode = "Unknown"
    if run_repo and not run_url and not run_runtime: mode = "Mode 1 (SAST Only)"
    elif run_url and not run_repo and not run_runtime: mode = "Mode 2 (DAST Only)"
    elif run_repo and run_url and not run_runtime: mode = "Mode 3 (Hybrid SAST + DAST)"
    elif run_repo and run_url and run_runtime: mode = "Mode 4 (Full Spectrum)"

    print(f"\n[Orchestrator] Starting Saarthi in {mode}\n")

    os.makedirs("scans", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    if run_repo:
        repo_path = state["project_root"]
        print(f"--- Repository Analysis: {repo_path} ---")
        subprocess.run(["python3", "parsers/context_builder.py", "--repo", repo_path], check=False)
        print_stage("Repository Context Builder")

        subprocess.run(["python3", "parsers/dependency_graph_builder.py"], check=False)
        print_stage("Dependency Graph")

        subprocess.run(["python3", "parsers/api_graph_builder.py"], check=False)
        print_stage("API Graph")

        subprocess.run(["python3", "parsers/method_index_builder.py", "--repo", repo_path], check=False)
        print_stage("Method Index")

        subprocess.run(["python3", "parsers/call_graph_builder.py"], check=False)
        print_stage("Call Graph")

    # Assessment Planning
    state = planning_agent(state)
    print_stage("Assessment Plan Generated")

    if run_url:
        print(f"\n--- Discovery & DAST: {state['target_url']} ---")
        state = start_runtime_observer(state)

        state = recon_agent(state)
        print_stage("Recon Agent")

        state = discovery_agent(state)
        print_stage("Discovery Agent")

        state = trust_boundary_agent(state)
        print_stage("Trust Boundary Analysis")

        state = attack_surface_agent(state)
        print_stage("Attack Surface Mapping")

        try:
            state = zap_agent(state)
            print_stage("OWASP ZAP Scan")

            state = zap_parser_agent(state)
            print_stage("ZAP Parsing")

            state = dast_correlation_agent(state)
            print_stage("DAST Correlation")
        except Exception as e:
            print(f"[Orchestrator] DAST Pipeline error: {e}")

        state = stop_runtime_observer(state)

    if run_repo:
        state = pipeline_agent(state)
        # pipeline_agent logs its own [✓] stages as requested

        state = llm_context_builder(state)
        print_stage("LLM Context Builder")

    # Bridge Mode 1 & 2 Findings
    if run_repo or run_url:
        state = context_agent(state)
        state = correlation_agent(state)

        if not run_url:
            state = trust_boundary_agent(state)
            state = attack_surface_agent(state)

        state = api_call_chain_agent(state)
        print_stage("API Call Chain Agent")

    if run_runtime:
        print("\n--- Runtime Intelligence ---")
        collector = OTelFileCollector(args.runtime)
        collector.start()
        state["runtime_events"] = collector.collect()
        collector.stop()
        state = runtime_correlation(state)
        print_stage("Runtime Correlator")

    print("\n--- Knowledge Graph & Reasoning ---")
    state = security_knowledge_graph_agent(state)
    print_stage("Security Knowledge Graph")

    state = attack_path_agent(state)
    print_stage("Attack Path Generation")

    state = security_reasoning_agent(state)
    print_stage("Security Reasoning")

    state = remediation_agent(state)
    print_stage("Remediation")

    state = report_agent(state)
    print_stage("Final Report Generated")

    print(f"\n[Orchestrator] Assessment Complete. Report: reports/final_security_assessment.md\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Orchestrator] Interrupted. Cleaning up...")
        stop_runtime_observer({})
