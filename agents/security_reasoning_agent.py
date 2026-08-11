import json
import os
from langchain_ollama import ChatOllama

OUTPUT_FILE = "reports/security_reasoning.json"

def run(state):
    knowledge_graph = state.get("security_knowledge_graph", {})
    attack_paths = state.get("attack_paths", [])
    llm_contexts = state.get("llm_contexts", [])

    # Other context
    sast_incidents = state.get("incidents", [])
    if not sast_incidents:
        sast_incidents = knowledge_graph.get("raw_inputs", {}).get("sast_incidents", [])

    if isinstance(sast_incidents, str):
        try:
            clean_sast = sast_incidents.replace('```json', '').replace('```', '').strip()
            sast_incidents = json.loads(clean_sast)
        except:
            sast_incidents = []

    dast_incidents = state.get("dast_incidents", [])
    if not dast_incidents:
        dast_incidents = knowledge_graph.get("raw_inputs", {}).get("dast_incidents", [])

    # Validation
    if not sast_incidents and not dast_incidents:
        print("[SecurityReasoningAgent] Warning: No incidents (SAST or DAST) propagated to reasoning agent.")
    attack_surface = state.get("attack_surface", {})
    trust_boundaries = state.get("trust_boundaries", [])

    # Runtime observations
    runtime_observations = state.get("security_knowledge_graph", {}).get("raw_inputs", {}).get("runtime_observations", [])
    runtime_evidence = state.get("security_knowledge_graph", {}).get("raw_inputs", {}).get("runtime_evidence", [])
    runtime_flow_evidence = state.get("security_knowledge_graph", {}).get("raw_inputs", {}).get("runtime_flow_evidence", [])
    llm_contexts = state.get("llm_contexts", [])

    # We pass minimal structure to avoid blowing up context window
    nodes_summary = [
        {"id": n.get("id"), "type": n.get("type"), "label": n.get("label")}
        for n in knowledge_graph.get("nodes", [])
    ]
    edges_summary = [
        {"source": e.get("source"), "target": e.get("target"), "relationship": e.get("relationship")}
        for e in knowledge_graph.get("edges", [])
    ]

    prompt = f"""
You are an expert AI Security Analyst.

Evaluate the consolidated Security Knowledge Graph, Attack Paths, and Runtime Observations to provide deep security reasoning.

KNOWLEDGE GRAPH NODES (Summary):
{json.dumps(nodes_summary, indent=2)[:3000]}

KNOWLEDGE GRAPH EDGES (Summary):
{json.dumps(edges_summary, indent=2)[:3000]}

RUNTIME OBSERVATIONS:
{json.dumps(runtime_observations, indent=2)[:2000]}

ATTACK PATHS:
{json.dumps(attack_paths, indent=2)[:2000]}

LLM FINDING CONTEXT:
{json.dumps(llm_contexts, indent=2)[:6000]}che

RUNTIME EVIDENCE:
{json.dumps(runtime_evidence, indent=2)[:2000]}

RUNTIME FLOW EVIDENCE (DATA FLOW):
{json.dumps(runtime_flow_evidence, indent=2)[:2000]}

LLM CONTEXT PACKS:
{json.dumps(llm_contexts, indent=2)[:12000]}

SAST FINDINGS:
{json.dumps(sast_incidents, indent=2)[:2000]}

DAST FINDINGS:
{json.dumps(dast_incidents, indent=2)[:2000]}

TRUST BOUNDARIES:
{json.dumps(trust_boundaries, indent=2)[:1000]}

Synthesize a comprehensive security reasoning that addresses:
1. Risk Score (0-100). If findings are RUNTIME CONFIRMED or reached a SINK, the score must be significantly higher.
   If RUNTIME FLOW EVIDENCE (Source-to-Sink) is present, the risk should be considered CRITICAL.
2. Overall Risk (CRITICAL, HIGH, MEDIUM, LOW).
3. Most Likely Attack (Easiest to execute given runtime behavior).
4. Most Dangerous Attack (Highest business impact).
5. Exploitability Assessment (How easy are these to exploit in the real world).
6. Business Impact (Impact on operations, data, reputation).
7. Prioritized Findings (Top 3 immediate concerns).
8. Remediation Priority (Which should be fixed first and why).
9. Remediation Order (Step-by-step sequence).

Return ONLY valid JSON in exactly this format:
{{
  "Risk Score": 0,
  "Overall Risk": "...",
  "Most Likely Attack": "...",
  "Most Dangerous Attack": "...",
  "Exploitability Assessment": "...",
  "Business Impact": "...",
  "Prioritized Findings": ["...", "...", "..."],
  "Remediation Priority": "...",
  "Remediation Order": ["...", "...", "..."]
}}
"""
    print(
        f"[SecurityReasoningAgent] LLM context packs available: {len(llm_contexts)}"
    )
    print("[SecurityReasoningAgent] Calling AI model for comprehensive runtime-aware reasoning...")

    try:
        llm = ChatOllama(model="qwen2.5:7b", temperature=0)
        response = llm.invoke(prompt)

        try:
            result = json.loads(response.content)
        except json.JSONDecodeError:
            # Fallback if markdown formatting is present
            content = response.content.replace('```json', '').replace('```', '').strip()
            result = json.loads(content)

    except Exception as e:
        print(f"[SecurityReasoningAgent] Model invocation failed: {e}")
        result = {
            "Risk Score": 0,
            "Overall Risk": "UNKNOWN",
            "Most Likely Attack": "Failed to determine.",
            "Most Dangerous Attack": "Failed to determine.",
            "Exploitability Assessment": "Failed to assess.",
            "Business Impact": "Failed to generate business impact.",
            "Prioritized Findings": [],
            "Remediation Priority": "Unknown",
            "Remediation Order": []
        }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    state["security_reasoning"] = result
    print("[SecurityReasoningAgent] Complete")
    return state
