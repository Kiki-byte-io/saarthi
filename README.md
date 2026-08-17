# Saarthi

Saarthi is an AI-Assisted Security Assessment Platform designed to move beyond simply aggregating scanner outputs and instead provide context-aware security analysis.

It combines **SAST, DAST, repository analysis, application/API context, security graphs, taint-flow analysis, attack-path reasoning, and security-focused reporting** to produce actionable security assessment results.

---

## Prerequisites

The following should be available before running the assessment:

Python 3
Python virtual environment
Git
Docker
Semgrep
OWASP ZAP
Saarthi repository
Target application/source code

## Architecture


Repository / Running Application
            ↓
      Discovery & Context
            ↓
   ┌────────┴────────┐
   ↓                 ↓
  SAST              DAST
   ↓                 ↓
Semgrep        OWASP ZAP
Trivy          Runtime Analysis
Gitleaks
   └────────┬────────┘
            ↓
     Security Knowledge
          Graph
            ↓
      Security Reasoning
            ↓
       Attack Paths
            ↓
       Remediation
            ↓
        Reporting

For more detailed architecture information, please see [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [RUNTIME_INTELLIGENCE.md](docs/RUNTIME_INTELLIGENCE.md).

## Core Components
1. Repository & Application Context

Saarthi builds application context by indexing:

Source files
Configuration files
Dependencies
API endpoints
Methods
Call graphs
Trust boundaries

This context is used to correlate scanner findings with the actual structure of the application.

## 2. Static Application Security Testing (SAST)

The SAST pipeline integrates multiple security analysis tools:

Semgrep
Performs source-code security analysis and identifies potentially vulnerable code patterns.

Trivy
Performs vulnerability and dependency analysis.

Gitleaks
Detects potential secrets, credentials, API keys, and other sensitive information committed to source code.

Source / Sink Analysis
Saarthi additionally identifies:

Sources – locations where externally controlled data enters the application.
Sinks – security-sensitive operations such as SQL execution, file operations, command execution, redirects, and other potentially dangerous operations.

The source and sink information is mapped to methods and combined with the call graph to identify candidate taint flows.

## 3. Dynamic Application Security Testing (DAST)

DAST is performed using OWASP ZAP against a running application.

The repository includes a ZAP baseline configuration:

zap.yaml

The baseline scan can be executed against a locally running application.

## 4. Security Knowledge Graph

Saarthi constructs a security knowledge graph that connects:

Application components
API endpoints
Methods
Vulnerability findings
Sources
Sinks
Trust boundaries
Attack-surface information

This allows individual scanner findings to be correlated with application structure rather than being treated as isolated alerts.

## 5. Attack Path Analysis

Saarthi derives candidate attack paths by correlating:

Sources
Methods
Call-graph relationships
Security-sensitive sinks
API endpoints
Vulnerability findings
Application context

This provides additional context beyond individual scanner findings.

## 6. Security Reasoning

The Security Reasoning Agent evaluates correlated findings using factors such as:

Severity
Exploitability
Application context
Attack paths
Potential impact

The results are used to prioritize security incidents.

## 7. Remediation & Reporting

The Remediation Agent generates actionable remediation guidance.

The Report Agent generates a consolidated security assessment containing executive and technical findings.



## Agent Responsibilities
- **Runtime Observer Agent**: Captures live application traffic using mitmproxy.
- **Recon & Discovery Agents**: Map the application's attack surface and runtime behavior, utilizing the observer.
- **Trust Boundary & API Chain Agents**: Identify data flow boundaries and endpoint logic.
- **Scanner Agents (ZAP, Pipeline)**: Execute DAST and SAST tools.
- **Security Knowledge Graph Agent**: Synthesizes findings, boundaries, and surfaces into a unified graph format (`nodes` and `edges`).
- **Attack Path Agent**: Derives realistic attack chains from the knowledge graph and runtime evidence.
- **Security Reasoning Agent**: The central AI "brain". Computes overall risk, business impact, exploitability, and prioritizes findings based on runtime awareness.
- **Remediation Agent**: Formulates strategies to fix identified risks.
- **Report Agent**: Generates the final, comprehensive Markdown assessment.

## Repository / Target Setup
              ↓
 Repository & API Discovery
              ↓
 Dependency & Method Analysis
              ↓
 Call Graph Construction
              ↓
 SAST Scanning
   ├── Semgrep
   ├── Trivy
   └── Gitleaks
              ↓
 Source / Sink & Taint Analysis
              ↓
 DAST
   └── OWASP ZAP
              ↓
 Finding Correlation
              ↓
 Security Knowledge Graph
              ↓
 Attack Path & Security Reasoning
              ↓
 Remediation Guidance
              ↓
 Final Security Report

## Data Flow & Example Execution Flow
1. **Setup**: The target URL and project root are defined.
2. **Phase 1 (Discovery)**: The platform crawls endpoints and maps boundaries.
3. **Phase 2 & 3 (SAST/DAST)**: Analyzers find vulnerabilities.
4. **Phase 4 (Knowledge)**: The `security_knowledge_graph.json` is generated, linking endpoints to vulnerabilities.
5. **Phase 5 (Reasoning)**: `attack_chains.json` and `security_reasoning.json` are created based on the AI's contextual evaluation of the graph.
6. **Phase 6 & 7 (Remediation & Reporting)**: Actionable guidance is generated, culminating in `final_security_assessment.md`.

## Example Reports
The platform generates several artifacts during execution:
- `reports/security_knowledge_graph.json`: Nodes and edges representing the application state.
- `reports/attack_chains.json`: Realistic exploitation sequences.
- `reports/security_reasoning.json`: Structured AI evaluation of risk and impact.
- `reports/final_security_assessment.md`: A consultant-grade executive and technical summary.

## Example Assessment: Nextcloud

Saarthi was tested against a Dockerized Nextcloud 28 test environment.

The application was exposed locally at:

http://127.0.0.1:8081

The Nextcloud source code was available locally at:

../targets/nextcloud-28

## Setup
1. Clone the Repository
>> git clone https://github.com/Kiki-byte-io/saarthi.git
>> cd saarthi

Switch to the required development branch:

>> git checkout feature/llm-context-v2

## Create / Activate the Python Virtual Environment

If the virtual environment already exists:

source venv/bin/activate

The terminal should then show:

(venv)

Verify Python:

which python
python --version

Verify Semgrep:

which semgrep
semgrep --version

If Semgrep is not installed inside the active environment:

python -m pip install semgrep

## Install Python Dependencies

If the project dependencies are defined in a requirements file:

pip install -r requirements.txt

If individual dependencies are required, verify them with:

python -c "import requests; print(requests.__version__)"

For BeautifulSoup:

python -c "from bs4 import BeautifulSoup; print('BeautifulSoup OK')"

For LangChain Ollama:

python -c "from langchain_ollama import ChatOllama; print('LangChain Ollama OK')"

## Running the Nextcloud Target

The Nextcloud Docker container can be checked with:

docker ps

Example:

nextcloud-28

Verify that the application is responding:

curl -I http://127.0.0.1:8081

A working instance should return an HTTP response such as:

HTTP/1.1 302 Found

## Running Saarthi

Run the complete Saarthi assessment pipeline against the Nextcloud source tree:

python3 -m orchestrator.graph --repo ../targets/nextcloud-28

The pipeline performs repository analysis followed by the SAST workflow and subsequent correlation, reasoning, remediation, and reporting stages.


## Running Individual Analysis Components

The repository also contains individual analysis components.

Source Index

python3 parsers/source_index_builder.py
Produces:
reports/source_index.json

Source Method Mapping

python3 parsers/source_method_mapper.py
Produces:
reports/source_method_map.json

Sink Index

python3 parsers/sink_index_builder.py
Produces:
reports/sink_index.json

Sink Method Mapping

python3 parsers/sink_method_mapper.py
Produces:
reports/sink_method_map.json

Call Graph

python3 parsers/call_graph_builder.py --repo ../targets/nextcloud-28
Produces:
reports/call_graph.json

Taint Flow Analysis

python3 parsers/taint_flow_builder.py
Produces:
reports/taint_flows.json

The taint-flow stage correlates source methods, call-graph paths, and sink methods to identify candidate source-to-sink flows.

## SAST

The main Saarthi pipeline invokes the configured SAST tools.

The major components are:

Semgrep
Trivy
Gitleaks

Scanner results are stored under:

scans/

and subsequently normalized and correlated by Saarthi.

## DAST with OWASP ZAP
1. Start Nextcloud

Make sure the Nextcloud Docker container is running:

docker ps

Verify:

curl -I http://127.0.0.1:8081

2. Run the ZAP Baseline Scan

From the Saarthi repository:

docker run --rm \
  --network host \
  -v "$(pwd):/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://127.0.0.1:8081 \
  -r nextcloud_zap_report.html

The report will be generated as:

nextcloud_zap_report.html

The report can then be opened in a browser for review.


ZAP Configuration

The repository contains:

zap.yaml

This configuration defines:

Target URL
Spider configuration
Passive scan configuration
Passive-scan wait
Summary output
HTML report generation

The target URL can be changed in zap.yaml if the application is exposed at a different address.

Generated Artifacts

During an assessment, Saarthi generates artifacts representing different stages of analysis.

Important artifacts include:

reports/
├── repository_context.json
├── dependency_graph.json
├── api_graph.json
├── method_index.json
├── call_graph.json
├── source_index.json
├── sink_index.json
├── source_method_map.json
├── sink_method_map.json
├── taint_flows.json
├── security_graph.json
├── attack_chains.json
├── security_reasoning.json
├── remediation_guidance.json
└── final_security_assessment.md

Scanner outputs are stored under:

scans/

The DAST report is generated as:

nextcloud_zap_report.html
Important Output Files
repository_context.json

Contains the discovered repository and source-file context.

dependency_graph.json

Represents discovered project dependencies.

api_graph.json

Contains statically discovered API endpoints and relationships.

method_index.json

Contains indexed methods discovered across the repository.

call_graph.json

Contains caller-to-callee relationships used for application flow analysis.

source_index.json

Contains identified external/input sources.

sink_index.json

Contains identified security-sensitive sinks.

source_method_map.json

Maps discovered sources to their containing methods or procedural contexts.

sink_method_map.json

Maps discovered sinks to their containing methods or procedural contexts.

taint_flows.json

Contains candidate source-to-sink flows derived from the call graph and source/sink mappings.

security_graph.json

Contains the security knowledge graph.

attack_chains.json

Contains candidate attack paths derived from the available security context.

security_reasoning.json

Contains structured security reasoning and prioritization.

remediation_guidance.json

Contains remediation recommendations.

final_security_assessment.md

Contains the consolidated security assessment.

Reviewing the DAST Report

After running ZAP:

ls -lh nextcloud_zap_report.html

Open the generated HTML file in a browser.

The ZAP baseline output reports:

PASS
WARN
FAIL
Informational findings

A baseline scan producing warnings does not automatically mean that every warning represents an exploitable vulnerability. Findings should be reviewed in the context of the application and configuration.

## Troubleshooting
python: command not found

The virtual environment is probably not activated.

Run:

source venv/bin/activate

Then:

which python
semgrep: command not found

Check:

which semgrep

If missing:

python -m pip install semgrep

Then:

semgrep --version
ModuleNotFoundError: No module named 'requests'

Install:

python -m pip install requests
ModuleNotFoundError: No module named 'bs4'

Install:

python -m pip install beautifulsoup4
ModuleNotFoundError: No module named 'langchain_ollama'

Install:

python -m pip install langchain-ollama
ZAP cannot resolve the Docker container name

If ZAP is running in a Docker container and the target is another Docker container, the target hostname may not resolve unless both containers share an appropriate Docker network.

For a locally published Nextcloud port, the ZAP container can instead use host networking:

--network host

and target:

http://127.0.0.1:8081

## Project Structure
saarthi/
│
├── agents/
│   └── Security analysis and reasoning agents
│
├── config/
│   └── Configuration files
│
├── docs/
│   └── Architecture and runtime documentation
│
├── orchestrator/
│   └── Assessment orchestration
│
├── parsers/
│   └── Repository, API, graph, source/sink and taint analysis
│
├── reports/
│   └── Generated assessment artifacts
│
├── runtime/
│   └── Runtime analysis components
│
├── runtime_agent/
│   └── Runtime intelligence
│
├── scans/
│   └── Scanner outputs
│
├── schemas/
│   └── Data schemas
│
└── zap.yaml
    └── OWASP ZAP baseline configuration
    
## Future Roadmap
- Deeper native integrations with modern frameworks (e.g., GraphQL, gRPC).
- AI-Assisted Custom Rule Discovery and continuous knowledge base updates.
- Extended Cloud-Native (Kubernetes/AWS) runtime boundary mapping.
- Enhanced Remediation via Automated Pull Requests.

## Execution
To run the full assessment pipeline:
python3 -m orchestrator.graph

