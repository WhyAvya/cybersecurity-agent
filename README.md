# Agentic Workflow for Source Code Vulnerability Discovery and Analysis



## 1. Project Overview



This project implements an agentic workflow for source code vulnerability discovery and analysis using static analysis tools and an open-source Large Language Model.



The system combines:



- **Semgrep** for static application security testing

- **Qwen2.5-Coder 7B** running locally through **Ollama**

- A multi-agent analysis workflow

- Benchmark-based evaluation

- Trustworthiness and failure analysis

- Real project scan mode with JSONL and Markdown reports



The main objective of this project is not only to detect vulnerabilities, but also to study how reliable, explainable, and trustworthy an LLM-assisted vulnerability analysis workflow can be.



The project was developed as a research-oriented cybersecurity prototype and later extended into a demo-ready end-to-end scanning system.



---



## 2. Key Features



- Semgrep-based vulnerability scanning

- Local open-source LLM reasoning using Qwen2.5-Coder

- Agentic workflow with scanner, analyzer, and reporter components

- Benchmark evaluation using labeled vulnerability data

- Semgrep-only baseline

- LLM-only baseline

- Hybrid Semgrep + LLM baseline

- Hybrid policy analysis

- False positive and false negative analysis

- Failure taxonomy generation

- Consistency testing

- Prompt sensitivity testing

- Real project scan mode using `scan.py`

- JSONL and Markdown vulnerability reports

- Human-review routing using `NEEDS_REVIEW`



---



## 3. Architecture and Workflow



The project uses a staged agentic pipeline.



```text

Source Code / Benchmark Dataset

&#x20;       |

&#x20;       v

Semgrep Static Analysis

&#x20;       |

&#x20;       v

Scanner Agent

- Reads Semgrep finding

- Fetches surrounding code context

&#x20;       |

&#x20;       v

Analyzer Agent

- Sends finding + context to Qwen2.5-Coder

- Classifies finding as TP, FP, or UNCERTAIN

- Produces confidence and reasoning

&#x20;       |

&#x20;       v

Reporter Agent

- Assigns priority

- Produces structured output

&#x20;       |

&#x20;       v

Evaluation / Report Generation

- Metrics for benchmark mode

- JSONL + Markdown reports for real scan mode

```



The system uses one locally running LLM but assigns it different roles through separate prompts and pipeline stages.



The main components are:



| Component | Purpose |

|---|---|

| `tools/semgrep_tool.py` | Runs Semgrep and extracts findings |

| `tools/context_fetcher.py` | Fetches surrounding source-code context |

| `agents/scanner_agent.py` | Prepares Semgrep findings for analysis |

| `agents/analyzer_agent.py` | Uses Qwen2.5-Coder to classify findings |

| `agents/reporter_agent.py` | Adds priority and final report metadata |

| `evaluation/` | Contains benchmark evaluation and trustworthiness scripts |

| `scan.py` | Runs real project scan mode |

| `reports/` | Stores generated scan reports |

| `test_projects/vulnerable_app/` | Sample vulnerable app for demo |



---



## 4. Project Structure



```text

cybersecurity-agent/

│

├── agents/

│   ├── analyzer_agent.py

│   ├── llm_baseline_agent.py

│   ├── reporter_agent.py

│   └── scanner_agent.py

│

├── evaluation/

│   ├── compare_hybrid_fair.py

│   ├── hybrid_baseline.py

│   ├── hybrid_policy_analysis.py

│   ├── llm_baseline.py

│   ├── load_ground_truth.py

│   ├── metrics.py

│   ├── semgrep_baseline.py

│   ├── week5_consistency_test.py

│   ├── week5_failure_analysis.py

│   ├── week5_generate_report.py

│   ├── week5_prompt_sensitivity.py

│   └── week5_trustworthiness_report.md

│

├── llm/

│   └── ollama_client.py

│

├── prompts/

│   ├── analyzer_prompt.txt

│   ├── llm_baseline_prompt.txt

│   ├── reporter_prompt.txt

│   └── scanner_prompt.txt

│

├── reports/

│   └── generated scan reports

│

├── results/

│   └── generated benchmark and analysis outputs

│

├── schemas/

│   └── verdict.py

│

├── test_projects/

│   └── vulnerable_app/

│       └── app.py

│

├── tools/

│   ├── context_fetcher.py

│   ├── cwe_lookup.py

│   ├── prompt_loader.py

│   └── semgrep_tool.py

│

├── scan.py

├── pipeline.py

├── evaluate_results.py

├── README.md

└── .gitignore

```



---



## 5. Installation and Setup



### 5.1 Clone the repository



```powershell

git clone https://github.com/WhyAvya/cybersecurity-agent.git

cd cybersecurity-agent

```



### 5.2 Create and activate virtual environment



On Windows PowerShell:



```powershell

python -m venv venv

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

.venvScriptsActivate.ps1

```



After activation, the terminal should show:



```text

(venv)

```



### 5.3 Install Python dependencies



If the project contains a `requirements.txt` file, run:



```powershell

pip install -r requirements.txt

```



If not, install the main dependencies manually:



```powershell

pip install requests semgrep

```



Optional dependencies may be required depending on the scripts being executed.



---



## 6. Ollama and Qwen Model Setup



This project uses a local LLM through Ollama.



### 6.1 Install Ollama



Download and install Ollama from the official Ollama website.



After installation, verify that Ollama is available:



```powershell

ollama --version

```



### 6.2 Pull Qwen2.5-Coder



```powershell

ollama pull qwen2.5-coder:7b

```



### 6.3 Verify the model



```powershell

ollama list

```



Expected output should include:



```text

qwen2.5-coder:7b

```



### 6.4 Test model response



```powershell

ollama run qwen2.5-coder:7b

```



Type:



```text

hello

```



Exit using:



```text

/bye

```



### 6.5 Verify Ollama API



The project communicates with Ollama through:



```text

http://localhost:11434/api/generate

```



Test the local API:



```powershell

Invoke-RestMethod http://localhost:11434/api/tags

```



If model data is returned, Ollama is running correctly.



---



## 7. Week 4: Benchmark Evaluation



Week 4 focused on experimental evaluation.



The following systems were evaluated:



1. Semgrep-only baseline

2. LLM-only baseline

3. Hybrid Semgrep + LLM pipeline

4. Hybrid policy variants



### 7.1 Load ground truth



```powershell

python -m evaluation.load_ground_truth

```



This creates:



```text

evaluation/ground_truth.json

```



### 7.2 Run Semgrep-only baseline



```powershell

python -m evaluation.semgrep_baseline

```



### 7.3 Run LLM-only baseline



For a 100-file sample:



```powershell

$env:MAX_FILES="100"

python -m evaluation.llm_baseline

```



This generates:



```text

results/llm_baseline_100.jsonl

```



### 7.4 Run hybrid baseline



```powershell

python -m evaluation.hybrid_baseline

```



This generates:



```text

results/hybrid_findings.jsonl

```



### 7.5 Run fair Semgrep vs hybrid comparison



```powershell

python -m evaluation.compare_hybrid_fair

```



This generates:



```text

results/week4_semgrep_vs_hybrid_fair.csv

```



### 7.6 Run hybrid policy analysis



```powershell

python -m evaluation.hybrid_policy_analysis

```



This generates:



```text

results/hybrid_policy_analysis.csv

```



### 7.7 Week 4 Results Summary



| System | Metric Type | Precision | Recall | F1 | FPR | Interpretation |

|---|---:|---:|---:|---:|---:|---|

| Semgrep only | Binary detection | 58.2% | 19.7% | 29.4% | 8.2% | Stable static-analysis baseline |

| LLM only | Binary detection | 34.7% | 100.0% | 51.5% | 97.0% | High recall but excessive false positives |

| Hybrid-Strict | Binary detection | 70.0% | 12.4% | 21.1% | 3.1% | Best precision and lowest false-positive rate |

| Hybrid-Review | Binary detection | 64.9% | 13.5% | 22.3% | 4.2% | Treats uncertain cases as review |

| Hybrid-Conf75 | Binary detection | 59.6% | 19.2% | 29.1% | 7.6% | Best balanced hybrid policy |



The Week 4 evaluation showed that LLM-only detection was highly sensitive and produced many false positives. The hybrid system improved false-positive control and made the workflow more explainable.



---



## 8. Week 5: Trustworthiness and Failure Analysis



Week 5 focused on understanding why the system fails.



The analysis included:



- False positives

- False negatives

- Failure taxonomy

- Consistency testing

- Prompt sensitivity testing

- Hallucinated findings

- Reasoning failures



### 8.1 Run failure analysis



```powershell

python -m evaluation.week5_failure_analysis

```



This generates:



```text

results/week5_hybrid_conf75_false_positives.jsonl

results/week5_hybrid_conf75_false_negatives.jsonl

results/week5_llm_false_positives.jsonl

results/week5_llm_false_negatives.jsonl

results/week5_failure_taxonomy.csv

```



### 8.2 Run consistency test



```powershell

python -m evaluation.week5_consistency_test

```



This generates:



```text

results/week5_consistency_results.csv

```



Observed result:



```text

Total repeated cases : 30

Matching verdicts    : 17

Consistency rate     : 56.7%

Avg confidence diff  : 0.103

```



### 8.3 Run prompt sensitivity test



```powershell

python -m evaluation.week5_prompt_sensitivity

```



This generates:



```text

results/week5_prompt_sensitivity.csv

results/week5_prompt_sensitivity_summary.csv

```



Observed result:



| Prompt Style | TP | FP | UNCERTAIN | Match Rate | Avg Confidence | Parse Success |

|---|---:|---:|---:|---:|---:|---:|

| Strict | 1 | 10 | 4 | 0.400 | 0.810 | 1.000 |

| Balanced | 6 | 1 | 8 | 0.267 | 0.750 | 1.000 |

| Recall-focused | 11 | 0 | 4 | 0.333 | 0.837 | 1.000 |



### 8.4 Generate trustworthiness report



```powershell

python -m evaluation.week5_generate_report

```



This generates:



```text

evaluation/week5_trustworthiness_report.md

```



### 8.5 Week 5 Key Findings



| Failure Type | Count |

|---|---:|

| TOOL_COVERAGE_GAP | 363 |

| HIGH_CONFIDENCE_HALLUCINATION | 43 |

| SANITIZATION_MISUNDERSTANDING | 41 |

| CWE_MISMATCH | 26 |

| FALSE_POSITIVE_FILTER_FAILURE | 23 |

| SPECULATIVE_REASONING | 20 |

| HIGH_CONFIDENCE_FALSE_POSITIVE | 8 |

| UNCERTAINTY_MISCLASSIFICATION | 2 |

| VULNERABLE_WITHOUT_VALID_CWE | 1 |



The most important finding was that the hybrid system is limited by Semgrep coverage. If Semgrep does not generate a finding, the LLM analyzer does not get a chance to reason about that vulnerable file.



The LLM-only baseline showed high-confidence hallucinations, meaning it sometimes predicted vulnerabilities with high confidence even when the ground truth labeled the file as safe.



---



## 9. Week 6: Real Project Scan Mode



Week 6 added a real scan mode using:



```text

scan.py

```



This allows the user to scan any Python file or folder.



### 9.1 Run real project scan



```powershell

python scan.py test_projectsvulnerable_app

```



Expected output:



```text

===== REAL SCAN MODE =====

Target path: test_projectsvulnerable_app

Semgrep config: auto



Raw Semgrep findings found: 9



===== SCAN COMPLETE =====

Raw Semgrep findings : 9

Accepted             : 5

Rejected             : 1

Needs review         : 3

JSONL report saved   : reportsscan_report_<timestamp>.jsonl

Markdown report saved: reportsscan_report_<timestamp>.md

```



### 9.2 Scan any other Python folder



```powershell

python scan.py pathtoyourpython_project

```



Example:



```powershell

python scan.py test_projectsvulnerable_app

```



### 9.3 Use custom Semgrep config



```powershell

python scan.py test_projectsvulnerable_app --config auto

```



or:



```powershell

python scan.py test_projectsvulnerable_app --config p/python

```



---



## 10. Report Output Explanation



The real scan mode generates two report files:



```text

reports/scan_report_<timestamp>.jsonl

reports/scan_report_<timestamp>.md

```



### 10.1 JSONL report



The JSONL file stores structured machine-readable findings.



Each line contains one finding:



```json

{

&#x20; "scan_mode": "real_project_scan",

&#x20; "status": "ACCEPTED",

&#x20; "file": "test_projectsvulnerable_appapp.py",

&#x20; "line": 13,

&#x20; "rule_id": "python.lang.security.dangerous-system-call.dangerous-system-call",

&#x20; "cwe": "CWE-078: OS Command Injection",

&#x20; "severity": "HIGH",

&#x20; "analyzer_verdict": "TP",

&#x20; "confidence": 0.9,

&#x20; "priority": "HIGH",

&#x20; "reasoning": "The code contains a dangerous system call using user-controlled input..."

}

```



### 10.2 Markdown report



The Markdown report is human-readable and contains:



- Scan summary

- Number of raw Semgrep findings

- Accepted vulnerabilities

- Rejected findings

- Findings needing human review

- File and line number

- Rule ID

- CWE

- Severity

- Analyzer verdict

- Confidence

- Priority

- LLM reasoning



### 10.3 Status Labels



| Status | Meaning |

|---|---|

| `ACCEPTED` | The finding is likely a real vulnerability |

| `REJECTED` | The finding is likely a false positive |

| `NEEDS_REVIEW` | The finding is uncertain, contradictory, or unstable and should be reviewed by a human |



The `NEEDS_REVIEW` category was added based on Week 5 trustworthiness findings. It prevents the system from blindly accepting or rejecting uncertain LLM outputs.



### 10.4 Priority Labels



| Priority | Meaning |

|---|---|

| `HIGH` | Strong vulnerability signal with high severity and confidence |

| `MEDIUM` | Needs attention or human review |

| `LOW` | Low-confidence or rejected finding |



---



## 11. Example Demo App



The repository includes a sample vulnerable application:



```text

test_projects/vulnerable_app/app.py

```



It contains examples of:



- OS command injection

- SQL injection

- Path traversal



Run:



```powershell

python scan.py test_projectsvulnerable_app

```



This produces a complete end-to-end vulnerability report.



---



## 12. Current Project Status



At the end of Week 6, the project supports two modes.



### 12.1 Benchmark Evaluation Mode



Used for research evaluation on labeled data.



```text

BenchmarkPython dataset

&#x20;       |

&#x20;       v

Semgrep / LLM / Hybrid evaluation

&#x20;       |

&#x20;       v

Metrics and trustworthiness analysis

```



### 12.2 Real Scan Mode



Used for scanning an actual Python project.



```text

User Python project

&#x20;       |

&#x20;       v

Semgrep scan

&#x20;       |

&#x20;       v

Scanner agent

&#x20;       |

&#x20;       v

Analyzer agent using Qwen2.5-Coder

&#x20;       |

&#x20;       v

Reporter

&#x20;       |

&#x20;       v

JSONL + Markdown report

```



The project is now working as both:



1. A benchmark-based research prototype

2. A real project vulnerability scan demo



---



## 13. Limitations



This project is a research prototype and has some important limitations.



### 13.1 Semgrep Coverage Limitation



The hybrid system depends on Semgrep findings. If Semgrep does not flag a vulnerability, the LLM analyzer does not analyze that file.



This was observed in Week 5 as the largest failure type:



```text

TOOL_COVERAGE_GAP

```



### 13.2 LLM Hallucination



The LLM sometimes predicts vulnerabilities with high confidence even when the code is safe. This was observed in the LLM-only baseline.



### 13.3 Prompt Sensitivity



The analyzer behavior changes when prompt wording changes. Strict, balanced, and recall-focused prompts produced different verdict distributions.



### 13.4 Consistency Issues



The same finding may receive different verdicts when analyzed multiple times. The consistency test showed a 56.7% verdict match rate.



### 13.5 CWE Mapping Issues



Semgrep rule metadata and benchmark CWE labels may not always align perfectly. The project includes CWE normalization and basic rule-based CWE inference, but CWE assignment can still be imperfect.



### 13.6 Not a Fully Autonomous Security Tool



This system should not be used as a fully autonomous vulnerability detector. It is better understood as a vulnerability triage and explanation assistant.



Human review is recommended for:



- `NEEDS_REVIEW` findings

- High-impact vulnerabilities

- Contradictory LLM reasoning

- Low-confidence findings

- Security-critical applications



---



## 14. Future Improvements



Possible future improvements include:



1. Add support for more programming languages.

2. Add more static analysis tools beyond Semgrep.

3. Improve source-to-sink dataflow extraction.

4. Improve CWE mapping and CWE alias handling.

5. Add better deduplication of repeated Semgrep findings.

6. Add deterministic LLM settings where supported.

7. Add voting or repeated-run analysis for unstable findings.

8. Add a web dashboard for viewing reports.

9. Add authentication and user accounts for multi-user scanning.

10. Add database storage for historical scan results.

11. Add Docker support for reproducible setup.

12. Add cloud deployment support.

13. Add CI/CD integration for GitHub repositories.

14. Add SARIF output for integration with security tools.

15. Add severity calibration using CVSS-like scoring.



---



## 15. Research Conclusion



The project demonstrates that combining static analysis tools with local LLM-based reasoning can improve vulnerability triage and explanation.



The hybrid workflow is more trustworthy than using an LLM alone because Semgrep provides grounded findings and the LLM provides contextual reasoning. However, the system still requires human review because of tool coverage gaps, prompt sensitivity, hallucinated reasoning, and occasional inconsistent verdicts.



The most reliable use case for this system is:



```text

Static analyzer finds candidate vulnerabilities

&#x20;       |

&#x20;       v

LLM explains and prioritizes findings

&#x20;       |

&#x20;       v

Human reviews accepted and uncertain cases

```



This makes the project suitable as a research prototype and demo-ready vulnerability analysis assistant.



---



## 16. Useful Commands



### Activate environment



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

.venvScriptsActivate.ps1

```



### Check Ollama model



```powershell

ollama list

```



### Test Ollama API



```powershell

Invoke-RestMethod http://localhost:11434/api/tags

```



### Run Week 4 evaluation



```powershell

python -m evaluation.load_ground_truth

python -m evaluation.semgrep_baseline

$env:MAX_FILES="100"

python -m evaluation.llm_baseline

python -m evaluation.hybrid_baseline

python -m evaluation.compare_hybrid_fair

python -m evaluation.hybrid_policy_analysis

```



### Run Week 5 trustworthiness analysis



```powershell

python -m evaluation.week5_failure_analysis

python -m evaluation.week5_consistency_test

python -m evaluation.week5_prompt_sensitivity

python -m evaluation.week5_generate_report

```



### Run Week 6 real scan mode



```powershell

python scan.py test_projectsvulnerable_app

```



### Open latest Markdown report



```powershell

notepad (Get-ChildItem reports*.md | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

```



### Open latest JSONL report



```powershell

notepad (Get-ChildItem reports*.jsonl | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

```



---



## 17. GitHub Branch



Current development branch:



```text

week4-evaluation

```



Major completed milestones:



- Week 4 evaluation

- Week 5 trustworthiness analysis

- Week 6 real scan mode

