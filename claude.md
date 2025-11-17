# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security analysis pipeline for automated vulnerability detection in software projects. Analyzes source code (SAST), dependencies (SCA), and exposed secrets, then generates professional remediation reports enhanced with local AI (Ollama).

**Current State**: Specification phase with complete agent architecture documentation. Go implementation not yet started.

**Target**: Commercial SaaS product for automated security scanning with AI-generated fixes.

## Architecture Pattern

The pipeline follows an **agent-based architecture** with sequential and parallel execution:

1. **Profiler Agent** → Analyzes project structure, languages, frameworks, dependencies
2. **Contextualization Agent** → Uses Ollama to determine which security agents to activate based on project context
3. **Parallel Security Scanners**:
   - **SAST Agent** (Semgrep) - Source code vulnerabilities
   - **SCA Agent** (Trivy) - Dependency CVEs
   - **Secrets Agent** (Gitleaks) - Exposed credentials
4. **Aggregator Agent** → Deduplicates, prioritizes, and categorizes findings
5. **Remediation Agent** → Uses Ollama to generate concrete code fixes
6. **Report Agent** → Generates multi-format reports (JSON/HTML/PDF/MD)

Each agent has two documentation files:
- `claude.md` - Detailed implementation specifications
- `agent.json` - MCP (Model Context Protocol) declaration for tool integration

## Project Structure

```
security_project/
├── CLAUDE.md              # This file
├── claude.md              # Original French architecture doc
└── agents/
    ├── profiler_agent/
    ├── contextualization_agent/
    ├── sast_agent/
    ├── sca_agent/
    ├── secrets_agent/
    ├── aggregator_agent/
    ├── remediation_agent/
    └── report_agent/
```

**Planned Structure** (not yet implemented):
```
internal/
├── agents/          # Agent implementations
├── pipeline/        # Orchestrator and shared context
└── models/          # Shared data structures
pkg/
├── ollama/          # Ollama client
└── utils/           # Shared utilities
cmd/pipeline/        # CLI entry point
```

## Key Design Decisions

### External Tool Integration

The pipeline wraps three security scanners:
- **Semgrep** (SAST) - Multi-language static analysis, 1000+ rules
- **Trivy** (SCA) - Dependency vulnerability scanner, CVE database
- **Gitleaks** (Secrets) - Credential and secret detection

**Important**: All must be installed separately. Check availability at agent initialization.

### Ollama Integration Strategy

Ollama (codellama) enhances analysis at multiple stages:

| Agent | Ollama Role | Benefit |
|-------|-------------|---------|
| Contextualization | Determines project type/domain/criticality | Optimal agent configuration |
| SAST | Validates vulnerabilities in context | -60-70% false positives |
| SCA | Evaluates CVE exploitability | Smart prioritization |
| Secrets | Distinguishes real secrets vs placeholders | -70-80% false positives |
| Remediation | Generates production-ready code fixes | Actionable patches |
| Report | Creates business-friendly executive summary | Management-ready reports |

**Why Ollama?**
- Local execution (GDPR-compliant, no API costs, no rate limits)
- Context preservation across pipeline stages
- Sufficient quality for validation and generation tasks

### Pipeline Context Flow

Each agent receives and updates a shared `pipeline.Context`:

```go
type Context struct {
    ProjectPath     string
    ProjectProfile  ProjectProfile      // From Profiler
    AnalysisConfig  AnalysisConfig      // From Contextualization
    Findings        []Finding           // Accumulated from SAST/SCA/Secrets
    AggregatedReport AggregatedReport   // From Aggregator
    RemediationPlans []RemediationPlan  // From Remediation
    Reports         map[string][]byte   // From Report
    Errors          []string
}
```

## Agent Implementation Notes

### Profiler Agent
- Language detection via file extensions (30+ languages)
- Framework identification via dependency files (package.json, go.mod, requirements.txt, etc.)
- Exclude: `node_modules/`, `vendor/`, `.git/`, `venv/`, `__pycache__/`, `build/`, `dist/`
- Must handle monorepos and multi-language projects

### Contextualization Agent
- Determines project type (API/CLI/web/library), domain (finance/crypto/healthcare), and criticality
- Activates SAST only if source files > 10
- Activates SCA only if dependencies exist
- Always activates Secrets (critical and fast)
- Configures severity thresholds per agent based on project context

### SAST Agent
- Use Semgrep with `--config auto` for default rules or specific rulesets for targeted scans
- Exit code 1 means findings found (not an error)
- Map Semgrep severity: ERROR→high, WARNING→medium, INFO→low
- Ollama validation optional but recommended for medium/low confidence findings
- Extract 20 lines of context around vulnerable code for validation

### SCA Agent
- Use Trivy in offline mode for reliability (no GitHub rate limits)
- Filter by CVSS score based on context severity config
- Ollama evaluates if CVE is actually exploitable in the project's context
- Distinguish direct vs transitive dependencies

### Secrets Agent
- Gitleaks can scan filesystem only (`detect`) or git history (`protect`)
- Git history scanning disabled by default (slow, high false positives)
- Ollama filters out test fixtures, example configs, and placeholder values
- Entropy threshold: 4.5+ (configurable)

### Aggregator Agent
- Deduplication strategies: exact match, similar (fuzzy), dependency chain
- Priority score (1-100): severity + CVSS + exploitability + context + confidence
- Calculate global Risk Score (0-100) for project
- Map findings to compliance frameworks (OWASP, CWE, PCI-DSS, ISO27001)

### Remediation Agent
- Generate three types of fixes:
  - Code patches (before/after with syntax highlighting)
  - Dependency updates (exact package manager commands)
  - Secret remediation (revocation + rotation steps)
- Include complexity estimate, time estimate, and required expertise level
- Provide alternatives when multiple fix approaches exist

### Report Agent
- Support formats: JSON (CI/CD), HTML (interactive), PDF (professional), Markdown (docs), CSV (spreadsheet)
- HTML uses Chart.js for vulnerability distribution graphs
- PDF generation requires wkhtmltopdf (optional dependency)
- Ollama generates executive summary in business-friendly language

## When Implementing

### Required External Dependencies

All commands must be verified at startup:

```bash
# Check availability
go version          # Go 1.21+
ollama --version    # Ollama
semgrep --version   # Python pip package
trivy --version     # Homebrew/binary
gitleaks version    # Homebrew/binary

# Install commands for user guidance
pip install semgrep
brew install trivy gitleaks wkhtmltopdf
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull codellama
```

### Configuration Files

Support both `.env` and `config.yaml`:

```yaml
pipeline:
  timeout: 30m
  max_parallel_agents: 3

agents:
  sast:
    enabled: true
    severity: medium
    validate_with_ollama: true
  sca:
    enabled: true
    severity: high
  secrets:
    enabled: true
    scan_git_history: false

ollama:
  url: http://localhost:11434
  model: codellama

reporting:
  output_dir: .security-scan
  formats: [json, html, pdf, markdown]
  include_executive_summary: true
```

### Error Handling

- **Scanner not installed**: Fail fast with installation instructions
- **Ollama unavailable**: Degrade gracefully (skip validation/enhancement steps)
- **Scanner error**: Log and continue with other agents
- **Timeout**: Configurable per-agent (default 5min for SAST/SCA, 2min for Secrets)

### Testing Strategy

Each agent should have:
1. Unit tests with mocked scanner output
2. Integration tests with real small projects (Go API, Python script, JS frontend, Solidity contract)
3. End-to-end test with sample vulnerable project

Test data location: `testdata/` with subdirectories per vulnerability type

### Performance Considerations

- Run SAST/SCA/Secrets agents in parallel (goroutines with context cancellation)
- Lazy load Ollama client (only when validation enabled)
- Cache project profile between runs (hash-based invalidation)
- Stream large scanner outputs instead of buffering in memory
- Limit Semgrep to relevant file extensions only

## CLI Interface

```bash
# Basic scan
./security-pipeline analyze /path/to/project

# With options
./security-pipeline analyze /path/to/project \
  --format json,html,pdf \
  --output ./reports \
  --severity high \
  --config ./custom-config.yaml

# Quick scan (skip Ollama validation)
./security-pipeline analyze /path/to/project --quick

# Specific agents only
./security-pipeline analyze /path/to/project --agents sast,secrets

# Verbose output
./security-pipeline analyze /path/to/project --verbose
```

Expected output structure:
```
.security-scan/
├── security-report-YYYYMMDD-HHMMSS.json
├── security-report-YYYYMMDD-HHMMSS.html
├── security-report-YYYYMMDD-HHMMSS.pdf
└── security-report-YYYYMMDD-HHMMSS.md
```

## Development Priorities

1. **Core pipeline orchestrator** - Context management, agent execution flow
2. **Profiler + Contextualization** - Foundation for all other agents
3. **SAST Agent** - Highest value (code vulnerabilities)
4. **Secrets Agent** - Fast to implement, high impact
5. **SCA Agent** - Dependency scanning
6. **Aggregator** - Deduplication and prioritization logic
7. **Remediation** - AI-generated fixes (differentiation feature)
8. **Report** - Multi-format output generation

## Security Considerations

- Never log secrets in plaintext (redact in logs and errors)
- Reports should redact secret values (show type and location only)
- All data processing is local (GDPR-compliant by design)
- Sandboxed execution for scanner subprocesses
- Validate all file paths to prevent traversal attacks in profiler
