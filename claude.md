# Security Analysis Pipeline

## Vue d'ensemble

Pipeline automatisée d'analyse de sécurité pour identifier les vulnérabilités dans des projets. Analyse le code source (SAST), les dépendances (SCA), et les secrets exposés, puis génère des rapports professionnels avec plans de remédiation.

## Objectif commercial

Produit SaaS/commercial pour scanner automatiquement des projets et fournir des rapports de sécurité actionnables avec fixes concrets générés par IA.

## Architecture

```
User Input
    ↓
Profiler Agent → Contextualization Agent
    ↓                       ↓
    ├──────────────┬────────┴────────┬──────────────┐
    ↓              ↓                 ↓              ↓
SAST Agent    SCA Agent       Secrets Agent    (parallel)
(Semgrep)     (Trivy)         (Gitleaks)
    ↓              ↓                 ↓
    └──────────────┴────────┬────────┘
                            ↓
                   Aggregator Agent
                            ↓
                  Remediation Agent
                            ↓
                    Report Agent
                            ↓
                  JSON/HTML/PDF/MD
```

## Stack technique

- **Langage** : Go 1.21+
- **IA locale** : Ollama (codellama)
- **Scanners** :
  - Semgrep (SAST - code vulnerabilities)
  - Trivy (SCA - dependency CVEs)
  - Gitleaks (Secrets detection)

## Agents de la pipeline

### 1. Profiler Agent
**Rôle** : Analyse initiale du projet
- Détecte langages (Go, Python, JS, etc.)
- Identifie frameworks (Gin, React, Django, etc.)
- Extrait dépendances (go.mod, package.json, etc.)
- Map structure du projet

**Scanner** : Filesystem analysis
**Output** : ProjectProfile (langages, frameworks, deps, structure)

### 2. Contextualization Agent
**Rôle** : Décide quels agents activer et avec quels paramètres
- Analyse le profil avec Ollama (type: api/cli, domain: finance/crypto, criticité)
- Active SAST si code source > 10 fichiers
- Active SCA si dépendances externes > 0
- Active Secrets (toujours - critique et rapide)
- Configure sévérité et règles par agent

**IA** : Ollama détermine contexte métier
**Output** : AnalysisConfig (agents activés, configs, priorités)

### 3. SAST Agent (Static Application Security Testing)
**Rôle** : Détecte vulnérabilités dans le code source
- SQL injection, XSS, command injection, path traversal
- Crypto weaknesses, insecure randomness
- Solidity (reentrancy, integer overflow, tx.origin)

**Scanner** : Semgrep (1000+ règles, 30+ langages)
**IA** : Ollama valide findings (réduit faux positifs 60-70%)
**Output** : Code vulnerabilities avec CWE/OWASP mapping

### 4. SCA Agent (Software Composition Analysis)
**Rôle** : Détecte CVEs dans les dépendances
- Scan dépendances avec Trivy (base CVE locale)
- Check contre NVD, GitHub Advisory, Alpine, etc.
- Support 15+ package managers

**Scanner** : Trivy (pas de rate limits)
**IA** : Ollama évalue exploitabilité dans contexte projet
**Output** : Vulnerable dependencies avec CVSS scores

### 5. Secrets Agent
**Rôle** : Détecte credentials exposés
- AWS keys, GitHub tokens, private keys, API keys
- 25+ types de secrets (1000+ patterns)
- Détection par regex + entropie

**Scanner** : Gitleaks (filesystem + git history)
**IA** : Ollama distingue vrais secrets vs placeholders (réduit faux positifs 70-80%)
**Output** : Exposed secrets avec plans de révocation

### 6. Aggregator Agent
**Rôle** : Consolide et déduplique les findings
- Déduplication (exact, similar, dependencies)
- Priorisation (1-100) : sévérité + CVSS + exploitabilité + contexte + confiance
- Catégorisation OWASP/CWE
- Calcul Risk Score global (0-100)
- Statistiques (par catégorie, sévérité, fichier)

**Logic** : Deduplication + prioritization + categorization
**Output** : AggregatedReport (52 findings sur 87, Risk Score: 67.5)

### 7. Remediation Agent
**Rôle** : Génère fixes concrets pour chaque finding
- Code patches (avant/après avec code compilable)
- Dependency updates (commandes exactes par package manager)
- Secrets remediation (révocation + rotation)
- Plans d'action étape par étape
- Tests de validation
- Alternatives de fix

**IA** : Ollama génère code production-ready + commandes + plans
**Output** : RemediationPlan par finding (complexity, time, expertise)

### 8. Report Agent
**Rôle** : Génère rapports professionnels multi-formats
- JSON (CI/CD integration)
- HTML (interactif avec Chart.js)
- PDF (professionnel via wkhtmltopdf)
- Markdown (documentation)
- CSV (spreadsheet export)

**IA** : Ollama génère executive summary (business-friendly)
**Output** : Reports + compliance mapping (OWASP/CWE/PCI-DSS/ISO27001)

## Rôle d'Ollama (IA locale)

Ollama (codellama) enrichit l'analyse à chaque étape :

| Agent | Rôle d'Ollama | Bénéfice |
|-------|---------------|----------|
| **Contextualization** | Détermine type/domain/criticité projet | Config optimale par contexte |
| **SAST** | Valide vulns + génère recommendations | -60-70% faux positifs |
| **SCA** | Évalue exploitabilité CVE dans contexte | Priorisation intelligente |
| **Secrets** | Distingue vrais secrets vs placeholders | -70-80% faux positifs |
| **Remediation** | Génère code fixes + commandes + plans | Fixes production-ready |
| **Report** | Génère executive summary business | Adapté audience management |

**Pourquoi Ollama ?**
- ✅ Local (gratuit, pas de rate limits, RGPD-compliant)
- ✅ Pas d'API keys nécessaires
- ✅ Rapide (suffisant pour validation/génération)
- ✅ Contexte projet préservé

## Structure du projet

```
security-pipeline/
├── claude.md                      # Ce fichier
├── main.go                        # Entry point
├── go.mod / go.sum
│
├── cmd/
│   └── pipeline/
│       └── main.go                # CLI
│
├── internal/
│   ├── agents/
│   │   ├── profiler/
│   │   │   ├── claude.md          # Doc agent
│   │   │   ├── agent.json         # MCP declaration
│   │   │   └── profiler.go
│   │   ├── contextualization/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   └── contextualization.go
│   │   ├── sast/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   ├── sast.go
│   │   │   └── semgrep/
│   │   │       ├── client.go
│   │   │       └── parser.go
│   │   ├── sca/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   ├── sca.go
│   │   │   └── trivy/
│   │   │       ├── client.go
│   │   │       └── parser.go
│   │   ├── secrets/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   ├── secrets.go
│   │   │   └── gitleaks/
│   │   │       ├── client.go
│   │   │       └── parser.go
│   │   ├── aggregator/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   ├── aggregator.go
│   │   │   └── deduplicator/
│   │   ├── remediation/
│   │   │   ├── claude.md
│   │   │   ├── agent.json
│   │   │   ├── remediation.go
│   │   │   └── generators/
│   │   └── report/
│   │       ├── claude.md
│   │       ├── agent.json
│   │       ├── report.go
│   │       └── formatters/
│   │
│   ├── pipeline/
│   │   ├── orchestrator.go        # Gère exécution séquentielle/parallèle
│   │   └── context.go             # Context partagé entre agents
│   │
│   └── models/
│       ├── finding.go
│       ├── vulnerability.go
│       └── report.go
│
├── pkg/
│   ├── ollama/
│   │   └── client.go              # Client Ollama
│   └── utils/
│       ├── logger.go
│       └── config.go
│
└── configs/
    └── config.yaml                # Pipeline config
```

## Installation

### Prérequis

```bash
# Go 1.21+
go version

# Ollama (IA locale)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull codellama

# Scanners
pip install semgrep
brew install trivy
brew install gitleaks

# PDF generation (optionnel)
brew install wkhtmltopdf
```

### Build

```bash
git clone <repo-url>
cd security-pipeline
go mod download
go build -o security-pipeline ./cmd/pipeline
```

## Configuration

### Fichier .env

```env
# Ollama (requis)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama

# Output (optionnel)
REPORT_OUTPUT_DIR=.security-scan
REPORT_THEME=light
```

### Fichier config.yaml

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
    entropy_threshold: 4.5
    scan_git_history: false

reporting:
  formats: [json, html, pdf, markdown]
  include_executive_summary: true
  include_compliance: true
```

## Usage

### CLI basique

```bash
# Scan projet
./security-pipeline analyze /path/to/project

# Avec options
./security-pipeline analyze /path/to/project \
  --format json,html,pdf \
  --output ./reports \
  --severity high

# Verbose
./security-pipeline analyze /path/to/project --verbose
```

### Output

```
============================================================
  SECURITY SCAN COMPLETE
============================================================

Project: my-api
Risk Score: 67.5/100 (HIGH)

Findings Summary:
  Critical: 3
  High:     12
  Medium:   28
  Low:      9
  Total:    52

Reports Generated:
  JSON: .security-scan/security-report-20251117-103000.json
  HTML: .security-scan/security-report-20251117-103000.html
  PDF:  .security-scan/security-report-20251117-103000.pdf
  MARKDOWN: .security-scan/security-report-20251117-103000.md

============================================================
```

## Sécurité du pipeline

- ✅ Aucune donnée envoyée hors du système (Ollama local)
- ✅ Secrets jamais loggés en clair
- ✅ Rapports avec secrets redacted
- ✅ RGPD-compliant (traitement local)
