# SCA Agent (Software Composition Analysis)

## Objectif
Analyser les dépendances tierces du projet pour détecter des vulnérabilités connues (CVEs) en utilisant **Trivy**. Identifier les versions vulnérables, évaluer l'exploitabilité avec Ollama, et proposer des mises à jour.

## Responsabilités

1. **Scan des dépendances** : Exécuter Trivy sur le projet
2. **Parsing du rapport** : Extraire les vulnérabilités du JSON Trivy
3. **Enrichissement contextuel** : Ollama évalue l'exploitabilité réelle
4. **Génération de findings** : Rapports avec CVE IDs, CVSS scores, recommendations
5. **Filtrage intelligent** : Prioriser selon sévérité et contexte projet

## Structure

```
internal/agents/sca/
├── claude.md              # Ce fichier
├── sca.go                 # Agent principal
├── trivy/
│   ├── client.go          # Wrapper Trivy CLI
│   └── parser.go          # Parser JSON Trivy
├── analyzer/
│   └── exploitability.go  # Analyse via Ollama
└── models.go              # Structures Finding, TrivyReport
```

## Pourquoi Trivy ?

✅ **Pas de rate limits** - Base CVE locale  
✅ **Multi-sources** - NVD, GitHub Advisory, Alpine, Ubuntu, etc.  
✅ **Ultra rapide** - Scan de 100 deps en ~2 secondes  
✅ **15+ langages** - Go, NPM, Python, Java, Rust, PHP, Ruby, etc.  
✅ **Gratuit et fiable** - Utilisé par des millions de devs  
✅ **JSON output** - Facile à parser  

## Input/Output

### Input
```go
type Input struct {
    ProjectPath   string
    Config        AgentConfig  // Depuis Contextualization
    // Config contient: Severity, SkipDevDeps, MaxFindings
}
```

### Output
```go
type Finding struct {
    ID              string    // UUID
    Type            string    // "vulnerable-dependency"
    Severity        string    // "low", "medium", "high", "critical"
    Title           string    // "Directory Traversal in gin"
    Description     string    // Détails de la CVE
    
    // Dependency info
    PackageName     string    // "github.com/gin-gonic/gin"
    InstalledVersion string   // "v1.7.0"
    FixedVersion    string    // "v1.7.7"
    PackageType     string    // "gomod", "npm", "pip"
    
    // Vulnerability info
    CVE             string    // "CVE-2020-28483"
    CVSS            float64   // 7.5
    CWE             []string  // ["CWE-22"]
    
    // Enrichissement
    Exploitability  string    // Analyse Ollama
    RiskLevel       string    // "low", "medium", "high", "critical"
    Recommendation  string    // Comment fix
    
    // References
    References      []string  // URLs vers advisories
    PublishedDate   time.Time
    
    Source          string    // "trivy"
    Timestamp       time.Time
}

type ScanResult struct {
    Findings           []Finding
    DependenciesChecked int
    VulnerableDeps     int
    Duration           time.Duration
    TrivyVersion       string
}
```

## Installation Trivy

### Vérification au démarrage

```go
func (a *SCAAgent) checkTrivyInstalled() error {
    cmd := exec.Command("trivy", "--version")
    output, err := cmd.Output()
    
    if err != nil {
        return fmt.Errorf("Trivy not installed. Install with: brew install trivy")
    }
    
    a.trivyVersion = parseVersion(string(output))
    return nil
}
```

### Installation automatique (optionnel)

```go
func (a *SCAAgent) installTrivy() error {
    // Détecter OS
    switch runtime.GOOS {
    case "linux":
        return exec.Command("sh", "-c", 
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin").Run()
    case "darwin":
        return exec.Command("brew", "install", "trivy").Run()
    default:
        return fmt.Errorf("unsupported OS, install manually")
    }
}
```

## Exécution de Trivy

### Commande de base

```go
func (c *TrivyClient) Scan(projectPath string, config ScanConfig) (*TrivyReport, error) {
    args := []string{
        "fs",                      // Filesystem scan
        "--format", "json",        // Output JSON
        "--quiet",                 // Pas de logs
        "--scanners", "vuln",      // Uniquement vulnérabilités
    }
    
    // Filtrer par sévérité
    if config.Severity != "" {
        severities := mapSeverityToTrivy(config.Severity)
        args = append(args, "--severity", severities)
    }
    
    // Skip dev dependencies (npm, pip)
    if config.SkipDevDeps {
        args = append(args, "--skip-dirs", "node_modules", "--skip-dirs", "venv")
    }
    
    // Cible
    args = append(args, projectPath)
    
    // Exécuter
    cmd := exec.Command("trivy", args...)
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("trivy scan failed: %w", err)
    }
    
    // Parser JSON
    var report TrivyReport
    if err := json.Unmarshal(output, &report); err != nil {
        return nil, fmt.Errorf("failed to parse trivy output: %w", err)
    }
    
    return &report, nil
}
```

### Mapping de sévérité

```go
func mapSeverityToTrivy(severity string) string {
    // Pipeline config → Trivy severity filter
    switch severity {
    case "critical":
        return "CRITICAL"
    case "high":
        return "HIGH,CRITICAL"
    case "medium":
        return "MEDIUM,HIGH,CRITICAL"
    case "low":
        return "LOW,MEDIUM,HIGH,CRITICAL"
    default:
        return "MEDIUM,HIGH,CRITICAL"
    }
}
```

## Structure JSON Trivy

### Format de sortie

```go
type TrivyReport struct {
    SchemaVersion int              `json:"SchemaVersion"`
    ArtifactName  string           `json:"ArtifactName"`
    ArtifactType  string           `json:"ArtifactType"`
    Results       []TrivyResult    `json:"Results"`
}

type TrivyResult struct {
    Target          string                `json:"Target"`        // "go.mod", "package-lock.json"
    Class           string                `json:"Class"`         // "lang-pkgs"
    Type            string                `json:"Type"`          // "gomod", "npm"
    Vulnerabilities []TrivyVulnerability  `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
    VulnerabilityID   string         `json:"VulnerabilityID"`   // "CVE-2020-28483"
    PkgName           string         `json:"PkgName"`           // "github.com/gin-gonic/gin"
    InstalledVersion  string         `json:"InstalledVersion"`  // "v1.7.0"
    FixedVersion      string         `json:"FixedVersion"`      // "v1.7.7"
    Severity          string         `json:"Severity"`          // "HIGH"
    Title             string         `json:"Title"`
    Description       string         `json:"Description"`
    References        []string       `json:"References"`
    PublishedDate     *time.Time     `json:"PublishedDate"`
    LastModifiedDate  *time.Time     `json:"LastModifiedDate"`
    PrimaryURL        string         `json:"PrimaryURL"`
    
    CVSS              map[string]CVSS `json:"CVSS"`
    CweIDs            []string       `json:"CweIDs"`
}

type CVSS struct {
    V2Vector string  `json:"V2Vector"`
    V3Vector string  `json:"V3Vector"`
    V2Score  float64 `json:"V2Score"`
    V3Score  float64 `json:"V3Score"`
}
```

## Conversion Trivy → Finding

```go
func (a *SCAAgent) convertTrivyToFindings(report *TrivyReport) []Finding {
    findings := []Finding{}
    
    for _, result := range report.Results {
        for _, vuln := range result.Vulnerabilities {
            // Extraire CVSS score
            cvssScore := extractCVSSScore(vuln.CVSS)
            
            finding := Finding{
                ID:               uuid.New().String(),
                Type:             "vulnerable-dependency",
                Severity:         normalizeSeverity(vuln.Severity),
                Title:            vuln.Title,
                Description:      vuln.Description,
                PackageName:      vuln.PkgName,
                InstalledVersion: vuln.InstalledVersion,
                FixedVersion:     vuln.FixedVersion,
                PackageType:      result.Type,
                CVE:              vuln.VulnerabilityID,
                CVSS:             cvssScore,
                CWE:              vuln.CweIDs,
                References:       vuln.References,
                PublishedDate:    *vuln.PublishedDate,
                Source:           "trivy",
                Timestamp:        time.Now(),
            }
            
            findings = append(findings, finding)
        }
    }
    
    return findings
}

func extractCVSSScore(cvss map[string]CVSS) float64 {
    // Priorité : NVD > autres sources
    if nvd, ok := cvss["nvd"]; ok && nvd.V3Score > 0 {
        return nvd.V3Score
    }
    
    // Fallback sur première source disponible
    for _, c := range cvss {
        if c.V3Score > 0 {
            return c.V3Score
        }
        if c.V2Score > 0 {
            return c.V2Score
        }
    }
    
    return 0.0
}

func normalizeSeverity(trivySeverity string) string {
    switch trivySeverity {
    case "CRITICAL":
        return "critical"
    case "HIGH":
        return "high"
    case "MEDIUM":
        return "medium"
    case "LOW":
        return "low"
    default:
        return "medium"
    }
}
```

## Enrichissement avec Ollama

### Évaluation de l'exploitabilité

```go
func (a *SCAAgent) assessExploitability(finding Finding, projectContext ProjectContext) error {
    prompt := fmt.Sprintf(`
Analyze the exploitability of this vulnerability in the specific project context.

CVE: %s
Package: %s@%s → Fixed in: %s
CVSS Score: %.1f
Severity: %s
Description: %s

Project Context:
- Type: %s (api/cli/library/smart-contract)
- Domain: %s (finance/crypto/general)
- Frameworks: %s
- Production-facing: %v

Question: Is this vulnerability ACTUALLY exploitable in THIS specific project?

Consider:
1. Does the project use the vulnerable functionality of this package?
2. Is the vulnerable code path accessible from outside?
3. Are there mitigating factors (authentication, input validation, firewalls)?
4. What's the real-world impact if exploited?

Respond in JSON:
{
  "exploitable": true/false,
  "confidence": "low/medium/high",
  "reasoning": "detailed explanation",
  "risk_level": "low/medium/high/critical",
  "attack_scenario": "how it could be exploited (if applicable)"
}
`,
        finding.CVE,
        finding.PackageName,
        finding.InstalledVersion,
        finding.FixedVersion,
        finding.CVSS,
        finding.Severity,
        finding.Description,
        projectContext.Type,
        projectContext.Domain,
        projectContext.Frameworks,
        projectContext.IsProduction,
    )
    
    response, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return err
    }
    
    var assessment ExploitabilityAssessment
    if err := json.Unmarshal([]byte(response), &assessment); err != nil {
        return err
    }
    
    // Enrichir le finding
    finding.Exploitability = assessment.Reasoning
    finding.RiskLevel = assessment.RiskLevel
    
    // Downgrade severity si non exploitable
    if !assessment.Exploitable && assessment.Confidence == "high" {
        finding.Severity = downgradeSeverity(finding.Severity)
    }
    
    return nil
}

type ExploitabilityAssessment struct {
    Exploitable    bool   `json:"exploitable"`
    Confidence     string `json:"confidence"`
    Reasoning      string `json:"reasoning"`
    RiskLevel      string `json:"risk_level"`
    AttackScenario string `json:"attack_scenario"`
}
```

### Génération de recommendations

```go
func (a *SCAAgent) generateRecommendation(finding Finding, projectContext ProjectContext) (string, error) {
    prompt := fmt.Sprintf(`
Generate a practical fix recommendation for this vulnerability.

Package: %s
Current version: %s
Fixed version: %s
CVE: %s
Language: %s (from %s)

Project context:
- Type: %s
- Has tests: %v

Provide:
1. **Immediate action**: Exact command to update (go get, npm install, pip install, etc.)
2. **Breaking changes**: What might break when upgrading (if known)
3. **Testing steps**: How to verify the fix works
4. **Alternative**: If upgrade not possible, what mitigations exist?

Keep it concise, actionable, and specific to %s projects.
Format as markdown.
`,
        finding.PackageName,
        finding.InstalledVersion,
        finding.FixedVersion,
        finding.CVE,
        projectContext.Language,
        finding.PackageType,
        projectContext.Type,
        projectContext.HasTests,
        projectContext.Language,
    )
    
    recommendation, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        // Fallback sur recommendation générique
        return fmt.Sprintf("Update %s to %s", finding.PackageName, finding.FixedVersion), nil
    }
    
    return recommendation, nil
}
```

## Implémentation

### sca.go

```go
package sca

type SCAAgent struct {
    trivyClient  *TrivyClient
    ollamaClient *ollama.Client
}

func New(ollamaClient *ollama.Client) *SCAAgent {
    return &SCAAgent{
        trivyClient:  NewTrivyClient(),
        ollamaClient: ollamaClient,
    }
}

func (a *SCAAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    config := pipelineCtx.AnalysisConfig.AgentConfigs["sca"]
    
    // 1. Vérifier Trivy installé
    if err := a.trivyClient.CheckInstalled(); err != nil {
        return fmt.Errorf("trivy not available: %w", err)
    }
    
    // 2. Préparer config scan
    scanConfig := ScanConfig{
        Severity:    config.Severity,
        SkipDevDeps: config.CustomParams["skip_dev_deps"].(bool),
    }
    
    // 3. Exécuter Trivy
    report, err := a.trivyClient.Scan(pipelineCtx.ProjectPath, scanConfig)
    if err != nil {
        return fmt.Errorf("trivy scan failed: %w", err)
    }
    
    // 4. Convertir en findings
    findings := a.convertTrivyToFindings(report)
    
    // 5. Extraire contexte projet (depuis Contextualization Agent)
    projectContext := ProjectContext{
        Type:         pipelineCtx.AnalysisConfig.ProjectContext.Type,
        Domain:       pipelineCtx.AnalysisConfig.ProjectContext.Domain,
        Frameworks:   extractFrameworks(pipelineCtx.ProjectProfile),
        IsProduction: pipelineCtx.AnalysisConfig.ProjectContext.Criticality != "low",
        HasTests:     pipelineCtx.ProjectProfile.FileTree.HasTests,
        Language:     getPrimaryLanguage(pipelineCtx.ProjectProfile),
    }
    
    // 6. Enrichir avec Ollama
    for i := range findings {
        // Évaluer exploitabilité
        if err := a.assessExploitability(&findings[i], projectContext); err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
        }
        
        // Générer recommendation
        rec, err := a.generateRecommendation(findings[i], projectContext)
        if err != nil {
            rec = fmt.Sprintf("Update to %s", findings[i].FixedVersion)
        }
        findings[i].Recommendation = rec
    }
    
    // 7. Filtrer par risk level (après analyse Ollama)
    filteredFindings := filterByRiskLevel(findings, config.Severity)
    
    // 8. Limiter nombre
    if len(filteredFindings) > config.MaxFindings {
        // Prioriser par CVSS score
        sort.Slice(filteredFindings, func(i, j int) bool {
            return filteredFindings[i].CVSS > filteredFindings[j].CVSS
        })
        filteredFindings = filteredFindings[:config.MaxFindings]
    }
    
    // 9. Injecter dans pipeline
    pipelineCtx.Findings = append(pipelineCtx.Findings, filteredFindings...)
    
    return nil
}
```

## Optimisations

### 1. Cache des scans Trivy

```go
// Trivy a son propre cache intégré
// Forcer mise à jour DB périodiquement
func (c *TrivyClient) UpdateDB() error {
    return exec.Command("trivy", "image", "--download-db-only").Run()
}
```

### 2. Scan incrémental (optionnel)

```go
// Scanner uniquement les dépendances modifiées
func (a *SCAAgent) scanIncremental(lastScan time.Time) {
    // Comparer go.mod/package.json avec version précédente
    // Scanner uniquement nouvelles deps
}
```

### 3. Timeout

```go
func (c *TrivyClient) ScanWithTimeout(projectPath string, timeout time.Duration) (*TrivyReport, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    cmd := exec.CommandContext(ctx, "trivy", "fs", "--format", "json", projectPath)
    output, err := cmd.Output()
    
    if ctx.Err() == context.DeadlineExceeded {
        return nil, fmt.Errorf("trivy scan timeout after %v", timeout)
    }
    
    // ... parse output
}
```

## Tests

### Mock Trivy output

```go
func TestSCAAgent_Execute(t *testing.T) {
    // Mock Trivy client
    mockTrivy := &MockTrivyClient{
        report: &TrivyReport{
            Results: []TrivyResult{
                {
                    Target: "go.mod",
                    Type:   "gomod",
                    Vulnerabilities: []TrivyVulnerability{
                        {
                            VulnerabilityID:  "CVE-2020-28483",
                            PkgName:          "github.com/gin-gonic/gin",
                            InstalledVersion: "v1.7.0",
                            FixedVersion:     "v1.7.7",
                            Severity:         "HIGH",
                            CVSS: map[string]CVSS{
                                "nvd": {V3Score: 7.5},
                            },
                        },
                    },
                },
            },
        },
    }
    
    agent := &SCAAgent{trivyClient: mockTrivy}
    
    // Test execution
    err := agent.Execute(ctx, pipelineCtx)
    assert.NoError(t, err)
    assert.Len(t, pipelineCtx.Findings, 1)
}
```

## Output Exemple

```json
{
  "findings": [
    {
      "id": "sca-f7b3c1a2",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "Directory Traversal in gin-gonic/gin",
      "description": "Gin before v1.7.7 allows directory traversal via ../",
      "package_name": "github.com/gin-gonic/gin",
      "installed_version": "v1.7.0",
      "fixed_version": "v1.7.7",
      "package_type": "gomod",
      "cve": "CVE-2020-28483",
      "cvss": 7.5,
      "cwe": ["CWE-22"],
      "exploitability": "Exploitable if the application uses StaticFS or Static methods with user-controlled paths. Medium confidence based on common usage patterns.",
      "risk_level": "high",
      "recommendation": "**Immediate action**: `go get github.com/gin-gonic/gin@v1.7.7`\n\n**Breaking changes**: None expected, patch release.\n\n**Testing**: Verify static file serving still works after upgrade.\n\n**Alternative**: If upgrade blocked, sanitize all file paths with filepath.Clean() before serving.",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-28483",
        "https://github.com/advisories/GHSA-h395-qcrw-5vmq"
      ],
      "source": "trivy",
      "timestamp": "2025-11-17T10:30:00Z"
    }
  ],
  "dependencies_checked": 42,
  "vulnerable_deps": 3,
  "duration": "2.8s",
  "trivy_version": "0.48.0"
}
```

## Prochaine Étape
Une fois SCA terminé, les findings enrichis par Ollama sont passés à l'**Aggregator Agent** avec ceux de SAST et Secrets.