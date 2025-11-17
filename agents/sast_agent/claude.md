# SAST Agent (Static Application Security Testing)

## Objectif
Analyser le code source pour détecter des vulnérabilités de sécurité en utilisant **Semgrep**. Identifier SQL injection, XSS, command injection, etc., puis enrichir avec Ollama pour validation contextuelle et génération de recommendations.

## Responsabilités

1. **Scan de code source** : Exécuter Semgrep sur le projet
2. **Parsing du rapport** : Extraire les vulnérabilités du JSON Semgrep
3. **Validation contextuelle** : Ollama confirme si vraie vulnérabilité
4. **Enrichissement** : Évaluer la criticité dans le contexte projet
5. **Génération de findings** : Rapports avec CWE, OWASP, recommendations

## Structure

```
internal/agents/sast/
├── claude.md              # Ce fichier
├── sast.go                # Agent principal
├── semgrep/
│   ├── client.go          # Wrapper Semgrep CLI
│   └── parser.go          # Parser JSON Semgrep
├── analyzer/
│   └── validator.go       # Validation via Ollama
└── models.go              # Structures Finding, SemgrepReport
```

## Pourquoi Semgrep ?

✅ **Multi-langages** - 30+ langages (Go, Python, JS, Java, Solidity, etc.)  
✅ **1000+ règles** - SQL injection, XSS, command injection, crypto, etc.  
✅ **AST parsing** - Analyse syntaxique précise, peu de faux positifs  
✅ **Rapide** - Utilise Tree-sitter, scan en quelques secondes  
✅ **Gratuit** - Open source, pas d'API keys  
✅ **Règles custom** - Possibilité d'ajouter ses propres patterns  
✅ **Remplace tout** - Bandit, ESLint Security, Gosec, Brakeman  

## Input/Output

### Input
```go
type Input struct {
    ProjectPath   string
    Languages     []string      // Depuis Profiler
    Config        AgentConfig   // Depuis Contextualization
    // Config contient: Rules, Severity, SkipPatterns, MaxFindings
}
```

### Output
```go
type Finding struct {
    ID            string    // UUID
    Type          string    // "sql-injection", "xss", "command-injection"
    Severity      string    // "low", "medium", "high", "critical"
    Title         string    // "SQL Injection in user query"
    Description   string    // Détails de la vulnérabilité
    FilePath      string    // Chemin du fichier
    LineNumber    int       // Ligne de code
    EndLineNumber int       // Fin du bloc vulnérable
    CodeSnippet   string    // Extrait de code
    Confidence    string    // "low", "medium", "high"
    CWE           string    // "CWE-89"
    OWASP         string    // "A03:2021 – Injection"
    
    // Enrichissement Ollama
    Exploitability string   // Analyse d'exploitabilité
    RiskLevel      string   // Risk ajusté selon contexte
    Recommendation string   // Comment fix
    
    CheckID        string   // ID règle Semgrep
    ValidatedBy    string   // "semgrep" ou "semgrep+ollama"
    Timestamp      time.Time
}

type ScanResult struct {
    Findings      []Finding
    FilesScanned  int
    RulesApplied  int
    Duration      time.Duration
    SemgrepVersion string
}
```

## Installation Semgrep

### Vérification au démarrage

```go
func (a *SASTAgent) checkSemgrepInstalled() error {
    cmd := exec.Command("semgrep", "--version")
    output, err := cmd.Output()
    
    if err != nil {
        return fmt.Errorf("Semgrep not installed. Install with: pip install semgrep")
    }
    
    a.semgrepVersion = parseVersion(string(output))
    return nil
}
```

### Installation automatique (optionnel)

```go
func (a *SASTAgent) installSemgrep() error {
    // Via pip
    return exec.Command("pip3", "install", "semgrep").Run()
}
```

## Exécution de Semgrep

### Commande de base

```go
func (c *SemgrepClient) Scan(projectPath string, config ScanConfig) (*SemgrepReport, error) {
    args := []string{
        "scan",
        "--config", "auto",        // Règles automatiques (p/security-audit)
        "--json",                  // Output JSON
        "--quiet",                 // Pas de logs
    }
    
    // Filtrer par sévérité
    if config.Severity != "" {
        args = append(args, "--severity", mapSeverityToSemgrep(config.Severity))
    }
    
    // Exclude patterns
    for _, pattern := range config.SkipPatterns {
        args = append(args, "--exclude", pattern)
    }
    
    // Règles spécifiques (si config.Rules non vide)
    if len(config.Rules) > 0 {
        // Utiliser rulesets spécifiques au lieu de "auto"
        args[2] = mapRulesToConfig(config.Rules)
    }
    
    // Timeout
    if config.TimeoutSeconds > 0 {
        args = append(args, "--timeout", fmt.Sprintf("%d", config.TimeoutSeconds))
    }
    
    // Cible
    args = append(args, projectPath)
    
    // Exécuter
    cmd := exec.Command("semgrep", args...)
    output, err := cmd.Output()
    if err != nil {
        // Semgrep retourne exit code 1 si findings trouvés
        if exitErr, ok := err.(*exec.ExitError); ok {
            output = exitErr.Stdout
        } else {
            return nil, fmt.Errorf("semgrep scan failed: %w", err)
        }
    }
    
    // Parser JSON
    var report SemgrepReport
    if err := json.Unmarshal(output, &report); err != nil {
        return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
    }
    
    return &report, nil
}
```

### Mapping de sévérité

```go
func mapSeverityToSemgrep(severity string) string {
    // Pipeline config → Semgrep severity
    switch severity {
    case "critical":
        return "ERROR"
    case "high":
        return "ERROR,WARNING"
    case "medium":
        return "ERROR,WARNING,INFO"
    case "low":
        return "ERROR,WARNING,INFO"
    default:
        return "ERROR,WARNING"
    }
}
```

### Mapping de règles

```go
func mapRulesToConfig(rules []string) string {
    // Mapper types de vulns vers rulesets Semgrep
    configs := []string{}
    
    for _, rule := range rules {
        switch rule {
        case "sql-injection":
            configs = append(configs, "p/sql-injection")
        case "xss":
            configs = append(configs, "p/xss")
        case "command-injection":
            configs = append(configs, "p/command-injection")
        case "path-traversal":
            configs = append(configs, "p/path-traversal")
        case "insecure-random":
            configs = append(configs, "p/insecure-randomness")
        case "weak-crypto":
            configs = append(configs, "p/crypto")
        }
    }
    
    if len(configs) == 0 {
        return "auto" // Fallback sur ruleset complet
    }
    
    return strings.Join(configs, ",")
}
```

## Structure JSON Semgrep

### Format de sortie

```go
type SemgrepReport struct {
    Results []SemgrepResult `json:"results"`
    Errors  []SemgrepError  `json:"errors"`
    Paths   SemgrepPaths    `json:"paths"`
    Version string          `json:"version"`
}

type SemgrepResult struct {
    CheckID  string              `json:"check_id"`
    Path     string              `json:"path"`
    Line     int                 `json:"line"`
    Column   int                 `json:"column"`
    EndLine  int                 `json:"end_line"`
    EndColumn int                `json:"end_column"`
    Message  string              `json:"message"`
    Severity string              `json:"severity"` // "ERROR", "WARNING", "INFO"
    Metadata SemgrepMetadata     `json:"metadata"`
    Extra    SemgrepExtra        `json:"extra"`
}

type SemgrepMetadata struct {
    CWE          []string          `json:"cwe"`
    OWASP        []string          `json:"owasp"`
    Category     string            `json:"category"`
    Technology   []string          `json:"technology"`
    Confidence   string            `json:"confidence"`
    Likelihood   string            `json:"likelihood"`
    Impact       string            `json:"impact"`
    Subcategory  []string          `json:"subcategory"`
}

type SemgrepExtra struct {
    Fingerprint string   `json:"fingerprint"`
    Lines       string   `json:"lines"`
    Message     string   `json:"message"`
    Metavars    map[string]interface{} `json:"metavars"`
}

type SemgrepError struct {
    Message  string `json:"message"`
    Path     string `json:"path"`
    Level    string `json:"level"`
}

type SemgrepPaths struct {
    Scanned []string `json:"scanned"`
}
```

## Conversion Semgrep → Finding

```go
func (a *SASTAgent) convertSemgrepToFindings(report *SemgrepReport) []Finding {
    findings := []Finding{}
    
    for _, result := range report.Results {
        // Extraire type de vulnérabilité depuis check_id
        vulnType := extractVulnType(result.CheckID)
        
        // Mapper sévérité
        severity := mapSemgrepSeverity(result.Severity, result.Metadata)
        
        // Extraire CWE et OWASP
        cwe := ""
        if len(result.Metadata.CWE) > 0 {
            cwe = result.Metadata.CWE[0]
        }
        
        owasp := ""
        if len(result.Metadata.OWASP) > 0 {
            owasp = result.Metadata.OWASP[0]
        }
        
        finding := Finding{
            ID:             uuid.New().String(),
            Type:           vulnType,
            Severity:       severity,
            Title:          extractTitle(result.Message),
            Description:    result.Message,
            FilePath:       result.Path,
            LineNumber:     result.Line,
            EndLineNumber:  result.EndLine,
            CodeSnippet:    result.Extra.Lines,
            Confidence:     mapConfidence(result.Metadata.Confidence),
            CWE:            cwe,
            OWASP:          owasp,
            CheckID:        result.CheckID,
            ValidatedBy:    "semgrep",
            Timestamp:      time.Now(),
        }
        
        findings = append(findings, finding)
    }
    
    return findings
}

func mapSemgrepSeverity(semgrepSev string, metadata SemgrepMetadata) string {
    // Utiliser impact + likelihood si disponible
    if metadata.Impact == "HIGH" && metadata.Likelihood == "HIGH" {
        return "critical"
    }
    
    // Sinon mapper sévérité standard
    switch semgrepSev {
    case "ERROR":
        return "high"
    case "WARNING":
        return "medium"
    case "INFO":
        return "low"
    default:
        return "medium"
    }
}

func extractVulnType(checkID string) string {
    // check_id format: "language.framework.security.category.specific"
    // Ex: "javascript.express.security.audit.xss.template-var-in-href"
    
    if strings.Contains(checkID, "sql-injection") {
        return "sql-injection"
    }
    if strings.Contains(checkID, "xss") || strings.Contains(checkID, "cross-site-scripting") {
        return "xss"
    }
    if strings.Contains(checkID, "command-injection") {
        return "command-injection"
    }
    if strings.Contains(checkID, "path-traversal") {
        return "path-traversal"
    }
    if strings.Contains(checkID, "crypto") {
        return "weak-crypto"
    }
    
    // Default: utiliser category
    return "code-vulnerability"
}
```

## Validation avec Ollama

### Confirmer la vulnérabilité

```go
func (a *SASTAgent) validateWithOllama(finding Finding, projectContext ProjectContext) (bool, error) {
    // Lire contexte élargi (20 lignes autour)
    codeContext, err := extractCodeContext(finding.FilePath, finding.LineNumber, 20)
    if err != nil {
        return true, err // En cas d'erreur, conserver le finding
    }
    
    prompt := fmt.Sprintf(`
You are a security expert. Analyze if this is a REAL security vulnerability or a false positive.

Finding:
- Type: %s
- File: %s
- Line: %d
- Semgrep Rule: %s
- Severity: %s

Vulnerable Code:
%s

Extended Context (20 lines):
%s

Project Context:
- Type: %s
- Domain: %s
- Frameworks: %s

Question: Is this a REAL %s vulnerability that can be exploited?

Consider:
1. Is user input actually involved?
2. Is the input properly validated/sanitized before this point?
3. Is this test code or dead code?
4. Are there security controls (auth, WAF, rate limiting)?
5. Can an attacker actually reach and exploit this code path?

Respond in JSON:
{
  "is_vulnerable": true/false,
  "confidence": "low/medium/high",
  "reasoning": "detailed explanation",
  "risk_level": "low/medium/high/critical",
  "exploitability": "description of how it could be exploited or why it can't be"
}
`,
        finding.Type,
        finding.FilePath,
        finding.LineNumber,
        finding.CheckID,
        finding.Severity,
        finding.CodeSnippet,
        codeContext,
        projectContext.Type,
        projectContext.Domain,
        projectContext.Frameworks,
        finding.Type,
    )
    
    response, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return true, err // Conserver en cas d'erreur
    }
    
    var validation ValidationResult
    if err := json.Unmarshal([]byte(response), &validation); err != nil {
        return true, err
    }
    
    // Enrichir le finding
    finding.Exploitability = validation.Exploitability
    finding.RiskLevel = validation.RiskLevel
    finding.ValidatedBy = "semgrep+ollama"
    
    // Ajuster confidence
    if validation.Confidence == "high" {
        finding.Confidence = "high"
    }
    
    return validation.IsVulnerable, nil
}

type ValidationResult struct {
    IsVulnerable   bool   `json:"is_vulnerable"`
    Confidence     string `json:"confidence"`
    Reasoning      string `json:"reasoning"`
    RiskLevel      string `json:"risk_level"`
    Exploitability string `json:"exploitability"`
}
```

### Générer recommendations

```go
func (a *SASTAgent) generateRecommendation(finding Finding) (string, error) {
    prompt := fmt.Sprintf(`
Generate a practical fix recommendation for this security vulnerability.

Vulnerability: %s
File: %s
Line: %d
Code:
%s

CWE: %s
OWASP: %s

Provide:
1. **Root cause**: Why is this vulnerable?
2. **Fix**: Exact code changes needed (with code examples)
3. **Alternative solutions**: Other ways to mitigate
4. **Testing**: How to verify the fix works

Keep it concise and actionable. Use markdown format with code blocks.
`,
        finding.Type,
        finding.FilePath,
        finding.LineNumber,
        finding.CodeSnippet,
        finding.CWE,
        finding.OWASP,
    )
    
    recommendation, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        // Fallback sur recommendation générique
        return generateGenericRecommendation(finding), nil
    }
    
    return recommendation, nil
}

func generateGenericRecommendation(finding Finding) string {
    recommendations := map[string]string{
        "sql-injection":      "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
        "xss":                "Sanitize user input and use proper output encoding. Consider using a templating engine with auto-escaping.",
        "command-injection":  "Avoid executing shell commands with user input. Use language APIs instead of shell commands.",
        "path-traversal":     "Validate and sanitize file paths. Use allowlists and reject paths with '../'.",
        "weak-crypto":        "Use strong cryptographic algorithms (AES-256, SHA-256). Avoid MD5, SHA-1, DES.",
    }
    
    if rec, ok := recommendations[finding.Type]; ok {
        return rec
    }
    
    return "Review and fix the security issue according to best practices."
}
```

## Implémentation

### sast.go

```go
package sast

type SASTAgent struct {
    semgrepClient *SemgrepClient
    ollamaClient  *ollama.Client
}

func New(ollamaClient *ollama.Client) *SASTAgent {
    return &SASTAgent{
        semgrepClient: NewSemgrepClient(),
        ollamaClient:  ollamaClient,
    }
}

func (a *SASTAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    config := pipelineCtx.AnalysisConfig.AgentConfigs["sast"]
    
    // 1. Vérifier Semgrep installé
    if err := a.semgrepClient.CheckInstalled(); err != nil {
        return fmt.Errorf("semgrep not available: %w", err)
    }
    
    // 2. Préparer config scan
    scanConfig := ScanConfig{
        Severity:       config.Severity,
        Rules:          config.Rules,
        SkipPatterns:   config.SkipPatterns,
        TimeoutSeconds: 300,
    }
    
    // 3. Exécuter Semgrep
    report, err := a.semgrepClient.Scan(pipelineCtx.ProjectPath, scanConfig)
    if err != nil {
        return fmt.Errorf("semgrep scan failed: %w", err)
    }
    
    // 4. Convertir en findings
    findings := a.convertSemgrepToFindings(report)
    
    // 5. Extraire contexte projet
    projectContext := ProjectContext{
        Type:       pipelineCtx.AnalysisConfig.ProjectContext.Type,
        Domain:     pipelineCtx.AnalysisConfig.ProjectContext.Domain,
        Frameworks: extractFrameworks(pipelineCtx.ProjectProfile),
    }
    
    // 6. Valider avec Ollama (réduire faux positifs)
    validatedFindings := []Finding{}
    
    for _, finding := range findings {
        // Skip validation si confiance déjà haute
        if finding.Confidence == "high" {
            validatedFindings = append(validatedFindings, finding)
            continue
        }
        
        // Valider avec Ollama
        isVuln, err := a.validateWithOllama(finding, projectContext)
        if err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
            validatedFindings = append(validatedFindings, finding)
            continue
        }
        
        if isVuln {
            validatedFindings = append(validatedFindings, finding)
        }
    }
    
    // 7. Générer recommendations
    for i := range validatedFindings {
        rec, err := a.generateRecommendation(validatedFindings[i])
        if err != nil {
            rec = generateGenericRecommendation(validatedFindings[i])
        }
        validatedFindings[i].Recommendation = rec
    }
    
    // 8. Filtrer par risk level
    filteredFindings := filterByRiskLevel(validatedFindings, config.Severity)
    
    // 9. Limiter nombre
    if len(filteredFindings) > config.MaxFindings {
        // Prioriser par severity
        sort.Slice(filteredFindings, func(i, j int) bool {
            return severityWeight(filteredFindings[i].Severity) > 
                   severityWeight(filteredFindings[j].Severity)
        })
        filteredFindings = filteredFindings[:config.MaxFindings]
    }
    
    // 10. Injecter dans pipeline
    pipelineCtx.Findings = append(pipelineCtx.Findings, filteredFindings...)
    
    return nil
}
```

## Règles Semgrep Disponibles

### Rulesets par défaut (avec `--config auto`)

- **p/security-audit** : Règles de sécurité générales
- **p/owasp-top-ten** : OWASP Top 10
- **p/cwe-top-25** : CWE Top 25

### Rulesets spécifiques

- **p/sql-injection** : SQL injection
- **p/xss** : Cross-site scripting
- **p/command-injection** : Command injection
- **p/path-traversal** : Path traversal
- **p/crypto** : Crypto issues
- **p/jwt** : JWT vulnerabilities
- **p/insecure-transport** : HTTP instead of HTTPS
- **p/default-passwords** : Hardcoded credentials

## Tests

### Mock Semgrep output

```go
func TestSASTAgent_Execute(t *testing.T) {
    mockSemgrep := &MockSemgrepClient{
        report: &SemgrepReport{
            Results: []SemgrepResult{
                {
                    CheckID:  "go.lang.security.audit.sqli.sql-injection",
                    Path:     "handlers/user.go",
                    Line:     42,
                    EndLine:  42,
                    Message:  "SQL injection vulnerability",
                    Severity: "ERROR",
                    Metadata: SemgrepMetadata{
                        CWE:   []string{"CWE-89"},
                        OWASP: []string{"A03:2021"},
                    },
                    Extra: SemgrepExtra{
                        Lines: "db.Query(\"SELECT * FROM users WHERE id = \" + userId)",
                    },
                },
            },
        },
    }
    
    agent := &SASTAgent{semgrepClient: mockSemgrep}
    
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
      "id": "sast-abc123",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection via string concatenation",
      "description": "Detected SQL statement that is tainted by user input",
      "file_path": "handlers/user.go",
      "line_number": 42,
      "end_line_number": 42,
      "code_snippet": "db.Query(\"SELECT * FROM users WHERE id = \" + userId)",
      "confidence": "high",
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection",
      "exploitability": "High risk: userId comes directly from HTTP request without validation. Attacker can inject arbitrary SQL.",
      "risk_level": "critical",
      "recommendation": "**Root cause**: User input concatenated directly into SQL query.\n\n**Fix**: Use parameterized query:\n```go\ndb.Query(\"SELECT * FROM users WHERE id = ?\", userId)\n```\n\n**Alternative**: Use an ORM like GORM with safe query builders.\n\n**Testing**: Try SQL injection payloads like `1 OR 1=1` to verify fix.",
      "check_id": "go.lang.security.audit.sqli.sql-injection",
      "validated_by": "semgrep+ollama",
      "timestamp": "2025-11-17T10:30:00Z"
    }
  ],
  "files_scanned": 142,
  "rules_applied": 856,
  "duration": "8.3s",
  "semgrep_version": "1.45.0"
}
```

## Prochaine Étape
Une fois SAST terminé avec Semgrep + Ollama, les findings sont passés à l'**Aggregator Agent** avec ceux de SCA et Secrets.