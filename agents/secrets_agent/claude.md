# Secrets Agent

## Objectif
Détecter les secrets, credentials, et tokens exposés dans le code source en utilisant **Gitleaks**. Identifier API keys, private keys, passwords hardcodés, puis enrichir avec Ollama pour validation et génération de recommendations de remédiation.

## Responsabilités

1. **Scan des secrets** : Exécuter Gitleaks sur le projet (filesystem + git history)
2. **Parsing du rapport** : Extraire les secrets détectés du JSON Gitleaks
3. **Validation contextuelle** : Ollama confirme si c'est un vrai secret actif
4. **Évaluation d'impact** : Déterminer la criticité selon type et contexte
5. **Génération de findings** : Rapports avec recommendations de rotation/révocation

## Structure

```
internal/agents/secrets/
├── claude.md              # Ce fichier
├── secrets.go             # Agent principal
├── gitleaks/
│   ├── client.go          # Wrapper Gitleaks CLI
│   └── parser.go          # Parser JSON Gitleaks
├── analyzer/
│   └── validator.go       # Validation via Ollama
└── models.go              # Structures Finding, GitleaksReport
```

## Pourquoi Gitleaks ?

✅ **Le plus rapide** - Écrit en Go, scan en secondes  
✅ **1000+ patterns** - AWS, GCP, Azure, GitHub, Stripe, etc.  
✅ **Détection entropie** - Trouve secrets custom non-patterns  
✅ **Git history** - Peut scanner commits passés  
✅ **JSON output** - Format structuré et facile à parser  
✅ **Standard industrie** - Utilisé par GitHub, GitLab  
✅ **Gratuit** - Open source, pas d'API keys  

## Input/Output

### Input
```go
type Input struct {
    ProjectPath   string
    Config        AgentConfig  // Depuis Contextualization
    // Config contient: Severity, EntropyThreshold, ScanGitHistory
}
```

### Output
```go
type Finding struct {
    ID              string    // UUID
    Type            string    // "exposed-secret"
    Severity        string    // Toujours "critical" par défaut
    Title           string    // "AWS Access Key exposed in config"
    Description     string    // Détails du secret
    FilePath        string    // Chemin du fichier
    LineNumber      int       // Ligne où le secret apparaît
    
    // Secret info
    SecretType      string    // "aws-access-key", "github-token", "private-key"
    Secret          string    // Secret redacted (premiers/derniers chars)
    Match           string    // Pattern qui a matché
    Entropy         float64   // Score d'entropie (si détection entropie)
    
    // Git info (si scan history)
    CommitHash      string    // Hash du commit
    CommitAuthor    string    // Auteur du commit
    CommitDate      time.Time // Date du commit
    
    // Enrichissement Ollama
    IsActive        bool      // Probable que le secret soit actif
    Impact          string    // Impact si exploité
    Recommendation  string    // Comment remédier
    
    RuleID          string    // ID règle Gitleaks
    Source          string    // "gitleaks"
    Timestamp       time.Time
}

type ScanResult struct {
    Findings         []Finding
    FilesScanned     int
    SecretsFound     int
    Duration         time.Duration
    GitleaksVersion  string
}
```

## Installation Gitleaks

### Vérification au démarrage

```go
func (a *SecretsAgent) checkGitleaksInstalled() error {
    cmd := exec.Command("gitleaks", "version")
    output, err := cmd.Output()
    
    if err != nil {
        return fmt.Errorf("Gitleaks not installed. Install with: brew install gitleaks")
    }
    
    a.gitleaksVersion = parseVersion(string(output))
    return nil
}
```

### Installation automatique (optionnel)

```go
func (a *SecretsAgent) installGitleaks() error {
    switch runtime.GOOS {
    case "darwin":
        return exec.Command("brew", "install", "gitleaks").Run()
    case "linux":
        return exec.Command("sh", "-c",
            "wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz && tar -xzf gitleaks_*.tar.gz && mv gitleaks /usr/local/bin/").Run()
    default:
        return fmt.Errorf("unsupported OS, install manually")
    }
}
```

## Exécution de Gitleaks

### Commande de base (filesystem scan)

```go
func (c *GitleaksClient) ScanFilesystem(projectPath string, config ScanConfig) (*GitleaksReport, error) {
    args := []string{
        "detect",
        "--source", projectPath,
        "--report-format", "json",
        "--report-path", "/tmp/gitleaks-report.json",
        "--no-git",                // Scan filesystem uniquement
    }
    
    // Verbose pour debugging (optionnel)
    if config.Verbose {
        args = append(args, "-v")
    }
    
    // Baseline pour ignorer secrets connus (optionnel)
    if config.BaselinePath != "" {
        args = append(args, "--baseline-path", config.BaselinePath)
    }
    
    // Config custom (optionnel)
    if config.ConfigPath != "" {
        args = append(args, "--config", config.ConfigPath)
    }
    
    // Exécuter
    cmd := exec.Command("gitleaks", args...)
    output, err := cmd.CombinedOutput()
    
    // Gitleaks retourne exit code 1 si secrets trouvés (c'est normal)
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            if exitErr.ExitCode() != 1 {
                return nil, fmt.Errorf("gitleaks failed: %s", output)
            }
        } else {
            return nil, err
        }
    }
    
    // Lire le rapport JSON
    reportData, err := os.ReadFile("/tmp/gitleaks-report.json")
    if err != nil {
        return nil, fmt.Errorf("failed to read gitleaks report: %w", err)
    }
    
    // Parser JSON
    var report GitleaksReport
    if err := json.Unmarshal(reportData, &report); err != nil {
        return nil, fmt.Errorf("failed to parse gitleaks report: %w", err)
    }
    
    return &report, nil
}
```

### Scan git history (optionnel)

```go
func (c *GitleaksClient) ScanGitHistory(projectPath string, config ScanConfig) (*GitleaksReport, error) {
    args := []string{
        "detect",
        "--source", projectPath,
        "--report-format", "json",
        "--report-path", "/tmp/gitleaks-history.json",
        // Pas de --no-git = scan git history
    }
    
    // Limiter profondeur (optionnel)
    if config.MaxDepth > 0 {
        args = append(args, "--log-opts", fmt.Sprintf("--max-count=%d", config.MaxDepth))
    }
    
    cmd := exec.Command("gitleaks", args...)
    // ... même logique que ScanFilesystem
}
```

## Structure JSON Gitleaks

### Format de sortie

```go
type GitleaksReport []GitleaksFinding

type GitleaksFinding struct {
    Description string    `json:"Description"`
    StartLine   int       `json:"StartLine"`
    EndLine     int       `json:"EndLine"`
    StartColumn int       `json:"StartColumn"`
    EndColumn   int       `json:"EndColumn"`
    Match       string    `json:"Match"`
    Secret      string    `json:"Secret"`
    File        string    `json:"File"`
    SymlinkFile string    `json:"SymlinkFile"`
    Commit      string    `json:"Commit"`
    Entropy     float64   `json:"Entropy"`
    Author      string    `json:"Author"`
    Email       string    `json:"Email"`
    Date        string    `json:"Date"`
    Message     string    `json:"Message"`
    Tags        []string  `json:"Tags"`
    RuleID      string    `json:"RuleID"`
    Fingerprint string    `json:"Fingerprint"`
}
```

### Exemple de finding Gitleaks

```json
{
  "Description": "AWS Access Key",
  "StartLine": 12,
  "EndLine": 12,
  "StartColumn": 15,
  "EndColumn": 35,
  "Match": "AKIAIOSFODNN7EXAMPLE",
  "Secret": "AKIAIOSFODNN7EXAMPLE",
  "File": "config/aws.go",
  "Commit": "abc123def456",
  "Entropy": 4.2,
  "Author": "John Doe",
  "Email": "john@example.com",
  "Date": "2023-11-15T10:30:00Z",
  "RuleID": "aws-access-token",
  "Tags": ["key", "AWS"]
}
```

## Conversion Gitleaks → Finding

```go
func (a *SecretsAgent) convertGitleaksToFindings(report *GitleaksReport) []Finding {
    findings := []Finding{}
    
    for _, glFinding := range *report {
        // Déterminer type de secret
        secretType := determineSecretType(glFinding.RuleID, glFinding.Tags)
        
        // Redact secret (garder premiers/derniers chars)
        redactedSecret := redactSecret(glFinding.Secret)
        
        // Parser date commit
        commitDate, _ := time.Parse(time.RFC3339, glFinding.Date)
        
        finding := Finding{
            ID:             uuid.New().String(),
            Type:           "exposed-secret",
            Severity:       "critical", // Toujours critical par défaut
            Title:          fmt.Sprintf("%s exposed in %s", glFinding.Description, glFinding.File),
            Description:    fmt.Sprintf("Detected %s in file %s", glFinding.Description, glFinding.File),
            FilePath:       glFinding.File,
            LineNumber:     glFinding.StartLine,
            SecretType:     secretType,
            Secret:         redactedSecret,
            Match:          glFinding.Match,
            Entropy:        glFinding.Entropy,
            CommitHash:     glFinding.Commit,
            CommitAuthor:   glFinding.Author,
            CommitDate:     commitDate,
            RuleID:         glFinding.RuleID,
            Source:         "gitleaks",
            Timestamp:      time.Now(),
        }
        
        findings = append(findings, finding)
    }
    
    return findings
}

func determineSecretType(ruleID string, tags []string) string {
    typeMap := map[string]string{
        "aws-access-token":        "aws-access-key",
        "github-pat":              "github-token",
        "slack-access-token":      "slack-token",
        "stripe-access-token":     "stripe-key",
        "private-key":             "private-key",
        "generic-api-key":         "api-key",
        "jwt":                     "jwt-token",
    }
    
    if secretType, ok := typeMap[ruleID]; ok {
        return secretType
    }
    
    // Fallback sur tags
    for _, tag := range tags {
        if strings.Contains(strings.ToLower(tag), "key") {
            return "api-key"
        }
    }
    
    return "credential"
}

func redactSecret(secret string) string {
    if len(secret) <= 8 {
        return "***"
    }
    
    // Garder premiers 4 et derniers 4 chars
    return secret[:4] + "***" + secret[len(secret)-4:]
}
```

## Validation avec Ollama

### Confirmer si secret actif

```go
func (a *SecretsAgent) validateWithOllama(finding Finding, projectContext ProjectContext) error {
    // Lire contexte autour du secret
    codeContext, _ := extractCodeContext(finding.FilePath, finding.LineNumber, 10)
    
    prompt := fmt.Sprintf(`
You are a security expert. Analyze if this is a REAL active secret or a false positive.

Secret Detection:
- Type: %s
- File: %s
- Line: %d
- Redacted: %s
- Entropy: %.2f

Code Context:
%s

Project Context:
- Type: %s
- Domain: %s
- Is Production: %v

Question: Is this likely an ACTIVE, REAL secret that poses a security risk?

Consider:
1. Is this a placeholder/example secret? (e.g., "YOUR_API_KEY_HERE", "xxx", "test123")
2. Is this in test/example files?
3. Is this commented out or unused?
4. Does the format match a real %s?
5. Is the entropy high enough to be real?
6. Is this in documentation/README?

Respond in JSON:
{
  "is_active": true/false,
  "confidence": "low/medium/high",
  "reasoning": "detailed explanation",
  "impact": "what happens if this secret is exploited",
  "recommendation": "immediate actions to take"
}
`,
        finding.SecretType,
        finding.FilePath,
        finding.LineNumber,
        finding.Secret,
        finding.Entropy,
        codeContext,
        projectContext.Type,
        projectContext.Domain,
        projectContext.IsProduction,
        finding.SecretType,
    )
    
    response, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return err
    }
    
    var validation SecretValidation
    if err := json.Unmarshal([]byte(response), &validation); err != nil {
        return err
    }
    
    // Enrichir le finding
    finding.IsActive = validation.IsActive
    finding.Impact = validation.Impact
    finding.Recommendation = validation.Recommendation
    
    // Downgrade severity si placeholder
    if !validation.IsActive && validation.Confidence == "high" {
        finding.Severity = "low"
    }
    
    return nil
}

type SecretValidation struct {
    IsActive       bool   `json:"is_active"`
    Confidence     string `json:"confidence"`
    Reasoning      string `json:"reasoning"`
    Impact         string `json:"impact"`
    Recommendation string `json:"recommendation"`
}
```

### Générer recommendations de remédiation

```go
func (a *SecretsAgent) generateRemediation(finding Finding, projectContext ProjectContext) (string, error) {
    prompt := fmt.Sprintf(`
Generate a detailed remediation plan for this exposed secret.

Secret Type: %s
File: %s
Exposed in Git: %v
Commit Hash: %s
Project Type: %s

Provide:
1. **Immediate Actions** (revoke, rotate)
   - Specific steps to revoke this exact secret type
   - How to rotate/generate new secret
2. **Code Fix** (remove from code, use environment variables)
   - Where to store secrets properly (env vars, vault, secrets manager)
   - Code changes needed
3. **Git History** (if exposed in commits)
   - How to remove from git history (git filter-repo, BFG)
   - Warning about public repos
4. **Prevention** (pre-commit hooks, secret scanning CI/CD)
   - Tools to prevent future leaks

Keep it actionable and specific to %s secrets.
Format in markdown with clear sections.
`,
        finding.SecretType,
        finding.FilePath,
        finding.CommitHash != "",
        finding.CommitHash,
        projectContext.Type,
        finding.SecretType,
    )
    
    remediation, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        // Fallback sur recommendation générique
        return generateGenericRemediation(finding), nil
    }
    
    return remediation, nil
}

func generateGenericRemediation(finding Finding) string {
    remediations := map[string]string{
        "aws-access-key": "1. Revoke key in AWS IAM Console\n2. Generate new key\n3. Store in environment variable or AWS Secrets Manager\n4. Remove from code and git history",
        "github-token":   "1. Revoke token at github.com/settings/tokens\n2. Generate new token with minimal scopes\n3. Store in environment variable\n4. Use GitHub Actions secrets for CI/CD",
        "private-key":    "1. Revoke/invalidate the private key\n2. Generate new key pair\n3. Never commit private keys\n4. Use key management services (AWS KMS, HashiCorp Vault)",
        "api-key":        "1. Revoke the API key in the service dashboard\n2. Generate new API key\n3. Store in .env file (gitignored)\n4. Use environment variables in code",
    }
    
    if rem, ok := remediations[finding.SecretType]; ok {
        return rem
    }
    
    return "1. Revoke the exposed secret immediately\n2. Rotate/generate new credentials\n3. Store secrets in environment variables or secret management system\n4. Remove from code and git history"
}
```

## Types de Secrets Détectés

### Patterns Gitleaks (1000+ règles)

**Cloud Providers**
- AWS Access Key, Secret Key
- GCP Service Account, API Key
- Azure Client Secret, Storage Key

**Version Control**
- GitHub Personal Access Token
- GitLab Token
- Bitbucket Token

**Payment**
- Stripe API Key, Secret Key
- PayPal Client ID, Secret
- Square Access Token

**Communication**
- Slack Token, Webhook
- Discord Webhook
- Twilio API Key

**Databases**
- MongoDB Connection String
- PostgreSQL Password
- Redis Password

**Crypto/Blockchain**
- Private Keys (RSA, ECDSA)
- Ethereum Private Keys
- Bitcoin Private Keys
- Mnemonic Phrases

**Generic**
- JWT Tokens
- API Keys (high entropy)
- Passwords (hardcoded)
- OAuth Tokens

## Configuration Custom (Optionnel)

### Fichier .gitleaks.toml

```toml
title = "Custom Gitleaks Config"

[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''(?i)api[_-]?key[_-]?=\s*['"]?([a-zA-Z0-9]{32,})['"]?'''
entropy = 3.5
secretGroup = 1
keywords = ["api_key", "apikey"]

[[rules]]
id = "ethereum-private-key"
description = "Ethereum Private Key"
regex = '''(?i)(0x)?[a-fA-F0-9]{64}'''
entropy = 4.5

[allowlist]
paths = [
  '''node_modules/''',
  '''vendor/''',
  '''\.git/''',
]

stopwords = [
  '''example''',
  '''test''',
  '''dummy''',
  '''placeholder''',
]
```

## Implémentation

### secrets.go

```go
package secrets

type SecretsAgent struct {
    gitleaksClient *GitleaksClient
    ollamaClient   *ollama.Client
}

func New(ollamaClient *ollama.Client) *SecretsAgent {
    return &SecretsAgent{
        gitleaksClient: NewGitleaksClient(),
        ollamaClient:   ollamaClient,
    }
}

func (a *SecretsAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    config := pipelineCtx.AnalysisConfig.AgentConfigs["secrets"]
    
    // 1. Vérifier Gitleaks installé
    if err := a.gitleaksClient.CheckInstalled(); err != nil {
        return fmt.Errorf("gitleaks not available: %w", err)
    }
    
    // 2. Préparer config scan
    scanConfig := ScanConfig{
        EntropyThreshold: config.CustomParams["entropy_threshold"].(float64),
        Verbose:          false,
    }
    
    // 3. Scan filesystem
    report, err := a.gitleaksClient.ScanFilesystem(pipelineCtx.ProjectPath, scanConfig)
    if err != nil {
        return fmt.Errorf("gitleaks scan failed: %w", err)
    }
    
    // 4. Scan git history (optionnel)
    if config.CustomParams["scan_git_history"].(bool) {
        historyReport, err := a.gitleaksClient.ScanGitHistory(pipelineCtx.ProjectPath, scanConfig)
        if err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
        } else {
            *report = append(*report, *historyReport...)
        }
    }
    
    // 5. Convertir en findings
    findings := a.convertGitleaksToFindings(report)
    
    // 6. Extraire contexte projet
    projectContext := ProjectContext{
        Type:         pipelineCtx.AnalysisConfig.ProjectContext.Type,
        Domain:       pipelineCtx.AnalysisConfig.ProjectContext.Domain,
        IsProduction: pipelineCtx.AnalysisConfig.ProjectContext.Criticality != "low",
    }
    
    // 7. Valider avec Ollama
    validatedFindings := []Finding{}
    
    for _, finding := range findings {
        // Valider si secret actif
        if err := a.validateWithOllama(finding, projectContext); err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
            validatedFindings = append(validatedFindings, finding)
            continue
        }
        
        // Garder uniquement secrets actifs
        if finding.IsActive {
            validatedFindings = append(validatedFindings, finding)
        }
    }
    
    // 8. Générer remediations
    for i := range validatedFindings {
        rem, err := a.generateRemediation(validatedFindings[i], projectContext)
        if err != nil {
            rem = generateGenericRemediation(validatedFindings[i])
        }
        validatedFindings[i].Recommendation = rem
    }
    
    // 9. Limiter nombre
    if len(validatedFindings) > config.MaxFindings {
        // Prioriser par type (private keys > api keys > tokens)
        sort.Slice(validatedFindings, func(i, j int) bool {
            return secretTypePriority(validatedFindings[i].SecretType) >
                   secretTypePriority(validatedFindings[j].SecretType)
        })
        validatedFindings = validatedFindings[:config.MaxFindings]
    }
    
    // 10. Injecter dans pipeline
    pipelineCtx.Findings = append(pipelineCtx.Findings, validatedFindings...)
    
    return nil
}

func secretTypePriority(secretType string) int {
    priorities := map[string]int{
        "private-key":    100,
        "aws-access-key": 90,
        "github-token":   80,
        "api-key":        70,
        "jwt-token":      60,
        "credential":     50,
    }
    
    if priority, ok := priorities[secretType]; ok {
        return priority
    }
    return 40
}
```

## Tests

### Mock Gitleaks output

```go
func TestSecretsAgent_Execute(t *testing.T) {
    mockGitleaks := &MockGitleaksClient{
        report: &GitleaksReport{
            {
                Description: "AWS Access Key",
                StartLine:   12,
                File:        "config/aws.go",
                Match:       "AKIAIOSFODNN7EXAMPLE",
                Secret:      "AKIAIOSFODNN7EXAMPLE",
                RuleID:      "aws-access-token",
                Entropy:     4.5,
            },
        },
    }
    
    agent := &SecretsAgent{gitleaksClient: mockGitleaks}
    
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
      "id": "secrets-xyz789",
      "type": "exposed-secret",
      "severity": "critical",
      "title": "AWS Access Key exposed in config/aws.go",
      "description": "Detected AWS Access Key in file config/aws.go",
      "file_path": "config/aws.go",
      "line_number": 12,
      "secret_type": "aws-access-key",
      "secret": "AKIA***MPLE",
      "match": "AKIAIOSFODNN7EXAMPLE",
      "entropy": 4.5,
      "commit_hash": "abc123def456",
      "commit_author": "John Doe",
      "commit_date": "2023-11-15T10:30:00Z",
      "is_active": true,
      "impact": "Full AWS account access. Attacker can create/delete resources, access S3 buckets, databases, etc.",
      "recommendation": "**Immediate Actions**:\n1. Revoke key in AWS IAM Console immediately\n2. Check CloudTrail for unauthorized usage\n3. Generate new access key with principle of least privilege\n\n**Code Fix**:\n```go\n// Before\nconst awsKey = \"AKIAIOSFODNN7EXAMPLE\"\n\n// After\nawsKey := os.Getenv(\"AWS_ACCESS_KEY_ID\")\n```\n\n**Git History**:\n```bash\ngit filter-repo --path config/aws.go --invert-paths\n```\n\n**Prevention**:\n- Add .env to .gitignore\n- Use pre-commit hook with gitleaks\n- Enable AWS Secrets Manager",
      "rule_id": "aws-access-token",
      "source": "gitleaks",
      "timestamp": "2025-11-17T10:30:00Z"
    }
  ],
  "files_scanned": 156,
  "secrets_found": 1,
  "duration": "1.2s",
  "gitleaks_version": "8.18.0"
}
```

## Prochaine Étape
Une fois Secrets terminé, tous les findings (SAST + SCA + Secrets) sont passés à l'**Aggregator Agent** pour consolidation et déduplication.