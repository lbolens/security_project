# Remediation Agent

## Objectif
Générer des suggestions de remédiation concrètes et actionnables pour chaque finding consolidé. Utilise Ollama pour créer des fixes de code, des commandes spécifiques, et des plans de remédiation étape par étape adaptés au contexte du projet.

## Responsabilités

1. **Analyse des findings** : Comprendre chaque vulnérabilité dans son contexte
2. **Génération de fixes** : Créer des patches de code concrets
3. **Commandes spécifiques** : Générer commandes CLI pour updates/fixes
4. **Plans d'action** : Créer workflows de remédiation étape par étape
5. **Évaluation de complexité** : Estimer effort/temps de fix
6. **Alternatives** : Proposer plusieurs approches de remédiation

## Structure

```
internal/agents/remediation/
├── claude.md              # Ce fichier
├── remediation.go         # Agent principal
├── generators/
│   ├── code_fix.go        # Génération de patches code
│   ├── command.go         # Génération de commandes
│   └── plan.go            # Génération de plans d'action
├── complexity/
│   └── estimator.go       # Estimation complexité fix
└── models.go              # Structures RemediationPlan
```

## Input/Output

### Input
```go
type Input struct {
    AggregatedReport  aggregator.AggregatedReport
    ProjectProfile    profiler.ProjectProfile
    ProjectContext    contextualization.ProjectContext
}
```

### Output
```go
type RemediationPlan struct {
    FindingID         string
    
    // Fix principal
    PrimaryFix        Fix
    AlternativeFixes  []Fix
    
    // Évaluation
    Complexity        string    // "low", "medium", "high"
    EstimatedTime     string    // "5 minutes", "1 hour", "1 day"
    RequiresExpertise string    // "junior", "mid", "senior"
    BreakingChange    bool
    
    // Plan d'action
    Steps             []RemediationStep
    Prerequisites     []string
    Testing           []TestStep
    
    // Resources
    References        []string
    Documentation     []string
    
    Metadata          RemediationMetadata
}

type Fix struct {
    Type          string    // "code-patch", "dependency-update", "configuration", "removal"
    Description   string
    
    // Code fix
    CodeBefore    string    // Code actuel
    CodeAfter     string    // Code proposé
    FilePath      string
    LineNumber    int
    
    // Dependency update
    Command       string    // "go get package@version"
    PackageName   string
    CurrentVersion string
    TargetVersion string
    
    // Configuration
    ConfigFile    string
    ConfigChanges map[string]interface{}
    
    // Metadata
    Impact        string    // Description de l'impact
    Rationale     string    // Pourquoi ce fix
}

type RemediationStep struct {
    Order         int
    Title         string
    Description   string
    Command       string    // Commande à exécuter
    ExpectedOutput string
    ValidationMethod string
}

type TestStep struct {
    Type          string    // "unit", "integration", "manual"
    Description   string
    Command       string
    ExpectedResult string
}

type RemediationMetadata struct {
    GeneratedAt   time.Time
    Confidence    string    // "low", "medium", "high"
    AutoApplicable bool    // Si le fix peut être appliqué automatiquement
    RiskLevel     string   // Risque du fix lui-même
}
```

## Génération de Fixes avec Ollama

### 1. Code Patches

```go
func (r *RemediationAgent) generateCodeFix(finding aggregator.ConsolidatedFinding, context ProjectContext) (*Fix, error) {
    // Lire le code actuel avec contexte
    codeContext, err := extractCodeContext(finding.FilePath, finding.LineNumber, 30)
    if err != nil {
        return nil, err
    }
    
    prompt := fmt.Sprintf(`
You are a security remediation expert. Generate a specific code fix for this vulnerability.

Vulnerability:
- Type: %s
- Category: %s
- Severity: %s
- File: %s
- Line: %d

Current Code:
%s

CWE: %s
OWASP: %s
Description: %s

Project Context:
- Language: %s
- Framework: %s
- Type: %s

Generate a SPECIFIC, WORKING code fix that:
1. Completely resolves the vulnerability
2. Maintains existing functionality
3. Follows best practices for %s
4. Is production-ready

Respond in JSON:
{
  "code_before": "exact current vulnerable code",
  "code_after": "fixed code with proper escaping/validation",
  "explanation": "why this fix works",
  "impact": "what changes functionally",
  "rationale": "security principles applied",
  "breaking_change": true/false
}

CRITICAL: The code_after must be complete, compilable, working code with proper imports if needed.
`,
        finding.Type,
        finding.Category,
        finding.Severity,
        finding.FilePath,
        finding.LineNumber,
        codeContext,
        strings.Join(finding.CWE, ", "),
        strings.Join(finding.OWASP, ", "),
        finding.Description,
        detectLanguage(finding.FilePath),
        context.Frameworks,
        context.Type,
        detectLanguage(finding.FilePath),
    )
    
    response, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    var fixData struct {
        CodeBefore     string `json:"code_before"`
        CodeAfter      string `json:"code_after"`
        Explanation    string `json:"explanation"`
        Impact         string `json:"impact"`
        Rationale      string `json:"rationale"`
        BreakingChange bool   `json:"breaking_change"`
    }
    
    if err := json.Unmarshal([]byte(response), &fixData); err != nil {
        return nil, err
    }
    
    fix := &Fix{
        Type:        "code-patch",
        Description: fixData.Explanation,
        CodeBefore:  fixData.CodeBefore,
        CodeAfter:   fixData.CodeAfter,
        FilePath:    finding.FilePath,
        LineNumber:  finding.LineNumber,
        Impact:      fixData.Impact,
        Rationale:   fixData.Rationale,
    }
    
    return fix, nil
}
```

### 2. Dependency Updates

```go
func (r *RemediationAgent) generateDependencyFix(finding aggregator.ConsolidatedFinding) (*Fix, error) {
    prompt := fmt.Sprintf(`
Generate specific commands to fix this dependency vulnerability.

Vulnerability:
- Package: %s
- Current Version: %s
- Fixed Version: %s
- CVE: %s
- CVSS: %.1f

Package Manager: %s

Generate:
1. Exact command to update the dependency
2. Command to verify the update
3. Any additional steps needed (rebuild, restart, etc.)

Respond in JSON:
{
  "update_command": "exact command to run",
  "verify_command": "command to verify update worked",
  "additional_steps": ["step 1", "step 2"],
  "breaking_changes": "description of potential breaking changes or 'none expected'",
  "rollback_command": "command to rollback if needed"
}
`,
        finding.ComponentName,
        extractCurrentVersion(finding),
        finding.FixedVersion,
        finding.CVE,
        finding.CVSS,
        detectPackageManager(finding),
    )
    
    response, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    var fixData struct {
        UpdateCommand   string   `json:"update_command"`
        VerifyCommand   string   `json:"verify_command"`
        AdditionalSteps []string `json:"additional_steps"`
        BreakingChanges string   `json:"breaking_changes"`
        RollbackCommand string   `json:"rollback_command"`
    }
    
    json.Unmarshal([]byte(response), &fixData)
    
    fix := &Fix{
        Type:           "dependency-update",
        Description:    fmt.Sprintf("Update %s to version %s", finding.ComponentName, finding.FixedVersion),
        Command:        fixData.UpdateCommand,
        PackageName:    finding.ComponentName,
        CurrentVersion: extractCurrentVersion(finding),
        TargetVersion:  finding.FixedVersion,
        Impact:         fixData.BreakingChanges,
        Rationale:      fmt.Sprintf("Resolves %s with CVSS score %.1f", finding.CVE, finding.CVSS),
    }
    
    return fix, nil
}
```

### 3. Secrets Remediation

```go
func (r *RemediationAgent) generateSecretsRemediation(finding aggregator.ConsolidatedFinding) (*Fix, error) {
    prompt := fmt.Sprintf(`
Generate a complete remediation plan for this exposed secret.

Secret Type: %s
File: %s
Line: %d
In Git History: %v

Project Type: %s

Generate a comprehensive plan:
1. How to revoke/invalidate this specific secret type
2. How to generate a new secret
3. Where to store the new secret (environment variable, vault, secrets manager)
4. Code changes needed to use env variable instead of hardcoded value
5. How to remove from git history if needed
6. Prevention measures (pre-commit hooks, CI/CD checks)

Respond in JSON with detailed steps.
`,
        finding.SecretType,
        finding.FilePath,
        finding.LineNumber,
        finding.CommitHash != "",
        finding.Category,
    )
    
    response, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    // Parse et créer Fix avec steps détaillés
    // ...
}
```

## Génération de Plans d'Action

### Plan étape par étape

```go
func (r *RemediationAgent) generateActionPlan(finding aggregator.ConsolidatedFinding, fix Fix) ([]RemediationStep, error) {
    prompt := fmt.Sprintf(`
Create a detailed, step-by-step remediation plan for a developer to follow.

Vulnerability: %s
Severity: %s
Fix Type: %s

Fix Description:
%s

Project Type: %s

Generate a numbered list of ACTIONABLE steps that a developer can follow.
Each step should be clear, specific, and verifiable.

Include:
1. Preparation steps (backup, branch creation)
2. Implementation steps (code changes, commands)
3. Testing steps (how to verify fix works)
4. Deployment steps (if applicable)
5. Monitoring/validation steps

Respond in JSON:
{
  "steps": [
    {
      "order": 1,
      "title": "Short title",
      "description": "Detailed description",
      "command": "command to run (if applicable)",
      "expected_output": "what to expect",
      "validation": "how to verify this step worked"
    }
  ],
  "estimated_time": "total time estimate",
  "prerequisites": ["prerequisite 1", "prerequisite 2"]
}
`,
        finding.Type,
        finding.Severity,
        fix.Type,
        fix.Description,
        finding.Category,
    )
    
    response, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    var planData struct {
        Steps          []RemediationStep `json:"steps"`
        EstimatedTime  string            `json:"estimated_time"`
        Prerequisites  []string          `json:"prerequisites"`
    }
    
    json.Unmarshal([]byte(response), &planData)
    
    return planData.Steps, nil
}
```

## Évaluation de Complexité

### Estimation automatique

```go
func (e *ComplexityEstimator) estimateComplexity(finding aggregator.ConsolidatedFinding, fix Fix) (string, string, string) {
    complexity := "medium"
    estimatedTime := "30 minutes"
    requiredExpertise := "mid"
    
    // Facteurs de complexité
    factors := []string{}
    
    // Type de fix
    switch fix.Type {
    case "dependency-update":
        complexity = "low"
        estimatedTime = "10 minutes"
        requiredExpertise = "junior"
    case "code-patch":
        if strings.Contains(fix.CodeAfter, "TODO") || len(fix.CodeAfter) > 500 {
            complexity = "high"
            estimatedTime = "2 hours"
            requiredExpertise = "senior"
        }
    case "configuration":
        complexity = "low"
        estimatedTime = "15 minutes"
        requiredExpertise = "junior"
    }
    
    // Sévérité
    if finding.Severity == "critical" {
        // Critical bugs nécessitent plus de tests
        factors = append(factors, "critical-severity")
        if complexity == "low" {
            complexity = "medium"
            estimatedTime = "30 minutes"
        }
    }
    
    // Breaking changes
    if fix.BreakingChange {
        factors = append(factors, "breaking-change")
        complexity = "high"
        estimatedTime = "4 hours"
        requiredExpertise = "senior"
    }
    
    // Localisation (core vs périphérie)
    if strings.Contains(finding.FilePath, "core") || strings.Contains(finding.FilePath, "auth") {
        factors = append(factors, "core-component")
        if complexity == "low" {
            complexity = "medium"
        }
        requiredExpertise = "senior"
    }
    
    // Nombre de lignes affectées
    if fix.CodeAfter != "" && fix.CodeBefore != "" {
        linesBefore := len(strings.Split(fix.CodeBefore, "\n"))
        linesAfter := len(strings.Split(fix.CodeAfter, "\n"))
        diff := abs(linesAfter - linesBefore)
        
        if diff > 20 {
            complexity = "high"
            estimatedTime = "3 hours"
        }
    }
    
    return complexity, estimatedTime, requiredExpertise
}
```

## Génération de Tests

### Tests de validation

```go
func (r *RemediationAgent) generateTests(finding aggregator.ConsolidatedFinding, fix Fix) ([]TestStep, error) {
    prompt := fmt.Sprintf(`
Generate test steps to verify this security fix works correctly.

Vulnerability Type: %s
Fix Type: %s
Language: %s

Fix Description:
%s

Generate:
1. Unit tests to verify the vulnerability is fixed
2. Integration tests if needed
3. Manual testing steps
4. Regression tests to ensure nothing broke

For each test, provide:
- Test type (unit/integration/manual)
- Description of what to test
- Command to run (if automated)
- Expected result

Respond in JSON:
{
  "tests": [
    {
      "type": "unit",
      "description": "Test description",
      "command": "pytest test_file.py::test_function",
      "expected_result": "All tests pass, vulnerability no longer exploitable"
    }
  ]
}
`,
        finding.Type,
        fix.Type,
        detectLanguage(finding.FilePath),
        fix.Description,
    )
    
    response, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    var testData struct {
        Tests []TestStep `json:"tests"`
    }
    
    json.Unmarshal([]byte(response), &testData)
    
    return testData.Tests, nil
}
```

## Génération de Fixes Alternatifs

### Plusieurs approches

```go
func (r *RemediationAgent) generateAlternatives(finding aggregator.ConsolidatedFinding, primaryFix Fix) ([]Fix, error) {
    prompt := fmt.Sprintf(`
The primary fix for this vulnerability is:
%s

Generate 2-3 ALTERNATIVE approaches to fix this same vulnerability.
Each alternative should be a valid, working solution with different trade-offs.

Consider alternatives like:
- Different security libraries
- Different architectural approaches
- Workarounds if upgrade not possible
- Configuration-based fixes vs code changes

For each alternative:
- Describe the approach
- List pros and cons vs primary fix
- Estimate complexity
- Provide code/commands

Respond in JSON with array of alternatives.
`,
        primaryFix.Description,
    )
    
    // Generate and parse alternatives
    // ...
}
```

## Implémentation

### remediation.go

```go
package remediation

type RemediationAgent struct {
    ollamaClient        *ollama.Client
    complexityEstimator *ComplexityEstimator
    codeGenerator       *CodeGenerator
    planGenerator       *PlanGenerator
}

func New(ollamaClient *ollama.Client) *RemediationAgent {
    return &RemediationAgent{
        ollamaClient:        ollamaClient,
        complexityEstimator: NewComplexityEstimator(),
        codeGenerator:       NewCodeGenerator(ollamaClient),
        planGenerator:       NewPlanGenerator(ollamaClient),
    }
}

func (r *RemediationAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    report := pipelineCtx.AggregatedReport
    remediationPlans := []RemediationPlan{}
    
    // Pour chaque finding, générer plan de remédiation
    for _, finding := range report.Findings {
        // 1. Générer fix principal
        primaryFix, err := r.generatePrimaryFix(finding, pipelineCtx.ProjectContext)
        if err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
            continue
        }
        
        // 2. Générer alternatives
        alternatives, _ := r.generateAlternatives(finding, *primaryFix)
        
        // 3. Estimer complexité
        complexity, estimatedTime, expertise := r.complexityEstimator.estimateComplexity(finding, *primaryFix)
        
        // 4. Générer plan d'action
        steps, _ := r.planGenerator.generateActionPlan(finding, *primaryFix)
        
        // 5. Générer tests
        tests, _ := r.generateTests(finding, *primaryFix)
        
        // 6. Collecter references/documentation
        references := r.collectReferences(finding)
        
        // 7. Créer plan complet
        plan := RemediationPlan{
            FindingID:         finding.ID,
            PrimaryFix:        *primaryFix,
            AlternativeFixes:  alternatives,
            Complexity:        complexity,
            EstimatedTime:     estimatedTime,
            RequiresExpertise: expertise,
            BreakingChange:    primaryFix.BreakingChange,
            Steps:             steps,
            Testing:           tests,
            References:        references,
            Metadata: RemediationMetadata{
                GeneratedAt:    time.Now(),
                Confidence:     estimateConfidence(*primaryFix),
                AutoApplicable: isAutoApplicable(*primaryFix),
                RiskLevel:      estimateFixRisk(*primaryFix),
            },
        }
        
        remediationPlans = append(remediationPlans, plan)
    }
    
    // Injecter dans pipeline context
    pipelineCtx.RemediationPlans = remediationPlans
    
    return nil
}

func (r *RemediationAgent) generatePrimaryFix(finding aggregator.ConsolidatedFinding, context ProjectContext) (*Fix, error) {
    // Router selon type de finding
    switch finding.Type {
    case "vulnerable-dependency":
        return r.generateDependencyFix(finding)
    case "exposed-secret":
        return r.generateSecretsRemediation(finding)
    default:
        // Code vulnerability
        return r.generateCodeFix(finding, context)
    }
}
```

## Output Exemple

```json
{
  "finding_id": "agg-001",
  "primary_fix": {
    "type": "code-patch",
    "description": "Replace string concatenation with parameterized query",
    "code_before": "db.Query(\"SELECT * FROM users WHERE id = \" + userId)",
    "code_after": "db.Query(\"SELECT * FROM users WHERE id = ?\", userId)",
    "file_path": "handlers/user.go",
    "line_number": 42,
    "impact": "No functional changes, only security improvement",
    "rationale": "Parameterized queries prevent SQL injection by separating SQL code from data"
  },
  "alternative_fixes": [
    {
      "type": "code-patch",
      "description": "Use ORM with safe query builder",
      "code_after": "db.Where(\"id = ?\", userId).First(&user)",
      "impact": "Requires GORM library, more idiomatic Go code",
      "rationale": "ORMs provide built-in protection against SQL injection"
    }
  ],
  "complexity": "low",
  "estimated_time": "10 minutes",
  "requires_expertise": "junior",
  "breaking_change": false,
  "steps": [
    {
      "order": 1,
      "title": "Create feature branch",
      "description": "Create a new branch for this security fix",
      "command": "git checkout -b fix/sql-injection-user-handler",
      "validation": "Confirm branch created with git branch"
    },
    {
      "order": 2,
      "title": "Update query to use parameterization",
      "description": "Replace string concatenation with ? placeholder",
      "command": null,
      "validation": "Code compiles without errors"
    },
    {
      "order": 3,
      "title": "Run tests",
      "description": "Execute unit and integration tests",
      "command": "go test ./handlers/...",
      "expected_output": "All tests pass",
      "validation": "No test failures, coverage maintained"
    },
    {
      "order": 4,
      "title": "Manual testing",
      "description": "Test with SQL injection payloads",
      "command": "curl -X GET 'http://localhost:8080/users/1%20OR%201=1'",
      "expected_output": "Returns error or empty result, not all users",
      "validation": "Injection attempts are blocked"
    },
    {
      "order": 5,
      "title": "Commit and push",
      "description": "Commit fix with clear message",
      "command": "git commit -m 'fix: prevent SQL injection in user handler' && git push",
      "validation": "Changes pushed to remote"
    }
  ],
  "testing": [
    {
      "type": "unit",
      "description": "Test that parameterized query works correctly",
      "command": "go test -run TestGetUserByID",
      "expected_result": "Test passes, correct user returned"
    },
    {
      "type": "manual",
      "description": "Attempt SQL injection with malicious input",
      "command": "curl 'http://localhost:8080/users/1%27%20OR%20%271%27=%271'",
      "expected_result": "Returns error or single user, not all users"
    }
  ],
  "references": [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
    "https://golang.org/pkg/database/sql/"
  ],
  "metadata": {
    "generated_at": "2025-11-17T10:30:00Z",
    "confidence": "high",
    "auto_applicable": true,
    "risk_level": "low"
  }
}
```

## Prochaine Étape
Une fois les plans de remédiation générés, le **Report Agent** crée le rapport final en JSON/HTML/PDF avec tous les findings et leurs plans de fix.