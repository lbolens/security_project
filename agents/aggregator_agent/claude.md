# Aggregator Agent

## Objectif
Consolider les findings des trois agents d'analyse (SAST, SCA, Secrets), éliminer les duplicatas, prioriser par criticité, et préparer un rapport structuré pour les agents suivants (Remediation et Report).

## Responsabilités

1. **Collecte des findings** : Récupérer tous les findings de SAST, SCA, Secrets
2. **Déduplication** : Identifier et fusionner les findings identiques/similaires
3. **Enrichissement** : Ajouter métadonnées (criticité globale, catégories)
4. **Priorisation** : Trier par sévérité, CVSS, impact business
5. **Catégorisation** : Grouper par type, fichier, composant
6. **Statistiques** : Générer métriques pour dashboard et reporting

## Structure

```
internal/agents/aggregator/
├── claude.md              # Ce fichier
├── aggregator.go          # Agent principal
├── deduplicator/
│   └── dedup.go           # Logique de déduplication
├── prioritizer/
│   └── priority.go        # Calcul de priorité
└── models.go              # Structures AggregatedReport
```

## Input/Output

### Input
```go
type Input struct {
    SASTFindings    []sast.Finding
    SCAFindings     []sca.Finding
    SecretsFindings []secrets.Finding
    ProjectProfile  profiler.ProjectProfile
    ProjectContext  contextualization.ProjectContext
}
```

### Output
```go
type AggregatedReport struct {
    Summary         ReportSummary
    Findings        []ConsolidatedFinding
    Statistics      Statistics
    Timeline        []TimelineEntry
    Metadata        ReportMetadata
}

type ReportSummary struct {
    TotalFindings       int
    CriticalFindings    int
    HighFindings        int
    MediumFindings      int
    LowFindings         int
    
    UniqueFindings      int       // Après déduplication
    DuplicatesRemoved   int
    
    SASTCount           int
    SCACount            int
    SecretsCount        int
    
    FilesAffected       int
    ComponentsAffected  int
    
    AverageCVSS         float64
    RiskScore           float64   // Score global 0-100
}

type ConsolidatedFinding struct {
    ID              string    // UUID unique post-agrégation
    OriginalIDs     []string  // IDs des findings sources
    
    Type            string    // "code-vulnerability", "vulnerable-dependency", "exposed-secret"
    Category        string    // "injection", "crypto", "access-control"
    Severity        string    // "low", "medium", "high", "critical"
    Priority        int       // 1-100 (calculé)
    
    Title           string
    Description     string
    
    // Location
    FilePath        string
    LineNumber      int
    ComponentName   string    // Package/module concerné
    
    // Technical details
    CWE             []string
    OWASP           []string
    CVSS            float64
    CVE             string    // Si applicable
    
    // Business impact
    BusinessImpact  string    // Analyse impact métier
    Exploitability  string
    RiskLevel       string
    
    // Remediation
    Recommendation  string
    FixComplexity   string    // "low", "medium", "high"
    
    // Metadata
    Sources         []string  // ["sast", "sca"] si détecté par plusieurs agents
    Confidence      string    // "low", "medium", "high"
    FirstDetected   time.Time
    Tags            []string
}

type Statistics struct {
    ByCategory      map[string]int  // injection: 5, crypto: 3, etc.
    BySeverity      map[string]int
    BySource        map[string]int
    ByFile          map[string]int
    ByComponent     map[string]int
    
    TopVulnerabilities []VulnerabilityCount
    MostAffectedFiles  []FileCount
    
    CoverageMetrics CoverageMetrics
}

type VulnerabilityCount struct {
    Type  string
    Count int
}

type FileCount struct {
    FilePath string
    Count    int
}

type CoverageMetrics struct {
    FilesScanned     int
    FilesWithIssues  int
    CoveragePercent  float64
    LinesAnalyzed    int
}

type TimelineEntry struct {
    Timestamp   time.Time
    Agent       string
    Action      string
    FindingID   string
    Description string
}

type ReportMetadata struct {
    ProjectName     string
    ScanDate        time.Time
    Duration        time.Duration
    PipelineVersion string
    Agents          []AgentInfo
}

type AgentInfo struct {
    Name     string
    Version  string
    Duration time.Duration
    Status   string
}
```

## Déduplication

### Stratégies de déduplication

#### 1. Déduplication exacte (même finding de plusieurs sources)

Exemple : SAST détecte hardcoded API key + Secrets détecte le même
```go
func (d *Deduplicator) deduplicateExact(findings []Finding) []ConsolidatedFinding {
    fingerprints := make(map[string][]Finding)
    
    for _, finding := range findings {
        // Créer fingerprint unique basé sur : file + line + type
        fp := generateFingerprint(finding)
        fingerprints[fp] = append(fingerprints[fp], finding)
    }
    
    consolidated := []ConsolidatedFinding{}
    for _, group := range fingerprints {
        if len(group) == 1 {
            consolidated = append(consolidated, convertToConsolidated(group[0]))
        } else {
            // Fusionner les findings similaires
            merged := mergeFindings(group)
            consolidated = append(consolidated, merged)
        }
    }
    
    return consolidated
}

func generateFingerprint(finding Finding) string {
    // Normaliser le chemin de fichier
    normalizedPath := normalizeFilePath(finding.FilePath)
    
    // Créer hash unique
    data := fmt.Sprintf("%s:%d:%s", 
        normalizedPath, 
        finding.LineNumber, 
        finding.Type,
    )
    
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

func mergeFindings(findings []Finding) ConsolidatedFinding {
    // Prendre le plus sévère comme base
    sort.Slice(findings, func(i, j int) bool {
        return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
    })
    
    base := findings[0]
    
    consolidated := ConsolidatedFinding{
        ID:          uuid.New().String(),
        OriginalIDs: extractIDs(findings),
        Type:        base.Type,
        Severity:    base.Severity,
        Title:       base.Title,
        Description: mergeDescriptions(findings),
        FilePath:    base.FilePath,
        LineNumber:  base.LineNumber,
        Sources:     extractSources(findings),
        Confidence:  "high", // Multiple sources = high confidence
    }
    
    return consolidated
}
```

#### 2. Déduplication similaire (même vulnérabilité, lignes différentes)

Exemple : SQL injection détectée à plusieurs endroits dans le même fichier
```go
func (d *Deduplicator) deduplicateSimilar(findings []ConsolidatedFinding) []ConsolidatedFinding {
    groups := make(map[string][]ConsolidatedFinding)
    
    for _, finding := range findings {
        // Grouper par : file + type (sans ligne)
        key := fmt.Sprintf("%s:%s", finding.FilePath, finding.Type)
        groups[key] = append(groups[key], finding)
    }
    
    deduplicated := []ConsolidatedFinding{}
    for _, group := range groups {
        if len(group) <= 3 {
            // Peu de findings similaires, garder séparés
            deduplicated = append(deduplicated, group...)
        } else {
            // Beaucoup de findings similaires, grouper
            grouped := groupSimilarFindings(group)
            deduplicated = append(deduplicated, grouped)
        }
    }
    
    return deduplicated
}

func groupSimilarFindings(findings []ConsolidatedFinding) ConsolidatedFinding {
    base := findings[0]
    
    lineNumbers := []int{}
    for _, f := range findings {
        lineNumbers = append(lineNumbers, f.LineNumber)
    }
    
    return ConsolidatedFinding{
        ID:          uuid.New().String(),
        OriginalIDs: extractIDs(findings),
        Type:        base.Type,
        Severity:    base.Severity,
        Title:       fmt.Sprintf("%s (found in %d locations)", base.Title, len(findings)),
        Description: fmt.Sprintf("%s\n\nDetected at lines: %v", base.Description, lineNumbers),
        FilePath:    base.FilePath,
        LineNumber:  lineNumbers[0], // Première occurrence
        Sources:     base.Sources,
        Tags:        []string{"multiple-occurrences"},
    }
}
```

#### 3. Déduplication de dépendances (même CVE, deps transitives)

Exemple : CVE-2023-1234 dans lib X utilisée par deps A, B, C
```go
func (d *Deduplicator) deduplicateDependencies(findings []ConsolidatedFinding) []ConsolidatedFinding {
    cveGroups := make(map[string][]ConsolidatedFinding)
    
    for _, finding := range findings {
        if finding.CVE != "" {
            cveGroups[finding.CVE] = append(cveGroups[finding.CVE], finding)
        }
    }
    
    deduplicated := []ConsolidatedFinding{}
    processed := make(map[string]bool)
    
    for cve, group := range cveGroups {
        if len(group) > 1 {
            // Même CVE, plusieurs dépendances
            merged := mergeDependencyFindings(group)
            deduplicated = append(deduplicated, merged)
            for _, f := range group {
                processed[f.ID] = true
            }
        }
    }
    
    // Ajouter findings non-groupés
    for _, finding := range findings {
        if !processed[finding.ID] {
            deduplicated = append(deduplicated, finding)
        }
    }
    
    return deduplicated
}

func mergeDependencyFindings(findings []ConsolidatedFinding) ConsolidatedFinding {
    base := findings[0]
    
    affectedDeps := []string{}
    for _, f := range findings {
        affectedDeps = append(affectedDeps, f.ComponentName)
    }
    
    return ConsolidatedFinding{
        ID:          uuid.New().String(),
        OriginalIDs: extractIDs(findings),
        Type:        base.Type,
        Severity:    base.Severity,
        Title:       fmt.Sprintf("%s affects %d dependencies", base.CVE, len(findings)),
        Description: fmt.Sprintf("%s\n\nAffected packages: %s", base.Description, strings.Join(affectedDeps, ", ")),
        CVE:         base.CVE,
        CVSS:        base.CVSS,
        ComponentName: strings.Join(affectedDeps, ", "),
        Sources:     []string{"sca"},
        Tags:        []string{"transitive-dependency"},
    }
}
```

## Priorisation

### Calcul de priorité (score 1-100)

```go
func (p *Prioritizer) calculatePriority(finding ConsolidatedFinding, context ProjectContext) int {
    score := 0
    
    // 1. Sévérité de base (0-40 points)
    score += severityScore(finding.Severity)
    
    // 2. CVSS (0-20 points)
    if finding.CVSS > 0 {
        score += int(finding.CVSS * 2)
    }
    
    // 3. Exploitabilité (0-15 points)
    score += exploitabilityScore(finding.Exploitability)
    
    // 4. Contexte projet (0-15 points)
    score += contextScore(finding, context)
    
    // 5. Confiance (0-10 points)
    score += confidenceScore(finding.Confidence, finding.Sources)
    
    // Normaliser à 1-100
    if score > 100 {
        score = 100
    }
    if score < 1 {
        score = 1
    }
    
    return score
}

func severityScore(severity string) int {
    scores := map[string]int{
        "critical": 40,
        "high":     30,
        "medium":   20,
        "low":      10,
    }
    return scores[severity]
}

func exploitabilityScore(exploitability string) int {
    if strings.Contains(strings.ToLower(exploitability), "easily exploitable") {
        return 15
    }
    if strings.Contains(strings.ToLower(exploitability), "exploitable") {
        return 10
    }
    if strings.Contains(strings.ToLower(exploitability), "difficult") {
        return 5
    }
    return 7
}

func contextScore(finding ConsolidatedFinding, context ProjectContext) int {
    score := 0
    
    // Production projects get higher priority
    if context.Criticality == "critical" {
        score += 15
    } else if context.Criticality == "high" {
        score += 10
    } else {
        score += 5
    }
    
    // Finance/Crypto domains get higher priority
    if context.Domain == "finance" || context.Domain == "crypto" {
        score += 5
    }
    
    // Public-facing APIs get higher priority
    if context.Type == "api" && strings.Contains(finding.FilePath, "handler") {
        score += 5
    }
    
    return score
}

func confidenceScore(confidence string, sources []string) int {
    score := 0
    
    // Confidence level
    switch confidence {
    case "high":
        score += 5
    case "medium":
        score += 3
    case "low":
        score += 1
    }
    
    // Multiple sources increase confidence
    if len(sources) > 1 {
        score += 5
    }
    
    return score
}
```

## Catégorisation

### Mapping vers catégories OWASP/CWE

```go
func (a *AggregatorAgent) categorizeFindings(findings []ConsolidatedFinding) {
    for i := range findings {
        findings[i].Category = determineCategory(findings[i])
    }
}

func determineCategory(finding ConsolidatedFinding) string {
    // Map par type
    typeCategories := map[string]string{
        "sql-injection":       "injection",
        "xss":                 "injection",
        "command-injection":   "injection",
        "path-traversal":      "access-control",
        "reentrancy":          "logic-error",
        "integer-overflow":    "numeric-error",
        "weak-crypto":         "cryptography",
        "exposed-secret":      "sensitive-data",
        "vulnerable-dependency": "vulnerable-components",
    }
    
    if category, ok := typeCategories[finding.Type]; ok {
        return category
    }
    
    // Map par CWE
    for _, cwe := range finding.CWE {
        if strings.Contains(cwe, "CWE-89") || strings.Contains(cwe, "CWE-79") {
            return "injection"
        }
        if strings.Contains(cwe, "CWE-22") {
            return "access-control"
        }
        if strings.Contains(cwe, "CWE-327") {
            return "cryptography"
        }
    }
    
    // Map par OWASP
    for _, owasp := range finding.OWASP {
        if strings.Contains(owasp, "A03") {
            return "injection"
        }
        if strings.Contains(owasp, "A02") {
            return "cryptography"
        }
        if strings.Contains(owasp, "A06") {
            return "vulnerable-components"
        }
    }
    
    return "other"
}
```

## Calcul du Risk Score Global

### Score 0-100 pour le projet

```go
func (a *AggregatorAgent) calculateRiskScore(summary ReportSummary, findings []ConsolidatedFinding) float64 {
    if len(findings) == 0 {
        return 0.0
    }
    
    // Weighted by severity
    score := float64(summary.CriticalFindings * 10)
    score += float64(summary.HighFindings * 5)
    score += float64(summary.MediumFindings * 2)
    score += float64(summary.LowFindings * 1)
    
    // Normalize to 0-100
    maxScore := float64(len(findings) * 10)
    normalized := (score / maxScore) * 100
    
    if normalized > 100 {
        normalized = 100
    }
    
    return math.Round(normalized*10) / 10
}
```

## Implémentation

### aggregator.go

```go
package aggregator

type AggregatorAgent struct {
    deduplicator *Deduplicator
    prioritizer  *Prioritizer
}

func New() *AggregatorAgent {
    return &AggregatorAgent{
        deduplicator: NewDeduplicator(),
        prioritizer:  NewPrioritizer(),
    }
}

func (a *AggregatorAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    startTime := time.Now()
    
    // 1. Collecter tous les findings
    allFindings := []Finding{}
    allFindings = append(allFindings, convertSASTFindings(pipelineCtx.Findings)...)
    allFindings = append(allFindings, convertSCAFindings(pipelineCtx.Findings)...)
    allFindings = append(allFindings, convertSecretsFindings(pipelineCtx.Findings)...)
    
    // 2. Déduplication
    deduplicated := a.deduplicator.Deduplicate(allFindings)
    
    // 3. Catégorisation
    a.categorizeFindings(deduplicated)
    
    // 4. Priorisation
    for i := range deduplicated {
        deduplicated[i].Priority = a.prioritizer.calculatePriority(
            deduplicated[i],
            pipelineCtx.AnalysisConfig.ProjectContext,
        )
    }
    
    // 5. Tri par priorité
    sort.Slice(deduplicated, func(i, j int) bool {
        return deduplicated[i].Priority > deduplicated[j].Priority
    })
    
    // 6. Générer statistiques
    stats := a.generateStatistics(deduplicated)
    
    // 7. Générer summary
    summary := a.generateSummary(allFindings, deduplicated, stats)
    
    // 8. Calculer risk score
    summary.RiskScore = a.calculateRiskScore(summary, deduplicated)
    
    // 9. Générer timeline
    timeline := a.generateTimeline(pipelineCtx)
    
    // 10. Créer rapport agrégé
    report := AggregatedReport{
        Summary:    summary,
        Findings:   deduplicated,
        Statistics: stats,
        Timeline:   timeline,
        Metadata: ReportMetadata{
            ProjectName:     pipelineCtx.ProjectProfile.Metadata.ProjectName,
            ScanDate:        time.Now(),
            Duration:        time.Since(startTime),
            PipelineVersion: "1.0.0",
            Agents:          extractAgentInfo(pipelineCtx),
        },
    }
    
    // 11. Injecter dans pipeline context
    pipelineCtx.AggregatedReport = report
    
    return nil
}

func (a *AggregatorAgent) generateStatistics(findings []ConsolidatedFinding) Statistics {
    stats := Statistics{
        ByCategory:  make(map[string]int),
        BySeverity:  make(map[string]int),
        BySource:    make(map[string]int),
        ByFile:      make(map[string]int),
        ByComponent: make(map[string]int),
    }
    
    for _, finding := range findings {
        stats.ByCategory[finding.Category]++
        stats.BySeverity[finding.Severity]++
        stats.ByFile[finding.FilePath]++
        
        if finding.ComponentName != "" {
            stats.ByComponent[finding.ComponentName]++
        }
        
        for _, source := range finding.Sources {
            stats.BySource[source]++
        }
    }
    
    // Top vulnerabilities
    stats.TopVulnerabilities = a.getTopVulnerabilities(findings, 10)
    
    // Most affected files
    stats.MostAffectedFiles = a.getMostAffectedFiles(stats.ByFile, 10)
    
    return stats
}

func (a *AggregatorAgent) generateSummary(original, deduplicated []ConsolidatedFinding, stats Statistics) ReportSummary {
    summary := ReportSummary{
        TotalFindings:     len(original),
        UniqueFindings:    len(deduplicated),
        DuplicatesRemoved: len(original) - len(deduplicated),
    }
    
    // Count by severity
    for severity, count := range stats.BySeverity {
        switch severity {
        case "critical":
            summary.CriticalFindings = count
        case "high":
            summary.HighFindings = count
        case "medium":
            summary.MediumFindings = count
        case "low":
            summary.LowFindings = count
        }
    }
    
    // Count by source
    summary.SASTCount = stats.BySource["sast"]
    summary.SCACount = stats.BySource["sca"]
    summary.SecretsCount = stats.BySource["secrets"]
    
    // Files/Components affected
    summary.FilesAffected = len(stats.ByFile)
    summary.ComponentsAffected = len(stats.ByComponent)
    
    // Average CVSS
    totalCVSS := 0.0
    cvssCount := 0
    for _, finding := range deduplicated {
        if finding.CVSS > 0 {
            totalCVSS += finding.CVSS
            cvssCount++
        }
    }
    if cvssCount > 0 {
        summary.AverageCVSS = totalCVSS / float64(cvssCount)
    }
    
    return summary
}
```

## Output Exemple

```json
{
  "summary": {
    "total_findings": 87,
    "unique_findings": 52,
    "duplicates_removed": 35,
    "critical_findings": 3,
    "high_findings": 12,
    "medium_findings": 28,
    "low_findings": 9,
    "sast_count": 28,
    "sca_count": 18,
    "secrets_count": 6,
    "files_affected": 34,
    "components_affected": 12,
    "average_cvss": 6.8,
    "risk_score": 67.5
  },
  "findings": [
    {
      "id": "agg-001",
      "original_ids": ["sast-abc123", "secrets-xyz789"],
      "type": "exposed-secret",
      "category": "sensitive-data",
      "severity": "critical",
      "priority": 95,
      "title": "AWS Access Key exposed in config",
      "file_path": "config/aws.go",
      "line_number": 12,
      "sources": ["sast", "secrets"],
      "confidence": "high"
    }
  ],
  "statistics": {
    "by_category": {
      "injection": 15,
      "vulnerable-components": 18,
      "sensitive-data": 6,
      "cryptography": 8,
      "access-control": 5
    },
    "by_severity": {
      "critical": 3,
      "high": 12,
      "medium": 28,
      "low": 9
    },
    "top_vulnerabilities": [
      {"type": "sql-injection", "count": 8},
      {"type": "xss", "count": 7}
    ],
    "most_affected_files": [
      {"file_path": "handlers/user.go", "count": 5},
      {"file_path": "api/auth.go", "count": 4}
    ]
  }
}
```

## Prochaine Étape
Une fois l'agrégation terminée, le **Remediation Agent** utilise ce rapport pour générer des suggestions de fix automatiques.