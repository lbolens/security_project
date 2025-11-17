# Report Agent

## Objectif
Générer des rapports de sécurité professionnels et actionnables dans plusieurs formats (JSON, HTML, PDF, Markdown). Créer des visualisations, dashboards, et rapports exécutifs adaptés à différentes audiences (développeurs, managers, executives).

## Responsabilités

1. **Export JSON** : Format structuré pour intégration CI/CD
2. **Génération HTML** : Rapport interactif avec visualisations
3. **Export PDF** : Rapport professionnel imprimable
4. **Rapport Markdown** : Documentation pour README/wikis
5. **Executive Summary** : Résumé pour management
6. **Developer Report** : Rapport technique détaillé
7. **Compliance Report** : Mapping OWASP/CWE/PCI-DSS

## Structure

```
internal/agents/report/
├── claude.md              # Ce fichier
├── report.go              # Agent principal
├── formatters/
│   ├── json.go            # Export JSON
│   ├── html.go            # Génération HTML
│   ├── pdf.go             # Export PDF
│   └── markdown.go        # Export Markdown
├── templates/
│   ├── executive.html     # Template executive summary
│   ├── technical.html     # Template rapport technique
│   └── developer.html     # Template pour devs
└── models.go              # Structures Report
```

## Input/Output

### Input
```go
type Input struct {
    AggregatedReport  aggregator.AggregatedReport
    RemediationPlans  []remediation.RemediationPlan
    ProjectProfile    profiler.ProjectProfile
    ProjectContext    contextualization.ProjectContext
    PipelineMetadata  PipelineMetadata
}
```

### Output
```go
type ReportOutput struct {
    JSON     []byte    // JSON structuré
    HTML     []byte    // HTML interactif
    PDF      []byte    // PDF professionnel
    Markdown []byte    // Markdown documentation
    
    Metadata ReportMetadata
}

type ReportMetadata struct {
    GeneratedAt       time.Time
    PipelineVersion   string
    ReportVersion     string
    ProjectName       string
    Formats           []string
    FilePaths         map[string]string  // format -> file path
}
```

## Format JSON

### Structure complète

```go
type JSONReport struct {
    Metadata      ReportMetadata              `json:"metadata"`
    Summary       Summary                     `json:"summary"`
    RiskScore     RiskScore                   `json:"risk_score"`
    Findings      []Finding                   `json:"findings"`
    Remediations  []RemediationPlan           `json:"remediations"`
    Statistics    Statistics                  `json:"statistics"`
    Timeline      []TimelineEntry             `json:"timeline"`
    Compliance    ComplianceMapping           `json:"compliance"`
}

type Summary struct {
    TotalFindings       int       `json:"total_findings"`
    CriticalFindings    int       `json:"critical_findings"`
    HighFindings        int       `json:"high_findings"`
    MediumFindings      int       `json:"medium_findings"`
    LowFindings         int       `json:"low_findings"`
    FilesAffected       int       `json:"files_affected"`
    ComponentsAffected  int       `json:"components_affected"`
    AverageCVSS         float64   `json:"average_cvss"`
}

type RiskScore struct {
    Overall       float64            `json:"overall"`        // 0-100
    Level         string             `json:"level"`          // "low", "medium", "high", "critical"
    Breakdown     RiskBreakdown      `json:"breakdown"`
    Trend         string             `json:"trend"`          // "improving", "stable", "worsening"
    Comparison    HistoricalComparison `json:"comparison"`
}

type ComplianceMapping struct {
    OWASP         map[string][]string  `json:"owasp"`          // OWASP category -> finding IDs
    CWE           map[string][]string  `json:"cwe"`            // CWE ID -> finding IDs
    PCIDSS        map[string][]string  `json:"pci_dss"`        // PCI-DSS requirement -> findings
    ISO27001      map[string][]string  `json:"iso_27001"`
    ComplianceScore float64            `json:"compliance_score"` // 0-100
}
```

### Exemple JSON output

```json
{
  "metadata": {
    "generated_at": "2025-11-17T10:30:00Z",
    "pipeline_version": "1.0.0",
    "report_version": "1.0",
    "project_name": "my-api",
    "scan_duration": "45.2s"
  },
  "summary": {
    "total_findings": 52,
    "critical_findings": 3,
    "high_findings": 12,
    "medium_findings": 28,
    "low_findings": 9,
    "files_affected": 34,
    "components_affected": 12,
    "average_cvss": 6.8
  },
  "risk_score": {
    "overall": 67.5,
    "level": "high",
    "breakdown": {
      "code_vulnerabilities": 45.0,
      "vulnerable_dependencies": 15.5,
      "exposed_secrets": 7.0
    },
    "trend": "stable"
  },
  "findings": [...],
  "remediations": [...],
  "statistics": {...},
  "compliance": {
    "owasp": {
      "A03:2021 - Injection": ["agg-001", "agg-005", "agg-012"],
      "A06:2021 - Vulnerable Components": ["agg-020", "agg-021"]
    },
    "cwe": {
      "CWE-89": ["agg-001", "agg-005"],
      "CWE-79": ["agg-012", "agg-013"]
    },
    "compliance_score": 72.5
  }
}
```

## Format HTML

### Structure du rapport HTML

```html
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {ProjectName}</title>
    <style>
        /* Modern, professional styling */
        /* Dark/Light mode support */
        /* Responsive design */
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <!-- Header -->
    <header>
        <h1>Security Scan Report</h1>
        <div class="metadata">
            <span>Project: {ProjectName}</span>
            <span>Date: {ScanDate}</span>
            <span>Risk Score: {RiskScore}/100</span>
        </div>
    </header>
    
    <!-- Executive Summary -->
    <section id="executive-summary">
        <h2>Executive Summary</h2>
        <div class="risk-indicator {RiskLevel}">
            <span class="score">{RiskScore}</span>
            <span class="level">{RiskLevel}</span>
        </div>
        <div class="summary-cards">
            <div class="card critical">
                <h3>{CriticalCount}</h3>
                <p>Critical</p>
            </div>
            <div class="card high">
                <h3>{HighCount}</h3>
                <p>High</p>
            </div>
            <!-- ... -->
        </div>
    </section>
    
    <!-- Charts -->
    <section id="visualizations">
        <h2>Security Overview</h2>
        <div class="charts">
            <canvas id="severityChart"></canvas>
            <canvas id="categoryChart"></canvas>
            <canvas id="trendChart"></canvas>
        </div>
    </section>
    
    <!-- Findings Table -->
    <section id="findings">
        <h2>Security Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <!-- Findings rows -->
            </tbody>
        </table>
    </section>
    
    <!-- Remediation Plans -->
    <section id="remediations">
        <h2>Remediation Plans</h2>
        <!-- Expandable remediation cards -->
    </section>
    
    <!-- Statistics -->
    <section id="statistics">
        <h2>Detailed Statistics</h2>
        <!-- Stats tables and charts -->
    </section>
    
    <script>
        // Interactive charts using Chart.js
        // Filtering and sorting
        // Expand/collapse details
    </script>
</body>
</html>
```

### Génération HTML

```go
func (r *ReportAgent) generateHTML(data ReportData) ([]byte, error) {
    // 1. Charger template
    tmpl, err := template.ParseFiles("templates/technical.html")
    if err != nil {
        return nil, err
    }
    
    // 2. Préparer données pour template
    templateData := struct {
        ProjectName    string
        ScanDate       string
        RiskScore      float64
        RiskLevel      string
        Summary        Summary
        Findings       []Finding
        Remediations   []RemediationPlan
        Charts         ChartsData
    }{
        ProjectName: data.ProjectProfile.Metadata.ProjectName,
        ScanDate:    data.Metadata.GeneratedAt.Format("2006-01-02 15:04:05"),
        RiskScore:   data.AggregatedReport.Summary.RiskScore,
        RiskLevel:   determineRiskLevel(data.AggregatedReport.Summary.RiskScore),
        Summary:     data.AggregatedReport.Summary,
        Findings:    data.AggregatedReport.Findings,
        Remediations: data.RemediationPlans,
        Charts:      r.generateChartsData(data),
    }
    
    // 3. Exécuter template
    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, templateData); err != nil {
        return nil, err
    }
    
    return buf.Bytes(), nil
}

func (r *ReportAgent) generateChartsData(data ReportData) ChartsData {
    return ChartsData{
        SeverityChart: ChartData{
            Labels: []string{"Critical", "High", "Medium", "Low"},
            Data: []int{
                data.AggregatedReport.Summary.CriticalFindings,
                data.AggregatedReport.Summary.HighFindings,
                data.AggregatedReport.Summary.MediumFindings,
                data.AggregatedReport.Summary.LowFindings,
            },
            Colors: []string{"#dc3545", "#fd7e14", "#ffc107", "#28a745"},
        },
        CategoryChart: generateCategoryChart(data.AggregatedReport.Statistics),
        TrendChart:    generateTrendChart(data.Timeline),
    }
}
```

## Format PDF

### Utilisation de wkhtmltopdf

```go
func (r *ReportAgent) generatePDF(htmlContent []byte) ([]byte, error) {
    // 1. Sauvegarder HTML temporairement
    tmpHTML := "/tmp/report.html"
    os.WriteFile(tmpHTML, htmlContent, 0644)
    
    // 2. Convertir HTML → PDF avec wkhtmltopdf
    tmpPDF := "/tmp/report.pdf"
    cmd := exec.Command("wkhtmltopdf",
        "--enable-local-file-access",
        "--print-media-type",
        "--page-size", "A4",
        "--margin-top", "10mm",
        "--margin-bottom", "10mm",
        "--margin-left", "10mm",
        "--margin-right", "10mm",
        tmpHTML,
        tmpPDF,
    )
    
    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("PDF generation failed: %w", err)
    }
    
    // 3. Lire PDF
    pdfData, err := os.ReadFile(tmpPDF)
    if err != nil {
        return nil, err
    }
    
    // 4. Cleanup
    os.Remove(tmpHTML)
    os.Remove(tmpPDF)
    
    return pdfData, nil
}
```

### Alternative : Générer PDF natif avec gofpdf

```go
import "github.com/jung-kurt/gofpdf"

func (r *ReportAgent) generatePDFNative(data ReportData) ([]byte, error) {
    pdf := gofpdf.New("P", "mm", "A4", "")
    
    // 1. Page de couverture
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 24)
    pdf.Cell(0, 20, "Security Scan Report")
    pdf.Ln(10)
    pdf.SetFont("Arial", "", 12)
    pdf.Cell(0, 10, fmt.Sprintf("Project: %s", data.ProjectProfile.Metadata.ProjectName))
    pdf.Ln(6)
    pdf.Cell(0, 10, fmt.Sprintf("Date: %s", data.Metadata.GeneratedAt.Format("2006-01-02")))
    
    // 2. Executive Summary
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(0, 10, "Executive Summary")
    pdf.Ln(10)
    
    // Risk Score avec couleur
    riskLevel := determineRiskLevel(data.AggregatedReport.Summary.RiskScore)
    pdf.SetFillColor(getRiskColor(riskLevel))
    pdf.Rect(20, pdf.GetY(), 50, 20, "F")
    pdf.SetFont("Arial", "B", 20)
    pdf.Text(30, pdf.GetY()+14, fmt.Sprintf("%.1f", data.AggregatedReport.Summary.RiskScore))
    
    // 3. Findings Summary
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(0, 10, "Findings Overview")
    pdf.Ln(10)
    
    // Table
    pdf.SetFont("Arial", "B", 12)
    pdf.Cell(60, 10, "Severity")
    pdf.Cell(40, 10, "Count")
    pdf.Ln(10)
    
    pdf.SetFont("Arial", "", 11)
    r.addTableRow(pdf, "Critical", data.AggregatedReport.Summary.CriticalFindings, "#dc3545")
    r.addTableRow(pdf, "High", data.AggregatedReport.Summary.HighFindings, "#fd7e14")
    r.addTableRow(pdf, "Medium", data.AggregatedReport.Summary.MediumFindings, "#ffc107")
    r.addTableRow(pdf, "Low", data.AggregatedReport.Summary.LowFindings, "#28a745")
    
    // 4. Top Findings (page par finding)
    for i, finding := range data.AggregatedReport.Findings[:min(10, len(data.AggregatedReport.Findings))] {
        pdf.AddPage()
        r.renderFinding(pdf, finding, i+1)
    }
    
    // 5. Output
    var buf bytes.Buffer
    if err := pdf.Output(&buf); err != nil {
        return nil, err
    }
    
    return buf.Bytes(), nil
}
```

## Format Markdown

### Rapport pour README/Wiki

```go
func (r *ReportAgent) generateMarkdown(data ReportData) ([]byte, error) {
    var md strings.Builder
    
    // Header
    md.WriteString(fmt.Sprintf("# Security Scan Report - %s\n\n", data.ProjectProfile.Metadata.ProjectName))
    md.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", data.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
    md.WriteString(fmt.Sprintf("**Risk Score:** %.1f/100 (%s)\n\n", 
        data.AggregatedReport.Summary.RiskScore,
        determineRiskLevel(data.AggregatedReport.Summary.RiskScore)))
    
    // Executive Summary
    md.WriteString("## Executive Summary\n\n")
    md.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", data.AggregatedReport.Summary.TotalFindings))
    md.WriteString(fmt.Sprintf("- **Critical:** %d\n", data.AggregatedReport.Summary.CriticalFindings))
    md.WriteString(fmt.Sprintf("- **High:** %d\n", data.AggregatedReport.Summary.HighFindings))
    md.WriteString(fmt.Sprintf("- **Medium:** %d\n", data.AggregatedReport.Summary.MediumFindings))
    md.WriteString(fmt.Sprintf("- **Low:** %d\n\n", data.AggregatedReport.Summary.LowFindings))
    
    // Top Findings
    md.WriteString("## Top 10 Critical/High Findings\n\n")
    
    topFindings := filterByPriority(data.AggregatedReport.Findings, 10)
    for i, finding := range topFindings {
        md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Title))
        md.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(finding.Severity)))
        md.WriteString(fmt.Sprintf("- **Category:** %s\n", finding.Category))
        md.WriteString(fmt.Sprintf("- **Location:** `%s:%d`\n", finding.FilePath, finding.LineNumber))
        md.WriteString(fmt.Sprintf("- **Priority:** %d/100\n\n", finding.Priority))
        md.WriteString(fmt.Sprintf("%s\n\n", finding.Description))
        
        // Quick fix
        if rem := findRemediationPlan(data.RemediationPlans, finding.ID); rem != nil {
            md.WriteString("**Quick Fix:**\n```\n")
            if rem.PrimaryFix.Command != "" {
                md.WriteString(rem.PrimaryFix.Command + "\n")
            } else if rem.PrimaryFix.CodeAfter != "" {
                md.WriteString(rem.PrimaryFix.CodeAfter + "\n")
            }
            md.WriteString("```\n\n")
        }
        
        md.WriteString("---\n\n")
    }
    
    // Statistics
    md.WriteString("## Statistics\n\n")
    md.WriteString("### By Category\n\n")
    for category, count := range data.AggregatedReport.Statistics.ByCategory {
        md.WriteString(fmt.Sprintf("- **%s:** %d\n", category, count))
    }
    md.WriteString("\n")
    
    md.WriteString("### Most Affected Files\n\n")
    for _, file := range data.AggregatedReport.Statistics.MostAffectedFiles[:min(5, len(data.AggregatedReport.Statistics.MostAffectedFiles))] {
        md.WriteString(fmt.Sprintf("- `%s`: %d findings\n", file.FilePath, file.Count))
    }
    
    return []byte(md.String()), nil
}
```

## Executive Summary (pour Management)

### Rapport non-technique

```go
func (r *ReportAgent) generateExecutiveSummary(data ReportData) ([]byte, error) {
    prompt := fmt.Sprintf(`
Generate an executive summary for management (non-technical audience).

Project: %s
Risk Score: %.1f/100 (%s)
Total Findings: %d
Critical: %d | High: %d | Medium: %d | Low: %d

Key Findings:
%s

Generate a 1-page executive summary in plain English covering:
1. Overall Security Posture (2-3 sentences)
2. Key Risks and Business Impact (bullet points)
3. Recommended Actions (priority order)
4. Timeline Estimate for remediation
5. Comparison to industry benchmarks (if critical > 5, mention high risk)

Keep it concise, use business language (avoid technical jargon).
Format in Markdown.
`,
        data.ProjectProfile.Metadata.ProjectName,
        data.AggregatedReport.Summary.RiskScore,
        determineRiskLevel(data.AggregatedReport.Summary.RiskScore),
        data.AggregatedReport.Summary.TotalFindings,
        data.AggregatedReport.Summary.CriticalFindings,
        data.AggregatedReport.Summary.HighFindings,
        data.AggregatedReport.Summary.MediumFindings,
        data.AggregatedReport.Summary.LowFindings,
        formatTopFindings(data.AggregatedReport.Findings, 5),
    )
    
    summary, err := r.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return nil, err
    }
    
    return []byte(summary), nil
}
```

## Compliance Mapping

### OWASP/CWE/PCI-DSS

```go
func (r *ReportAgent) generateComplianceMapping(findings []Finding) ComplianceMapping {
    mapping := ComplianceMapping{
        OWASP:    make(map[string][]string),
        CWE:      make(map[string][]string),
        PCIDSS:   make(map[string][]string),
        ISO27001: make(map[string][]string),
    }
    
    for _, finding := range findings {
        // OWASP mapping
        for _, owasp := range finding.OWASP {
            mapping.OWASP[owasp] = append(mapping.OWASP[owasp], finding.ID)
        }
        
        // CWE mapping
        for _, cwe := range finding.CWE {
            mapping.CWE[cwe] = append(mapping.CWE[cwe], finding.ID)
        }
        
        // PCI-DSS mapping (basé sur type de vulnérabilité)
        pciRequirements := mapToPCIDSS(finding)
        for _, req := range pciRequirements {
            mapping.PCIDSS[req] = append(mapping.PCIDSS[req], finding.ID)
        }
        
        // ISO 27001 mapping
        isoControls := mapToISO27001(finding)
        for _, control := range isoControls {
            mapping.ISO27001[control] = append(mapping.ISO27001[control], finding.ID)
        }
    }
    
    // Calculer score de compliance
    mapping.ComplianceScore = calculateComplianceScore(findings)
    
    return mapping
}

func mapToPCIDSS(finding Finding) []string {
    requirements := []string{}
    
    switch finding.Category {
    case "injection":
        requirements = append(requirements, "6.5.1") // Injection flaws
    case "cryptography":
        requirements = append(requirements, "4.1")   // Encryption
        requirements = append(requirements, "8.2.1") // Strong cryptography
    case "access-control":
        requirements = append(requirements, "7.1")   // Access control
    case "sensitive-data":
        requirements = append(requirements, "3.4")   // Protect stored cardholder data
    }
    
    return requirements
}
```

## Implémentation

### report.go

```go
package report

type ReportAgent struct {
    ollamaClient *ollama.Client
    formatters   map[string]Formatter
}

type Formatter interface {
    Format(data ReportData) ([]byte, error)
}

func New(ollamaClient *ollama.Client) *ReportAgent {
    return &ReportAgent{
        ollamaClient: ollamaClient,
        formatters: map[string]Formatter{
            "json":     NewJSONFormatter(),
            "html":     NewHTMLFormatter(),
            "pdf":      NewPDFFormatter(),
            "markdown": NewMarkdownFormatter(),
        },
    }
}

func (r *ReportAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    // 1. Préparer données complètes
    reportData := ReportData{
        AggregatedReport: pipelineCtx.AggregatedReport,
        RemediationPlans: pipelineCtx.RemediationPlans,
        ProjectProfile:   pipelineCtx.ProjectProfile,
        ProjectContext:   pipelineCtx.AnalysisConfig.ProjectContext,
        PipelineMetadata: extractPipelineMetadata(pipelineCtx),
    }
    
    // 2. Générer compliance mapping
    compliance := r.generateComplianceMapping(reportData.AggregatedReport.Findings)
    reportData.Compliance = compliance
    
    // 3. Générer executive summary avec Ollama
    execSummary, _ := r.generateExecutiveSummary(reportData)
    reportData.ExecutiveSummary = string(execSummary)
    
    // 4. Générer rapports dans tous les formats
    reports := make(map[string][]byte)
    
    for format, formatter := range r.formatters {
        output, err := formatter.Format(reportData)
        if err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, 
                fmt.Sprintf("Failed to generate %s report: %v", format, err))
            continue
        }
        reports[format] = output
    }
    
    // 5. Sauvegarder rapports
    outputDir := filepath.Join(pipelineCtx.ProjectPath, ".security-scan")
    os.MkdirAll(outputDir, 0755)
    
    filePaths := make(map[string]string)
    for format, data := range reports {
        filename := fmt.Sprintf("security-report-%s.%s", 
            time.Now().Format("20060102-150405"), 
            format)
        filePath := filepath.Join(outputDir, filename)
        
        if err := os.WriteFile(filePath, data, 0644); err != nil {
            pipelineCtx.Errors = append(pipelineCtx.Errors, err.Error())
            continue
        }
        
        filePaths[format] = filePath
    }
    
    // 6. Créer output final
    reportOutput := ReportOutput{
        JSON:     reports["json"],
        HTML:     reports["html"],
        PDF:      reports["pdf"],
        Markdown: reports["markdown"],
        Metadata: ReportMetadata{
            GeneratedAt:     time.Now(),
            PipelineVersion: "1.0.0",
            ReportVersion:   "1.0",
            ProjectName:     reportData.ProjectProfile.Metadata.ProjectName,
            Formats:         []string{"json", "html", "pdf", "markdown"},
            FilePaths:       filePaths,
        },
    }
    
    // 7. Injecter dans pipeline context
    pipelineCtx.ReportOutput = reportOutput
    
    // 8. Afficher résumé dans console
    r.printSummary(reportData, filePaths)
    
    return nil
}

func (r *ReportAgent) printSummary(data ReportData, filePaths map[string]string) {
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("  SECURITY SCAN COMPLETE")
    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("\nProject: %s\n", data.ProjectProfile.Metadata.ProjectName)
    fmt.Printf("Risk Score: %.1f/100 (%s)\n\n", 
        data.AggregatedReport.Summary.RiskScore,
        determineRiskLevel(data.AggregatedReport.Summary.RiskScore))
    
    fmt.Println("Findings Summary:")
    fmt.Printf("  Critical: %d\n", data.AggregatedReport.Summary.CriticalFindings)
    fmt.Printf("  High:     %d\n", data.AggregatedReport.Summary.HighFindings)
    fmt.Printf("  Medium:   %d\n", data.AggregatedReport.Summary.MediumFindings)
    fmt.Printf("  Low:      %d\n", data.AggregatedReport.Summary.LowFindings)
    fmt.Printf("  Total:    %d\n\n", data.AggregatedReport.Summary.TotalFindings)
    
    fmt.Println("Reports Generated:")
    for format, path := range filePaths {
        fmt.Printf("  %s: %s\n", strings.ToUpper(format), path)
    }
    fmt.Println("\n" + strings.Repeat("=", 60) + "\n")
}
```

## Output Example Console

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

## Prochaine Étape
Le Report Agent est le dernier de la pipeline ! Tous les agents sont maintenant complets. La pipeline complète est :
**Profiler → Contextualization → [SAST, SCA, Secrets] → Aggregator → Remediation → Report**