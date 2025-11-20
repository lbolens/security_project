package types

import "time"

// Input/Output structures

type ReportInput struct {
	AggregatedReport AggregatedReport  `json:"aggregated_report"`
	RemediationPlans []RemediationPlan `json:"remediation_plans"`
	ProjectProfile   ProjectProfile    `json:"project_profile"`
	ProjectContext   ProjectContext    `json:"project_context"`
	Config           ReportConfig      `json:"config"`
}

type ReportConfig struct {
	Formats                  []string `json:"formats"`
	OutputDir                string   `json:"output_dir"`
	IncludeExecutiveSummary  bool     `json:"include_executive_summary"`
	IncludeComplianceMapping bool     `json:"include_compliance_mapping"`
	IncludeVisualizations    bool     `json:"include_visualizations"`
	Theme                    string   `json:"theme"`
}

type ReportOutput struct {
	Reports  map[string]string `json:"reports"` // format -> content (base64 or path)
	Metadata ReportMetadata    `json:"metadata"`
	Summary  ReportSummary     `json:"summary"`
}

type ReportMetadata struct {
	GeneratedAt     time.Time         `json:"generated_at"`
	PipelineVersion string            `json:"pipeline_version"`
	ReportVersion   string            `json:"report_version"`
	ProjectName     string            `json:"project_name"`
	Formats         []string          `json:"formats"`
	FilePaths       map[string]string `json:"file_paths"`
}

type ReportSummary struct {
	TotalFindings    int     `json:"total_findings"`
	RiskScore        float64 `json:"risk_score"`
	RiskLevel        string  `json:"risk_level"`
	FilesGenerated   int     `json:"files_generated"`
	ExecutiveSummary string  `json:"executive_summary,omitempty"`
}

// Shared structures (copied from other agents for standalone usage)

type AggregatedReport struct {
	Summary    Summary    `json:"summary"`
	Findings   []Finding  `json:"findings"`
	Statistics Statistics `json:"statistics"`
}

type Summary struct {
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	HighFindings     int     `json:"high_findings"`
	MediumFindings   int     `json:"medium_findings"`
	LowFindings      int     `json:"low_findings"`
	RiskScore        float64 `json:"risk_score"`
}

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	FilePath    string   `json:"file_path"`
	LineNumber  int      `json:"line_number"`
	Priority    int      `json:"priority"`
	Description string   `json:"description"`
	OWASP       []string `json:"owasp"`
	CWE         []string `json:"cwe"`
}

type Statistics struct {
	ByCategory        map[string]int `json:"by_category"`
	MostAffectedFiles []FileStats    `json:"most_affected_files"`
}

type FileStats struct {
	FilePath string `json:"file_path"`
	Count    int    `json:"count"`
}

type RemediationPlan struct {
	FindingID  string `json:"finding_id"`
	PrimaryFix Fix    `json:"primary_fix"`
}

type Fix struct {
	Command   string `json:"command"`
	CodeAfter string `json:"code_after"`
}

type ProjectProfile struct {
	Metadata ProjectMetadata `json:"metadata"`
}

type ProjectMetadata struct {
	ProjectName string `json:"project_name"`
}

type ProjectContext struct {
	// Add fields as needed
}

// Internal Report Data (used by formatters)

type ReportData struct {
	AggregatedReport AggregatedReport
	RemediationPlans []RemediationPlan
	ProjectProfile   ProjectProfile
	ProjectContext   ProjectContext
	Compliance       ComplianceMapping
	ExecutiveSummary string
}

type ComplianceMapping struct {
	OWASP           map[string][]string `json:"owasp"`
	CWE             map[string][]string `json:"cwe"`
	PCIDSS          map[string][]string `json:"pci_dss"`
	ISO27001        map[string][]string `json:"iso_27001"`
	ComplianceScore float64             `json:"compliance_score"`
}

type RiskScore struct {
	Overall   float64       `json:"overall"`
	Level     string        `json:"level"`
	Breakdown RiskBreakdown `json:"breakdown"`
	Trend     string        `json:"trend"`
}

type RiskBreakdown struct {
	CodeVulnerabilities    float64 `json:"code_vulnerabilities"`
	VulnerableDependencies float64 `json:"vulnerable_dependencies"`
	ExposedSecrets         float64 `json:"exposed_secrets"`
}
