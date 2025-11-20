package main

type ScanDependenciesInput struct {
	ProjectPath    string         `json:"project_path"`
	Config         AgentConfig    `json:"config"`
	ProjectContext ProjectContext `json:"project_context"`
}

type AgentConfig struct {
	Severity            string `json:"severity"`
	SkipDevDeps         bool   `json:"skip_dev_deps"`
	CheckDirectOnly     bool   `json:"check_direct_only"`
	MaxFindings         int    `json:"max_findings"`
	AssessExploitability bool  `json:"assess_exploitability"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
}

type ProjectContext struct {
	Type         string   `json:"type"`
	Domain       string   `json:"domain"`
	Frameworks   []string `json:"frameworks"`
	IsProduction bool     `json:"is_production"`
	HasTests     bool     `json:"has_tests"`
}

type Finding struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	PackageName      string   `json:"package_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	PackageType      string   `json:"package_type,omitempty"`
	CVE              string   `json:"cve"`
	CVSS             float64  `json:"cvss"`
	CWE              []string `json:"cwe,omitempty"`
	Exploitability   string   `json:"exploitability,omitempty"`
	RiskLevel        string   `json:"risk_level,omitempty"`
	Recommendation   string   `json:"recommendation,omitempty"`
	References       []string `json:"references,omitempty"`
	PublishedDate    string   `json:"published_date,omitempty"`
	Source           string   `json:"source,omitempty"`
	Timestamp        string   `json:"timestamp,omitempty"`
}

type ScanSummary struct {
	DependenciesChecked    int            `json:"dependencies_checked"`
	VulnerableDeps         int            `json:"vulnerable_deps"`
	FindingsBySeverity     map[string]int `json:"findings_by_severity"`
	FindingsByPackageType  map[string]int `json:"findings_by_package_type"`
	DurationMs             int64          `json:"duration_ms"`
	TrivyVersion           string         `json:"trivy_version,omitempty"`
}

type ScanOutput struct {
	Findings    []Finding   `json:"findings"`
	ScanSummary ScanSummary `json:"scan_summary"`
	Errors      []string    `json:"errors,omitempty"`
}

type AssessExploitabilityInput struct {
	Finding        Finding        `json:"finding"`
	ProjectContext ProjectContext `json:"project_context"`
}

type ExploitabilityAssessment struct {
	Exploitable    bool   `json:"exploitable"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	RiskLevel      string `json:"risk_level"`
	AttackScenario string `json:"attack_scenario,omitempty"`
}

type GenerateFixRecommendationInput struct {
	Finding        Finding        `json:"finding"`
	ProjectContext ProjectContext `json:"project_context"`
}

type GenerateFixRecommendationOutput struct {
	Recommendation string `json:"recommendation"`
}

type UpdateTrivyDBOutput struct {
	Success   bool   `json:"success"`
	UpdatedAt string `json:"updated_at,omitempty"`
	DBVersion string `json:"db_version,omitempty"`
}

type TrivyReport struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`
	ArtifactType  string         `json:"ArtifactType"`
	Results       []TrivyResult  `json:"Results"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	Severity         string             `json:"Severity"`
	Title            string             `json:"Title"`
	Description      string             `json:"Description"`
	References       []string           `json:"References"`
	PublishedDate    string             `json:"PublishedDate"`
	LastModifiedDate string             `json:"LastModifiedDate"`
	PrimaryURL       string             `json:"PrimaryURL"`
	CVSS             map[string]CVSSObj `json:"CVSS"`
	CweIDs           []string           `json:"CweIDs"`
}

type CVSSObj struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}

type ScanConfig struct {
	Severity        string
	SkipDevDeps     bool
	CheckDirectOnly bool
	TimeoutSeconds  int
}
