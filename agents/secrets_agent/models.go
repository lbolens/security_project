package main

type ScanSecretsInput struct {
	ProjectPath    string         `json:"project_path"`
	Config         AgentConfig    `json:"config"`
	ProjectContext ProjectContext `json:"project_context"`
}

type AgentConfig struct {
	Severity          string  `json:"severity"`
	EntropyThreshold  float64 `json:"entropy_threshold"`
	ScanGitHistory    bool    `json:"scan_git_history"`
	MaxDepth          int     `json:"max_depth"`
	MaxFindings       int     `json:"max_findings"`
	ValidateWithOllama bool   `json:"validate_with_ollama"`
	BaselinePath      string  `json:"baseline_path"`
	ConfigPath        string  `json:"config_path"`
}

type ProjectContext struct {
	Type         string `json:"type"`
	Domain       string `json:"domain"`
	IsProduction bool   `json:"is_production"`
}

type Finding struct {
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title,omitempty"`
	Description    string  `json:"description,omitempty"`
	FilePath       string  `json:"file_path"`
	LineNumber     int     `json:"line_number"`
	SecretType     string  `json:"secret_type"`
	Secret         string  `json:"secret"`
	Match          string  `json:"match,omitempty"`
	Entropy        float64 `json:"entropy,omitempty"`
	CommitHash     string  `json:"commit_hash,omitempty"`
	CommitAuthor   string  `json:"commit_author,omitempty"`
	CommitDate     string  `json:"commit_date,omitempty"`
	IsActive       bool    `json:"is_active,omitempty"`
	Impact         string  `json:"impact,omitempty"`
	Recommendation string  `json:"recommendation,omitempty"`
	RuleID         string  `json:"rule_id,omitempty"`
	Source         string  `json:"source,omitempty"`
	Timestamp      string  `json:"timestamp,omitempty"`
}

type ScanSummary struct {
	FilesScanned      int            `json:"files_scanned"`
	SecretsFound      int            `json:"secrets_found"`
	ActiveSecrets     int            `json:"active_secrets"`
	FindingsByType    map[string]int `json:"findings_by_type"`
	DurationMs        int64          `json:"duration_ms"`
	GitleaksVersion   string         `json:"gitleaks_version,omitempty"`
	GitHistoryScanned bool           `json:"git_history_scanned"`
}

type ScanOutput struct {
	Findings    []Finding   `json:"findings"`
	ScanSummary ScanSummary `json:"scan_summary"`
	Errors      []string    `json:"errors,omitempty"`
}

type ValidateSecretInput struct {
	Finding        Finding        `json:"finding"`
	CodeContext    string         `json:"code_context"`
	ProjectContext ProjectContext `json:"project_context"`
}

type SecretValidation struct {
	IsActive       bool   `json:"is_active"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	Impact         string `json:"impact,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type GenerateRemediationInput struct {
	Finding        Finding        `json:"finding"`
	ProjectContext ProjectContext `json:"project_context"`
}

type GenerateRemediationOutput struct {
	Remediation string `json:"remediation"`
}

type ScanGitHistoryInput struct {
	ProjectPath string `json:"project_path"`
	MaxDepth    int    `json:"max_depth"`
}

type ScanGitHistoryOutput struct {
	Findings        []Finding `json:"findings"`
	CommitsScanned  int       `json:"commits_scanned"`
}

type GitleaksReport []GitleaksFinding

type GitleaksFinding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

type ScanConfig struct {
	EntropyThreshold float64
	ScanGitHistory   bool
	MaxDepth         int
	BaselinePath     string
	ConfigPath       string
	Verbose          bool
}
