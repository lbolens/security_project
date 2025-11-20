package main

type ScanProjectInput struct {
	ProjectPath    string         `json:"project_path"`
	Languages      []string       `json:"languages"`
	Config         AgentConfig    `json:"config"`
	ProjectContext ProjectContext `json:"project_context"`
}

type AgentConfig struct {
	Rules                   []string `json:"rules"`
	Severity                string   `json:"severity"`
	SkipPatterns            []string `json:"skip_patterns"`
	MaxFindings             int      `json:"max_findings"`
	ValidateWithOllama      bool     `json:"validate_with_ollama"`
	GenerateRecommendations bool     `json:"generate_recommendations"`
	ConfidenceThreshold     string   `json:"confidence_threshold"`
	TimeoutSeconds          int      `json:"timeout_seconds"`
}

type ProjectContext struct {
	Type       string   `json:"type"`
	Domain     string   `json:"domain"`
	Frameworks []string `json:"frameworks"`
}

type Finding struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description,omitempty"`
	FilePath       string `json:"file_path"`
	LineNumber     int    `json:"line_number"`
	EndLineNumber  int    `json:"end_line_number,omitempty"`
	CodeSnippet    string `json:"code_snippet,omitempty"`
	Confidence     string `json:"confidence"`
	CWE            string `json:"cwe,omitempty"`
	OWASP          string `json:"owasp,omitempty"`
	Exploitability string `json:"exploitability,omitempty"`
	RiskLevel      string `json:"risk_level,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	CheckID        string `json:"check_id,omitempty"`
	ValidatedBy    string `json:"validated_by,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
}

type ScanSummary struct {
	FilesScanned       int            `json:"files_scanned"`
	RulesApplied       int            `json:"rules_applied"`
	DurationMs         int64          `json:"duration_ms"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByType     map[string]int `json:"findings_by_type"`
	SemgrepVersion     string         `json:"semgrep_version,omitempty"`
}

type ScanOutput struct {
	Findings    []Finding   `json:"findings"`
	ScanSummary ScanSummary `json:"scan_summary"`
	Errors      []string    `json:"errors,omitempty"`
}

type ValidateFindingInput struct {
	Finding        Finding        `json:"finding"`
	CodeContext    string         `json:"code_context"`
	ProjectContext ProjectContext `json:"project_context"`
}

type ValidationResult struct {
	IsVulnerable   bool   `json:"is_vulnerable"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	RiskLevel      string `json:"risk_level"`
	Exploitability string `json:"exploitability,omitempty"`
}

type GenerateFixRecommendationInput struct {
	Finding Finding `json:"finding"`
}

type GenerateFixRecommendationOutput struct {
	Recommendation string `json:"recommendation"`
}

type GetAvailableRulesetsOutput struct {
	Rulesets []Ruleset `json:"rulesets"`
}

type Ruleset struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RuleCount   int      `json:"rule_count"`
	Languages   []string `json:"languages"`
}

type SemgrepReport struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors"`
	Paths   SemgrepPaths    `json:"paths"`
	Version string          `json:"version"`
}

type SemgrepResult struct {
	CheckID   string       `json:"check_id"`
	Path      string       `json:"path"`
	Line      int          `json:"start"`
	Column    int          `json:"start_col"`
	EndLine   int          `json:"end"`
	EndColumn int          `json:"end_col"`
	Extra     SemgrepExtra `json:"extra"`
}

type SemgrepMetadata struct {
	CWE         []string `json:"cwe"`
	OWASP       []string `json:"owasp"`
	Category    string   `json:"category"`
	Technology  []string `json:"technology"`
	Confidence  string   `json:"confidence"`
	Likelihood  string   `json:"likelihood"`
	Impact      string   `json:"impact"`
	Subcategory []string `json:"subcategory"`
}

type SemgrepExtra struct {
	Fingerprint string                 `json:"fingerprint"`
	Lines       string                 `json:"lines"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Metadata    SemgrepMetadata        `json:"metadata"`
	Metavars    map[string]interface{} `json:"metavars"`
}

type SemgrepError struct {
	Message string `json:"message"`
	Path    string `json:"path"`
	Level   string `json:"level"`
}

type SemgrepPaths struct {
	Scanned []string `json:"scanned"`
}

type ScanConfig struct {
	Rules          []string
	Severity       string
	SkipPatterns   []string
	TimeoutSeconds int
}

type OllamaValidation struct {
	IsVulnerable   bool   `json:"is_vulnerable"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	RiskLevel      string `json:"risk_level"`
	Exploitability string `json:"exploitability"`
}
