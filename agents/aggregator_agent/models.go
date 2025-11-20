package main

type AggregateInput struct {
	SASTFindings    []map[string]interface{} `json:"sast_findings"`
	SCAFindings     []map[string]interface{} `json:"sca_findings"`
	SecretsFindings []map[string]interface{} `json:"secrets_findings"`
	ProjectProfile  map[string]interface{}   `json:"project_profile"`
	ProjectContext  map[string]interface{}   `json:"project_context"`
	Config          AggregateConfig          `json:"config"`
}

type AggregateConfig struct {
	EnableDeduplication   bool   `json:"enable_deduplication"`
	DedupStrategy         string `json:"dedup_strategy"`
	MinConfidence         string `json:"min_confidence"`
	GroupSimilarFindings  bool   `json:"group_similar_findings"`
	SimilarityThreshold   int    `json:"similarity_threshold"`
}

type AggregateOutput struct {
	Summary    Summary               `json:"summary"`
	Findings   []ConsolidatedFinding `json:"findings"`
	Statistics Statistics            `json:"statistics"`
	Timeline   []TimelineEntry       `json:"timeline"`
	Metadata   Metadata              `json:"metadata"`
}

type Summary struct {
	TotalFindings      int     `json:"total_findings"`
	UniqueFindings     int     `json:"unique_findings"`
	DuplicatesRemoved  int     `json:"duplicates_removed"`
	CriticalFindings   int     `json:"critical_findings"`
	HighFindings       int     `json:"high_findings"`
	MediumFindings     int     `json:"medium_findings"`
	LowFindings        int     `json:"low_findings"`
	SASTCount          int     `json:"sast_count"`
	SCACount           int     `json:"sca_count"`
	SecretsCount       int     `json:"secrets_count"`
	FilesAffected      int     `json:"files_affected"`
	ComponentsAffected int     `json:"components_affected"`
	AverageCVSS        float64 `json:"average_cvss"`
	RiskScore          float64 `json:"risk_score"`
}

type ConsolidatedFinding struct {
	ID             string   `json:"id"`
	OriginalIDs    []string `json:"original_ids"`
	Type           string   `json:"type"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Priority       int      `json:"priority"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	FilePath       string   `json:"file_path"`
	LineNumber     int      `json:"line_number"`
	ComponentName  string   `json:"component_name"`
	CWE            []string `json:"cwe"`
	OWASP          []string `json:"owasp"`
	CVSS           float64  `json:"cvss"`
	CVE            string   `json:"cve"`
	BusinessImpact string   `json:"business_impact"`
	Exploitability string   `json:"exploitability"`
	RiskLevel      string   `json:"risk_level"`
	Recommendation string   `json:"recommendation"`
	FixComplexity  string   `json:"fix_complexity"`
	Sources        []string `json:"sources"`
	Confidence     string   `json:"confidence"`
	FirstDetected  string   `json:"first_detected"`
	Tags           []string `json:"tags"`
}

type Statistics struct {
	ByCategory         map[string]int      `json:"by_category"`
	BySeverity         map[string]int      `json:"by_severity"`
	BySource           map[string]int      `json:"by_source"`
	ByFile             map[string]int      `json:"by_file"`
	ByComponent        map[string]int      `json:"by_component"`
	TopVulnerabilities []VulnerabilityCount `json:"top_vulnerabilities"`
	MostAffectedFiles  []FileCount          `json:"most_affected_files"`
	CoverageMetrics    CoverageMetrics      `json:"coverage_metrics"`
}

type VulnerabilityCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type FileCount struct {
	FilePath string `json:"file_path"`
	Count    int    `json:"count"`
}

type CoverageMetrics struct {
	FilesScanned    int     `json:"files_scanned"`
	FilesWithIssues int     `json:"files_with_issues"`
	CoveragePercent float64 `json:"coverage_percent"`
	LinesAnalyzed   int     `json:"lines_analyzed"`
}

type TimelineEntry struct {
	Timestamp   string `json:"timestamp"`
	Agent       string `json:"agent"`
	Action      string `json:"action"`
	FindingID   string `json:"finding_id"`
	Description string `json:"description"`
}

type Metadata struct {
	ProjectName     string      `json:"project_name"`
	ScanDate        string      `json:"scan_date"`
	DurationMS      int64       `json:"duration_ms"`
	PipelineVersion string      `json:"pipeline_version"`
	Agents          []AgentInfo `json:"agents"`
}

type AgentInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"`
}

type DeduplicateInput struct {
	Findings []map[string]interface{} `json:"findings"`
	Strategy string                   `json:"strategy"`
}

type DeduplicationOutput struct {
	DeduplicatedFindings []ConsolidatedFinding `json:"deduplicated_findings"`
	DuplicatesRemoved    int                   `json:"duplicates_removed"`
	DedupGroups          []DedupGroup          `json:"dedup_groups"`
}

type DedupGroup struct {
	Fingerprint string `json:"fingerprint"`
	Count       int    `json:"count"`
	MergedInto  string `json:"merged_into"`
}

type PriorityInput struct {
	Finding        map[string]interface{} `json:"finding"`
	ProjectContext map[string]interface{} `json:"project_context"`
}

type PriorityOutput struct {
	Priority       int            `json:"priority"`
	ScoreBreakdown ScoreBreakdown `json:"score_breakdown"`
}

type ScoreBreakdown struct {
	SeverityScore       int `json:"severity_score"`
	CVSSScore           int `json:"cvss_score"`
	ExploitabilityScore int `json:"exploitability_score"`
	ContextScore        int `json:"context_score"`
	ConfidenceScore     int `json:"confidence_score"`
}

type RiskScoreInput struct {
	Findings []map[string]interface{} `json:"findings"`
}

type RiskScoreOutput struct {
	RiskScore float64           `json:"risk_score"`
	RiskLevel string            `json:"risk_level"`
	Breakdown RiskScoreBreakdown `json:"breakdown"`
}

type RiskScoreBreakdown struct {
	CriticalImpact float64 `json:"critical_impact"`
	HighImpact     float64 `json:"high_impact"`
	MediumImpact   float64 `json:"medium_impact"`
	LowImpact      float64 `json:"low_impact"`
}

type StatisticsInput struct {
	Findings []map[string]interface{} `json:"findings"`
	TopN     int                      `json:"top_n"`
}

type StatisticsOutput struct {
	Statistics Statistics `json:"statistics"`
}
