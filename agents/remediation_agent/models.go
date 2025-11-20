package main

type RemediationInput struct {
	AggregatedReport map[string]interface{} `json:"aggregated_report"`
	ProjectProfile   map[string]interface{} `json:"project_profile"`
	ProjectContext   map[string]interface{} `json:"project_context"`
	Config           RemediationConfig      `json:"config"`
}

type RemediationConfig struct {
	GenerateAlternatives bool `json:"generate_alternatives"`
	MaxAlternatives      int  `json:"max_alternatives"`
	IncludeTests         bool `json:"include_tests"`
	DetailedSteps        bool `json:"detailed_steps"`
	EstimateComplexity   bool `json:"estimate_complexity"`
}

type RemediationOutput struct {
	RemediationPlans []RemediationPlan  `json:"remediation_plans"`
	Summary          RemediationSummary `json:"summary"`
}

type RemediationPlan struct {
	FindingID         string              `json:"finding_id"`
	PrimaryFix        Fix                 `json:"primary_fix"`
	AlternativeFixes  []Fix               `json:"alternative_fixes"`
	Complexity        string              `json:"complexity"`
	EstimatedTime     string              `json:"estimated_time"`
	RequiresExpertise string              `json:"requires_expertise"`
	BreakingChange    bool                `json:"breaking_change"`
	Steps             []RemediationStep   `json:"steps"`
	Prerequisites     []string            `json:"prerequisites"`
	Testing           []TestStep          `json:"testing"`
	References        []string            `json:"references"`
	Documentation     []string            `json:"documentation"`
	Metadata          RemediationMetadata `json:"metadata"`
}

type Fix struct {
	Type           string `json:"type"`
	Description    string `json:"description"`
	CodeBefore     string `json:"code_before,omitempty"`
	CodeAfter      string `json:"code_after,omitempty"`
	FilePath       string `json:"file_path,omitempty"`
	LineNumber     int    `json:"line_number,omitempty"`
	Command        string `json:"command,omitempty"`
	PackageName    string `json:"package_name,omitempty"`
	CurrentVersion string `json:"current_version,omitempty"`
	TargetVersion  string `json:"target_version,omitempty"`
	Impact         string `json:"impact"`
	Rationale      string `json:"rationale"`
	BreakingChange bool   `json:"breaking_change"`
}

type RemediationStep struct {
	Order            int    `json:"order"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	Command          string `json:"command,omitempty"`
	ExpectedOutput   string `json:"expected_output,omitempty"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

type TestStep struct {
	Type           string `json:"type"`
	Description    string `json:"description"`
	Command        string `json:"command,omitempty"`
	ExpectedResult string `json:"expected_result"`
}

type RemediationMetadata struct {
	GeneratedAt    string `json:"generated_at"`
	Confidence     string `json:"confidence"`
	AutoApplicable bool   `json:"auto_applicable"`
	RiskLevel      string `json:"risk_level"`
}

type RemediationSummary struct {
	TotalPlans          int              `json:"total_plans"`
	ByComplexity        ComplexityCounts `json:"by_complexity"`
	ByType              TypeCounts       `json:"by_type"`
	EstimatedTotalTime  string           `json:"estimated_total_time"`
	AutoApplicableCount int              `json:"auto_applicable_count"`
}

type ComplexityCounts struct {
	Low    int `json:"low"`
	Medium int `json:"medium"`
	High   int `json:"high"`
}

type TypeCounts struct {
	CodePatch        int `json:"code_patch"`
	DependencyUpdate int `json:"dependency_update"`
	Configuration    int `json:"configuration"`
	Removal          int `json:"removal"`
}

type CodeFixInput struct {
	Finding        map[string]interface{} `json:"finding"`
	ProjectContext map[string]interface{} `json:"project_context"`
}

type CodeFixOutput struct {
	Fix Fix `json:"fix"`
}

type DependencyFixInput struct {
	Finding map[string]interface{} `json:"finding"`
}

type DependencyFixOutput struct {
	Fix DependencyFixDetails `json:"fix"`
}

type DependencyFixDetails struct {
	UpdateCommand   string `json:"update_command"`
	VerifyCommand   string `json:"verify_command"`
	RollbackCommand string `json:"rollback_command"`
}

type ActionPlanInput struct {
	Finding map[string]interface{} `json:"finding"`
	Fix     map[string]interface{} `json:"fix"`
}

type ActionPlanOutput struct {
	Steps         []RemediationStep `json:"steps"`
	EstimatedTime string            `json:"estimated_time,omitempty"`
	Prerequisites []string          `json:"prerequisites,omitempty"`
}

type ComplexityInput struct {
	Finding map[string]interface{} `json:"finding"`
	Fix     map[string]interface{} `json:"fix"`
}

type ComplexityOutput struct {
	Complexity        string   `json:"complexity"`
	EstimatedTime     string   `json:"estimated_time"`
	RequiresExpertise string   `json:"requires_expertise"`
	Factors           []string `json:"factors"`
}

type TestsInput struct {
	Finding map[string]interface{} `json:"finding"`
	Fix     map[string]interface{} `json:"fix"`
}

type TestsOutput struct {
	Tests []TestStep `json:"tests"`
}
