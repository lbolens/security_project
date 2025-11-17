package main

type ContextualizeAnalysisInput struct {
	ProjectProfile ProjectProfile `json:"project_profile"`
	Options        Options        `json:"options"`
}

type Options struct {
	ForceAllAgents     bool   `json:"force_all_agents"`
	SeverityThreshold  string `json:"severity_threshold"`
	UseOllamaAnalysis  bool   `json:"use_ollama_analysis"`
}

type ProjectProfile struct {
	Languages    []Language   `json:"languages"`
	Frameworks   []Framework  `json:"frameworks"`
	Dependencies []Dependency `json:"dependencies"`
	FileTree     FileTree     `json:"file_tree"`
	Metadata     Metadata     `json:"metadata"`
}

type Language struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	FileCount  int     `json:"file_count"`
	Percentage float64 `json:"percentage"`
}

type Framework struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Language string `json:"language"`
}

type Dependency struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Language string `json:"language"`
	IsDevDep bool   `json:"is_dev_dep"`
}

type FileTree struct {
	TotalFiles  int      `json:"total_files"`
	TotalDirs   int      `json:"total_dirs"`
	HasTests    bool     `json:"has_tests"`
	HasDocs     bool     `json:"has_docs"`
	ConfigFiles []string `json:"config_files,omitempty"`
}

type Metadata struct {
	ProjectName string `json:"project_name"`
	SizeBytes   int64  `json:"size_bytes"`
	IsGitRepo   bool   `json:"is_git_repo"`
}

type AnalysisConfig struct {
	EnabledAgents  []string               `json:"enabled_agents"`
	AgentConfigs   map[string]AgentConfig `json:"agent_configs"`
	Priority       []string               `json:"priority"`
	SkipReasons    map[string]string      `json:"skip_reasons"`
	ProjectContext *ProjectContext        `json:"project_context,omitempty"`
}

type AgentConfig struct {
	Enabled      bool                   `json:"enabled"`
	Severity     string                 `json:"severity"`
	Rules        []string               `json:"rules"`
	SkipPatterns []string               `json:"skip_patterns"`
	MaxFindings  int                    `json:"max_findings,omitempty"`
	CustomParams map[string]interface{} `json:"custom_params,omitempty"`
}

type ProjectContext struct {
	Type             string   `json:"type"`
	Domain           string   `json:"domain"`
	Criticality      string   `json:"criticality"`
	SecurityConcerns []string `json:"security_concerns,omitempty"`
}

type GetAgentConfigInput struct {
	AgentName      string         `json:"agent_name"`
	ProjectProfile ProjectProfile `json:"project_profile"`
}

type GetAgentConfigOutput struct {
	AgentConfig AgentConfig `json:"agent_config"`
}

type AnalyzeProjectContextInput struct {
	ProjectProfile ProjectProfile `json:"project_profile"`
}

type AnalyzeProjectContextOutput struct {
	Type             string   `json:"type"`
	Domain           string   `json:"domain"`
	Criticality      string   `json:"criticality"`
	SecurityConcerns []string `json:"security_concerns,omitempty"`
}
