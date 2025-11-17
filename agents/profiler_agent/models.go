package main

type AnalyzeProjectInput struct {
	ProjectPath string  `json:"project_path"`
	Options     Options `json:"options"`
}

type Options struct {
	ExcludePatterns []string `json:"exclude_patterns"`
	MaxDepth        int      `json:"max_depth"`
	IncludeDevDeps  bool     `json:"include_dev_deps"`
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
	Name      string `json:"name"`
	Version   string `json:"version"`
	Language  string `json:"language"`
	IsDevDep  bool   `json:"is_dev_dep"`
	FilePath  string `json:"file_path,omitempty"`
}

type FileTree struct {
	TotalFiles  int      `json:"total_files"`
	TotalDirs   int      `json:"total_dirs"`
	MaxDepth    int      `json:"max_depth"`
	HasTests    bool     `json:"has_tests"`
	HasDocs     bool     `json:"has_docs"`
	ConfigFiles []string `json:"config_files,omitempty"`
}

type Metadata struct {
	ProjectName    string `json:"project_name"`
	SizeBytes      int64  `json:"size_bytes"`
	IsGitRepo      bool   `json:"is_git_repo"`
	ScanDurationMs int64  `json:"scan_duration_ms,omitempty"`
}

type ProjectProfile struct {
	Languages    []Language   `json:"languages"`
	Frameworks   []Framework  `json:"frameworks"`
	Dependencies []Dependency `json:"dependencies"`
	FileTree     FileTree     `json:"file_tree"`
	Metadata     Metadata     `json:"metadata"`
}

type DetectLanguagesInput struct {
	ProjectPath string `json:"project_path"`
}

type DetectLanguagesOutput struct {
	Languages []Language `json:"languages"`
}

type ExtractDependenciesInput struct {
	ProjectPath string `json:"project_path"`
	Language    string `json:"language"`
}

type ExtractDependenciesOutput struct {
	Dependencies []Dependency `json:"dependencies"`
	SourceFile   string       `json:"source_file,omitempty"`
}
