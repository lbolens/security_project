package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"profiler_agent/detectors"
)

type Profiler struct {
	excludePatterns []string
	maxDepth        int
	includeDevDeps  bool
}

func NewProfiler(excludePatterns []string, maxDepth int, includeDevDeps bool) *Profiler {
	return &Profiler{
		excludePatterns: excludePatterns,
		maxDepth:        maxDepth,
		includeDevDeps:  includeDevDeps,
	}
}

func (p *Profiler) AnalyzeProject(projectPath string) (*ProjectProfile, error) {
	startTime := time.Now()

	languages, err := detectors.DetectLanguages(projectPath, p.maxDepth, p.excludePatterns)
	if err != nil {
		return nil, err
	}

	langModels := make([]Language, len(languages))
	for i, lang := range languages {
		langModels[i] = Language{
			Name:       lang.Name,
			Version:    lang.Version,
			FileCount:  lang.FileCount,
			Percentage: lang.Percentage,
		}
	}

	frameworks, err := detectors.DetectFrameworks(projectPath, languages)
	if err != nil {
		return nil, err
	}

	fwModels := make([]Framework, len(frameworks))
	for i, fw := range frameworks {
		fwModels[i] = Framework{
			Name:     fw.Name,
			Version:  fw.Version,
			Language: fw.Language,
		}
	}

	dependencies, err := detectors.ExtractDependencies(projectPath, languages, p.includeDevDeps)
	if err != nil {
		return nil, err
	}

	depModels := make([]Dependency, len(dependencies))
	for i, dep := range dependencies {
		depModels[i] = Dependency{
			Name:     dep.Name,
			Version:  dep.Version,
			Language: dep.Language,
			IsDevDep: dep.IsDevDep,
			FilePath: dep.FilePath,
		}
	}

	fileTree, err := p.analyzeFileTree(projectPath)
	if err != nil {
		return nil, err
	}

	metadata, err := p.extractMetadata(projectPath)
	if err != nil {
		return nil, err
	}

	metadata.ScanDurationMs = time.Since(startTime).Milliseconds()

	return &ProjectProfile{
		Languages:    langModels,
		Frameworks:   fwModels,
		Dependencies: depModels,
		FileTree:     *fileTree,
		Metadata:     *metadata,
	}, nil
}

func (p *Profiler) DetectLanguages(projectPath string) (*DetectLanguagesOutput, error) {
	languages, err := detectors.DetectLanguages(projectPath, p.maxDepth, p.excludePatterns)
	if err != nil {
		return nil, err
	}

	langModels := make([]Language, len(languages))
	for i, lang := range languages {
		langModels[i] = Language{
			Name:       lang.Name,
			FileCount:  lang.FileCount,
			Percentage: lang.Percentage,
		}
	}

	return &DetectLanguagesOutput{
		Languages: langModels,
	}, nil
}

func (p *Profiler) ExtractDependencies(projectPath string, language string) (*ExtractDependenciesOutput, error) {
	dependencies, sourceFile, err := detectors.ExtractDependenciesForLanguage(projectPath, language, p.includeDevDeps)
	if err != nil {
		return nil, err
	}

	depModels := make([]Dependency, len(dependencies))
	for i, dep := range dependencies {
		depModels[i] = Dependency{
			Name:     dep.Name,
			Version:  dep.Version,
			IsDevDep: dep.IsDevDep,
		}
	}

	return &ExtractDependenciesOutput{
		Dependencies: depModels,
		SourceFile:   sourceFile,
	}, nil
}

func (p *Profiler) analyzeFileTree(projectPath string) (*FileTree, error) {
	totalFiles := 0
	totalDirs := 0
	maxDepth := 0
	hasTests := false
	hasDocs := false
	configFiles := []string{}

	testPatterns := []string{"_test.", ".test.", "test/", "tests/", "__tests__/"}
	docPatterns := []string{"README", ".md", "docs/", "doc/"}
	configPatterns := []string{".env", "config.", ".yaml", ".yml", ".toml", ".ini"}

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(projectPath, path)
		depth := strings.Count(relPath, string(filepath.Separator))

		if p.maxDepth > 0 && depth > p.maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if shouldExcludeDir(d.Name()) {
				return filepath.SkipDir
			}
			totalDirs++
			if depth > maxDepth {
				maxDepth = depth
			}
			return nil
		}

		totalFiles++

		fileName := d.Name()
		for _, pattern := range testPatterns {
			if strings.Contains(fileName, pattern) || strings.Contains(relPath, pattern) {
				hasTests = true
				break
			}
		}

		for _, pattern := range docPatterns {
			if strings.Contains(fileName, pattern) || strings.Contains(relPath, pattern) {
				hasDocs = true
				break
			}
		}

		for _, pattern := range configPatterns {
			if strings.Contains(fileName, pattern) {
				configFiles = append(configFiles, relPath)
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &FileTree{
		TotalFiles:  totalFiles,
		TotalDirs:   totalDirs,
		MaxDepth:    maxDepth,
		HasTests:    hasTests,
		HasDocs:     hasDocs,
		ConfigFiles: configFiles,
	}, nil
}

func (p *Profiler) extractMetadata(projectPath string) (*Metadata, error) {
	projectName := filepath.Base(projectPath)

	totalSize := int64(0)
	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if shouldExcludeDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err == nil {
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	gitDir := filepath.Join(projectPath, ".git")
	isGitRepo := false
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		isGitRepo = true
	}

	return &Metadata{
		ProjectName: projectName,
		SizeBytes:   totalSize,
		IsGitRepo:   isGitRepo,
	}, nil
}

func shouldExcludeDir(dirName string) bool {
	return detectors.ExcludedDirs[dirName]
}
