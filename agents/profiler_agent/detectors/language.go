package detectors

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var LanguageExtensions = map[string]string{
	".go":   "Go",
	".py":   "Python",
	".js":   "JavaScript",
	".ts":   "TypeScript",
	".jsx":  "JavaScript",
	".tsx":  "TypeScript",
	".java": "Java",
	".c":    "C",
	".cpp":  "C++",
	".cs":   "C#",
	".rb":   "Ruby",
	".php":  "PHP",
	".rs":   "Rust",
	".sol":  "Solidity",
}

var ExcludedDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	"venv":         true,
	"__pycache__":  true,
	"build":        true,
	"dist":         true,
	".next":        true,
	".nuxt":        true,
	"target":       true,
	".idea":        true,
	".vscode":      true,
}

type Language struct {
	Name       string
	Version    string
	FileCount  int
	Percentage float64
}

func DetectLanguages(projectPath string, maxDepth int, excludePatterns []string) ([]Language, error) {
	langCount := make(map[string]int)
	totalFiles := 0
	currentDepth := 0

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(projectPath, path)
		depth := strings.Count(relPath, string(filepath.Separator))

		if maxDepth > 0 && depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if shouldExcludeDir(d.Name(), excludePatterns) {
				return filepath.SkipDir
			}
			if depth > currentDepth {
				currentDepth = depth
			}
			return nil
		}

		ext := filepath.Ext(path)
		if lang, ok := LanguageExtensions[ext]; ok {
			langCount[lang]++
			totalFiles++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	languages := make([]Language, 0, len(langCount))
	for lang, count := range langCount {
		percentage := 0.0
		if totalFiles > 0 {
			percentage = float64(count) / float64(totalFiles) * 100.0
		}
		languages = append(languages, Language{
			Name:       lang,
			FileCount:  count,
			Percentage: percentage,
		})
	}

	return languages, nil
}

func shouldExcludeDir(dirName string, extraPatterns []string) bool {
	if ExcludedDirs[dirName] {
		return true
	}

	for _, pattern := range extraPatterns {
		if matched, _ := filepath.Match(pattern, dirName); matched {
			return true
		}
	}

	return false
}
