package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ExtractCodeContext(filePath string, lineNumber, contextLines int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Sprintf("// Unable to read file: %s", filePath), nil
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Sprintf("// Unable to read file: %s", filePath), nil
	}

	lines := strings.Split(string(content), "\n")

	if lineNumber < 1 || lineNumber > len(lines) {
		return string(content), nil
	}

	start := lineNumber - contextLines
	if start < 0 {
		start = 0
	}

	end := lineNumber + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	return strings.Join(lines[start:end], "\n"), nil
}

func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".c", ".cpp", ".cc":
		return "c++"
	case ".sol":
		return "solidity"
	default:
		return "unknown"
	}
}

func DetectPackageManager(finding map[string]interface{}) string {
	componentName := GetStringValue(finding, "component_name")
	filePath := GetStringValue(finding, "file_path")

	if strings.Contains(filePath, "package.json") || strings.Contains(filePath, "node_modules") {
		return "npm"
	}

	if strings.Contains(filePath, "requirements.txt") || strings.Contains(filePath, "Pipfile") {
		return "pip"
	}

	if strings.Contains(filePath, "go.mod") {
		return "go"
	}

	if strings.Contains(filePath, "pom.xml") {
		return "maven"
	}

	if strings.Contains(filePath, "build.gradle") {
		return "gradle"
	}

	if strings.Contains(filePath, "Gemfile") {
		return "bundler"
	}

	if strings.Contains(componentName, "/") {
		return "go"
	}

	return "unknown"
}

func EstimateConfidence(fix Fix, factors []string) string {
	if fix.Type == "dependency-update" {
		return "high"
	}

	if len(factors) == 0 {
		return "medium"
	}

	if contains(factors, "breaking-change") || contains(factors, "large-code-change") {
		return "medium"
	}

	return "high"
}

func IsAutoApplicable(fix Fix) bool {
	if fix.Type == "dependency-update" {
		return true
	}

	if fix.Type == "code-patch" && !fix.BreakingChange && len(fix.CodeAfter) < 200 {
		return true
	}

	return false
}

func EstimateFixRisk(fix Fix) string {
	if fix.BreakingChange {
		return "high"
	}

	if fix.Type == "removal" {
		return "high"
	}

	if fix.Type == "dependency-update" {
		return "low"
	}

	if fix.Type == "configuration" {
		return "medium"
	}

	return "low"
}

func BuildOllamaPrompt(template string, args ...interface{}) string {
	return fmt.Sprintf(template, args...)
}

func UUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("uuid-%d", time.Now().UnixNano())
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func Now() string {
	return time.Now().Format(time.RFC3339)
}

func GetStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func GetIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return 0
}

func GetFloatValue(m map[string]interface{}, key string) float64 {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return 0.0
}

func GetBoolValue(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
