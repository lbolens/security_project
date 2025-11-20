package main

import (
	"strings"
)

func EstimateComplexity(input ComplexityInput) (*ComplexityOutput, error) {
	finding := input.Finding
	fix := input.Fix

	complexity, estimatedTime, expertise, factors := calculateComplexity(finding, fix)

	return &ComplexityOutput{
		Complexity:        complexity,
		EstimatedTime:     estimatedTime,
		RequiresExpertise: expertise,
		Factors:           factors,
	}, nil
}

func calculateComplexity(finding, fix map[string]interface{}) (string, string, string, []string) {
	complexity := "medium"
	estimatedTime := "30 minutes"
	expertise := "mid"
	factors := []string{}

	fixType := GetStringValue(fix, "type")

	switch fixType {
	case "dependency-update":
		complexity = "low"
		estimatedTime = "10 minutes"
		expertise = "junior"
		factors = append(factors, "simple-dependency-update")

	case "configuration":
		complexity = "low"
		estimatedTime = "15 minutes"
		expertise = "junior"
		factors = append(factors, "configuration-change")

	case "code-patch":
		codeBefore := GetStringValue(fix, "code_before")
		codeAfter := GetStringValue(fix, "code_after")

		if len(codeAfter) > 500 {
			complexity = "high"
			estimatedTime = "2 hours"
			expertise = "senior"
			factors = append(factors, "large-code-change")
		}

		linesBefore := len(strings.Split(codeBefore, "\n"))
		linesAfter := len(strings.Split(codeAfter, "\n"))
		diff := abs(linesAfter - linesBefore)

		if diff > 20 {
			complexity = "high"
			estimatedTime = "3 hours"
			factors = append(factors, "significant-refactoring")
		}

	case "removal":
		complexity = "high"
		estimatedTime = "4 hours"
		expertise = "senior"
		factors = append(factors, "code-removal")
	}

	severity := GetStringValue(finding, "severity")
	if severity == "critical" {
		factors = append(factors, "critical-severity")
		if complexity == "low" {
			complexity = "medium"
			estimatedTime = "30 minutes"
		}
	}

	breakingChange := GetBoolValue(fix, "breaking_change")
	if breakingChange {
		complexity = "high"
		estimatedTime = "4 hours"
		expertise = "senior"
		factors = append(factors, "breaking-change")
	}

	filePath := GetStringValue(finding, "file_path")
	if strings.Contains(filePath, "core") || strings.Contains(filePath, "auth") || strings.Contains(filePath, "security") {
		factors = append(factors, "core-component")
		if complexity == "low" {
			complexity = "medium"
		}
		expertise = "senior"
	}

	return complexity, estimatedTime, expertise, factors
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
