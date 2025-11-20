package main

import (
	"fmt"
	"time"
)

func GenerateRemediationPlans(input RemediationInput) (*RemediationOutput, error) {
	if input.Config.MaxAlternatives == 0 {
		input.Config.MaxAlternatives = 2
	}

	findings := extractFindings(input.AggregatedReport)

	var plans []RemediationPlan

	for _, finding := range findings {
		primaryFix, err := generatePrimaryFix(finding, input.ProjectContext)
		if err != nil {
			continue
		}

		alternatives := []Fix{}
		if input.Config.GenerateAlternatives {
			alternatives = GenerateAlternatives(finding, primaryFix, input.Config.MaxAlternatives)
		}

		complexity := "medium"
		estimatedTime := "30 minutes"
		expertise := "mid"
		factors := []string{}

		if input.Config.EstimateComplexity {
			complexityOutput, _ := EstimateComplexity(ComplexityInput{
				Finding: finding,
				Fix:     fixToMap(primaryFix),
			})
			complexity = complexityOutput.Complexity
			estimatedTime = complexityOutput.EstimatedTime
			expertise = complexityOutput.RequiresExpertise
			factors = complexityOutput.Factors
		}

		steps := []RemediationStep{}
		prerequisites := []string{}
		if input.Config.DetailedSteps {
			planOutput, _ := GenerateActionPlan(ActionPlanInput{
				Finding: finding,
				Fix:     fixToMap(primaryFix),
			})
			steps = planOutput.Steps
			prerequisites = planOutput.Prerequisites
		}

		tests := []TestStep{}
		if input.Config.IncludeTests {
			testsOutput, _ := GenerateTests(TestsInput{
				Finding: finding,
				Fix:     fixToMap(primaryFix),
			})
			tests = testsOutput.Tests
		}

		references := collectReferences(finding)
		documentation := collectDocumentation(finding)

		plan := RemediationPlan{
			FindingID:         GetStringValue(finding, "id"),
			PrimaryFix:        primaryFix,
			AlternativeFixes:  alternatives,
			Complexity:        complexity,
			EstimatedTime:     estimatedTime,
			RequiresExpertise: expertise,
			BreakingChange:    primaryFix.BreakingChange,
			Steps:             steps,
			Prerequisites:     prerequisites,
			Testing:           tests,
			References:        references,
			Documentation:     documentation,
			Metadata: RemediationMetadata{
				GeneratedAt:    time.Now().Format(time.RFC3339),
				Confidence:     EstimateConfidence(primaryFix, factors),
				AutoApplicable: IsAutoApplicable(primaryFix),
				RiskLevel:      EstimateFixRisk(primaryFix),
			},
		}

		plans = append(plans, plan)
	}

	summary := generateSummary(plans)

	return &RemediationOutput{
		RemediationPlans: plans,
		Summary:          summary,
	}, nil
}

func generatePrimaryFix(finding map[string]interface{}, context map[string]interface{}) (Fix, error) {
	findingType := GetStringValue(finding, "type")

	switch findingType {
	case "vulnerable-dependency":
		return GenerateDependencyFixFromFinding(finding)
	case "exposed-secret":
		return GenerateSecretsRemediation(finding)
	default:
		return GenerateCodeFixFromFinding(finding, context)
	}
}

func extractFindings(report map[string]interface{}) []map[string]interface{} {
	var findings []map[string]interface{}

	if findingsRaw, ok := report["findings"].([]interface{}); ok {
		for _, f := range findingsRaw {
			if findingMap, ok := f.(map[string]interface{}); ok {
				findings = append(findings, findingMap)
			}
		}
	}

	return findings
}

func generateSummary(plans []RemediationPlan) RemediationSummary {
	summary := RemediationSummary{
		TotalPlans: len(plans),
		ByComplexity: ComplexityCounts{
			Low:    0,
			Medium: 0,
			High:   0,
		},
		ByType: TypeCounts{
			CodePatch:        0,
			DependencyUpdate: 0,
			Configuration:    0,
			Removal:          0,
		},
		AutoApplicableCount: 0,
	}

	totalMinutes := 0

	for _, plan := range plans {
		switch plan.Complexity {
		case "low":
			summary.ByComplexity.Low++
		case "medium":
			summary.ByComplexity.Medium++
		case "high":
			summary.ByComplexity.High++
		}

		switch plan.PrimaryFix.Type {
		case "code-patch":
			summary.ByType.CodePatch++
		case "dependency-update":
			summary.ByType.DependencyUpdate++
		case "configuration":
			summary.ByType.Configuration++
		case "removal":
			summary.ByType.Removal++
		}

		if plan.Metadata.AutoApplicable {
			summary.AutoApplicableCount++
		}

		totalMinutes += parseTimeEstimate(plan.EstimatedTime)
	}

	summary.EstimatedTotalTime = formatTotalTime(totalMinutes)

	return summary
}

func collectReferences(finding map[string]interface{}) []string {
	refs := []string{}

	category := GetStringValue(finding, "category")
	findingType := GetStringValue(finding, "type")

	if category == "injection" || findingType == "sql-injection" {
		refs = append(refs, "https://owasp.org/www-community/attacks/SQL_Injection")
		refs = append(refs, "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html")
	}

	if category == "cryptography" {
		refs = append(refs, "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/")
	}

	if category == "sensitive-data" {
		refs = append(refs, "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure")
	}

	if len(refs) == 0 {
		refs = append(refs, "https://owasp.org/www-project-top-ten/")
	}

	return refs
}

func collectDocumentation(finding map[string]interface{}) []string {
	docs := []string{}

	filePath := GetStringValue(finding, "file_path")
	lang := DetectLanguage(filePath)

	switch lang {
	case "go":
		docs = append(docs, "https://golang.org/doc/")
	case "python":
		docs = append(docs, "https://docs.python.org/3/")
	case "javascript", "typescript":
		docs = append(docs, "https://developer.mozilla.org/en-US/docs/Web/JavaScript")
	case "java":
		docs = append(docs, "https://docs.oracle.com/en/java/")
	}

	return docs
}

func fixToMap(f Fix) map[string]interface{} {
	return map[string]interface{}{
		"type":            f.Type,
		"description":     f.Description,
		"code_before":     f.CodeBefore,
		"code_after":      f.CodeAfter,
		"file_path":       f.FilePath,
		"line_number":     f.LineNumber,
		"command":         f.Command,
		"package_name":    f.PackageName,
		"current_version": f.CurrentVersion,
		"target_version":  f.TargetVersion,
		"impact":          f.Impact,
		"rationale":       f.Rationale,
		"breaking_change": f.BreakingChange,
	}
}

func parseTimeEstimate(estimate string) int {
	if estimate == "" {
		return 30
	}

	switch estimate {
	case "5 minutes":
		return 5
	case "10 minutes":
		return 10
	case "15 minutes":
		return 15
	case "30 minutes":
		return 30
	case "1 hour":
		return 60
	case "2 hours":
		return 120
	case "3 hours":
		return 180
	case "4 hours":
		return 240
	default:
		return 30
	}
}

func formatTotalTime(minutes int) string {
	if minutes < 60 {
		return fmt.Sprintf("%d minutes", minutes)
	}

	hours := minutes / 60
	remainingMinutes := minutes % 60

	if remainingMinutes == 0 {
		return fmt.Sprintf("%d hours", hours)
	}

	return fmt.Sprintf("%d hours %d minutes", hours, remainingMinutes)
}
