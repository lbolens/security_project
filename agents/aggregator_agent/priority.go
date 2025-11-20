package main

import (
	"strings"
)

func CalculatePriority(input PriorityInput) (*PriorityOutput, error) {
	finding := mapToFinding(input.Finding)
	context := input.ProjectContext

	severityScore := calculateSeverityScore(finding.Severity)
	cvssScore := calculateCVSSScore(finding.CVSS)
	exploitabilityScore := calculateExploitabilityScore(finding.Exploitability)
	contextScore := calculateContextScore(finding, context)
	confidenceScore := calculateConfidenceScore(finding.Confidence, finding.Sources)

	total := severityScore + cvssScore + exploitabilityScore + contextScore + confidenceScore

	if total > 100 {
		total = 100
	}
	if total < 1 {
		total = 1
	}

	return &PriorityOutput{
		Priority: total,
		ScoreBreakdown: ScoreBreakdown{
			SeverityScore:       severityScore,
			CVSSScore:           cvssScore,
			ExploitabilityScore: exploitabilityScore,
			ContextScore:        contextScore,
			ConfidenceScore:     confidenceScore,
		},
	}, nil
}

func calculateSeverityScore(severity string) int {
	scores := map[string]int{
		"critical": 40,
		"high":     30,
		"medium":   20,
		"low":      10,
	}
	if score, ok := scores[severity]; ok {
		return score
	}
	return 10
}

func calculateCVSSScore(cvss float64) int {
	if cvss > 0 {
		score := int(cvss * 2)
		if score > 20 {
			score = 20
		}
		return score
	}
	return 0
}

func calculateExploitabilityScore(exploitability string) int {
	lower := strings.ToLower(exploitability)
	if strings.Contains(lower, "easily exploitable") {
		return 15
	}
	if strings.Contains(lower, "exploitable") {
		return 10
	}
	if strings.Contains(lower, "difficult") {
		return 5
	}
	return 7
}

func calculateContextScore(finding ConsolidatedFinding, context map[string]interface{}) int {
	score := 0

	criticality := getStringValue(context, "criticality")
	if criticality == "critical" {
		score += 15
	} else if criticality == "high" {
		score += 10
	} else {
		score += 5
	}

	domain := getStringValue(context, "domain")
	if domain == "finance" || domain == "crypto" {
		score += 5
	}

	projectType := getStringValue(context, "type")
	if projectType == "api" && strings.Contains(finding.FilePath, "handler") {
		score += 5
	}

	return score
}

func calculateConfidenceScore(confidence string, sources []string) int {
	score := 0

	switch confidence {
	case "high":
		score += 5
	case "medium":
		score += 3
	case "low":
		score += 1
	}

	if len(sources) > 1 {
		score += 5
	}

	return score
}
