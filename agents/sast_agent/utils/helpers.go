package utils

import "sort"

func SeverityWeight(severity string) int {
	weights := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	if weight, ok := weights[severity]; ok {
		return weight
	}
	return 0
}

func ConfidenceWeight(confidence string) int {
	weights := map[string]int{
		"high":   3,
		"medium": 2,
		"low":    1,
	}

	if weight, ok := weights[confidence]; ok {
		return weight
	}
	return 0
}

func FilterBySeverity(findings []Finding, minSeverity string) []Finding {
	minWeight := SeverityWeight(minSeverity)
	filtered := []Finding{}

	for _, finding := range findings {
		if SeverityWeight(finding.Severity) >= minWeight {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func FilterByConfidence(findings []Finding, minConfidence string) []Finding {
	minWeight := ConfidenceWeight(minConfidence)
	filtered := []Finding{}

	for _, finding := range findings {
		if ConfidenceWeight(finding.Confidence) >= minWeight {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func SortByPriority(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		severityI := SeverityWeight(sorted[i].Severity)
		severityJ := SeverityWeight(sorted[j].Severity)

		if severityI != severityJ {
			return severityI > severityJ
		}

		confidenceI := ConfidenceWeight(sorted[i].Confidence)
		confidenceJ := ConfidenceWeight(sorted[j].Confidence)

		return confidenceI > confidenceJ
	})

	return sorted
}

func LimitFindings(findings []Finding, maxFindings int) []Finding {
	if maxFindings <= 0 || len(findings) <= maxFindings {
		return findings
	}

	sorted := SortByPriority(findings)
	return sorted[:maxFindings]
}

func CountBySeverity(findings []Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, finding := range findings {
		counts[finding.Severity]++
	}

	return counts
}

func CountByType(findings []Finding) map[string]int {
	counts := make(map[string]int)

	for _, finding := range findings {
		counts[finding.Type]++
	}

	return counts
}

type Finding struct {
	Severity   string
	Confidence string
	Type       string
}
