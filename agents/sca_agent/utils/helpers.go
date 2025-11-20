package utils

import (
	"sort"
)

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

func FilterByRiskLevel(findings []Finding, minRiskLevel string) []Finding {
	minWeight := SeverityWeight(minRiskLevel)
	filtered := []Finding{}

	for _, finding := range findings {
		riskLevel := finding.RiskLevel
		if riskLevel == "" {
			riskLevel = finding.Severity
		}

		if SeverityWeight(riskLevel) >= minWeight {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func SortByPriority(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CVSS != sorted[j].CVSS {
			return sorted[i].CVSS > sorted[j].CVSS
		}

		severityI := SeverityWeight(sorted[i].Severity)
		severityJ := SeverityWeight(sorted[j].Severity)

		return severityI > severityJ
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

func CountByPackageType(findings []Finding) map[string]int {
	counts := make(map[string]int)

	for _, finding := range findings {
		counts[finding.PackageType]++
	}

	return counts
}

func DowngradeSeverity(severity string) string {
	switch severity {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func CountUniqueDependencies(findings []Finding) int {
	packages := make(map[string]bool)

	for _, finding := range findings {
		packages[finding.PackageName] = true
	}

	return len(packages)
}

type Finding struct {
	Severity     string
	CVSS         float64
	PackageName  string
	PackageType  string
	RiskLevel    string
}
