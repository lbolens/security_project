package utils

import "sort"

func SecretTypePriority(secretType string) int {
	priorities := map[string]int{
		"private-key":          100,
		"ethereum-private-key": 95,
		"bitcoin-private-key":  95,
		"mnemonic-phrase":      95,
		"aws-access-key":       90,
		"aws-secret-key":       90,
		"gcp-api-key":          90,
		"azure-client-secret":  90,
		"stripe-key":           85,
		"paypal-secret":        85,
		"github-token":         80,
		"gitlab-token":         80,
		"slack-token":          75,
		"api-key":              70,
		"jwt-token":            65,
		"oauth-token":          65,
		"mongodb-uri":          60,
		"postgres-password":    60,
		"redis-password":       60,
		"credential":           50,
	}

	if priority, ok := priorities[secretType]; ok {
		return priority
	}
	return 40
}

func FilterFindings(findings []Finding, minSeverity string) []Finding {
	severityWeight := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	minWeight := severityWeight[minSeverity]
	filtered := []Finding{}

	for _, finding := range findings {
		if severityWeight[finding.Severity] >= minWeight {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func SortByPriority(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		priorityI := SecretTypePriority(sorted[i].SecretType)
		priorityJ := SecretTypePriority(sorted[j].SecretType)

		if priorityI != priorityJ {
			return priorityI > priorityJ
		}

		if sorted[i].IsActive != sorted[j].IsActive {
			return sorted[i].IsActive
		}

		return sorted[i].Entropy > sorted[j].Entropy
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

func CountByType(findings []Finding) map[string]int {
	counts := make(map[string]int)

	for _, finding := range findings {
		counts[finding.SecretType]++
	}

	return counts
}

func CountActiveSecrets(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.IsActive {
			count++
		}
	}
	return count
}

type Finding struct {
	Severity   string
	SecretType string
	IsActive   bool
	Entropy    float64
}
