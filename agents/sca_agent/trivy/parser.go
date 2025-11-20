package trivy

import "strings"

func NormalizeSeverity(trivySeverity string) string {
	switch trivySeverity {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func ExtractCVSSScore(cvss map[string]CVSS) float64 {
	if nvd, ok := cvss["nvd"]; ok && nvd.V3Score > 0 {
		return nvd.V3Score
	}

	for _, c := range cvss {
		if c.V3Score > 0 {
			return c.V3Score
		}
		if c.V2Score > 0 {
			return c.V2Score
		}
	}

	return 0.0
}

func ExtractTitle(vuln Vulnerability) string {
	if vuln.Title != "" {
		return vuln.Title
	}

	if vuln.VulnerabilityID != "" && vuln.PkgName != "" {
		return vuln.VulnerabilityID + " in " + vuln.PkgName
	}

	return "Vulnerability in " + vuln.PkgName
}

func NormalizePackageType(trivyType string) string {
	typeMap := map[string]string{
		"gomod":   "gomod",
		"npm":     "npm",
		"yarn":    "npm",
		"pnpm":    "npm",
		"pip":     "pip",
		"pipenv":  "pip",
		"poetry":  "pip",
		"maven":   "maven",
		"gradle":  "gradle",
		"cargo":   "cargo",
		"bundler": "bundler",
		"composer": "composer",
		"nuget":   "nuget",
	}

	lowerType := strings.ToLower(trivyType)
	if normalized, ok := typeMap[lowerType]; ok {
		return normalized
	}

	return trivyType
}
