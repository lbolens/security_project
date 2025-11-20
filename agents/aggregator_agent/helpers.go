package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"path/filepath"
	"strings"
)

func normalizePath(path string) string {
	path = filepath.Clean(path)
	path = strings.ReplaceAll(path, "\\", "/")
	return strings.ToLower(path)
}

func extractIDs(findings []ConsolidatedFinding) []string {
	ids := make([]string, 0)
	seen := make(map[string]bool)

	for _, f := range findings {
		if !seen[f.ID] {
			ids = append(ids, f.ID)
			seen[f.ID] = true
		}

		for _, origID := range f.OriginalIDs {
			if !seen[origID] && origID != f.ID {
				ids = append(ids, origID)
				seen[origID] = true
			}
		}
	}

	return ids
}

func extractSources(findings []ConsolidatedFinding) []string {
	sourcesMap := make(map[string]bool)

	for _, f := range findings {
		for _, source := range f.Sources {
			sourcesMap[source] = true
		}
	}

	var sources []string
	for source := range sourcesMap {
		sources = append(sources, source)
	}

	return sources
}

func mergeDescriptions(findings []ConsolidatedFinding) string {
	if len(findings) == 0 {
		return ""
	}

	base := findings[0].Description

	if len(findings) == 1 {
		return base
	}

	sources := extractSources(findings)
	return fmt.Sprintf("%s\n\nDetected by multiple sources: %s", base, strings.Join(sources, ", "))
}

func severityWeight(severity string) int {
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

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("uuid-%d", len(b))
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func roundFloat(val float64) float64 {
	return math.Round(val*10) / 10
}

func calculateRiskLevel(severity string) string {
	return severity
}

func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getIntValue(m map[string]interface{}, key string) int {
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

func getFloatValue(m map[string]interface{}, key string) float64 {
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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func mapToFinding(m map[string]interface{}) ConsolidatedFinding {
	finding := ConsolidatedFinding{
		ID:             getStringValue(m, "id"),
		Type:           getStringValue(m, "type"),
		Category:       getStringValue(m, "category"),
		Severity:       getStringValue(m, "severity"),
		Priority:       getIntValue(m, "priority"),
		Title:          getStringValue(m, "title"),
		Description:    getStringValue(m, "description"),
		FilePath:       getStringValue(m, "file_path"),
		LineNumber:     getIntValue(m, "line_number"),
		ComponentName:  getStringValue(m, "component_name"),
		CVE:            getStringValue(m, "cve"),
		CVSS:           getFloatValue(m, "cvss"),
		BusinessImpact: getStringValue(m, "business_impact"),
		Exploitability: getStringValue(m, "exploitability"),
		RiskLevel:      getStringValue(m, "risk_level"),
		Recommendation: getStringValue(m, "recommendation"),
		FixComplexity:  getStringValue(m, "fix_complexity"),
		Confidence:     getStringValue(m, "confidence"),
		FirstDetected:  getStringValue(m, "first_detected"),
	}

	if originalIDs, ok := m["original_ids"].([]interface{}); ok {
		for _, id := range originalIDs {
			if idStr, ok := id.(string); ok {
				finding.OriginalIDs = append(finding.OriginalIDs, idStr)
			}
		}
	}

	if sources, ok := m["sources"].([]interface{}); ok {
		for _, s := range sources {
			if sStr, ok := s.(string); ok {
				finding.Sources = append(finding.Sources, sStr)
			}
		}
	}

	if cweList, ok := m["cwe"].([]interface{}); ok {
		for _, cwe := range cweList {
			if cweStr, ok := cwe.(string); ok {
				finding.CWE = append(finding.CWE, cweStr)
			}
		}
	}

	if owaspList, ok := m["owasp"].([]interface{}); ok {
		for _, owasp := range owaspList {
			if owaspStr, ok := owasp.(string); ok {
				finding.OWASP = append(finding.OWASP, owaspStr)
			}
		}
	}

	if tags, ok := m["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				finding.Tags = append(finding.Tags, tagStr)
			}
		}
	}

	if finding.OriginalIDs == nil {
		finding.OriginalIDs = []string{}
	}
	if finding.Sources == nil {
		finding.Sources = []string{}
	}
	if finding.CWE == nil {
		finding.CWE = []string{}
	}
	if finding.OWASP == nil {
		finding.OWASP = []string{}
	}
	if finding.Tags == nil {
		finding.Tags = []string{}
	}

	return finding
}
