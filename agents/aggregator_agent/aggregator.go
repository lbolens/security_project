package main

import (
	"fmt"
	"sort"
	"time"
)

func AggregateFindings(input AggregateInput) (*AggregateOutput, error) {
	startTime := time.Now()

	if input.Config.DedupStrategy == "" {
		input.Config.DedupStrategy = "similar"
	}
	if input.Config.SimilarityThreshold == 0 {
		input.Config.SimilarityThreshold = 3
	}

	allFindings := convertAllFindings(input.SASTFindings, input.SCAFindings, input.SecretsFindings)

	totalBeforeDedup := len(allFindings)

	deduplicated := allFindings
	if input.Config.EnableDeduplication {
		dedupInput := DeduplicateInput{
			Findings: convertFindingsToMaps(allFindings),
			Strategy: input.Config.DedupStrategy,
		}
		dedupOutput, err := DeduplicateFindings(dedupInput)
		if err != nil {
			return nil, err
		}
		deduplicated = dedupOutput.DeduplicatedFindings
	}

	categorizeFindings(deduplicated)

	projectContext := input.ProjectContext
	for i := range deduplicated {
		priorityInput := PriorityInput{
			Finding:        findingToMap(deduplicated[i]),
			ProjectContext: projectContext,
		}
		priorityOutput, _ := CalculatePriority(priorityInput)
		deduplicated[i].Priority = priorityOutput.Priority
		deduplicated[i].RiskLevel = calculateRiskLevel(deduplicated[i].Severity)
	}

	sort.Slice(deduplicated, func(i, j int) bool {
		return deduplicated[i].Priority > deduplicated[j].Priority
	})

	statsInput := StatisticsInput{
		Findings: convertFindingsToMaps(deduplicated),
		TopN:     10,
	}
	statsOutput, _ := GenerateStatistics(statsInput)
	stats := statsOutput.Statistics

	summary := generateSummary(totalBeforeDedup, deduplicated, stats)

	riskScoreInput := RiskScoreInput{
		Findings: convertFindingsToMaps(deduplicated),
	}
	riskScoreOutput, _ := CalculateRiskScore(riskScoreInput)
	summary.RiskScore = riskScoreOutput.RiskScore

	timeline := generateTimeline(input)

	projectName := getStringValue(input.ProjectProfile, "project_name")
	if projectName == "" {
		projectName = "Unknown Project"
	}

	metadata := Metadata{
		ProjectName:     projectName,
		ScanDate:        time.Now().Format(time.RFC3339),
		DurationMS:      time.Since(startTime).Milliseconds(),
		PipelineVersion: "1.0.0",
		Agents: []AgentInfo{
			{Name: "sast-agent", Version: "1.0.0", DurationMS: 0, Status: "success"},
			{Name: "sca-agent", Version: "1.0.0", DurationMS: 0, Status: "success"},
			{Name: "secrets-agent", Version: "1.0.0", DurationMS: 0, Status: "success"},
		},
	}

	return &AggregateOutput{
		Summary:    summary,
		Findings:   deduplicated,
		Statistics: stats,
		Timeline:   timeline,
		Metadata:   metadata,
	}, nil
}

func convertAllFindings(sast, sca, secrets []map[string]interface{}) []ConsolidatedFinding {
	var findings []ConsolidatedFinding

	for _, f := range sast {
		findings = append(findings, convertToConsolidated(f, "sast"))
	}

	for _, f := range sca {
		findings = append(findings, convertToConsolidated(f, "sca"))
	}

	for _, f := range secrets {
		findings = append(findings, convertToConsolidated(f, "secrets"))
	}

	return findings
}

func convertToConsolidated(raw map[string]interface{}, source string) ConsolidatedFinding {
	finding := ConsolidatedFinding{
		ID:            getStringValue(raw, "id"),
		OriginalIDs:   []string{getStringValue(raw, "id")},
		Type:          getStringValue(raw, "type"),
		Severity:      getStringValue(raw, "severity"),
		Title:         getStringValue(raw, "title"),
		Description:   getStringValue(raw, "description"),
		FilePath:      getStringValue(raw, "file_path"),
		LineNumber:    getIntValue(raw, "line_number"),
		ComponentName: getStringValue(raw, "component_name"),
		CVE:           getStringValue(raw, "cve"),
		CVSS:          getFloatValue(raw, "cvss"),
		Exploitability: getStringValue(raw, "exploitability"),
		Recommendation: getStringValue(raw, "recommendation"),
		FixComplexity:  getStringValue(raw, "fix_complexity"),
		Confidence:     getStringValue(raw, "confidence"),
		Sources:        []string{source},
		FirstDetected:  time.Now().Format(time.RFC3339),
		Tags:           []string{},
	}

	if cweList, ok := raw["cwe"].([]interface{}); ok {
		for _, cwe := range cweList {
			if cweStr, ok := cwe.(string); ok {
				finding.CWE = append(finding.CWE, cweStr)
			}
		}
	}

	if owaspList, ok := raw["owasp"].([]interface{}); ok {
		for _, owasp := range owaspList {
			if owaspStr, ok := owasp.(string); ok {
				finding.OWASP = append(finding.OWASP, owaspStr)
			}
		}
	}

	if finding.CWE == nil {
		finding.CWE = []string{}
	}
	if finding.OWASP == nil {
		finding.OWASP = []string{}
	}

	return finding
}

func categorizeFindings(findings []ConsolidatedFinding) {
	for i := range findings {
		findings[i].Category = determineCategory(findings[i])
	}
}

func determineCategory(finding ConsolidatedFinding) string {
	typeCategories := map[string]string{
		"sql-injection":         "injection",
		"xss":                   "injection",
		"command-injection":     "injection",
		"path-traversal":        "access-control",
		"reentrancy":            "logic-error",
		"integer-overflow":      "numeric-error",
		"weak-crypto":           "cryptography",
		"exposed-secret":        "sensitive-data",
		"vulnerable-dependency": "vulnerable-components",
	}

	if category, ok := typeCategories[finding.Type]; ok {
		return category
	}

	for _, cwe := range finding.CWE {
		if contains(cwe, "CWE-89") || contains(cwe, "CWE-79") {
			return "injection"
		}
		if contains(cwe, "CWE-22") {
			return "access-control"
		}
		if contains(cwe, "CWE-327") {
			return "cryptography"
		}
	}

	for _, owasp := range finding.OWASP {
		if contains(owasp, "A03") {
			return "injection"
		}
		if contains(owasp, "A02") {
			return "cryptography"
		}
		if contains(owasp, "A06") {
			return "vulnerable-components"
		}
	}

	return "other"
}

func generateSummary(totalBefore int, findings []ConsolidatedFinding, stats Statistics) Summary {
	summary := Summary{
		TotalFindings:      totalBefore,
		UniqueFindings:     len(findings),
		DuplicatesRemoved:  totalBefore - len(findings),
		CriticalFindings:   stats.BySeverity["critical"],
		HighFindings:       stats.BySeverity["high"],
		MediumFindings:     stats.BySeverity["medium"],
		LowFindings:        stats.BySeverity["low"],
		SASTCount:          stats.BySource["sast"],
		SCACount:           stats.BySource["sca"],
		SecretsCount:       stats.BySource["secrets"],
		FilesAffected:      len(stats.ByFile),
		ComponentsAffected: len(stats.ByComponent),
	}

	totalCVSS := 0.0
	cvssCount := 0
	for _, finding := range findings {
		if finding.CVSS > 0 {
			totalCVSS += finding.CVSS
			cvssCount++
		}
	}
	if cvssCount > 0 {
		summary.AverageCVSS = roundFloat(totalCVSS / float64(cvssCount))
	}

	return summary
}

func generateTimeline(input AggregateInput) []TimelineEntry {
	timeline := []TimelineEntry{}

	now := time.Now()

	if len(input.SASTFindings) > 0 {
		timeline = append(timeline, TimelineEntry{
			Timestamp:   now.Add(-3 * time.Minute).Format(time.RFC3339),
			Agent:       "sast-agent",
			Action:      "scan_completed",
			FindingID:   "",
			Description: fmt.Sprintf("Found %d code vulnerabilities", len(input.SASTFindings)),
		})
	}

	if len(input.SCAFindings) > 0 {
		timeline = append(timeline, TimelineEntry{
			Timestamp:   now.Add(-2 * time.Minute).Format(time.RFC3339),
			Agent:       "sca-agent",
			Action:      "scan_completed",
			FindingID:   "",
			Description: fmt.Sprintf("Found %d dependency vulnerabilities", len(input.SCAFindings)),
		})
	}

	if len(input.SecretsFindings) > 0 {
		timeline = append(timeline, TimelineEntry{
			Timestamp:   now.Add(-1 * time.Minute).Format(time.RFC3339),
			Agent:       "secrets-agent",
			Action:      "scan_completed",
			FindingID:   "",
			Description: fmt.Sprintf("Found %d exposed secrets", len(input.SecretsFindings)),
		})
	}

	timeline = append(timeline, TimelineEntry{
		Timestamp:   now.Format(time.RFC3339),
		Agent:       "aggregator-agent",
		Action:      "aggregation_completed",
		FindingID:   "",
		Description: "Consolidated and prioritized findings",
	})

	return timeline
}

func convertFindingsToMaps(findings []ConsolidatedFinding) []map[string]interface{} {
	result := make([]map[string]interface{}, len(findings))
	for i, f := range findings {
		result[i] = findingToMap(f)
	}
	return result
}

func findingToMap(f ConsolidatedFinding) map[string]interface{} {
	return map[string]interface{}{
		"id":              f.ID,
		"original_ids":    f.OriginalIDs,
		"type":            f.Type,
		"category":        f.Category,
		"severity":        f.Severity,
		"priority":        f.Priority,
		"title":           f.Title,
		"description":     f.Description,
		"file_path":       f.FilePath,
		"line_number":     f.LineNumber,
		"component_name":  f.ComponentName,
		"cwe":             f.CWE,
		"owasp":           f.OWASP,
		"cvss":            f.CVSS,
		"cve":             f.CVE,
		"business_impact": f.BusinessImpact,
		"exploitability":  f.Exploitability,
		"risk_level":      f.RiskLevel,
		"recommendation":  f.Recommendation,
		"fix_complexity":  f.FixComplexity,
		"sources":         f.Sources,
		"confidence":      f.Confidence,
		"first_detected":  f.FirstDetected,
		"tags":            f.Tags,
	}
}
