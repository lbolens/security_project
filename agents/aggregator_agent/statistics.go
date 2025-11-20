package main

import (
	"sort"
)

func GenerateStatistics(input StatisticsInput) (*StatisticsOutput, error) {
	if input.TopN == 0 {
		input.TopN = 10
	}

	findings := make([]ConsolidatedFinding, len(input.Findings))
	for i, f := range input.Findings {
		findings[i] = mapToFinding(f)
	}

	stats := buildStatistics(findings, input.TopN)

	return &StatisticsOutput{
		Statistics: stats,
	}, nil
}

func buildStatistics(findings []ConsolidatedFinding, topN int) Statistics {
	stats := Statistics{
		ByCategory:  make(map[string]int),
		BySeverity:  make(map[string]int),
		BySource:    make(map[string]int),
		ByFile:      make(map[string]int),
		ByComponent: make(map[string]int),
	}

	typeCounts := make(map[string]int)

	for _, finding := range findings {
		stats.ByCategory[finding.Category]++
		stats.BySeverity[finding.Severity]++
		stats.ByFile[finding.FilePath]++

		if finding.ComponentName != "" {
			stats.ByComponent[finding.ComponentName]++
		}

		for _, source := range finding.Sources {
			stats.BySource[source]++
		}

		typeCounts[finding.Type]++
	}

	stats.TopVulnerabilities = getTopVulnerabilities(typeCounts, topN)
	stats.MostAffectedFiles = getMostAffectedFiles(stats.ByFile, topN)
	stats.CoverageMetrics = calculateCoverageMetrics(findings, stats.ByFile)

	return stats
}

func getTopVulnerabilities(typeCounts map[string]int, topN int) []VulnerabilityCount {
	var vulnerabilities []VulnerabilityCount

	for vulnType, count := range typeCounts {
		vulnerabilities = append(vulnerabilities, VulnerabilityCount{
			Type:  vulnType,
			Count: count,
		})
	}

	sort.Slice(vulnerabilities, func(i, j int) bool {
		return vulnerabilities[i].Count > vulnerabilities[j].Count
	})

	if len(vulnerabilities) > topN {
		vulnerabilities = vulnerabilities[:topN]
	}

	return vulnerabilities
}

func getMostAffectedFiles(fileCounts map[string]int, topN int) []FileCount {
	var files []FileCount

	for filePath, count := range fileCounts {
		files = append(files, FileCount{
			FilePath: filePath,
			Count:    count,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Count > files[j].Count
	})

	if len(files) > topN {
		files = files[:topN]
	}

	return files
}

func calculateCoverageMetrics(findings []ConsolidatedFinding, fileMap map[string]int) CoverageMetrics {
	filesScanned := 100
	filesWithIssues := len(fileMap)

	linesAnalyzed := 0
	for _, finding := range findings {
		if finding.LineNumber > linesAnalyzed {
			linesAnalyzed = finding.LineNumber
		}
	}

	coveragePercent := 0.0
	if filesScanned > 0 {
		coveragePercent = roundFloat(float64(filesWithIssues) / float64(filesScanned) * 100)
	}

	return CoverageMetrics{
		FilesScanned:    filesScanned,
		FilesWithIssues: filesWithIssues,
		CoveragePercent: coveragePercent,
		LinesAnalyzed:   linesAnalyzed,
	}
}
