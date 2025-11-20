package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func DeduplicateFindings(input DeduplicateInput) (*DeduplicationOutput, error) {
	if input.Strategy == "" {
		input.Strategy = "similar"
	}

	findings := make([]ConsolidatedFinding, len(input.Findings))
	for i, f := range input.Findings {
		findings[i] = mapToFinding(f)
	}

	originalCount := len(findings)

	var deduplicated []ConsolidatedFinding
	var dedupGroups []DedupGroup

	switch input.Strategy {
	case "exact":
		deduplicated, dedupGroups = deduplicateExact(findings)
	case "similar":
		deduplicated, dedupGroups = deduplicateSimilar(findings)
	case "aggressive":
		deduplicated, dedupGroups = deduplicateAggressive(findings)
	default:
		deduplicated, dedupGroups = deduplicateSimilar(findings)
	}

	return &DeduplicationOutput{
		DeduplicatedFindings: deduplicated,
		DuplicatesRemoved:    originalCount - len(deduplicated),
		DedupGroups:          dedupGroups,
	}, nil
}

func deduplicateExact(findings []ConsolidatedFinding) ([]ConsolidatedFinding, []DedupGroup) {
	fingerprints := make(map[string][]ConsolidatedFinding)

	for _, finding := range findings {
		fp := generateFingerprint(finding)
		fingerprints[fp] = append(fingerprints[fp], finding)
	}

	var consolidated []ConsolidatedFinding
	var groups []DedupGroup

	for fp, group := range fingerprints {
		if len(group) == 1 {
			consolidated = append(consolidated, group[0])
		} else {
			merged := mergeFindings(group)
			consolidated = append(consolidated, merged)
			groups = append(groups, DedupGroup{
				Fingerprint: fp,
				Count:       len(group),
				MergedInto:  merged.ID,
			})
		}
	}

	return consolidated, groups
}

func deduplicateSimilar(findings []ConsolidatedFinding) ([]ConsolidatedFinding, []DedupGroup) {
	exact, exactGroups := deduplicateExact(findings)

	groups := make(map[string][]ConsolidatedFinding)

	for _, finding := range exact {
		key := fmt.Sprintf("%s:%s", normalizePath(finding.FilePath), finding.Type)
		groups[key] = append(groups[key], finding)
	}

	var deduplicated []ConsolidatedFinding
	var dedupGroups []DedupGroup
	dedupGroups = append(dedupGroups, exactGroups...)

	for key, group := range groups {
		if len(group) <= 3 {
			deduplicated = append(deduplicated, group...)
		} else {
			grouped := groupSimilarFindings(group)
			deduplicated = append(deduplicated, grouped)
			dedupGroups = append(dedupGroups, DedupGroup{
				Fingerprint: key,
				Count:       len(group),
				MergedInto:  grouped.ID,
			})
		}
	}

	return deduplicated, dedupGroups
}

func deduplicateAggressive(findings []ConsolidatedFinding) ([]ConsolidatedFinding, []DedupGroup) {
	similar, similarGroups := deduplicateSimilar(findings)

	cveGroups := make(map[string][]ConsolidatedFinding)

	for _, finding := range similar {
		if finding.CVE != "" {
			cveGroups[finding.CVE] = append(cveGroups[finding.CVE], finding)
		}
	}

	var deduplicated []ConsolidatedFinding
	var dedupGroups []DedupGroup
	dedupGroups = append(dedupGroups, similarGroups...)

	processed := make(map[string]bool)

	for cve, group := range cveGroups {
		if len(group) > 1 {
			merged := mergeDependencyCVEs(group)
			deduplicated = append(deduplicated, merged)
			dedupGroups = append(dedupGroups, DedupGroup{
				Fingerprint: cve,
				Count:       len(group),
				MergedInto:  merged.ID,
			})
			for _, f := range group {
				processed[f.ID] = true
			}
		}
	}

	for _, finding := range similar {
		if !processed[finding.ID] {
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated, dedupGroups
}

func generateFingerprint(finding ConsolidatedFinding) string {
	normalizedPath := normalizePath(finding.FilePath)
	data := fmt.Sprintf("%s:%d:%s", normalizedPath, finding.LineNumber, finding.Type)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func mergeFindings(findings []ConsolidatedFinding) ConsolidatedFinding {
	sort.Slice(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
	})

	base := findings[0]

	originalIDs := extractIDs(findings)
	sources := extractSources(findings)
	description := mergeDescriptions(findings)

	merged := base
	merged.ID = generateUUID()
	merged.OriginalIDs = originalIDs
	merged.Sources = sources
	merged.Description = description
	merged.Confidence = "high"

	return merged
}

func groupSimilarFindings(findings []ConsolidatedFinding) ConsolidatedFinding {
	base := findings[0]

	lineNumbers := []int{}
	originalIDs := []string{}
	for _, f := range findings {
		lineNumbers = append(lineNumbers, f.LineNumber)
		originalIDs = append(originalIDs, f.ID)
	}

	grouped := base
	grouped.ID = generateUUID()
	grouped.OriginalIDs = originalIDs
	grouped.Title = fmt.Sprintf("%s (found in %d locations)", base.Title, len(findings))
	grouped.Description = fmt.Sprintf("%s\n\nDetected at lines: %v", base.Description, lineNumbers)
	grouped.LineNumber = lineNumbers[0]
	grouped.Tags = append(grouped.Tags, "multiple-occurrences")

	return grouped
}

func mergeDependencyCVEs(findings []ConsolidatedFinding) ConsolidatedFinding {
	base := findings[0]

	affectedDeps := []string{}
	originalIDs := []string{}
	for _, f := range findings {
		affectedDeps = append(affectedDeps, f.ComponentName)
		originalIDs = append(originalIDs, f.ID)
	}

	merged := base
	merged.ID = generateUUID()
	merged.OriginalIDs = originalIDs
	merged.Title = fmt.Sprintf("%s affects %d dependencies", base.CVE, len(findings))
	merged.Description = fmt.Sprintf("%s\n\nAffected packages: %s", base.Description, strings.Join(affectedDeps, ", "))
	merged.ComponentName = strings.Join(affectedDeps, ", ")
	merged.Sources = []string{"sca"}
	merged.Tags = append(merged.Tags, "transitive-dependency")

	return merged
}
