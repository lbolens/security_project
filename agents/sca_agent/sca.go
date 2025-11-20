package main

import (
	"fmt"
	"sort"
	"time"

	"sca_agent/analyzer"
	"sca_agent/trivy"
	"sca_agent/utils"

	"github.com/google/uuid"
)

type SCAScanner struct {
	trivyClient  *trivy.Client
	ollamaClient *analyzer.OllamaClient
}

func NewSCAScanner() *SCAScanner {
	return &SCAScanner{
		trivyClient:  trivy.NewClient(),
		ollamaClient: analyzer.NewOllamaClient(),
	}
}

func (s *SCAScanner) ScanDependencies(input ScanDependenciesInput) (*ScanOutput, error) {
	startTime := time.Now()

	if err := s.trivyClient.CheckInstalled(); err != nil {
		return nil, fmt.Errorf("trivy check failed: %w", err)
	}

	scanConfig := trivy.ScanConfig{
		Severity:        input.Config.Severity,
		SkipDevDeps:     input.Config.SkipDevDeps,
		CheckDirectOnly: input.Config.CheckDirectOnly,
		TimeoutSeconds:  input.Config.TimeoutSeconds,
	}

	if scanConfig.TimeoutSeconds == 0 {
		scanConfig.TimeoutSeconds = 300
	}

	report, err := s.trivyClient.Scan(input.ProjectPath, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	findings := s.convertToFindings(report)

	if input.Config.AssessExploitability {
		findings = s.assessFindings(findings, input.ProjectContext)
	}

	for i := range findings {
		rec, err := s.ollamaClient.GenerateRecommendation(
			analyzer.FindingInput{
				CVE:              findings[i].CVE,
				PackageName:      findings[i].PackageName,
				InstalledVersion: findings[i].InstalledVersion,
				FixedVersion:     findings[i].FixedVersion,
				CVSS:             findings[i].CVSS,
				Severity:         findings[i].Severity,
				Description:      findings[i].Description,
				PackageType:      findings[i].PackageType,
			},
			analyzer.ProjectContextInput{
				Type:         input.ProjectContext.Type,
				Domain:       input.ProjectContext.Domain,
				Frameworks:   input.ProjectContext.Frameworks,
				IsProduction: input.ProjectContext.IsProduction,
				HasTests:     input.ProjectContext.HasTests,
			},
		)
		if err == nil {
			findings[i].Recommendation = rec
		}
	}

	findings = s.filterByRiskLevel(findings, input.Config.Severity)
	findings = s.sortByPriority(findings)

	if input.Config.MaxFindings > 0 && len(findings) > input.Config.MaxFindings {
		findings = findings[:input.Config.MaxFindings]
	}

	durationMs := time.Since(startTime).Milliseconds()

	summary := ScanSummary{
		DependenciesChecked:   s.countTotalDependencies(report),
		VulnerableDeps:        s.countUniqueDependencies(findings),
		FindingsBySeverity:    s.countBySeverity(findings),
		FindingsByPackageType: s.countByPackageType(findings),
		DurationMs:            durationMs,
		TrivyVersion:          s.trivyClient.GetVersion(),
	}

	return &ScanOutput{
		Findings:    findings,
		ScanSummary: summary,
		Errors:      []string{},
	}, nil
}

func (s *SCAScanner) convertToFindings(report *trivy.Report) []Finding {
	findings := []Finding{}

	for _, result := range report.Results {
		if result.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			cvssScore := trivy.ExtractCVSSScore(vuln.CVSS)
			severity := trivy.NormalizeSeverity(vuln.Severity)
			packageType := trivy.NormalizePackageType(result.Type)

			finding := Finding{
				ID:               uuid.New().String(),
				Type:             "vulnerable-dependency",
				Severity:         severity,
				Title:            trivy.ExtractTitle(vuln),
				Description:      vuln.Description,
				PackageName:      vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				PackageType:      packageType,
				CVE:              vuln.VulnerabilityID,
				CVSS:             cvssScore,
				CWE:              vuln.CweIDs,
				References:       vuln.References,
				PublishedDate:    vuln.PublishedDate,
				Source:           "trivy",
				Timestamp:        time.Now().Format(time.RFC3339),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *SCAScanner) assessFindings(findings []Finding, projectContext ProjectContext) []Finding {
	assessed := make([]Finding, len(findings))

	for i, finding := range findings {
		assessment, err := s.ollamaClient.AssessExploitability(
			analyzer.FindingInput{
				CVE:              finding.CVE,
				PackageName:      finding.PackageName,
				InstalledVersion: finding.InstalledVersion,
				FixedVersion:     finding.FixedVersion,
				CVSS:             finding.CVSS,
				Severity:         finding.Severity,
				Description:      finding.Description,
				PackageType:      finding.PackageType,
			},
			analyzer.ProjectContextInput{
				Type:         projectContext.Type,
				Domain:       projectContext.Domain,
				Frameworks:   projectContext.Frameworks,
				IsProduction: projectContext.IsProduction,
				HasTests:     projectContext.HasTests,
			},
		)

		if err == nil {
			finding.Exploitability = assessment.Reasoning
			finding.RiskLevel = assessment.RiskLevel

			if !assessment.Exploitable && assessment.Confidence == "high" {
				finding.Severity = utils.DowngradeSeverity(finding.Severity)
			}
		} else {
			finding.RiskLevel = finding.Severity
		}

		assessed[i] = finding
	}

	return assessed
}

func (s *SCAScanner) countTotalDependencies(report *trivy.Report) int {
	total := 0
	for _, result := range report.Results {
		if result.Vulnerabilities != nil {
			total += len(result.Vulnerabilities)
		}
	}
	return total
}

func (s *SCAScanner) filterByRiskLevel(findings []Finding, minRiskLevel string) []Finding {
	minWeight := utils.SeverityWeight(minRiskLevel)
	filtered := []Finding{}

	for _, finding := range findings {
		riskLevel := finding.RiskLevel
		if riskLevel == "" {
			riskLevel = finding.Severity
		}

		if utils.SeverityWeight(riskLevel) >= minWeight {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func (s *SCAScanner) sortByPriority(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CVSS != sorted[j].CVSS {
			return sorted[i].CVSS > sorted[j].CVSS
		}

		severityI := utils.SeverityWeight(sorted[i].Severity)
		severityJ := utils.SeverityWeight(sorted[j].Severity)

		return severityI > severityJ
	})

	return sorted
}

func (s *SCAScanner) countUniqueDependencies(findings []Finding) int {
	packages := make(map[string]bool)
	for _, finding := range findings {
		packages[finding.PackageName] = true
	}
	return len(packages)
}

func (s *SCAScanner) countBySeverity(findings []Finding) map[string]int {
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

func (s *SCAScanner) countByPackageType(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.PackageType]++
	}
	return counts
}

func (s *SCAScanner) AssessExploitability(input AssessExploitabilityInput) (*ExploitabilityAssessment, error) {
	result, err := s.ollamaClient.AssessExploitability(
		analyzer.FindingInput{
			CVE:              input.Finding.CVE,
			PackageName:      input.Finding.PackageName,
			InstalledVersion: input.Finding.InstalledVersion,
			FixedVersion:     input.Finding.FixedVersion,
			CVSS:             input.Finding.CVSS,
			Severity:         input.Finding.Severity,
			Description:      input.Finding.Description,
			PackageType:      input.Finding.PackageType,
		},
		analyzer.ProjectContextInput{
			Type:         input.ProjectContext.Type,
			Domain:       input.ProjectContext.Domain,
			Frameworks:   input.ProjectContext.Frameworks,
			IsProduction: input.ProjectContext.IsProduction,
			HasTests:     input.ProjectContext.HasTests,
		},
	)

	if err != nil {
		return nil, err
	}

	return &ExploitabilityAssessment{
		Exploitable:    result.Exploitable,
		Confidence:     result.Confidence,
		Reasoning:      result.Reasoning,
		RiskLevel:      result.RiskLevel,
		AttackScenario: result.AttackScenario,
	}, nil
}

func (s *SCAScanner) GenerateFixRecommendation(input GenerateFixRecommendationInput) (*GenerateFixRecommendationOutput, error) {
	rec, err := s.ollamaClient.GenerateRecommendation(
		analyzer.FindingInput{
			CVE:              input.Finding.CVE,
			PackageName:      input.Finding.PackageName,
			InstalledVersion: input.Finding.InstalledVersion,
			FixedVersion:     input.Finding.FixedVersion,
			CVSS:             input.Finding.CVSS,
			Severity:         input.Finding.Severity,
			Description:      input.Finding.Description,
			PackageType:      input.Finding.PackageType,
		},
		analyzer.ProjectContextInput{
			Type:         input.ProjectContext.Type,
			Domain:       input.ProjectContext.Domain,
			Frameworks:   input.ProjectContext.Frameworks,
			IsProduction: input.ProjectContext.IsProduction,
			HasTests:     input.ProjectContext.HasTests,
		},
	)

	if err != nil {
		return nil, err
	}

	return &GenerateFixRecommendationOutput{
		Recommendation: rec,
	}, nil
}

func (s *SCAScanner) UpdateTrivyDB() (*UpdateTrivyDBOutput, error) {
	if err := s.trivyClient.UpdateDB(); err != nil {
		return &UpdateTrivyDBOutput{
			Success: false,
		}, err
	}

	return &UpdateTrivyDBOutput{
		Success:   true,
		UpdatedAt: time.Now().Format(time.RFC3339),
		DBVersion: s.trivyClient.GetVersion(),
	}, nil
}
