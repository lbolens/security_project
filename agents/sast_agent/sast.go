package main

import (
	"fmt"
	"time"

	"sast_agent/analyzer"
	"sast_agent/semgrep"
	"sast_agent/utils"

	"github.com/google/uuid"
)

type SASTScanner struct {
	semgrepClient *semgrep.Client
	ollamaClient  *analyzer.OllamaClient
}

func NewSASTScanner() *SASTScanner {
	return &SASTScanner{
		semgrepClient: semgrep.NewClient(),
		ollamaClient:  analyzer.NewOllamaClient(),
	}
}

func (s *SASTScanner) ScanProject(input ScanProjectInput) (*ScanOutput, error) {
	startTime := time.Now()

	if err := s.semgrepClient.CheckInstalled(); err != nil {
		return nil, fmt.Errorf("semgrep check failed: %w", err)
	}

	scanConfig := semgrep.ScanConfig{
		Rules:          input.Config.Rules,
		Severity:       input.Config.Severity,
		SkipPatterns:   input.Config.SkipPatterns,
		TimeoutSeconds: input.Config.TimeoutSeconds,
	}

	if scanConfig.TimeoutSeconds == 0 {
		scanConfig.TimeoutSeconds = 300
	}

	report, err := s.semgrepClient.Scan(input.ProjectPath, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("semgrep scan failed: %w", err)
	}

	findings := s.convertToFindings(report)

	if input.Config.ValidateWithOllama {
		findings = s.validateFindings(findings, input.ProjectContext, input.Config.ConfidenceThreshold)
	}

	if input.Config.GenerateRecommendations {
		for i := range findings {
			rec, err := s.ollamaClient.GenerateRecommendation(analyzer.RecommendationInput{
				Type:        findings[i].Type,
				FilePath:    findings[i].FilePath,
				LineNumber:  findings[i].LineNumber,
				CodeSnippet: findings[i].CodeSnippet,
				CWE:         findings[i].CWE,
				OWASP:       findings[i].OWASP,
			})
			if err == nil {
				findings[i].Recommendation = rec
			}
		}
	}

	// Apply max findings limit
	if input.Config.MaxFindings > 0 && len(findings) > input.Config.MaxFindings {
		findings = findings[:input.Config.MaxFindings]
	}

	durationMs := time.Since(startTime).Milliseconds()

	// Count findings by severity and type
	findingsBySeverity := make(map[string]int)
	findingsByType := make(map[string]int)
	for _, f := range findings {
		findingsBySeverity[f.Severity]++
		findingsByType[f.Type]++
	}

	summary := ScanSummary{
		FilesScanned:       len(report.Paths.Scanned),
		RulesApplied:       len(report.Results),
		DurationMs:         durationMs,
		FindingsBySeverity: findingsBySeverity,
		FindingsByType:     findingsByType,
		SemgrepVersion:     s.semgrepClient.GetVersion(),
	}

	errors := []string{}
	for _, e := range report.Errors {
		errors = append(errors, e.Message)
	}

	return &ScanOutput{
		Findings:    findings,
		ScanSummary: summary,
		Errors:      errors,
	}, nil
}

func (s *SASTScanner) convertToFindings(report *semgrep.Report) []Finding {
	findings := []Finding{}

	for _, result := range report.Results {
		vulnType := semgrep.ExtractVulnType(result.CheckID)
		severity := semgrep.MapSemgrepSeverity(result.Extra.Severity, result.Extra.Metadata)
		confidence := semgrep.MapConfidence(result.Extra.Metadata.Confidence)

		cwe := ""
		if len(result.Extra.Metadata.CWE) > 0 {
			cwe = result.Extra.Metadata.CWE[0]
		}

		owasp := ""
		if len(result.Extra.Metadata.OWASP) > 0 {
			owasp = result.Extra.Metadata.OWASP[0]
		}

		finding := Finding{
			ID:            uuid.New().String(),
			Type:          vulnType,
			Severity:      severity,
			Title:         semgrep.ExtractTitle(result.Extra.Message),
			Description:   result.Extra.Message,
			FilePath:      result.Path,
			LineNumber:    result.Start.Line,
			EndLineNumber: result.End.Line,
			CodeSnippet:   result.Extra.Lines,
			Confidence:    confidence,
			CWE:           cwe,
			OWASP:         owasp,
			CheckID:       result.CheckID,
			ValidatedBy:   "semgrep",
			Timestamp:     time.Now().Format(time.RFC3339),
		}

		findings = append(findings, finding)
	}

	return findings
}

func (s *SASTScanner) validateFindings(findings []Finding, projectContext ProjectContext, confidenceThreshold string) []Finding {
	validated := []Finding{}

	for _, finding := range findings {
		if finding.Confidence == "high" {
			validated = append(validated, finding)
			continue
		}

		codeContext, err := analyzer.ExtractCodeContext(finding.FilePath, finding.LineNumber, 10)
		if err != nil {
			validated = append(validated, finding)
			continue
		}

		validation, err := s.ollamaClient.ValidateFinding(
			analyzer.FindingInput{
				Type:        finding.Type,
				FilePath:    finding.FilePath,
				LineNumber:  finding.LineNumber,
				CodeSnippet: finding.CodeSnippet,
				CheckID:     finding.CheckID,
			},
			codeContext,
			analyzer.ProjectContextInput{
				Type:       projectContext.Type,
				Domain:     projectContext.Domain,
				Frameworks: projectContext.Frameworks,
			},
		)

		if err != nil {
			validated = append(validated, finding)
			continue
		}

		if validation.IsVulnerable {
			finding.Exploitability = validation.Exploitability
			finding.RiskLevel = validation.RiskLevel
			finding.Confidence = validation.Confidence
			finding.ValidatedBy = "semgrep+ollama"
			validated = append(validated, finding)
		}
	}

	return validated
}

func (s *SASTScanner) ValidateFinding(input ValidateFindingInput) (*ValidationResult, error) {
	result, err := s.ollamaClient.ValidateFinding(
		analyzer.FindingInput{
			Type:        input.Finding.Type,
			FilePath:    input.Finding.FilePath,
			LineNumber:  input.Finding.LineNumber,
			CodeSnippet: input.Finding.CodeSnippet,
			CheckID:     input.Finding.CheckID,
		},
		input.CodeContext,
		analyzer.ProjectContextInput{
			Type:       input.ProjectContext.Type,
			Domain:     input.ProjectContext.Domain,
			Frameworks: input.ProjectContext.Frameworks,
		},
	)
	if err != nil {
		return nil, err
	}
	return &ValidationResult{
		IsVulnerable:   result.IsVulnerable,
		Confidence:     result.Confidence,
		Reasoning:      result.Reasoning,
		RiskLevel:      result.RiskLevel,
		Exploitability: result.Exploitability,
	}, nil
}

func (s *SASTScanner) GenerateFixRecommendation(input GenerateFixRecommendationInput) (*GenerateFixRecommendationOutput, error) {
	rec, err := s.ollamaClient.GenerateRecommendation(analyzer.RecommendationInput{
		Type:        input.Finding.Type,
		FilePath:    input.Finding.FilePath,
		LineNumber:  input.Finding.LineNumber,
		CodeSnippet: input.Finding.CodeSnippet,
		CWE:         input.Finding.CWE,
		OWASP:       input.Finding.OWASP,
	})

	if err != nil {
		return nil, err
	}

	return &GenerateFixRecommendationOutput{
		Recommendation: rec,
	}, nil
}

func (s *SASTScanner) GetAvailableRulesets() (*GetAvailableRulesetsOutput, error) {
	rulesets := []Ruleset{
		{
			Name:        "p/security-audit",
			Description: "General security rules for multiple languages",
			RuleCount:   1000,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "Ruby", "PHP"},
		},
		{
			Name:        "p/owasp-top-ten",
			Description: "OWASP Top 10 security vulnerabilities",
			RuleCount:   500,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "Ruby", "PHP"},
		},
		{
			Name:        "p/cwe-top-25",
			Description: "CWE Top 25 Most Dangerous Software Weaknesses",
			RuleCount:   300,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "C", "C++"},
		},
		{
			Name:        "p/sql-injection",
			Description: "SQL injection detection rules",
			RuleCount:   50,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "PHP", "Ruby"},
		},
		{
			Name:        "p/xss",
			Description: "Cross-site scripting (XSS) detection",
			RuleCount:   40,
			Languages:   []string{"JavaScript", "TypeScript", "Go", "Python", "Java", "PHP"},
		},
		{
			Name:        "p/command-injection",
			Description: "OS command injection vulnerabilities",
			RuleCount:   30,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "PHP", "Ruby"},
		},
		{
			Name:        "p/crypto",
			Description: "Cryptographic vulnerabilities and weak algorithms",
			RuleCount:   60,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "C", "C++"},
		},
		{
			Name:        "p/jwt",
			Description: "JWT security vulnerabilities",
			RuleCount:   20,
			Languages:   []string{"Go", "Python", "JavaScript", "TypeScript", "Java"},
		},
		{
			Name:        "p/smart-contracts",
			Description: "Smart contract security (Solidity)",
			RuleCount:   80,
			Languages:   []string{"Solidity"},
		},
	}

	return &GetAvailableRulesetsOutput{
		Rulesets: rulesets,
	}, nil
}

func convertFindings(findings []Finding) []utils.Finding {
	result := make([]utils.Finding, len(findings))
	for i, f := range findings {
		result[i] = utils.Finding{
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Type:       f.Type,
		}
	}
	return result
}

func convertBackFindings(utilFindings []utils.Finding) []Finding {
	return []Finding{}
}
