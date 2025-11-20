package main

import (
	"fmt"
	"sort" // Added for sort.Slice
	"time"

	"secrets_agent/analyzer"
	"secrets_agent/gitleaks"
	"secrets_agent/utils"

	"github.com/google/uuid"
)

type SecretsScanner struct {
	gitleaksClient *gitleaks.Client
	ollamaClient   *analyzer.OllamaClient
}

func NewSecretsScanner() *SecretsScanner {
	return &SecretsScanner{
		gitleaksClient: gitleaks.NewClient(),
		ollamaClient:   analyzer.NewOllamaClient(),
	}
}

func (s *SecretsScanner) ScanSecrets(input ScanSecretsInput) (*ScanOutput, error) {
	startTime := time.Now()

	if err := s.gitleaksClient.CheckInstalled(); err != nil {
		return nil, fmt.Errorf("gitleaks check failed: %w", err)
	}

	scanConfig := gitleaks.ScanConfig{
		EntropyThreshold: input.Config.EntropyThreshold,
		ScanGitHistory:   input.Config.ScanGitHistory,
		MaxDepth:         input.Config.MaxDepth,
		BaselinePath:     input.Config.BaselinePath,
		ConfigPath:       input.Config.ConfigPath,
		Verbose:          false,
	}

	report, err := s.gitleaksClient.ScanFilesystem(input.ProjectPath, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("gitleaks filesystem scan failed: %w", err)
	}

	filesScanned := len(*report)
	gitHistoryScanned := false

	if input.Config.ScanGitHistory {
		historyReport, err := s.gitleaksClient.ScanGitHistory(input.ProjectPath, scanConfig)
		if err == nil {
			*report = append(*report, *historyReport...)
			gitHistoryScanned = true
		}
	}

	findings := s.convertToFindings(report, input.ProjectContext)

	secretsFound := len(findings)

	if input.Config.ValidateWithOllama {
		findings = s.validateFindings(findings, input.ProjectContext)
	}

	for i := range findings {
		rec, err := s.ollamaClient.GenerateRemediation(
			analyzer.RemediationInput{
				SecretType: findings[i].SecretType,
				FilePath:   findings[i].FilePath,
				CommitHash: findings[i].CommitHash,
				IsInGit:    findings[i].CommitHash != "",
			},
			analyzer.ProjectContextInput{
				Type:         input.ProjectContext.Type,
				Domain:       input.ProjectContext.Domain,
				IsProduction: input.ProjectContext.IsProduction,
			},
		)
		if err == nil {
			findings[i].Recommendation = rec
		}
	}

	findings = s.sortByPriority(findings)

	if input.Config.MaxFindings > 0 && len(findings) > input.Config.MaxFindings {
		findings = findings[:input.Config.MaxFindings]
	}

	durationMs := time.Since(startTime).Milliseconds()

	summary := ScanSummary{
		FilesScanned:      filesScanned,
		SecretsFound:      secretsFound,
		ActiveSecrets:     s.countActiveSecrets(findings),
		FindingsByType:    s.countByType(findings),
		DurationMs:        durationMs,
		GitleaksVersion:   s.gitleaksClient.GetVersion(),
		GitHistoryScanned: gitHistoryScanned,
	}

	return &ScanOutput{
		Findings:    findings,
		ScanSummary: summary,
		Errors:      []string{},
	}, nil
}

func (s *SecretsScanner) convertToFindings(report *gitleaks.Report, projectContext ProjectContext) []Finding {
	findings := []Finding{}

	for _, glFinding := range *report {
		secretType := gitleaks.DetermineSecretType(glFinding.RuleID, glFinding.Tags)
		redactedSecret := gitleaks.RedactSecret(glFinding.Secret)
		severity := gitleaks.CalculateSeverity(secretType, projectContext.IsProduction)

		title := fmt.Sprintf("%s exposed in %s", glFinding.Description, glFinding.File)
		description := fmt.Sprintf("Detected %s in file %s at line %d", glFinding.Description, glFinding.File, glFinding.StartLine)

		finding := Finding{
			ID:           uuid.New().String(),
			Type:         "exposed-secret",
			Severity:     severity,
			Title:        title,
			Description:  description,
			FilePath:     glFinding.File,
			LineNumber:   glFinding.StartLine,
			SecretType:   secretType,
			Secret:       redactedSecret,
			Match:        glFinding.Match,
			Entropy:      glFinding.Entropy,
			CommitHash:   glFinding.Commit,
			CommitAuthor: glFinding.Author,
			CommitDate:   glFinding.Date,
			RuleID:       glFinding.RuleID,
			Source:       "gitleaks",
			Timestamp:    time.Now().Format(time.RFC3339),
		}

		findings = append(findings, finding)
	}

	return findings
}

func (s *SecretsScanner) validateFindings(findings []Finding, projectContext ProjectContext) []Finding {
	validated := []Finding{}

	for _, finding := range findings {
		codeContext, err := analyzer.ExtractCodeContext(finding.FilePath, finding.LineNumber, 5)
		if err != nil {
			codeContext = ""
		}

		validation, err := s.ollamaClient.ValidateSecret(
			analyzer.FindingInput{
				SecretType: finding.SecretType,
				FilePath:   finding.FilePath,
				LineNumber: finding.LineNumber,
				Secret:     finding.Secret,
				Entropy:    finding.Entropy,
				Match:      finding.Match,
			},
			codeContext,
			analyzer.ProjectContextInput{
				Type:         projectContext.Type,
				Domain:       projectContext.Domain,
				IsProduction: projectContext.IsProduction,
			},
		)

		if err == nil {
			finding.IsActive = validation.IsActive
			finding.Impact = validation.Impact

			if !validation.IsActive && validation.Confidence == "high" {
				continue
			}
		} else {
			finding.IsActive = true
		}

		validated = append(validated, finding)
	}

	return validated
}

func (s *SecretsScanner) ValidateSecret(input ValidateSecretInput) (*SecretValidation, error) {
	result, err := s.ollamaClient.ValidateSecret(
		analyzer.FindingInput{
			SecretType: input.Finding.SecretType,
			FilePath:   input.Finding.FilePath,
			LineNumber: input.Finding.LineNumber,
			Secret:     input.Finding.Secret,
			Entropy:    input.Finding.Entropy,
			Match:      input.Finding.Match,
		},
		input.CodeContext,
		analyzer.ProjectContextInput{
			Type:         input.ProjectContext.Type,
			Domain:       input.ProjectContext.Domain,
			IsProduction: input.ProjectContext.IsProduction,
		},
	)

	if err != nil {
		return nil, err
	}

	return &SecretValidation{
		IsActive:       result.IsActive,
		Confidence:     result.Confidence,
		Reasoning:      result.Reasoning,
		Impact:         result.Impact,
		Recommendation: result.Recommendation,
	}, nil
}

func (s *SecretsScanner) GenerateRemediation(input GenerateRemediationInput) (*GenerateRemediationOutput, error) {
	rec, err := s.ollamaClient.GenerateRemediation(
		analyzer.RemediationInput{
			SecretType: input.Finding.SecretType,
			FilePath:   input.Finding.FilePath,
			CommitHash: input.Finding.CommitHash,
			IsInGit:    input.Finding.CommitHash != "",
		},
		analyzer.ProjectContextInput{
			Type:         input.ProjectContext.Type,
			Domain:       input.ProjectContext.Domain,
			IsProduction: input.ProjectContext.IsProduction,
		},
	)

	if err != nil {
		return nil, err
	}

	return &GenerateRemediationOutput{
		Remediation: rec,
	}, nil
}

func (s *SecretsScanner) ScanGitHistory(input ScanGitHistoryInput) (*ScanGitHistoryOutput, error) {
	scanConfig := gitleaks.ScanConfig{
		MaxDepth: input.MaxDepth,
	}

	report, err := s.gitleaksClient.ScanGitHistory(input.ProjectPath, scanConfig)
	if err != nil {
		return nil, fmt.Errorf("git history scan failed: %w", err)
	}

	findings := s.convertToFindings(report, ProjectContext{IsProduction: false})

	return &ScanGitHistoryOutput{
		Findings:       findings,
		CommitsScanned: len(*report),
	}, nil
}

func (s *SecretsScanner) sortByPriority(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		priorityI := utils.SecretTypePriority(sorted[i].SecretType)
		priorityJ := utils.SecretTypePriority(sorted[j].SecretType)

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

func (s *SecretsScanner) countActiveSecrets(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.IsActive {
			count++
		}
	}
	return count
}

func (s *SecretsScanner) countByType(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.SecretType]++
	}
	return counts
}
