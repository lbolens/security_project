package main

import (
	"fmt"
	"os"
	"path/filepath"
	"report_agent/formatters"
	"report_agent/types"
	"security_project/pkg/ollama"
	"time"
)

type Formatter interface {
	Format(data types.ReportData) ([]byte, error)
}

func GenerateReports(input types.ReportInput) (types.ReportOutput, error) {
	// 1. Prepare data
	reportData := types.ReportData{
		AggregatedReport: input.AggregatedReport,
		RemediationPlans: input.RemediationPlans,
		ProjectProfile:   input.ProjectProfile,
		ProjectContext:   input.ProjectContext,
	}

	// 2. Generate compliance mapping (Stub)
	reportData.Compliance = types.ComplianceMapping{
		ComplianceScore: 85.0,
	}

	// 3. Generate Executive Summary
	if input.Config.IncludeExecutiveSummary {
		ollamaURL := os.Getenv("OLLAMA_URL")
		ollamaModel := os.Getenv("OLLAMA_MODEL")

		client := ollama.NewClient(ollamaURL, ollamaModel)

		// Check if Ollama is available
		if err := client.CheckHealth(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Ollama is not available (%v). Skipping Executive Summary generation.\n", err)
			reportData.ExecutiveSummary = "Executive Summary could not be generated because the AI service is unavailable."
		} else {
			// Construct prompt
			prompt := fmt.Sprintf("Generate a professional executive summary for a security report. Project: %s. Risk Score: %.2f. Total Findings: %d. Critical: %d. High: %d.",
				input.ProjectProfile.Metadata.ProjectName,
				input.AggregatedReport.Summary.RiskScore,
				input.AggregatedReport.Summary.TotalFindings,
				input.AggregatedReport.Summary.CriticalFindings,
				input.AggregatedReport.Summary.HighFindings,
			)

			summary, err := client.Generate(prompt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating executive summary: %v\n", err)
				reportData.ExecutiveSummary = "Error generating Executive Summary."
			} else {
				reportData.ExecutiveSummary = summary
			}
		}
	}

	// 3. Initialize formatters
	// Determine absolute path to template
	cwd, _ := os.Getwd()
	// Assuming the binary is run from the root of the project or agents/report_agent
	// We might need a more robust way to find templates, but for now:
	templatePath := filepath.Join(cwd, "templates/technical.html")
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		// Try relative to executable if needed, or assume CWD is agents/report_agent
		templatePath = "templates/technical.html"
	}

	htmlFormatter := formatters.NewHTMLFormatter(templatePath)

	formattersMap := map[string]Formatter{
		"json":     formatters.NewJSONFormatter(),
		"markdown": formatters.NewMarkdownFormatter(),
		"html":     htmlFormatter,
		"pdf":      formatters.NewPDFFormatter(htmlFormatter),
	}

	// 4. Generate reports
	reports := make(map[string]string) // Content or path
	filePaths := make(map[string]string)

	outputDir := input.Config.OutputDir
	if outputDir == "" {
		outputDir = ".security-scan"
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return types.ReportOutput{}, fmt.Errorf("failed to create output dir: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	filesGenerated := 0

	for _, format := range input.Config.Formats {
		formatter, ok := formattersMap[format]
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: unsupported format %s\n", format)
			continue
		}

		output, err := formatter.Format(reportData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating %s report: %v\n", format, err)
			continue
		}

		filename := fmt.Sprintf("security-report-%s.%s", timestamp, format)
		filePath := filepath.Join(outputDir, filename)

		if err := os.WriteFile(filePath, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s report: %v\n", format, err)
			continue
		}

		filePaths[format] = filePath
		reports[format] = filePath // Returning path for now as content might be large
		filesGenerated++
	}

	return types.ReportOutput{
		Reports: reports,
		Metadata: types.ReportMetadata{
			GeneratedAt:     time.Now(),
			PipelineVersion: "1.0.0",
			ReportVersion:   "1.0",
			ProjectName:     input.ProjectProfile.Metadata.ProjectName,
			Formats:         input.Config.Formats,
			FilePaths:       filePaths,
		},
		Summary: types.ReportSummary{
			TotalFindings:    input.AggregatedReport.Summary.TotalFindings,
			RiskScore:        input.AggregatedReport.Summary.RiskScore,
			RiskLevel:        "high", // Placeholder
			FilesGenerated:   filesGenerated,
			ExecutiveSummary: reportData.ExecutiveSummary,
		},
	}, nil
}
