package formatters

import (
	"fmt"
	"report_agent/types"
	"strings"
	"time"
)

type MarkdownFormatter struct{}

func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

func (f *MarkdownFormatter) Format(data types.ReportData) ([]byte, error) {
	var md strings.Builder

	// Header
	md.WriteString(fmt.Sprintf("# Security Scan Report - %s\n\n", data.ProjectProfile.Metadata.ProjectName))
	md.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	md.WriteString(fmt.Sprintf("**Risk Score:** %.1f/100\n\n", data.AggregatedReport.Summary.RiskScore))

	// Executive Summary
	md.WriteString("## Executive Summary\n\n")
	if data.ExecutiveSummary != "" {
		md.WriteString(data.ExecutiveSummary + "\n\n")
	} else {
		md.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", data.AggregatedReport.Summary.TotalFindings))
		md.WriteString(fmt.Sprintf("- **Critical:** %d\n", data.AggregatedReport.Summary.CriticalFindings))
		md.WriteString(fmt.Sprintf("- **High:** %d\n", data.AggregatedReport.Summary.HighFindings))
		md.WriteString(fmt.Sprintf("- **Medium:** %d\n", data.AggregatedReport.Summary.MediumFindings))
		md.WriteString(fmt.Sprintf("- **Low:** %d\n\n", data.AggregatedReport.Summary.LowFindings))
	}

	// Findings
	md.WriteString("## Findings\n\n")
	for i, finding := range data.AggregatedReport.Findings {
		md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Title))
		md.WriteString(fmt.Sprintf("- **Severity:** %s\n", finding.Severity))
		md.WriteString(fmt.Sprintf("- **Category:** %s\n", finding.Category))
		md.WriteString(fmt.Sprintf("- **Location:** `%s:%d`\n\n", finding.FilePath, finding.LineNumber))
		md.WriteString(fmt.Sprintf("%s\n\n", finding.Description))
	}

	return []byte(md.String()), nil
}
