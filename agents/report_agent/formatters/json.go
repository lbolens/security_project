package formatters

import (
	"encoding/json"
	"report_agent/types"
	"time"
)

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Format(data types.ReportData) ([]byte, error) {
	// Construct the JSON report structure
	// Note: This duplicates some logic from models.go but is specific for the JSON output format

	type JSONReport struct {
		Metadata     types.ReportMetadata    `json:"metadata"`
		Summary      types.Summary           `json:"summary"`
		RiskScore    types.RiskScore         `json:"risk_score"`
		Findings     []types.Finding         `json:"findings"`
		Remediations []types.RemediationPlan `json:"remediations"`
		Statistics   types.Statistics        `json:"statistics"`
		Compliance   types.ComplianceMapping `json:"compliance"`
	}

	jsonReport := JSONReport{
		Metadata: types.ReportMetadata{
			GeneratedAt:     time.Now(),
			PipelineVersion: "1.0.0",
			ReportVersion:   "1.0",
			ProjectName:     data.ProjectProfile.Metadata.ProjectName,
		},
		Summary:      data.AggregatedReport.Summary,
		Findings:     data.AggregatedReport.Findings,
		Remediations: data.RemediationPlans,
		Statistics:   data.AggregatedReport.Statistics,
		Compliance:   data.Compliance,
		RiskScore: types.RiskScore{
			Overall: data.AggregatedReport.Summary.RiskScore,
			Level:   "high", // Placeholder
		},
	}

	return json.MarshalIndent(jsonReport, "", "  ")
}
