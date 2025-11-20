package formatters

import (
	"bytes"
	"html/template"
	"report_agent/types"
	"time"
)

type HTMLFormatter struct {
	templatePath string
}

func NewHTMLFormatter(templatePath string) *HTMLFormatter {
	return &HTMLFormatter{templatePath: templatePath}
}

type HTMLTemplateData struct {
	ProjectName  string
	ScanDate     string
	RiskScore    float64
	Summary      types.Summary
	Findings     []types.Finding
	Remediations []types.RemediationPlan
}

func (f *HTMLFormatter) Format(data types.ReportData) ([]byte, error) {
	tmpl, err := template.ParseFiles(f.templatePath)
	if err != nil {
		return nil, err
	}

	templateData := HTMLTemplateData{
		ProjectName:  data.ProjectProfile.Metadata.ProjectName,
		ScanDate:     time.Now().Format("2006-01-02 15:04:05"),
		RiskScore:    data.AggregatedReport.Summary.RiskScore,
		Summary:      data.AggregatedReport.Summary,
		Findings:     data.AggregatedReport.Findings,
		Remediations: data.RemediationPlans,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
