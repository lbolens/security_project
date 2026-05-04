package formatters

import (
	"fmt"
	"os"
	"os/exec"
	"report_agent/types"
)

type PDFFormatter struct {
	htmlFormatter *HTMLFormatter
}

func NewPDFFormatter(htmlFormatter *HTMLFormatter) *PDFFormatter {
	return &PDFFormatter{htmlFormatter: htmlFormatter}
}

func (f *PDFFormatter) Format(data types.ReportData) ([]byte, error) {
	// 1. Generate HTML first
	htmlContent, err := f.htmlFormatter.Format(data)
	if err != nil {
		return nil, err
	}

	// 2. Save HTML temporarily
	tmpHTMLFile, err := os.CreateTemp("", "report-*.html")
	if err != nil {
		return nil, err
	}
	tmpHTML := tmpHTMLFile.Name()
	if err := os.WriteFile(tmpHTML, htmlContent, 0644); err != nil {
		tmpHTMLFile.Close()
		return nil, err
	}
	defer os.Remove(tmpHTML)

	// 3. Convert HTML -> PDF with wkhtmltopdf
	tmpPDF := "/tmp/report.pdf"
	cmd := exec.Command("wkhtmltopdf",
		"--enable-local-file-access",
		"--page-size", "A4",
		tmpHTML,
		tmpPDF,
	)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("PDF generation failed (wkhtmltopdf required): %w", err)
	}
	defer os.Remove(tmpPDF)

	// 4. Read PDF
	pdfData, err := os.ReadFile(tmpPDF)
	if err != nil {
		return nil, err
	}

	return pdfData, nil
}
