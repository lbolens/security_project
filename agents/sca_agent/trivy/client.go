package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Client struct {
	version string
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) CheckInstalled() error {
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("trivy not installed. Install with: brew install trivy")
	}

	c.version = strings.TrimSpace(string(output))
	return nil
}

func (c *Client) GetVersion() string {
	return c.version
}

func (c *Client) Scan(projectPath string, config ScanConfig) (*Report, error) {
	args := []string{
		"fs",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
	}

	if config.Severity != "" {
		severities := mapSeverityToTrivy(config.Severity)
		if severities != "" {
			args = append(args, "--severity", severities)
		}
	}

	if config.SkipDevDeps {
		args = append(args, "--skip-dirs", "node_modules", "--skip-dirs", "venv", "--skip-dirs", "__pycache__")
	}

	args = append(args, projectPath)

	var cmd *exec.Cmd
	if config.TimeoutSeconds > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TimeoutSeconds)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "trivy", args...)
	} else {
		cmd = exec.Command("trivy", args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx := cmd.ProcessState; ctx != nil && ctx.ExitCode() != 0 {
			return nil, fmt.Errorf("trivy scan failed: %s", string(output))
		}
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}

	var report Report
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return &report, nil
}

func (c *Client) UpdateDB() error {
	cmd := exec.Command("trivy", "image", "--download-db-only")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy db update failed: %w", err)
	}
	return nil
}

func mapSeverityToTrivy(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH,CRITICAL"
	case "medium":
		return "MEDIUM,HIGH,CRITICAL"
	case "low":
		return "LOW,MEDIUM,HIGH,CRITICAL"
	default:
		return "MEDIUM,HIGH,CRITICAL"
	}
}

type ScanConfig struct {
	Severity        string
	SkipDevDeps     bool
	CheckDirectOnly bool
	TimeoutSeconds  int
}

type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Vulnerabilities []Vulnerability  `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Severity         string            `json:"Severity"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	References       []string          `json:"References"`
	PublishedDate    string            `json:"PublishedDate"`
	LastModifiedDate string            `json:"LastModifiedDate"`
	PrimaryURL       string            `json:"PrimaryURL"`
	CVSS             map[string]CVSS   `json:"CVSS"`
	CweIDs           []string          `json:"CweIDs"`
}

type CVSS struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}
