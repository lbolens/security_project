package gitleaks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Client struct {
	version string
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) CheckInstalled() error {
	cmd := exec.Command("gitleaks", "version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("gitleaks not installed. Install with: brew install gitleaks")
	}

	c.version = strings.TrimSpace(string(output))
	return nil
}

func (c *Client) GetVersion() string {
	return c.version
}

func (c *Client) ScanFilesystem(projectPath string, config ScanConfig) (*Report, error) {
	reportPath := "/tmp/gitleaks-report.json"

	args := []string{
		"detect",
		"--source", projectPath,
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-git",
	}

	if config.Verbose {
		args = append(args, "-v")
	}

	if config.BaselinePath != "" {
		args = append(args, "--baseline-path", config.BaselinePath)
	}

	if config.ConfigPath != "" {
		args = append(args, "--config", config.ConfigPath)
	}

	cmd := exec.Command("gitleaks", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("gitleaks failed: %s", output)
			}
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return &Report{}, nil
	}

	var report Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks report: %w", err)
	}

	return &report, nil
}

func (c *Client) ScanGitHistory(projectPath string, config ScanConfig) (*Report, error) {
	reportPath := "/tmp/gitleaks-history.json"

	args := []string{
		"detect",
		"--source", projectPath,
		"--report-format", "json",
		"--report-path", reportPath,
	}

	if config.MaxDepth > 0 {
		args = append(args, "--log-opts", fmt.Sprintf("--max-count=%d", config.MaxDepth))
	}

	if config.BaselinePath != "" {
		args = append(args, "--baseline-path", config.BaselinePath)
	}

	if config.ConfigPath != "" {
		args = append(args, "--config", config.ConfigPath)
	}

	cmd := exec.Command("gitleaks", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("gitleaks git scan failed: %s", output)
			}
		} else {
			return nil, fmt.Errorf("gitleaks git execution failed: %w", err)
		}
	}

	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return &Report{}, nil
	}

	var report Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks history report: %w", err)
	}

	return &report, nil
}

type ScanConfig struct {
	EntropyThreshold float64
	ScanGitHistory   bool
	MaxDepth         int
	BaselinePath     string
	ConfigPath       string
	Verbose          bool
}

type Report []Finding

type Finding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}
