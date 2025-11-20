package semgrep

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
	cmd := exec.Command("semgrep", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("semgrep not installed. Install with: pip install semgrep")
	}

	c.version = strings.TrimSpace(string(output))
	return nil
}

func (c *Client) GetVersion() string {
	return c.version
}

func (c *Client) Scan(projectPath string, config ScanConfig) (*Report, error) {
	args := []string{
		"scan",
		"--json",
		"--quiet",
		"--no-git-ignore",
	}

	configArg := "--config"
	if len(config.Rules) > 0 {
		configValue := mapRulesToConfig(config.Rules)
		args = append(args, configArg, configValue)
	} else {
		rulesPath := os.Getenv("SEMGREP_RULES_PATH")
		if rulesPath != "" {
			args = append(args, configArg, rulesPath)
		} else {
			args = append(args, configArg, "auto")
		}
	}

	if config.Severity != "" {
		semgrepSevs := mapSeverityToSemgrep(config.Severity)
		for _, sev := range semgrepSevs {
			args = append(args, "--severity", sev)
		}
	}

	for _, pattern := range config.SkipPatterns {
		args = append(args, "--exclude", pattern)
	}

	if config.TimeoutSeconds > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", config.TimeoutSeconds))
	}

	args = append(args, projectPath)

	cmd := exec.Command("semgrep", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
			} else {
				return nil, fmt.Errorf("semgrep scan failed: %s", string(output))
			}
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	var report Report
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	return &report, nil
}

func mapSeverityToSemgrep(severity string) []string {
	switch severity {
	case "critical":
		return []string{"ERROR"}
	case "high":
		return []string{"ERROR", "WARNING"}
	case "medium":
		return []string{"ERROR", "WARNING", "INFO"}
	case "low":
		return []string{"ERROR", "WARNING", "INFO"}
	default:
		return []string{}
	}
}

func mapRulesToConfig(rules []string) string {
	configs := []string{}

	ruleMap := map[string]string{
		"sql-injection":       "p/sql-injection",
		"xss":                 "p/xss",
		"command-injection":   "p/command-injection",
		"path-traversal":      "p/path-traversal",
		"unsafe-reflection":   "p/security-audit",
		"prototype-pollution": "p/security-audit",
		"eval-usage":          "p/javascript",
		"insecure-random":     "p/insecure-randomness",
		"deserialization":     "p/security-audit",
		"yaml-load":           "p/python",
		"reentrancy":          "p/smart-contracts",
		"integer-overflow":    "p/smart-contracts",
		"delegatecall":        "p/smart-contracts",
		"tx-origin":           "p/smart-contracts",
		"hardcoded-secrets":   "p/secrets",
		"weak-crypto":         "p/crypto",
		"xxe":                 "p/xxe",
		"ldap-injection":      "p/security-audit",
		"jwt-vulnerabilities": "p/jwt",
		"insecure-transport":  "p/insecure-transport",
	}

	seen := make(map[string]bool)
	for _, rule := range rules {
		if configVal, ok := ruleMap[rule]; ok {
			if !seen[configVal] {
				configs = append(configs, configVal)
				seen[configVal] = true
			}
		}
	}

	if len(configs) == 0 {
		return "auto"
	}

	return strings.Join(configs, ",")
}

type ScanConfig struct {
	Rules          []string
	Severity       string
	SkipPatterns   []string
	TimeoutSeconds int
}

type Report struct {
	Results []Result `json:"results"`
	Errors  []Error  `json:"errors"`
	Paths   Paths    `json:"paths"`
	Version string   `json:"version"`
}

type Result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   Start  `json:"start"`
	End     End    `json:"end"`
	Extra   Extra  `json:"extra"`
}

type Start struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type End struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type Extra struct {
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Metadata Metadata `json:"metadata"`
	Lines    string   `json:"lines"`
}

type Metadata struct {
	CWE         []string `json:"cwe"`
	OWASP       []string `json:"owasp"`
	Category    string   `json:"category"`
	Technology  []string `json:"technology"`
	Confidence  string   `json:"confidence"`
	Likelihood  string   `json:"likelihood"`
	Impact      string   `json:"impact"`
	Subcategory []string `json:"subcategory"`
}

type Error struct {
	Message string `json:"message"`
	Path    string `json:"path"`
	Level   string `json:"level"`
}

type Paths struct {
	Scanned []string `json:"scanned"`
}
