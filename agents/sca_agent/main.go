package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sca_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: scan_dependencies, assess_exploitability, generate_fix_recommendation, update_trivy_db\n")
		os.Exit(1)
	}

	toolName := os.Args[1]

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	var output interface{}

	switch toolName {
	case "scan_dependencies":
		output, err = handleScanDependencies(input)
	case "assess_exploitability":
		output, err = handleAssessExploitability(input)
	case "generate_fix_recommendation":
		output, err = handleGenerateFixRecommendation(input)
	case "update_trivy_db":
		output, err = handleUpdateTrivyDB(input)
	default:
		fmt.Fprintf(os.Stderr, "Unknown tool: %s\n", toolName)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}

func handleScanDependencies(input []byte) (*ScanOutput, error) {
	var params ScanDependenciesInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	if params.Config.Severity == "" {
		params.Config.Severity = "medium"
	}

	if params.Config.TimeoutSeconds == 0 {
		params.Config.TimeoutSeconds = 300
	}

	if params.Config.MaxFindings == 0 {
		params.Config.MaxFindings = 100
	}

	scanner := NewSCAScanner()
	return scanner.ScanDependencies(params)
}

func handleAssessExploitability(input []byte) (*ExploitabilityAssessment, error) {
	var params AssessExploitabilityInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.Finding.CVE == "" || params.Finding.PackageName == "" {
		return nil, fmt.Errorf("finding.cve and finding.package_name are required")
	}

	scanner := NewSCAScanner()
	return scanner.AssessExploitability(params)
}

func handleGenerateFixRecommendation(input []byte) (*GenerateFixRecommendationOutput, error) {
	var params GenerateFixRecommendationInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	scanner := NewSCAScanner()
	return scanner.GenerateFixRecommendation(params)
}

func handleUpdateTrivyDB(input []byte) (*UpdateTrivyDBOutput, error) {
	scanner := NewSCAScanner()
	return scanner.UpdateTrivyDB()
}
