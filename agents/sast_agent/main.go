package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sast_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: scan_project, validate_finding, generate_fix_recommendation, get_available_rulesets\n")
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
	case "scan_project":
		output, err = handleScanProject(input)
	case "validate_finding":
		output, err = handleValidateFinding(input)
	case "generate_fix_recommendation":
		output, err = handleGenerateFixRecommendation(input)
	case "get_available_rulesets":
		output, err = handleGetAvailableRulesets(input)
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

func handleScanProject(input []byte) (*ScanOutput, error) {
	var params ScanProjectInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	if len(params.Languages) == 0 {
		return nil, fmt.Errorf("languages is required")
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

	scanner := NewSASTScanner()
	return scanner.ScanProject(params)
}

func handleValidateFinding(input []byte) (*ValidationResult, error) {
	var params ValidateFindingInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.Finding.Type == "" || params.Finding.FilePath == "" {
		return nil, fmt.Errorf("finding.type and finding.file_path are required")
	}

	if params.CodeContext == "" {
		return nil, fmt.Errorf("code_context is required")
	}

	scanner := NewSASTScanner()
	return scanner.ValidateFinding(params)
}

func handleGenerateFixRecommendation(input []byte) (*GenerateFixRecommendationOutput, error) {
	var params GenerateFixRecommendationInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	scanner := NewSASTScanner()
	return scanner.GenerateFixRecommendation(params)
}

func handleGetAvailableRulesets(input []byte) (*GetAvailableRulesetsOutput, error) {
	scanner := NewSASTScanner()
	return scanner.GetAvailableRulesets()
}
