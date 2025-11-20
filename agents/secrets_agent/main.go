package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: secrets_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: scan_secrets, validate_secret, generate_remediation, scan_git_history\n")
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
	case "scan_secrets":
		output, err = handleScanSecrets(input)
	case "validate_secret":
		output, err = handleValidateSecret(input)
	case "generate_remediation":
		output, err = handleGenerateRemediation(input)
	case "scan_git_history":
		output, err = handleScanGitHistory(input)
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

func handleScanSecrets(input []byte) (*ScanOutput, error) {
	var params ScanSecretsInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	if params.Config.Severity == "" {
		params.Config.Severity = "critical"
	}

	if params.Config.EntropyThreshold == 0 {
		params.Config.EntropyThreshold = 4.5
	}

	if params.Config.MaxFindings == 0 {
		params.Config.MaxFindings = 50
	}

	scanner := NewSecretsScanner()
	return scanner.ScanSecrets(params)
}

func handleValidateSecret(input []byte) (*SecretValidation, error) {
	var params ValidateSecretInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.Finding.SecretType == "" || params.Finding.FilePath == "" {
		return nil, fmt.Errorf("finding.secret_type and finding.file_path are required")
	}

	if params.CodeContext == "" {
		return nil, fmt.Errorf("code_context is required")
	}

	scanner := NewSecretsScanner()
	return scanner.ValidateSecret(params)
}

func handleGenerateRemediation(input []byte) (*GenerateRemediationOutput, error) {
	var params GenerateRemediationInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	scanner := NewSecretsScanner()
	return scanner.GenerateRemediation(params)
}

func handleScanGitHistory(input []byte) (*ScanGitHistoryOutput, error) {
	var params ScanGitHistoryInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	if params.MaxDepth == 0 {
		params.MaxDepth = 100
	}

	scanner := NewSecretsScanner()
	return scanner.ScanGitHistory(params)
}
