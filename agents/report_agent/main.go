package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"report_agent/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: report_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: generate_reports\n")
		os.Exit(1)
	}

	toolName := os.Args[1]

	// Read input from stdin
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	var output interface{}

	switch toolName {
	case "generate_reports":
		output, err = handleGenerateReports(inputData)
	default:
		fmt.Fprintf(os.Stderr, "Unknown tool: %s\n", toolName)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Write output to stdout
	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(outputJSON))
}

func handleGenerateReports(inputData []byte) (*types.ReportOutput, error) {
	var input types.ReportInput
	if err := json.Unmarshal(inputData, &input); err != nil {
		return nil, fmt.Errorf("error parsing input JSON: %w", err)
	}

	// Set defaults if config is missing
	if len(input.Config.Formats) == 0 {
		input.Config.Formats = []string{"json", "html", "markdown"}
	}

	// Generate reports
	output, err := GenerateReports(input)
	if err != nil {
		return nil, fmt.Errorf("error generating reports: %w", err)
	}

	return &output, nil
}
