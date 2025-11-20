package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type MCPRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req MCPRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeError(-32700, "Parse error: "+err.Error())
			continue
		}

		result, err := handleRequest(req)
		if err != nil {
			writeError(-32603, err.Error())
			continue
		}

		writeResult(result)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
	}
}

func handleRequest(req MCPRequest) (interface{}, error) {
	switch req.Method {
	case "aggregate_findings":
		return handleAggregateFindings(req.Params)
	case "deduplicate_findings":
		return handleDeduplicateFindings(req.Params)
	case "calculate_priority":
		return handleCalculatePriority(req.Params)
	case "calculate_risk_score":
		return handleCalculateRiskScore(req.Params)
	case "generate_statistics":
		return handleGenerateStatistics(req.Params)
	default:
		return nil, fmt.Errorf("unknown method: %s", req.Method)
	}
}

func handleAggregateFindings(params json.RawMessage) (interface{}, error) {
	var input AggregateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}

	return AggregateFindings(input)
}

func handleDeduplicateFindings(params json.RawMessage) (interface{}, error) {
	var input DeduplicateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}

	return DeduplicateFindings(input)
}

func handleCalculatePriority(params json.RawMessage) (interface{}, error) {
	var input PriorityInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}

	return CalculatePriority(input)
}

func handleCalculateRiskScore(params json.RawMessage) (interface{}, error) {
	var input RiskScoreInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}

	return CalculateRiskScore(input)
}

func handleGenerateStatistics(params json.RawMessage) (interface{}, error) {
	var input StatisticsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}

	return GenerateStatistics(input)
}

func writeResult(result interface{}) {
	response := MCPResponse{Result: result}
	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}

func writeError(code int, message string) {
	response := MCPResponse{
		Error: &MCPError{
			Code:    code,
			Message: message,
		},
	}
	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}
