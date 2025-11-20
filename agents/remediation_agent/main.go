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
	case "generate_remediation_plans":
		return handleGenerateRemediationPlans(req.Params)
	case "generate_code_fix":
		return handleGenerateCodeFix(req.Params)
	case "generate_dependency_fix":
		return handleGenerateDependencyFix(req.Params)
	case "generate_action_plan":
		return handleGenerateActionPlan(req.Params)
	case "estimate_complexity":
		return handleEstimateComplexity(req.Params)
	case "generate_tests":
		return handleGenerateTests(req.Params)
	default:
		return nil, fmt.Errorf("unknown method: %s", req.Method)
	}
}

func handleGenerateRemediationPlans(params json.RawMessage) (interface{}, error) {
	var input RemediationInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return GenerateRemediationPlans(input)
}

func handleGenerateCodeFix(params json.RawMessage) (interface{}, error) {
	var input CodeFixInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return GenerateCodeFix(input)
}

func handleGenerateDependencyFix(params json.RawMessage) (interface{}, error) {
	var input DependencyFixInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return GenerateDependencyFix(input)
}

func handleGenerateActionPlan(params json.RawMessage) (interface{}, error) {
	var input ActionPlanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return GenerateActionPlan(input)
}

func handleEstimateComplexity(params json.RawMessage) (interface{}, error) {
	var input ComplexityInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return EstimateComplexity(input)
}

func handleGenerateTests(params json.RawMessage) (interface{}, error) {
	var input TestsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return GenerateTests(input)
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
