package main

import (
	"encoding/json"
	"fmt"
)

func GenerateActionPlan(input ActionPlanInput) (*ActionPlanOutput, error) {
	finding := input.Finding
	fix := input.Fix

	fixType := GetStringValue(fix, "type")
	severity := GetStringValue(finding, "severity")
	findingType := GetStringValue(finding, "type")
	category := GetStringValue(finding, "category")
	fixDescription := GetStringValue(fix, "description")

	prompt := fmt.Sprintf(`Create a detailed, step-by-step remediation plan for a developer to follow.

Vulnerability: %s
Severity: %s
Fix Type: %s

Fix Description:
%s

Project Type: %s

Generate a numbered list of ACTIONABLE steps that a developer can follow.
Each step should be clear, specific, and verifiable.

Include:
1. Preparation steps (backup, branch creation)
2. Implementation steps (code changes, commands)
3. Testing steps (how to verify fix works)
4. Deployment steps (if applicable)
5. Monitoring/validation steps

Respond in JSON:
{
  "steps": [
    {
      "order": 1,
      "title": "Short title",
      "description": "Detailed description",
      "command": "command to run (if applicable)",
      "expected_output": "what to expect",
      "validation": "how to verify this step worked"
    }
  ],
  "estimated_time": "total time estimate",
  "prerequisites": ["prerequisite 1", "prerequisite 2"]
}`,
		findingType,
		severity,
		fixType,
		fixDescription,
		category,
	)

	response, err := callOllama(prompt)
	if err != nil {
		return generateFallbackActionPlan(fixType, finding, fix), nil
	}

	var planData struct {
		Steps         []RemediationStep `json:"steps"`
		EstimatedTime string            `json:"estimated_time"`
		Prerequisites []string          `json:"prerequisites"`
	}

	if err := json.Unmarshal([]byte(response), &planData); err != nil {
		return generateFallbackActionPlan(fixType, finding, fix), nil
	}

	return &ActionPlanOutput{
		Steps:         planData.Steps,
		EstimatedTime: planData.EstimatedTime,
		Prerequisites: planData.Prerequisites,
	}, nil
}

func generateFallbackActionPlan(fixType string, finding, fix map[string]interface{}) *ActionPlanOutput {
	steps := generateStepsForFixType(fixType, finding, fix)
	prerequisites := generatePrerequisites(fixType)
	estimatedTime := estimatePlanTime(steps)

	return &ActionPlanOutput{
		Steps:         steps,
		EstimatedTime: estimatedTime,
		Prerequisites: prerequisites,
	}
}

func generateStepsForFixType(fixType string, finding, fix map[string]interface{}) []RemediationStep {
	var steps []RemediationStep

	steps = append(steps, RemediationStep{
		Order:            1,
		Title:            "Create feature branch",
		Description:      "Create a new branch for this security fix",
		Command:          fmt.Sprintf("git checkout -b fix/%s", GetStringValue(finding, "type")),
		ValidationMethod: "Confirm branch created with git branch",
	})

	switch fixType {
	case "code-patch":
		steps = append(steps, generateCodePatchSteps(finding, fix)...)
	case "dependency-update":
		steps = append(steps, generateDependencyUpdateSteps(finding, fix)...)
	case "configuration":
		steps = append(steps, generateConfigurationSteps(finding, fix)...)
	default:
		steps = append(steps, RemediationStep{
			Order:            2,
			Title:            "Apply fix",
			Description:      GetStringValue(fix, "description"),
			ValidationMethod: "Verify fix is applied correctly",
		})
	}

	steps = append(steps, RemediationStep{
		Order:            len(steps) + 1,
		Title:            "Run tests",
		Description:      "Execute all test suites",
		Command:          "make test",
		ExpectedOutput:   "All tests pass",
		ValidationMethod: "No test failures",
	})

	steps = append(steps, RemediationStep{
		Order:            len(steps) + 1,
		Title:            "Commit changes",
		Description:      "Commit fix with descriptive message",
		Command:          fmt.Sprintf("git commit -m 'fix: %s'", GetStringValue(fix, "description")),
		ValidationMethod: "Changes committed successfully",
	})

	return steps
}

func generateCodePatchSteps(finding, fix map[string]interface{}) []RemediationStep {
	return []RemediationStep{
		{
			Order:            2,
			Title:            "Update code",
			Description:      fmt.Sprintf("Apply code fix in %s", GetStringValue(fix, "file_path")),
			ValidationMethod: "Code compiles without errors",
		},
		{
			Order:            3,
			Title:            "Verify fix",
			Description:      "Ensure vulnerability is resolved",
			ValidationMethod: "Security scanner shows vulnerability is fixed",
		},
	}
}

func generateDependencyUpdateSteps(finding, fix map[string]interface{}) []RemediationStep {
	return []RemediationStep{
		{
			Order:            2,
			Title:            "Update dependency",
			Description:      fmt.Sprintf("Update %s to %s", GetStringValue(fix, "package_name"), GetStringValue(fix, "target_version")),
			Command:          GetStringValue(fix, "command"),
			ExpectedOutput:   "Dependency updated successfully",
			ValidationMethod: "Package version matches target",
		},
		{
			Order:            3,
			Title:            "Rebuild application",
			Description:      "Rebuild to use updated dependency",
			Command:          "make build",
			ExpectedOutput:   "Build succeeds",
			ValidationMethod: "Application builds without errors",
		},
	}
}

func generateConfigurationSteps(finding, fix map[string]interface{}) []RemediationStep {
	return []RemediationStep{
		{
			Order:            2,
			Title:            "Update configuration",
			Description:      "Apply configuration changes",
			ValidationMethod: "Configuration is valid",
		},
		{
			Order:            3,
			Title:            "Restart service",
			Description:      "Restart to apply configuration",
			Command:          "systemctl restart service",
			ExpectedOutput:   "Service restarted successfully",
			ValidationMethod: "Service is running with new config",
		},
	}
}

func generatePrerequisites(fixType string) []string {
	prerequisites := []string{
		"Git repository initialized",
		"Working directory is clean",
	}

	switch fixType {
	case "dependency-update":
		prerequisites = append(prerequisites, "Package manager installed")
		prerequisites = append(prerequisites, "Lock file backed up")
	case "code-patch":
		prerequisites = append(prerequisites, "Development environment set up")
		prerequisites = append(prerequisites, "Test suite available")
	case "configuration":
		prerequisites = append(prerequisites, "Access to configuration files")
		prerequisites = append(prerequisites, "Backup of current configuration")
	}

	return prerequisites
}

func estimatePlanTime(steps []RemediationStep) string {
	baseTime := len(steps) * 5

	if baseTime < 30 {
		return "15-30 minutes"
	} else if baseTime < 60 {
		return "30-60 minutes"
	} else {
		return "1-2 hours"
	}
}
