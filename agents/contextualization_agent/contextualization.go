package main

import (
	"contextualization_agent/rules"
	"contextualization_agent/utils"
)

type Contextualizer struct {
	ollamaClient *utils.OllamaClient
}

func NewContextualizer() *Contextualizer {
	return &Contextualizer{
		ollamaClient: utils.NewOllamaClient(),
	}
}

func (c *Contextualizer) ContextualizeAnalysis(profile ProjectProfile, options Options) (*AnalysisConfig, error) {
	var projectContext *ProjectContext

	if options.UseOllamaAnalysis {
		languages := []string{}
		for _, lang := range profile.Languages {
			languages = append(languages, lang.Name)
		}

		frameworks := []string{}
		for _, fw := range profile.Frameworks {
			frameworks = append(frameworks, fw.Name)
		}

		ollamaContext, err := c.ollamaClient.AnalyzeProjectContext(
			languages,
			frameworks,
			len(profile.Dependencies),
			profile.FileTree.HasTests,
			profile.FileTree.ConfigFiles,
		)

		if err == nil {
			projectContext = &ProjectContext{
				Type:             ollamaContext.Type,
				Domain:           ollamaContext.Domain,
				Criticality:      ollamaContext.Criticality,
				SecurityConcerns: ollamaContext.SecurityConcerns,
			}
		} else {
			projectContext = c.analyzeHeuristic(profile)
		}
	} else {
		projectContext = c.analyzeHeuristic(profile)
	}

	config := &AnalysisConfig{
		EnabledAgents:  []string{},
		AgentConfigs:   make(map[string]AgentConfig),
		Priority:       []string{},
		SkipReasons:    make(map[string]string),
		ProjectContext: projectContext,
	}

	rulesProfile := c.convertToRulesProfile(profile)
	rulesContext := rules.ProjectContext{
		Type:        projectContext.Type,
		Domain:      projectContext.Domain,
		Criticality: projectContext.Criticality,
	}

	severityThreshold := options.SeverityThreshold
	if severityThreshold == "" {
		severityThreshold = "medium"
	}

	shouldActivateSAST, sastSkipReason := rules.ShouldActivateSAST(rulesProfile)
	if shouldActivateSAST || options.ForceAllAgents {
		sastConfig := rules.ConfigureSAST(rulesProfile, rulesContext, severityThreshold)
		config.EnabledAgents = append(config.EnabledAgents, "sast")
		config.AgentConfigs["sast"] = c.convertToAgentConfig(sastConfig)
	} else {
		config.SkipReasons["sast"] = sastSkipReason
		config.AgentConfigs["sast"] = AgentConfig{Enabled: false}
	}

	shouldActivateSCA, scaSkipReason := rules.ShouldActivateSCA(rulesProfile)
	if shouldActivateSCA || options.ForceAllAgents {
		scaConfig := rules.ConfigureSCA(rulesProfile, rulesContext, severityThreshold)
		config.EnabledAgents = append(config.EnabledAgents, "sca")
		config.AgentConfigs["sca"] = c.convertToAgentConfig(scaConfig)
	} else {
		config.SkipReasons["sca"] = scaSkipReason
		config.AgentConfigs["sca"] = AgentConfig{Enabled: false}
	}

	shouldActivateSecrets, _ := rules.ShouldActivateSecrets(rulesProfile)
	if shouldActivateSecrets || options.ForceAllAgents {
		secretsConfig := rules.ConfigureSecrets(rulesProfile, rulesContext, severityThreshold)
		config.EnabledAgents = append(config.EnabledAgents, "secrets")
		config.AgentConfigs["secrets"] = c.convertToAgentConfig(secretsConfig)
	} else {
		config.AgentConfigs["secrets"] = AgentConfig{Enabled: false}
	}

	config.Priority = rules.DeterminePriority(config.EnabledAgents)

	return config, nil
}

func (c *Contextualizer) GetAgentConfig(agentName string, profile ProjectProfile) (*AgentConfig, error) {
	rulesProfile := c.convertToRulesProfile(profile)
	projectContext := c.analyzeHeuristic(profile)
	rulesContext := rules.ProjectContext{
		Type:        projectContext.Type,
		Domain:      projectContext.Domain,
		Criticality: projectContext.Criticality,
	}

	var agentConfig rules.AgentConfig

	switch agentName {
	case "sast":
		agentConfig = rules.ConfigureSAST(rulesProfile, rulesContext, "medium")
	case "sca":
		agentConfig = rules.ConfigureSCA(rulesProfile, rulesContext, "medium")
	case "secrets":
		agentConfig = rules.ConfigureSecrets(rulesProfile, rulesContext, "medium")
	default:
		return &AgentConfig{Enabled: false}, nil
	}

	config := c.convertToAgentConfig(agentConfig)
	return &config, nil
}

func (c *Contextualizer) AnalyzeProjectContext(profile ProjectProfile) (*AnalyzeProjectContextOutput, error) {
	languages := []string{}
	for _, lang := range profile.Languages {
		languages = append(languages, lang.Name)
	}

	frameworks := []string{}
	for _, fw := range profile.Frameworks {
		frameworks = append(frameworks, fw.Name)
	}

	ollamaContext, err := c.ollamaClient.AnalyzeProjectContext(
		languages,
		frameworks,
		len(profile.Dependencies),
		profile.FileTree.HasTests,
		profile.FileTree.ConfigFiles,
	)

	if err != nil {
		heuristic := c.analyzeHeuristic(profile)
		return &AnalyzeProjectContextOutput{
			Type:             heuristic.Type,
			Domain:           heuristic.Domain,
			Criticality:      heuristic.Criticality,
			SecurityConcerns: heuristic.SecurityConcerns,
		}, nil
	}

	return &AnalyzeProjectContextOutput{
		Type:             ollamaContext.Type,
		Domain:           ollamaContext.Domain,
		Criticality:      ollamaContext.Criticality,
		SecurityConcerns: ollamaContext.SecurityConcerns,
	}, nil
}

func (c *Contextualizer) analyzeHeuristic(profile ProjectProfile) *ProjectContext {
	context := &ProjectContext{
		Type:             "unknown",
		Domain:           "general",
		Criticality:      "medium",
		SecurityConcerns: []string{},
	}

	frameworkNames := []string{}
	for _, fw := range profile.Frameworks {
		frameworkNames = append(frameworkNames, fw.Name)
	}

	languageNames := []string{}
	for _, lang := range profile.Languages {
		languageNames = append(languageNames, lang.Name)
	}

	if utils.HasWebFramework(frameworkNames) {
		if containsAny(frameworkNames, []string{"React", "Vue", "Angular", "Next.js"}) {
			context.Type = "frontend"
		} else {
			context.Type = "api"
		}
		context.Criticality = "high"
		context.SecurityConcerns = append(context.SecurityConcerns, "xss", "csrf", "injection")
	} else if utils.HasSolidityCode(languageNames) {
		context.Type = "smart-contract"
		context.Domain = "crypto"
		context.Criticality = "critical"
		context.SecurityConcerns = append(context.SecurityConcerns, "reentrancy", "overflow", "access-control")
	} else if len(profile.Frameworks) == 0 && len(profile.Languages) == 1 {
		context.Type = "cli"
		context.Criticality = "low"
		context.SecurityConcerns = append(context.SecurityConcerns, "command-injection", "path-traversal")
	} else {
		context.Type = "library"
		context.Criticality = "medium"
		context.SecurityConcerns = append(context.SecurityConcerns, "input-validation", "injection")
	}

	if utils.IsCryptoProject(frameworkNames) {
		context.Domain = "crypto"
		context.Criticality = "critical"
	}

	return context
}

func (c *Contextualizer) convertToRulesProfile(profile ProjectProfile) rules.ProjectProfile {
	languages := make([]rules.Language, len(profile.Languages))
	for i, lang := range profile.Languages {
		languages[i] = rules.Language{
			Name:       lang.Name,
			FileCount:  lang.FileCount,
			Percentage: lang.Percentage,
		}
	}

	frameworks := make([]rules.Framework, len(profile.Frameworks))
	for i, fw := range profile.Frameworks {
		frameworks[i] = rules.Framework{
			Name:     fw.Name,
			Language: fw.Language,
		}
	}

	dependencies := make([]rules.Dependency, len(profile.Dependencies))
	for i, dep := range profile.Dependencies {
		dependencies[i] = rules.Dependency{
			Name:     dep.Name,
			Language: dep.Language,
		}
	}

	return rules.ProjectProfile{
		Languages:    languages,
		Frameworks:   frameworks,
		Dependencies: dependencies,
		FileTree: rules.FileTree{
			TotalFiles: profile.FileTree.TotalFiles,
			HasTests:   profile.FileTree.HasTests,
			HasDocs:    profile.FileTree.HasDocs,
		},
	}
}

func (c *Contextualizer) convertToAgentConfig(config rules.AgentConfig) AgentConfig {
	return AgentConfig{
		Enabled:      config.Enabled,
		Severity:     config.Severity,
		Rules:        config.Rules,
		SkipPatterns: config.SkipPatterns,
		MaxFindings:  config.MaxFindings,
		CustomParams: config.CustomParams,
	}
}

func containsAny(items []string, targets []string) bool {
	for _, item := range items {
		for _, target := range targets {
			if item == target {
				return true
			}
		}
	}
	return false
}
