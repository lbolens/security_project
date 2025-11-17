package rules

type AgentConfig struct {
	Enabled      bool
	Severity     string
	Rules        []string
	SkipPatterns []string
	MaxFindings  int
	CustomParams map[string]interface{}
}

func ConfigureSAST(profile ProjectProfile, context ProjectContext, severityThreshold string) AgentConfig {
	config := AgentConfig{
		Enabled:      true,
		Severity:     severityThreshold,
		Rules:        []string{},
		SkipPatterns: []string{},
		CustomParams: make(map[string]interface{}),
	}

	for _, lang := range profile.Languages {
		switch lang.Name {
		case "Go":
			config.Rules = append(config.Rules,
				"sql-injection",
				"command-injection",
				"path-traversal",
				"unsafe-reflection",
			)
		case "JavaScript", "TypeScript":
			config.Rules = append(config.Rules,
				"xss",
				"prototype-pollution",
				"eval-usage",
				"insecure-random",
			)
		case "Python":
			config.Rules = append(config.Rules,
				"sql-injection",
				"command-injection",
				"deserialization",
				"yaml-load",
			)
		case "Solidity":
			config.Rules = append(config.Rules,
				"reentrancy",
				"integer-overflow",
				"delegatecall",
				"tx-origin",
			)
		case "Java":
			config.Rules = append(config.Rules,
				"sql-injection",
				"xxe",
				"deserialization",
				"path-traversal",
			)
		case "Ruby":
			config.Rules = append(config.Rules,
				"sql-injection",
				"command-injection",
				"mass-assignment",
			)
		case "PHP":
			config.Rules = append(config.Rules,
				"sql-injection",
				"xss",
				"file-inclusion",
				"command-injection",
			)
		}
	}

	if hasWebFramework(profile.Frameworks) {
		config.Severity = "high"
	}

	if context.Criticality == "critical" || context.Criticality == "high" {
		config.Severity = "high"
	}

	config.SkipPatterns = generateSkipPatterns(profile, context)

	if profile.FileTree.TotalFiles > 1000 {
		config.MaxFindings = 50
	} else {
		config.MaxFindings = 100
	}

	return config
}

func ConfigureSCA(profile ProjectProfile, context ProjectContext, severityThreshold string) AgentConfig {
	config := AgentConfig{
		Enabled:      true,
		Severity:     "high",
		Rules:        []string{},
		SkipPatterns: []string{},
		CustomParams: make(map[string]interface{}),
	}

	if !isProductionProject(profile) {
		config.CustomParams["skip_dev_deps"] = true
	} else {
		config.CustomParams["skip_dev_deps"] = false
	}

	if len(profile.Dependencies) > 100 {
		config.CustomParams["check_direct_only"] = true
	} else {
		config.CustomParams["check_direct_only"] = false
	}

	if profile.FileTree.TotalFiles > 1000 {
		config.MaxFindings = 50
	} else {
		config.MaxFindings = 100
	}

	return config
}

func ConfigureSecrets(profile ProjectProfile, context ProjectContext, severityThreshold string) AgentConfig {
	config := AgentConfig{
		Enabled:      true,
		Severity:     "critical",
		Rules:        []string{"api-keys", "private-keys", "tokens", "passwords"},
		SkipPatterns: []string{},
		CustomParams: make(map[string]interface{}),
	}

	if hasSolidityCode(profile.Languages) {
		config.Rules = append(config.Rules, "private-keys-eth", "mnemonics")
	}

	if isCryptoProject(profile.Frameworks) || context.Domain == "crypto" {
		config.CustomParams["entropy_threshold"] = 4.0
	} else {
		config.CustomParams["entropy_threshold"] = 4.5
	}

	config.SkipPatterns = append(config.SkipPatterns,
		"node_modules/",
		"vendor/",
		".git/",
	)

	if profile.FileTree.TotalFiles > 1000 {
		config.MaxFindings = 50
	} else {
		config.MaxFindings = 100
	}

	return config
}

func DeterminePriority(enabledAgents []string) []string {
	priority := []string{}

	for _, agent := range []string{"secrets", "sast", "sca"} {
		for _, enabled := range enabledAgents {
			if enabled == agent {
				priority = append(priority, agent)
				break
			}
		}
	}

	return priority
}

func generateSkipPatterns(profile ProjectProfile, context ProjectContext) []string {
	patterns := []string{
		"node_modules/",
		"vendor/",
		".git/",
		"dist/",
		"build/",
		".next/",
		".nuxt/",
		"target/",
	}

	if context.Criticality != "critical" && context.Criticality != "high" {
		patterns = append(patterns,
			"*_test.go",
			"*.test.js",
			"*.test.ts",
			"test/",
			"tests/",
			"__tests__/",
		)
	}

	return patterns
}

func hasWebFramework(frameworks []Framework) bool {
	webFrameworks := map[string]bool{
		"React":       true,
		"Vue":         true,
		"Angular":     true,
		"Express":     true,
		"Next.js":     true,
		"Gin":         true,
		"Django":      true,
		"Flask":       true,
		"FastAPI":     true,
		"Spring Boot": true,
	}

	for _, fw := range frameworks {
		if webFrameworks[fw.Name] {
			return true
		}
	}
	return false
}

func hasSolidityCode(languages []Language) bool {
	for _, lang := range languages {
		if lang.Name == "Solidity" {
			return true
		}
	}
	return false
}

func isCryptoProject(frameworks []Framework) bool {
	cryptoFrameworks := map[string]bool{
		"Hardhat": true,
		"Truffle": true,
		"Foundry": true,
	}

	for _, fw := range frameworks {
		if cryptoFrameworks[fw.Name] {
			return true
		}
	}
	return false
}

func isProductionProject(profile ProjectProfile) bool {
	return profile.FileTree.HasTests
}
