# Contextualization Agent

## Objectif
Analyser le profil du projet généré par le Profiler Agent et décider intelligemment quels agents de sécurité activer (SAST/SCA/Secrets) et avec quels paramètres. C'est le "routeur intelligent" de la pipeline.

## Responsabilités

1. **Décision d'activation** : Déterminer quels agents SAST/SCA/Secrets sont pertinents
2. **Configuration des agents** : Paramétrer chaque agent selon le contexte (sévérité, règles, patterns)
3. **Optimisation** : Éviter d'exécuter des agents inutiles (ex: SCA si pas de dépendances externes)
4. **Priorisation** : Définir l'ordre d'importance des analyses

## Structure

```
internal/agents/contextualization/
├── claude.md              # Ce fichier
├── contextualization.go   # Agent principal
├── rules/
│   ├── activation.go      # Règles d'activation des agents
│   └── config.go          # Génération de configs par agent
└── models.go              # Structures AnalysisConfig
```

## Input/Output

### Input
```go
type Input struct {
    ProjectProfile  profiler.ProjectProfile  // Du Profiler Agent
}
```

### Output
```go
type AnalysisConfig struct {
    EnabledAgents  []string              // ["sast", "sca", "secrets"]
    AgentConfigs   map[string]AgentConfig
    Priority       []string              // Ordre d'exécution suggéré
    SkipReasons    map[string]string     // Pourquoi certains agents sont désactivés
}

type AgentConfig struct {
    Enabled       bool
    Severity      string                 // "low", "medium", "high", "critical"
    Rules         []string               // Règles spécifiques à activer
    SkipPatterns  []string               // Patterns à ignorer
    MaxFindings   int                    // Limite de findings
    CustomParams  map[string]interface{} // Params spécifiques à l'agent
}
```

## Logique de Décision

### 1. Activation SAST Agent

**Activer si :**
- Le projet contient du code compilé/interprété (Go, Python, JS, Java, etc.)
- Plus de 10 fichiers de code source détectés

**Ne PAS activer si :**
- Projet purement config (YAML, JSON uniquement)
- Moins de 5 fichiers de code

**Configuration selon langage :**
```go
func configureSAST(profile profiler.ProjectProfile) AgentConfig {
    config := AgentConfig{
        Enabled:  true,
        Severity: "medium",
    }
    
    // Règles par langage
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
        }
    }
    
    // Sévérité selon type de projet
    if hasWebFramework(profile) {
        config.Severity = "high" // Plus critique pour apps web
    }
    
    return config
}
```

### 2. Activation SCA Agent

**Activer si :**
- Le projet a des dépendances externes (> 0 dependencies)
- Fichiers de dépendances détectés (go.mod, package.json, etc.)

**Ne PAS activer si :**
- Aucune dépendance externe
- Projet standalone sans package manager

**Configuration selon contexte :**
```go
func configureSCA(profile profiler.ProjectProfile) AgentConfig {
    config := AgentConfig{
        Enabled:  len(profile.Dependencies) > 0,
        Severity: "high", // CVEs sont toujours critiques
    }
    
    // Skip dev dependencies si projet non-critique
    if !isProductionProject(profile) {
        config.CustomParams["skip_dev_deps"] = true
    }
    
    // Limiter scope selon nombre de deps
    if len(profile.Dependencies) > 100 {
        config.CustomParams["check_direct_only"] = true // Ignorer deps transitives
    }
    
    return config
}
```

### 3. Activation Secrets Agent

**Activer si :**
- Projet contient des fichiers de config (.env, config.yaml, etc.)
- C'est un projet avec infrastructure (docker, k8s, terraform)
- Présence de scripts (bash, python)

**TOUJOURS activer** : La détection de secrets est critique et rapide

**Configuration selon contexte :**
```go
func configureSecrets(profile profiler.ProjectProfile) AgentConfig {
    config := AgentConfig{
        Enabled:  true, // Toujours activé
        Severity: "critical",
    }
    
    // Patterns à chercher selon langages
    patterns := []string{
        "api-keys",
        "private-keys",
        "tokens",
        "passwords",
    }
    
    // Ajouter patterns blockchain si Solidity détecté
    if hasSolidityCode(profile) {
        patterns = append(patterns, "private-keys-eth", "mnemonics")
    }
    
    config.Rules = patterns
    
    // Entropie plus stricte si projet finance/crypto
    if isCryptoProject(profile) {
        config.CustomParams["entropy_threshold"] = 4.0
    } else {
        config.CustomParams["entropy_threshold"] = 4.5
    }
    
    return config
}
```

## Utilisation d'Ollama

Ollama intervient pour des décisions complexes :

### Cas d'usage
1. **Identifier le type de projet** : API, CLI tool, lib, smart contract, etc.
2. **Détecter le domaine** : Finance, healthcare, e-commerce, crypto
3. **Évaluer la criticité** : Production vs dev, internal vs public

```go
func (a *ContextualizationAgent) analyzeWithOllama(profile profiler.ProjectProfile) (ProjectContext, error) {
    prompt := fmt.Sprintf(`
Analyze this project profile and determine:
1. Project type (api, cli, library, smart-contract, frontend, etc.)
2. Domain (finance, healthcare, ecommerce, crypto, general)
3. Criticality level (low, medium, high, critical)
4. Key security concerns based on frameworks and dependencies

Project Profile:
- Languages: %v
- Frameworks: %v
- Dependencies count: %d
- Has tests: %v
- Config files: %v

Respond in JSON format.
`, 
        formatLanguages(profile.Languages),
        formatFrameworks(profile.Frameworks),
        len(profile.Dependencies),
        profile.FileTree.HasTests,
        profile.FileTree.ConfigFiles,
    )
    
    response, err := a.ollamaClient.Generate(prompt, "codellama")
    if err != nil {
        return ProjectContext{}, err
    }
    
    var context ProjectContext
    json.Unmarshal([]byte(response), &context)
    return context, nil
}
```

### Contexte enrichi
```go
type ProjectContext struct {
    Type         string   // "api", "cli", "smart-contract"
    Domain       string   // "finance", "crypto", "general"
    Criticality  string   // "low", "medium", "high", "critical"
    Concerns     []string // ["sql-injection", "key-exposure"]
}
```

## Règles de Priorisation

### Ordre d'exécution des agents

**Priorité 1** : Secrets Agent
- Rapide à exécuter
- Critique (fuite de credentials)
- Peut bloquer la suite si credentials exposés

**Priorité 2** : SAST Agent
- Vulnérabilités dans code custom
- Plus long que Secrets

**Priorité 3** : SCA Agent
- Dépend d'APIs externes (NVD, GitHub)
- Peut être lent si beaucoup de deps

```go
func (a *ContextualizationAgent) determinePriority(config AnalysisConfig) []string {
    priority := []string{}
    
    // Secrets toujours en premier
    if config.AgentConfigs["secrets"].Enabled {
        priority = append(priority, "secrets")
    }
    
    // SAST si activé
    if config.AgentConfigs["sast"].Enabled {
        priority = append(priority, "sast")
    }
    
    // SCA en dernier (dépend d'APIs externes)
    if config.AgentConfigs["sca"].Enabled {
        priority = append(priority, "sca")
    }
    
    return priority
}
```

## Optimisations

### Skip patterns intelligents
```go
func generateSkipPatterns(profile profiler.ProjectProfile) []string {
    patterns := []string{
        "node_modules/",
        "vendor/",
        ".git/",
        "dist/",
        "build/",
    }
    
    // Skip tests si pas critique
    if !isCriticalProject(profile) {
        patterns = append(patterns, "*_test.go", "*.test.js", "test/", "tests/")
    }
    
    return patterns
}
```

### Limiter les findings
```go
// Pour grands projets, limiter nombre de findings par agent
if profile.FileTree.TotalFiles > 1000 {
    config.MaxFindings = 50 // Top 50 vulns seulement
}
```

## Implémentation

### contextualization.go
```go
package contextualization

type ContextualizationAgent struct {
    ollamaClient *ollama.Client
}

func New(ollamaClient *ollama.Client) *ContextualizationAgent {
    return &ContextualizationAgent{
        ollamaClient: ollamaClient,
    }
}

func (a *ContextualizationAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    profile := pipelineCtx.ProjectProfile
    
    // 1. Analyser le contexte avec Ollama
    projectCtx, err := a.analyzeWithOllama(profile)
    if err != nil {
        // Fallback sur analyse heuristique
        projectCtx = a.analyzeHeuristic(profile)
    }
    
    // 2. Configurer chaque agent
    analysisConfig := AnalysisConfig{
        EnabledAgents: []string{},
        AgentConfigs:  make(map[string]AgentConfig),
        SkipReasons:   make(map[string]string),
    }
    
    // SAST
    sastConfig := a.configureSAST(profile, projectCtx)
    if sastConfig.Enabled {
        analysisConfig.EnabledAgents = append(analysisConfig.EnabledAgents, "sast")
        analysisConfig.AgentConfigs["sast"] = sastConfig
    } else {
        analysisConfig.SkipReasons["sast"] = "No source code files detected"
    }
    
    // SCA
    scaConfig := a.configureSCA(profile, projectCtx)
    if scaConfig.Enabled {
        analysisConfig.EnabledAgents = append(analysisConfig.EnabledAgents, "sca")
        analysisConfig.AgentConfigs["sca"] = scaConfig
    } else {
        analysisConfig.SkipReasons["sca"] = "No external dependencies found"
    }
    
    // Secrets
    secretsConfig := a.configureSecrets(profile, projectCtx)
    analysisConfig.EnabledAgents = append(analysisConfig.EnabledAgents, "secrets")
    analysisConfig.AgentConfigs["secrets"] = secretsConfig
    
    // 3. Déterminer priorité
    analysisConfig.Priority = a.determinePriority(analysisConfig)
    
    // 4. Injecter dans pipeline context
    pipelineCtx.AnalysisConfig = analysisConfig
    
    return nil
}
```

## Tests

### Scénarios de test

**Projet API REST Go avec deps**
- ✅ SAST activé (rules: sql-injection, command-injection)
- ✅ SCA activé (check deps via NVD)
- ✅ Secrets activé (entropy standard)

**Frontend React standalone**
- ✅ SAST activé (rules: xss, prototype-pollution)
- ❌ SCA désactivé si pas de deps backend
- ✅ Secrets activé (API keys dans .env)

**Smart contract Solidity**
- ✅ SAST activé (rules: reentrancy, overflow)
- ✅ SCA activé (libs Hardhat/OpenZeppelin)
- ✅ Secrets activé (entropy stricte pour private keys)

**Projet config-only (Terraform)**
- ❌ SAST désactivé (pas de code applicatif)
- ❌ SCA désactivé (pas de deps runtime)
- ✅ Secrets activé (credentials AWS/GCP)

## Output Exemple

```json
{
  "enabled_agents": ["secrets", "sast", "sca"],
  "agent_configs": {
    "sast": {
      "enabled": true,
      "severity": "high",
      "rules": ["sql-injection", "xss", "command-injection"],
      "skip_patterns": ["*_test.go"],
      "max_findings": 100
    },
    "sca": {
      "enabled": true,
      "severity": "high",
      "rules": [],
      "custom_params": {
        "skip_dev_deps": false,
        "check_direct_only": false
      }
    },
    "secrets": {
      "enabled": true,
      "severity": "critical",
      "rules": ["api-keys", "private-keys", "tokens"],
      "custom_params": {
        "entropy_threshold": 4.5
      }
    }
  },
  "priority": ["secrets", "sast", "sca"],
  "skip_reasons": {}
}
```

## Prochaine Étape
Une fois la configuration générée, les agents **SAST**, **SCA** et **Secrets** s'exécutent en parallèle avec leurs configs respectives.