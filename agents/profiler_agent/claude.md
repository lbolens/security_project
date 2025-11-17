# Project Profiler Agent

## Objectif
Scanner un projet et extraire son profil complet : langages, frameworks, dépendances, structure. C'est la base pour tous les autres agents.

## Responsabilités

1. **Détection des langages** : Identifier tous les langages présents (Go, Python, JS, etc.)
2. **Identification des frameworks** : Détecter frameworks/libs (React, Django, Gin, etc.)
3. **Extraction des dépendances** : Parser les fichiers de dépendances (go.mod, package.json, requirements.txt, etc.)
4. **Analyse de structure** : Mapper l'arborescence du projet
5. **Génération du profil** : Créer un objet `ProjectProfile` pour le contexte pipeline

## Structure

```
internal/agents/profiler/
├── claude.md          # Ce fichier
├── profiler.go        # Agent principal
├── detectors/
│   ├── language.go    # Détection langages par extensions
│   ├── framework.go   # Détection frameworks par patterns
│   └── deps.go        # Parsers de dépendances
└── models.go          # Structures ProjectProfile
```

## Input/Output

### Input
```go
type Input struct {
    ProjectPath string // Chemin absolu du projet à analyser
}
```

### Output
```go
type ProjectProfile struct {
    Languages    []Language
    Frameworks   []Framework
    Dependencies []Dependency
    FileTree     FileTree
    Metadata     Metadata
}

type Language struct {
    Name       string  // "Go", "Python", "JavaScript"
    Version    string  // Optionnel, si détectable
    FileCount  int     // Nombre de fichiers
    Percentage float64 // % du projet
}

type Framework struct {
    Name     string // "React", "Gin", "Django"
    Version  string // Depuis package manager
    Language string // Langage associé
}

type Dependency struct {
    Name        string
    Version     string
    Language    string
    IsDevDep    bool   // Dépendance de dev ou prod
    FilePath    string // Où elle est déclarée
}

type FileTree struct {
    TotalFiles   int
    TotalDirs    int
    MaxDepth     int
    HasTests     bool
    HasDocs      bool
    ConfigFiles  []string // .env, config.yaml, etc.
}

type Metadata struct {
    ProjectName string // Nom du dossier racine
    Size        int64  // Taille en bytes
    GitRepo     bool   // Si c'est un repo git
}
```

## Détection des Langages

### Stratégie
1. Scanner récursivement tous les fichiers
2. Mapper extensions → langages
3. Calculer statistiques (nombre de fichiers, %)

### Extensions à détecter
```go
var LanguageExtensions = map[string]string{
    ".go":   "Go",
    ".py":   "Python",
    ".js":   "JavaScript",
    ".ts":   "TypeScript",
    ".jsx":  "JavaScript",
    ".tsx":  "TypeScript",
    ".java": "Java",
    ".c":    "C",
    ".cpp":  "C++",
    ".cs":   "C#",
    ".rb":   "Ruby",
    ".php":  "PHP",
    ".rs":   "Rust",
    ".sol":  "Solidity",
}
```

### Exclusions
Ignorer : `node_modules/`, `vendor/`, `.git/`, `venv/`, `__pycache__/`, `build/`, `dist/`

## Détection des Frameworks

### Stratégie par langage

**JavaScript/TypeScript**
- Lire `package.json` → chercher dans `dependencies` et `devDependencies`
- Patterns : `"react"`, `"vue"`, `"angular"`, `"express"`, `"next"`

**Python**
- Lire `requirements.txt`, `Pipfile`, `pyproject.toml`
- Patterns : `django`, `flask`, `fastapi`

**Go**
- Lire `go.mod`
- Patterns : `gin-gonic/gin`, `gorilla/mux`, `fiber`, `echo`

**Java**
- Lire `pom.xml` (Maven) ou `build.gradle` (Gradle)
- Patterns : `spring-boot`, `quarkus`, `micronaut`

**Solidity**
- Lire `package.json` ou `hardhat.config.js`
- Patterns : `hardhat`, `truffle`, `foundry`

## Extraction des Dépendances

### Parsers à implémenter

**Go** (`go.mod`)
```go
func parseGoMod(path string) ([]Dependency, error) {
    // Parser format:
    // require (
    //     github.com/gin-gonic/gin v1.9.0
    // )
}
```

**JavaScript/TypeScript** (`package.json`)
```go
func parsePackageJSON(path string) ([]Dependency, error) {
    // JSON standard, utiliser encoding/json
    // Séparer dependencies (prod) et devDependencies
}
```

**Python** (`requirements.txt`)
```go
func parseRequirementsTxt(path string) ([]Dependency, error) {
    // Format: package==version ou package>=version
}
```

**Rust** (`Cargo.toml`)
```go
func parseCargoToml(path string) ([]Dependency, error) {
    // TOML format
}
```

**Java** (`pom.xml`)
```go
func parsePomXML(path string) ([]Dependency, error) {
    // XML parsing
}
```

## Analyse de Structure

### Métriques à collecter
- Nombre total de fichiers et dossiers
- Profondeur maximale de l'arborescence
- Présence de tests (`*_test.go`, `*.test.js`, `test/`, `tests/`)
- Présence de docs (`README.md`, `docs/`, `*.md`)
- Fichiers de configuration (`.env`, `config.*`, `.yaml`)

### Fichiers sensibles à noter
- `.env`, `.env.local` → Potentiels secrets
- `docker-compose.yml` → Setup infrastructure
- `.github/workflows/` → CI/CD

## Implémentation

### profiler.go
```go
package profiler

type ProfilerAgent struct {
    languageDetector  *LanguageDetector
    frameworkDetector *FrameworkDetector
    depsParser        *DependencyParser
}

func New() *ProfilerAgent {
    return &ProfilerAgent{
        languageDetector:  NewLanguageDetector(),
        frameworkDetector: NewFrameworkDetector(),
        depsParser:        NewDependencyParser(),
    }
}

func (a *ProfilerAgent) Execute(ctx context.Context, pipelineCtx *pipeline.Context) error {
    // 1. Scanner l'arborescence
    fileTree, err := a.scanFileTree(pipelineCtx.ProjectPath)
    if err != nil {
        return err
    }
    
    // 2. Détecter langages
    languages, err := a.languageDetector.Detect(pipelineCtx.ProjectPath)
    if err != nil {
        return err
    }
    
    // 3. Détecter frameworks
    frameworks, err := a.frameworkDetector.Detect(pipelineCtx.ProjectPath, languages)
    if err != nil {
        return err
    }
    
    // 4. Parser dépendances
    deps, err := a.depsParser.Parse(pipelineCtx.ProjectPath, languages)
    if err != nil {
        return err
    }
    
    // 5. Construire profil
    profile := ProjectProfile{
        Languages:    languages,
        Frameworks:   frameworks,
        Dependencies: deps,
        FileTree:     fileTree,
        Metadata:     extractMetadata(pipelineCtx.ProjectPath),
    }
    
    // 6. Injecter dans le contexte pipeline
    pipelineCtx.ProjectProfile = profile
    
    return nil
}
```

### detectors/language.go
```go
func (d *LanguageDetector) Detect(projectPath string) ([]Language, error) {
    langCount := make(map[string]int)
    
    err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
        // Ignorer dossiers exclus
        if d.IsDir() && shouldExclude(d.Name()) {
            return filepath.SkipDir
        }
        
        // Compter par extension
        ext := filepath.Ext(path)
        if lang, ok := LanguageExtensions[ext]; ok {
            langCount[lang]++
        }
        
        return nil
    })
    
    // Convertir en []Language avec percentages
    return convertToLanguages(langCount), err
}
```

## Utilisation Ollama (optionnel)

Pour des cas ambigus, Ollama peut aider :
- Confirmer un framework si pattern pas clair
- Identifier langage custom ou DSL
- Comprendre architecture complexe

```go
func (a *ProfilerAgent) analyzeWithOllama(projectPath string) (string, error) {
    prompt := fmt.Sprintf(
        "Analyze this project structure and identify the main framework:\n%s",
        getProjectStructureSummary(projectPath),
    )
    
    return a.ollamaClient.Generate(prompt, "codellama")
}
```

**Note** : Ollama pas critique ici, la détection par patterns suffit 95% du temps.

## Tests

### Test avec projets réels
- Projet Go simple (un seul `main.go`)
- API REST Gin avec dépendances
- Frontend React/TypeScript
- Projet Python Django
- Smart contract Solidity avec Hardhat

### Cas limites
- Projet multi-langages (backend Go + frontend React)
- Monorepo avec plusieurs sous-projets
- Projet sans fichier de dépendances

## Performance

- **Lazy loading** : Parser les dépendances uniquement si nécessaire
- **Cache** : Mémoriser résultats pour éviter re-scan
- **Concurrence** : Scanner langages en parallèle si projet > 10k fichiers

## Output Exemple

```json
{
  "languages": [
    {"name": "Go", "version": "1.21", "file_count": 42, "percentage": 78.5},
    {"name": "JavaScript", "version": "", "file_count": 12, "percentage": 21.5}
  ],
  "frameworks": [
    {"name": "Gin", "version": "1.9.0", "language": "Go"}
  ],
  "dependencies": [
    {"name": "github.com/gin-gonic/gin", "version": "1.9.0", "language": "Go", "is_dev": false},
    {"name": "github.com/stretchr/testify", "version": "1.8.0", "language": "Go", "is_dev": true}
  ],
  "file_tree": {
    "total_files": 54,
    "total_dirs": 12,
    "max_depth": 4,
    "has_tests": true,
    "has_docs": true,
    "config_files": [".env", "config.yaml"]
  },
  "metadata": {
    "project_name": "my-api",
    "size": 2458624,
    "git_repo": true
  }
}
```

## Prochaine Étape
Une fois le profil généré, le **Contextualization Agent** l'utilisera pour décider quels agents SAST/SCA/Secrets activer.