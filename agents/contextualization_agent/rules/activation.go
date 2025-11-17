package rules

type Language struct {
	Name       string
	FileCount  int
	Percentage float64
}

type Framework struct {
	Name     string
	Language string
}

type Dependency struct {
	Name     string
	Language string
}

type FileTree struct {
	TotalFiles int
	HasTests   bool
	HasDocs    bool
}

type ProjectProfile struct {
	Languages    []Language
	Frameworks   []Framework
	Dependencies []Dependency
	FileTree     FileTree
}

type ProjectContext struct {
	Type        string
	Domain      string
	Criticality string
}

func ShouldActivateSAST(profile ProjectProfile) (bool, string) {
	totalCodeFiles := 0
	for _, lang := range profile.Languages {
		totalCodeFiles += lang.FileCount
	}

	if totalCodeFiles < 5 {
		return false, "Less than 5 source code files detected"
	}

	if len(profile.Languages) == 0 {
		return false, "No programming languages detected"
	}

	return true, ""
}

func ShouldActivateSCA(profile ProjectProfile) (bool, string) {
	if len(profile.Dependencies) == 0 {
		return false, "No external dependencies found"
	}

	return true, ""
}

func ShouldActivateSecrets(profile ProjectProfile) (bool, string) {
	return true, ""
}
