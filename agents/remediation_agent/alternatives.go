package main

import (
	"fmt"
)

func GenerateAlternatives(finding map[string]interface{}, primaryFix Fix, maxAlternatives int) []Fix {
	var alternatives []Fix

	findingType := GetStringValue(finding, "type")
	filePath := GetStringValue(finding, "file_path")
	lang := DetectLanguage(filePath)

	switch findingType {
	case "sql-injection":
		alternatives = append(alternatives, generateORMAlternative(lang, finding))
		alternatives = append(alternatives, generateQueryBuilderAlternative(lang, finding))

	case "xss":
		alternatives = append(alternatives, generateTemplateEngineAlternative(lang, finding))
		alternatives = append(alternatives, generateSanitizationLibraryAlternative(lang, finding))

	case "weak-crypto":
		alternatives = append(alternatives, generateCryptoLibraryAlternative(lang, finding))

	case "vulnerable-dependency":
		alternatives = append(alternatives, generateDependencyAlternativeAlternative(finding))

	default:
		alternatives = append(alternatives, generateGenericAlternative(finding, primaryFix))
	}

	if len(alternatives) > maxAlternatives {
		alternatives = alternatives[:maxAlternatives]
	}

	return alternatives
}

func generateORMAlternative(lang string, finding map[string]interface{}) Fix {
	var codeAfter string
	var description string

	switch lang {
	case "go":
		codeAfter = `db.Where("id = ?", userId).First(&user)`
		description = "Use GORM ORM with safe query builder"
	case "python":
		codeAfter = `user = User.query.filter_by(id=user_id).first()`
		description = "Use SQLAlchemy ORM"
	default:
		codeAfter = "// Use ORM library"
		description = "Use ORM with built-in query protection"
	}

	return Fix{
		Type:           "code-patch",
		Description:    description,
		CodeAfter:      codeAfter,
		FilePath:       GetStringValue(finding, "file_path"),
		LineNumber:     GetIntValue(finding, "line_number"),
		Impact:         "Requires ORM library dependency, more idiomatic code",
		Rationale:      "ORMs provide built-in SQL injection protection",
		BreakingChange: false,
	}
}

func generateQueryBuilderAlternative(lang string, finding map[string]interface{}) Fix {
	return Fix{
		Type:           "code-patch",
		Description:    "Use query builder library",
		CodeAfter:      `query := builder.Select("*").From("users").Where(builder.Eq{"id": userId})`,
		FilePath:       GetStringValue(finding, "file_path"),
		LineNumber:     GetIntValue(finding, "line_number"),
		Impact:         "Requires query builder library",
		Rationale:      "Query builders provide safe, composable query construction",
		BreakingChange: false,
	}
}

func generateTemplateEngineAlternative(lang string, finding map[string]interface{}) Fix {
	var codeAfter string

	switch lang {
	case "go":
		codeAfter = `tmpl.Execute(w, data) // Template auto-escapes`
	case "python":
		codeAfter = `return render_template('page.html', data=user_input)`
	default:
		codeAfter = "// Use template engine with auto-escaping"
	}

	return Fix{
		Type:           "code-patch",
		Description:    "Use template engine with auto-escaping",
		CodeAfter:      codeAfter,
		FilePath:       GetStringValue(finding, "file_path"),
		LineNumber:     GetIntValue(finding, "line_number"),
		Impact:         "May require template refactoring",
		Rationale:      "Template engines provide automatic context-aware escaping",
		BreakingChange: false,
	}
}

func generateSanitizationLibraryAlternative(lang string, finding map[string]interface{}) Fix {
	return Fix{
		Type:           "code-patch",
		Description:    "Use dedicated sanitization library",
		CodeAfter:      `sanitized := sanitizer.Sanitize(userInput)`,
		FilePath:       GetStringValue(finding, "file_path"),
		LineNumber:     GetIntValue(finding, "line_number"),
		Impact:         "Requires sanitization library dependency",
		Rationale:      "Dedicated libraries provide comprehensive XSS protection",
		BreakingChange: false,
	}
}

func generateCryptoLibraryAlternative(lang string, finding map[string]interface{}) Fix {
	return Fix{
		Type:           "code-patch",
		Description:    "Use modern cryptographic library",
		CodeAfter:      `hash, _ := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)`,
		FilePath:       GetStringValue(finding, "file_path"),
		LineNumber:     GetIntValue(finding, "line_number"),
		Impact:         "Stronger security, slightly higher CPU usage",
		Rationale:      "Argon2 is the modern standard for password hashing",
		BreakingChange: true,
	}
}

func generateDependencyAlternativeAlternative(finding map[string]interface{}) Fix {
	packageName := GetStringValue(finding, "component_name")

	return Fix{
		Type:           "removal",
		Description:    fmt.Sprintf("Remove %s and use alternative library", packageName),
		Impact:         "Requires code refactoring to use alternative",
		Rationale:      "If update is not available, switching to maintained alternative",
		BreakingChange: true,
	}
}

func generateGenericAlternative(finding map[string]interface{}, primaryFix Fix) Fix {
	return Fix{
		Type:           primaryFix.Type,
		Description:    "Alternative approach: " + primaryFix.Description,
		Impact:         "Different implementation with similar outcome",
		Rationale:      "Provides flexibility in implementation choice",
		BreakingChange: false,
	}
}
