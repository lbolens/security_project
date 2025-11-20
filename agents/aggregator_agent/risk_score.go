package main

import (
	"math"
)

func CalculateRiskScore(input RiskScoreInput) (*RiskScoreOutput, error) {
	findings := make([]ConsolidatedFinding, len(input.Findings))
	for i, f := range input.Findings {
		findings[i] = mapToFinding(f)
	}

	if len(findings) == 0 {
		return &RiskScoreOutput{
			RiskScore: 0.0,
			RiskLevel: "low",
			Breakdown: RiskScoreBreakdown{
				CriticalImpact: 0,
				HighImpact:     0,
				MediumImpact:   0,
				LowImpact:      0,
			},
		}, nil
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	score := float64(criticalCount*10 + highCount*5 + mediumCount*2 + lowCount*1)

	maxScore := float64(len(findings) * 10)
	normalized := (score / maxScore) * 100

	if normalized > 100 {
		normalized = 100
	}

	normalized = math.Round(normalized*10) / 10

	riskLevel := "low"
	if normalized >= 76 {
		riskLevel = "critical"
	} else if normalized >= 51 {
		riskLevel = "high"
	} else if normalized >= 26 {
		riskLevel = "medium"
	}

	breakdown := RiskScoreBreakdown{
		CriticalImpact: float64(criticalCount * 10),
		HighImpact:     float64(highCount * 5),
		MediumImpact:   float64(mediumCount * 2),
		LowImpact:      float64(lowCount * 1),
	}

	return &RiskScoreOutput{
		RiskScore: normalized,
		RiskLevel: riskLevel,
		Breakdown: breakdown,
	}, nil
}
