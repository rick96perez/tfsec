package rules

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type FlatResult struct {
	RuleID          string            `json:"external_id"`
	LongID          string            `json:"title"`
	RuleSummary     string            `json:"summary"`
	RuleProvider    provider.Provider `json:"rule_provider"`
	RuleService     string            `json:"rule_service"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          Status            `json:"status"`
	Resource        string            `json:"resource"`
	Path            string            `json:"path"`
	Line            int               `json:"line"`
	Location        FlatRange         `json:"location"`
	Type            string            `json:"annotation_type"`
}

type FlatRange struct {
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r Results) Flatten() []FlatResult {
	var results []FlatResult
	for _, original := range r {
		results = append(results, original.Flatten())
	}
	return results
}

func (r *Result) Flatten() FlatResult {
	rng := r.metadata.Range()
	path := rng.GetFilename()

	cwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}

	file := strings.ReplaceAll(path, cwd+"/", "")

	return FlatResult{
		RuleID:          r.rule.AVDID + "-" + r.Rule().LongID() + "-" + strconv.Itoa(rng.GetStartLine()),
		LongID:          r.Rule().LongID(),
		RuleSummary:     r.rule.Summary,
		RuleProvider:    r.rule.Provider,
		RuleService:     r.rule.Service,
		Impact:          r.rule.Impact,
		Resolution:      r.rule.Resolution,
		Links:           r.rule.Links,
		Description:     r.Description(),
		RangeAnnotation: r.Annotation(),
		Severity:        r.rule.Severity,
		Status:          r.status,
		Resource:        r.metadata.Reference().LogicalID(),
		Path:            file,
		Line:            rng.GetStartLine(),
		Location: FlatRange{
			Filename:  file,
			StartLine: rng.GetStartLine(),
			EndLine:   rng.GetEndLine(),
		},
		Type: "VULNERABILITY",
	}
}
