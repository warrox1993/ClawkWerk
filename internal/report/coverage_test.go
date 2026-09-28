package report

import (
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func ctrl(id string) cyfun.ControlMeta { return cyfun.ControlMeta{ID: id, Function: cyfun.Protect} }

func hostHA(id string, st assess.Status, msg string) assess.HostAssessment {
	return assess.HostAssessment{
		Host:     assess.HostRef{ID: id},
		Findings: []assess.Finding{{HostID: id, Status: st, Message: msg}},
	}
}

func TestCoverageRow_Classification(t *testing.T) {
	cases := []struct {
		name       string
		r          assess.ControlResult
		wantMethod string
		wantDetail string // sous-chaîne attendue (vide = pas de vérif)
	}{
		{"déclaratif", assess.ControlResult{Meta: ctrl("GV.PO-01.1")}, "Déclaratif (questionnaire)", ""},
		{"n/a", assess.ControlResult{Meta: ctrl("X"), NotApplicable: true}, "N/A (attesté)", ""},
		{"scan mesuré", assess.ControlResult{
			Meta:            ctrl("DE.CM-01.2"),
			HostAssessments: []assess.HostAssessment{hostHA("PC1", assess.StatusPass, "ok")},
		}, "Scan technique", "1 hôte(s) mesuré(s)"},
		{"repli sur attestation", assess.ControlResult{
			Meta:                ctrl("PR.AA-01.1"),
			ImplFromAttestation: true,
			HostAssessments:     []assess.HostAssessment{hostHA("WIN7", assess.StatusError, "droits insuffisants : lecture refusée")},
		}, "Attestation de repli (scan indisponible)", "droits insuffisants"},
		{"non évalué OS", assess.ControlResult{
			Meta:            ctrl("PR.DS-11.1"),
			HostAssessments: []assess.HostAssessment{hostHA("MAC", assess.StatusNA, "non applicable")},
		}, "NON ÉVALUÉ", "OS non supporté"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := coverageRow(c.r)
			if row.Method != c.wantMethod {
				t.Errorf("Method = %q, attendu %q", row.Method, c.wantMethod)
			}
			if c.wantDetail != "" && !strings.Contains(row.Detail, c.wantDetail) {
				t.Errorf("Detail %q ne contient pas %q", row.Detail, c.wantDetail)
			}
		})
	}
}
