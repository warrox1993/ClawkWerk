package report

import (
	"strings"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/session"
)

func TestBuild_PopulatesHostRisks_MeasuredOnly(t *testing.T) {
	results := []assess.ControlResult{
		{
			Meta: cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, KeyMeasure: true},
			HostAssessments: []assess.HostAssessment{{
				Host:     assess.HostRef{ID: "PC1"},
				Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusFail, Message: "pas d'AV"}},
			}},
		},
		{ // attestation de repli : constat NON mesuré, doit être ignoré du risque
			Meta:                cyfun.ControlMeta{ID: "PR.AA-01.1", Function: cyfun.Protect, KeyMeasure: true},
			ImplFromAttestation: true,
			HostAssessments: []assess.HostAssessment{{
				Host:     assess.HostRef{ID: "PC1"},
				Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusError, Message: "droits insuffisants"}},
			}},
		},
	}
	v := Build(session.AuditSession{Results: results})
	if len(v.HostRisks) != 1 || v.HostRisks[0].HostID != "PC1" {
		t.Fatalf("HostRisks inattendu : %+v", v.HostRisks)
	}
	if v.HostRisks[0].Score != 100 { // un seul constat mesuré, un fail KM -> 100/100
		t.Errorf("score = %d, attendu 100", v.HostRisks[0].Score)
	}
	if v.HostRisks[0].MeasuredControls != 1 { // l'attestation n'est pas comptée
		t.Errorf("contrôles mesurés = %d, attendu 1", v.HostRisks[0].MeasuredControls)
	}
}

func TestHTML_RendersHostRiskSectionWithDisclaimer(t *testing.T) {
	results := []assess.ControlResult{{
		Meta: cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, KeyMeasure: true},
		HostAssessments: []assess.HostAssessment{{
			Host:     assess.HostRef{ID: "PC1"},
			Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusFail, Message: "pas d'AV"}},
		}},
	}}
	out, err := HTML(Build(session.AuditSession{Results: results}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "risque technique") {
		t.Error("la section de risque technique doit être présente")
	}
	if !strings.Contains(s, "PC1") {
		t.Error("l'hôte à risque doit apparaître")
	}
	if !strings.Contains(strings.ToLower(s), "pas un verdict de conformité") {
		t.Error("l'avertissement d'intégrité (≠ conformité CyFun) doit être affiché")
	}
}
