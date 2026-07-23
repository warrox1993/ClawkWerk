package session

import (
	"strings"
	"testing"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/scope"
)

func km(id string, doc, impl cyfun.MaturityLevel) assess.ControlResult {
	return assess.ControlResult{
		Meta:      cyfun.ControlMeta{ID: id, KeyMeasure: true},
		FinalDoc:  doc,
		FinalImpl: impl,
	}
}

func TestComputeConformity_NonConformKeyMeasure(t *testing.T) {
	// Doc=3, Impl=1 -> moyenne 2,0 < 2,5 -> Key Measure non conforme.
	c := ComputeConformity([]assess.ControlResult{km("DE.CM-01.2", cyfun.Defined, cyfun.Initial)}, cyfun.LevelBasic)
	if c.KeyMeasuresConform {
		t.Error("le Key Measure à 2,0 doit être non conforme")
	}
	if len(c.NonConformKeyMeasures) != 1 || c.NonConformKeyMeasures[0] != "DE.CM-01.2" {
		t.Errorf("liste des KM non conformes inattendue : %v", c.NonConformKeyMeasures)
	}
	if c.Conform {
		t.Error("la session ne doit pas être conforme")
	}
}

func TestComputeConformity_Conform(t *testing.T) {
	// Deux KM à moyenne 3,0 -> total 3,0 ≥ 2,5 et tous les KM ≥ 2,5.
	c := ComputeConformity([]assess.ControlResult{
		km("A", cyfun.Defined, cyfun.Defined),
		km("B", cyfun.Defined, cyfun.Defined),
	}, cyfun.LevelBasic)
	if !c.Conform {
		t.Errorf("attendu conforme, obtenu %+v", c)
	}
	if c.TotalMaturity != 3.0 {
		t.Errorf("TotalMaturity = %v, attendu 3.0", c.TotalMaturity)
	}
}

// Cas limite officiel : total conforme mais un KM sous le seuil => NON conforme.
func TestComputeConformity_TotalOKButKeyMeasureFails(t *testing.T) {
	c := ComputeConformity([]assess.ControlResult{
		km("KM-fail", cyfun.Repeatable, cyfun.Repeatable), // 2,0
		km("KM-high", cyfun.Optimizing, cyfun.Optimizing), // 5,0
	}, cyfun.LevelBasic)
	// total = (2+5)/2 = 3,5 ≥ 2,5, mais KM-fail échoue.
	if c.TotalMaturity < cyfun.BasicTotalThreshold {
		t.Fatalf("pré-condition : total %v devait être ≥ 2,5", c.TotalMaturity)
	}
	if c.Conform {
		t.Error("un seul KM sous le seuil doit rendre la session non conforme")
	}
}

func TestAuditSession_JSONContainsDisclaimerAndSchema(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	s := New("sess-1", scope.AuditScope{ClientRef: "ACME"},
		[]assess.ControlResult{km("DE.CM-01.2", cyfun.Defined, cyfun.Defined)}, nil, ts, ts)
	b, err := s.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, Disclaimer) {
		t.Error("le disclaimer légal doit figurer dans la sortie JSON")
	}
	if !strings.Contains(js, `"schema_version": "1.0"`) {
		t.Error("schema_version absent")
	}
	if !strings.Contains(js, `"conform"`) {
		t.Error("verdict de conformité absent")
	}
}
