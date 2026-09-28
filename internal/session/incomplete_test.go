package session

import (
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Un contrôle NON évalué (ni scan, ni attestation, ni N/A) bloque le verdict :
// pas de conforme/non-conforme, il est listé « à évaluer », et il est EXCLU de
// la moyenne — jamais noté 0, ce qui fabriquerait une fausse faille.
func TestComputeConformity_IncompleteBlocksVerdict(t *testing.T) {
	res := []assess.ControlResult{
		km("A", cyfun.Defined, cyfun.Defined),                  // évalué : 3,0
		km("B", cyfun.Defined, cyfun.Defined),                  // évalué : 3,0
		{Meta: cyfun.ControlMeta{ID: "GAP", KeyMeasure: true}}, // non évalué : 0/0
	}
	c := ComputeConformity(res, cyfun.LevelBasic)

	if !c.Incomplete {
		t.Fatal("l'audit doit être marqué incomplet")
	}
	if c.Conform {
		t.Error("aucun verdict conforme tant qu'il subsiste des trous")
	}
	if len(c.UnassessedControls) != 1 || c.UnassessedControls[0] != "GAP" {
		t.Errorf("liste des non évalués inattendue : %v", c.UnassessedControls)
	}
	// GAP exclu de la moyenne : total = moyenne(A,B) = 3,0, et NON (3+3+0)/3 = 2,0.
	if c.TotalMaturity != 3.0 {
		t.Errorf("le non évalué doit être exclu de la moyenne ; total=%v attendu 3.0", c.TotalMaturity)
	}
	// Un KM non évalué n'est pas « non conforme » : il est à évaluer.
	for _, id := range c.NonConformKeyMeasures {
		if id == "GAP" {
			t.Error("un contrôle non évalué ne doit pas être classé « non conforme »")
		}
	}
}

// Un contrôle attesté N/A est considéré évalué : il ne rend pas l'audit incomplet.
func TestComputeConformity_NAIsAssessed(t *testing.T) {
	na := km("NA", cyfun.NotAssessed, cyfun.NotAssessed)
	na.NotApplicable = true
	c := ComputeConformity([]assess.ControlResult{
		km("A", cyfun.Defined, cyfun.Defined),
		na,
	}, cyfun.LevelBasic)
	if c.Incomplete {
		t.Error("un contrôle N/A attesté ne doit pas rendre l'audit incomplet")
	}
}

// Audit COMPLET : parité préservée — Incomplete faux, verdict délivré.
func TestComputeConformity_CompleteStillVerdicts(t *testing.T) {
	c := ComputeConformity([]assess.ControlResult{
		km("A", cyfun.Defined, cyfun.Defined),
		km("B", cyfun.Defined, cyfun.Defined),
	}, cyfun.LevelBasic)
	if c.Incomplete {
		t.Error("audit complet : ne doit pas être incomplet")
	}
	if !c.Conform {
		t.Error("audit complet à 3,0 : doit être conforme")
	}
}
