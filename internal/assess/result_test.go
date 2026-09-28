package assess

import (
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Verrouille la règle de conformité OFFICIELLE : pour un Key Measure au
// niveau Basic, moyenne(Doc, Impl) ≥ 2,5.
func TestControlResult_MaturityAndConformity(t *testing.T) {
	km := cyfun.ControlMeta{ID: "DE.CM-01.2", KeyMeasure: true}

	// Doc=2, Impl=3 -> moyenne 2,5 -> CONFORME (seuil atteint).
	r := ControlResult{Meta: km, FinalDoc: cyfun.Repeatable, FinalImpl: cyfun.Defined}
	if got := r.Maturity(); got != 2.5 {
		t.Errorf("Maturity = %v, attendu 2.5", got)
	}
	if !r.ConformBasic() {
		t.Error("moyenne 2,5 doit être conforme au seuil Basic")
	}

	// Doc=2, Impl=2 -> moyenne 2,0 -> NON conforme.
	r2 := ControlResult{Meta: km, FinalDoc: cyfun.Repeatable, FinalImpl: cyfun.Repeatable}
	if r2.ConformBasic() {
		t.Error("moyenne 2,0 ne doit PAS être conforme")
	}

	// Un contrôle non-Key-Measure n'est pas bloquant individuellement.
	nk := ControlResult{Meta: cyfun.ControlMeta{KeyMeasure: false}, FinalDoc: cyfun.Initial, FinalImpl: cyfun.Initial}
	if !nk.ConformBasic() {
		t.Error("un non-Key-Measure ne doit pas échouer au seuil individuel")
	}
}

func TestWorstCase(t *testing.T) {
	// Trois hôtes ; on ignore le non évalué et on retient le plus faible.
	has := []HostAssessment{
		{ProposedImplLevel: cyfun.Managed},
		{ProposedImplLevel: cyfun.NotAssessed}, // ignoré
		{ProposedImplLevel: cyfun.Repeatable},  // le pire évalué
	}
	got, _ := WorstCase(has)
	if got != cyfun.Repeatable {
		t.Errorf("WorstCase = %d, attendu Repeatable (2)", got)
	}

	// Aucun hôte évaluable -> NotAssessed.
	none, _ := WorstCase([]HostAssessment{{ProposedImplLevel: cyfun.NotAssessed}})
	if none != cyfun.NotAssessed {
		t.Errorf("WorstCase (aucun) = %d, attendu NotAssessed (0)", none)
	}
}
