package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func patchRaw(t *testing.T, pending int) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(PatchEvidence{PendingSecurityUpdates: pending, Manager: "apt"})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 2 contrôles réutilisent la MÊME sonde PatchEvidence avec la même logique MIXTE :
// 0 correctif => Defined (plafond) ; quelques-uns => Repeatable ; beaucoup => Initial.
func TestVulnFam_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		pending int
		wantLvl cyfun.MaturityLevel
	}{
		{"RA0102 aucun => Defined", Vuln0102Evaluator{}, 0, cyfun.Defined},
		{"RA0102 quelques-uns => Repeatable", Vuln0102Evaluator{}, 3, cyfun.Repeatable},
		{"RA0102 beaucoup => Initial", Vuln0102Evaluator{}, 25, cyfun.Initial},
		{"RA0106 aucun => Defined", Vuln0106Evaluator{}, 0, cyfun.Defined},
		{"RA0106 quelques-uns => Repeatable", Vuln0106Evaluator{}, 1, cyfun.Repeatable},
		{"RA0106 beaucoup => Initial", Vuln0106Evaluator{}, 42, cyfun.Initial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(patchRaw(t, c.pending))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined, même sans aucun correctif en attente :
// le processus continu de gestion des vulnérabilités reste organisationnel (à attester).
func TestVulnFam_CapsAtDefined(t *testing.T) {
	for _, eval := range []assess.Evaluator{Vuln0102Evaluator{}, Vuln0106Evaluator{}} {
		ha := eval.Evaluate(patchRaw(t, 0))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("gestion vuln MIXTE a proposé %d > Defined — plafond violé", ha.ProposedImplLevel)
		}
	}
}

// Les métadonnées portent le bon niveau (Important) et le bon flag KM (false).
func TestVulnFam_Meta(t *testing.T) {
	if IDRA0102Meta.Level != cyfun.LevelImportant || IDRA0102Meta.KeyMeasure {
		t.Error("ID.RA-01.2 doit être Important + non-KM")
	}
	if IDRA0106Meta.Level != cyfun.LevelImportant || IDRA0106Meta.KeyMeasure {
		t.Error("ID.RA-01.6 doit être Important + non-KM")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestVulnFam_CollectErrIsNotAssessed(t *testing.T) {
	ha := Vuln0102Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("collecte échouée: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}
