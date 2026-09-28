package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// evaluator commun à la famille : signature identique, on teste les trois via
// une petite indirection pour ne pas dupliquer le tableau de cas.
type invFamEvaluator interface {
	Evaluate(assess.RawEvidence) assess.HostAssessment
}

func TestInventoryFamEvaluators(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	evaluators := map[string]invFamEvaluator{
		"ID.AM-02.2": SwInv0202Evaluator{},
		"ID.AM-02.4": SwInv0204Evaluator{},
		"ID.AM-02.5": SwInv0205Evaluator{},
	}
	cases := []struct {
		name     string
		ev       SoftwareInventoryEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"énumération impossible", SoftwareInventoryEvidence{InstalledCount: 0}, cyfun.Initial, assess.StatusFail},
		{"compte négatif (illisible)", SoftwareInventoryEvidence{InstalledCount: -1}, cyfun.Initial, assess.StatusFail},
		{"énumérable", SoftwareInventoryEvidence{InstalledCount: 742}, cyfun.Defined, assess.StatusPartial},
	}
	for id, e := range evaluators {
		for _, c := range cases {
			t.Run(id+"/"+c.name, func(t *testing.T) {
				data, _ := json.Marshal(c.ev)
				ha := e.Evaluate(assess.RawEvidence{ControlID: id, Host: host, Data: data})
				if ha.ProposedImplLevel != c.wantLvl {
					t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
				}
				if ha.Findings[0].Status != c.wantStat {
					t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
				}
			})
		}
	}
}

func TestInventoryFamEvaluators_capAtDefined(t *testing.T) {
	// MIXTE : même un parc énorme ne peut PAS proposer mieux que Defined(3).
	// L'inventaire tenu + la liste autorisée (Managed/Optimizing) relèvent de
	// l'axe Documentation, jamais d'un scan hôte.
	data, _ := json.Marshal(SoftwareInventoryEvidence{InstalledCount: 100000})
	evaluators := []invFamEvaluator{SwInv0202Evaluator{}, SwInv0204Evaluator{}, SwInv0205Evaluator{}}
	for _, e := range evaluators {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("%T a proposé %d > Defined(3) — interdit", e, ha.ProposedImplLevel)
		}
	}
}

func TestInventoryFamEvaluators_collectErr(t *testing.T) {
	// Collecte échouée → NotAssessed + StatusError, jamais un score par défaut.
	evaluators := []invFamEvaluator{SwInv0202Evaluator{}, SwInv0204Evaluator{}, SwInv0205Evaluator{}}
	for _, e := range evaluators {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, CollectErr: "timeout SSH"})
		if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
			t.Fatalf("%T : collecte échouée mal gérée: %+v", e, ha)
		}
	}
}

func TestInventoryFamEvaluators_unreadableEvidence(t *testing.T) {
	evaluators := []invFamEvaluator{SwInv0202Evaluator{}, SwInv0204Evaluator{}, SwInv0205Evaluator{}}
	for _, e := range evaluators {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, Data: []byte("{pas du json")})
		if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
			t.Fatalf("%T : preuve illisible mal gérée: %+v", e, ha)
		}
	}
}
