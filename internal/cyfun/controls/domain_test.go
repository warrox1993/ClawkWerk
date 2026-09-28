package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// evaluator par contrôle : true → Defined, false → Repeatable, statut Partial.
func TestDirectoryEvaluators(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	evals := map[string]assess.Evaluator{
		"PR.AA-01.2": Directory0102Evaluator{},
		"PR.AA-05.5": Directory0505Evaluator{},
	}
	cases := []struct {
		name    string
		ev      DomainEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"annuaire présent", DomainEvidence{DomainJoined: true}, cyfun.Defined},
		{"annuaire absent", DomainEvidence{DomainJoined: false}, cyfun.Repeatable},
	}
	for id, eval := range evals {
		for _, c := range cases {
			t.Run(id+"/"+c.name, func(t *testing.T) {
				data, _ := json.Marshal(c.ev)
				ha := eval.Evaluate(assess.RawEvidence{Host: host, Data: data})
				if ha.ProposedImplLevel != c.wantLvl {
					t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
				}
				if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusPartial {
					t.Errorf("statut attendu Partial, got %+v", ha.Findings)
				}
			})
		}
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined(3), même annuaire présent : le
// formalisme (gestion/revue) s'atteste par preuve organisationnelle (override tracé).
func TestDirectoryEvaluator_capsAtDefined(t *testing.T) {
	data, _ := json.Marshal(DomainEvidence{DomainJoined: true})
	for _, eval := range []assess.Evaluator{Directory0102Evaluator{}, Directory0505Evaluator{}} {
		ha := eval.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("le scan a proposé %d > Defined(3) — interdit", ha.ProposedImplLevel)
		}
	}
}

// Collecte échouée → NotAssessed (jamais un score fabriqué).
func TestDirectoryEvaluator_collectErr(t *testing.T) {
	for _, eval := range []assess.Evaluator{Directory0102Evaluator{}, Directory0505Evaluator{}} {
		ha := eval.Evaluate(assess.RawEvidence{
			Host:       assess.HostRef{ID: "PC-01"},
			CollectErr: "timeout WinRM",
		})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("collecte échouée: attendu NotAssessed, got %d", ha.ProposedImplLevel)
		}
		if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusError {
			t.Errorf("attendu un finding StatusError, got %+v", ha.Findings)
		}
	}
}

// Preuve illisible → NotAssessed.
func TestDirectoryEvaluator_garbageData(t *testing.T) {
	ha := Directory0102Evaluator{}.Evaluate(assess.RawEvidence{
		Host: assess.HostRef{ID: "PC-01"},
		Data: []byte("pas du json"),
	})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("preuve illisible: attendu NotAssessed, got %d", ha.ProposedImplLevel)
	}
}

func TestDomainNormalizers(t *testing.T) {
	// Windows JSON : domain_joined true.
	out, err := DomainWindowsNormalizer([]byte(`{"domain_joined":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev DomainEvidence
	json.Unmarshal(out, &ev)
	if !ev.DomainJoined {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux "yes" → true, "no" → false.
	out, err = DomainLinuxNormalizer([]byte("yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.DomainJoined {
		t.Fatalf("normalisation Linux 'yes' inattendue: %+v", ev)
	}
	out, err = DomainLinuxNormalizer([]byte("no\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.DomainJoined {
		t.Fatalf("normalisation Linux 'no' inattendue: %+v", ev)
	}
}

func TestDomainNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := DomainWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := DomainWindowsNormalizer([]byte(`{}`)); err == nil {
		t.Error("attendu une erreur quand domain_joined est absent")
	}
	if _, err := DomainLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
