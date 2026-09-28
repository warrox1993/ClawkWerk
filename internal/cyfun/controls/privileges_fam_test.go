package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func privAdminRaw(t *testing.T, count int, builtinDisabled bool) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(LocalAdminEvidence{AdminCount: count, BuiltinAdminDisabled: builtinDisabled})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 2 contrôles réutilisent la MÊME sonde LocalAdmin avec des seuils par
// niveau ; tous deux MIXTES plafonnent à Defined (surveillance/audit attestés).
func TestPrivileges_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		count   int
		builtin bool
		wantLvl cyfun.MaturityLevel
	}{
		// Important (05.7) : seuils 5 / 2.
		{"0507 beaucoup => Repeatable", PrivAccounts0507Evaluator{}, 8, true, cyfun.Repeatable},
		{"0507 modéré => Defined", PrivAccounts0507Evaluator{}, 4, true, cyfun.Defined},
		{"0507 ≤2 intégré actif => Defined", PrivAccounts0507Evaluator{}, 2, false, cyfun.Defined},
		{"0507 ≤2 intégré désactivé => Defined (plafond)", PrivAccounts0507Evaluator{}, 2, true, cyfun.Defined},
		// Essential (05.9) : seuils stricts 3 / 1 — 4 admins bascule en Repeatable.
		{"0509 stricter: 4 => Repeatable", PrivAccounts0509Evaluator{}, 4, true, cyfun.Repeatable},
		{"0509 modéré 2 => Defined", PrivAccounts0509Evaluator{}, 2, true, cyfun.Defined},
		{"0509 ≤1 intégré désactivé => Defined", PrivAccounts0509Evaluator{}, 1, true, cyfun.Defined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(privAdminRaw(t, c.count, c.builtin))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

// Preuve « parfaite » (0 admin, intégré désactivé) : le MIXTE ne doit JAMAIS
// dépasser Defined, la surveillance/audit continu restant à attester.
func TestPrivileges_CapAtDefined(t *testing.T) {
	for _, eval := range []assess.Evaluator{PrivAccounts0507Evaluator{}, PrivAccounts0509Evaluator{}} {
		ha := eval.Evaluate(privAdminRaw(t, 0, true))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("%T a proposé %d > Defined — plafond violé", eval, ha.ProposedImplLevel)
		}
	}
}

// Les métadonnées portent le bon niveau et le flag non-KM.
func TestPrivileges_Meta(t *testing.T) {
	if PRAA0507Meta.Level != cyfun.LevelImportant || PRAA0507Meta.KeyMeasure {
		t.Error("PR.AA-05.7 doit être Important + non-KM")
	}
	if PRAA0509Meta.Level != cyfun.LevelEssential || PRAA0509Meta.KeyMeasure {
		t.Error("PR.AA-05.9 doit être Essential + non-KM")
	}
	if PRAA0507Meta.Requirement != "Privileged users shall be managed and monitored." {
		t.Errorf("PR.AA-05.7 requirement inattendu: %q", PRAA0507Meta.Requirement)
	}
	if PRAA0509Meta.Requirement != "Privileged users shall be managed, monitored and audited." {
		t.Errorf("PR.AA-05.9 requirement inattendu: %q", PRAA0509Meta.Requirement)
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestPrivileges_CollectErrIsNotAssessed(t *testing.T) {
	for _, eval := range []assess.Evaluator{PrivAccounts0507Evaluator{}, PrivAccounts0509Evaluator{}} {
		ha := eval.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d, attendu NotAssessed", eval, ha.ProposedImplLevel)
		}
	}
}

// Preuve JSON illisible : NotAssessed via errorAssessment, jamais un score forcé.
func TestPrivileges_BadJSONIsNotAssessed(t *testing.T) {
	ha := PrivAccounts0507Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: []byte("{pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("JSON illisible: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}
