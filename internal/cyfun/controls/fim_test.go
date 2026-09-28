package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func fimRaw(t *testing.T, present, autoResp bool) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(FimEvidence{FimPresent: present, AutoResponse: autoResp})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Chaque contrôle lit la présence de l'outil FIM. PR.DS-01.2 : présent =>
// Defined/Pass, absent => Initial/Fail. PR.DS-01.3 (réponse à attester) :
// présent => Defined/Partial, absent => Initial/Fail.
func TestFim_Evaluators(t *testing.T) {
	cases := []struct {
		name       string
		eval       assess.Evaluator
		raw        assess.RawEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"DS0102 présent => Defined/Pass", Fim0102Evaluator{}, fimRaw(t, true, false), cyfun.Defined, assess.StatusPass},
		{"DS0102 absent => Initial/Fail", Fim0102Evaluator{}, fimRaw(t, false, false), cyfun.Initial, assess.StatusFail},
		{"DS0103 présent => Defined/Partial", Fim0103Evaluator{}, fimRaw(t, true, false), cyfun.Defined, assess.StatusPartial},
		{"DS0103 absent => Initial/Fail", Fim0103Evaluator{}, fimRaw(t, false, false), cyfun.Initial, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(c.raw)
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// Les deux contrôles MIXTES ne dépassent jamais Defined, même sur un état
// parfait (FIM présent + réponse automatisée revendiquée).
func TestFim_CapsAtDefined(t *testing.T) {
	for _, e := range []assess.Evaluator{Fim0102Evaluator{}, Fim0103Evaluator{}} {
		ha := e.Evaluate(fimRaw(t, true, true))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("%T a proposé %d > Defined — plafond violé", e, ha.ProposedImplLevel)
		}
	}
}

// Métadonnées : niveaux Essential et non-KM conformes à la source CCB.
func TestFim_Meta(t *testing.T) {
	if PRDS0102Meta.Level != cyfun.LevelEssential || PRDS0102Meta.KeyMeasure {
		t.Error("PR.DS-01.2 doit être Essential + non-KM")
	}
	if PRDS0103Meta.Level != cyfun.LevelEssential || PRDS0103Meta.KeyMeasure {
		t.Error("PR.DS-01.3 doit être Essential + non-KM")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, jamais une fausse faille.
func TestFim_CollectErrIsNotAssessed(t *testing.T) {
	for _, e := range []assess.Evaluator{Fim0102Evaluator{}, Fim0103Evaluator{}} {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d, attendu NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}

func TestFimWindowsNormalizer(t *testing.T) {
	out, err := FimWindowsNormalizer([]byte(`{"fim_present":true,"auto_response":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev FimEvidence
	json.Unmarshal(out, &ev)
	if !ev.FimPresent || ev.AutoResponse {
		t.Fatalf("mapping Windows inattendu: %+v", ev)
	}
}

func TestFimWindowsNormalizer_MissingField(t *testing.T) {
	if _, err := FimWindowsNormalizer([]byte(`{"auto_response":false}`)); err == nil {
		t.Fatal("champ fim_present absent doit produire une erreur")
	}
}

func TestFimLinuxNormalizer(t *testing.T) {
	out, err := FimLinuxNormalizer([]byte("yes\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev FimEvidence
	json.Unmarshal(out, &ev)
	if !ev.FimPresent || ev.AutoResponse {
		t.Fatalf("mapping Linux inattendu: %+v", ev)
	}
}

func TestFimLinuxNormalizer_Empty(t *testing.T) {
	if _, err := FimLinuxNormalizer([]byte("   \n")); err == nil {
		t.Fatal("sortie vide doit produire une erreur")
	}
}
