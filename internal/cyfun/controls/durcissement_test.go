package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func hardeningRaw(t *testing.T, legacy, ports int) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(HardeningEvidence{LegacyServices: legacy, OpenListeningPorts: ports})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 3 contrôles réutilisent la MÊME sonde Hardening avec des seuils/plafonds par
// niveau : Essential (SCAN pur) plafonne à Managed ; le KM baseline (MIXTE) à Defined.
func TestDurcissement_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		legacy  int
		ports   int
		wantLvl cyfun.MaturityLevel
	}{
		{"PS0103 legacy => Initial", PortHardeningEvaluator{}, 1, 2, cyfun.Initial},
		{"PS0103 surface large => Repeatable", PortHardeningEvaluator{}, 0, 12, cyfun.Repeatable},
		{"PS0103 maîtrisée => Defined", PortHardeningEvaluator{}, 0, 5, cyfun.Defined},
		{"PS0103 minimale => Managed", PortHardeningEvaluator{}, 0, 2, cyfun.Managed},
		{"PS0102 minimale => Managed", EssentialFunctionsEvaluator{}, 0, 2, cyfun.Managed},
		{"PS0101 KM minimale plafonnée Defined", BaselineHardeningEvaluator{}, 0, 2, cyfun.Defined},
		{"PS0101 KM legacy => Initial", BaselineHardeningEvaluator{}, 3, 2, cyfun.Initial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(hardeningRaw(t, c.legacy, c.ports))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined, même sur une surface parfaite.
func TestDurcissement_BaselineCapsAtDefined(t *testing.T) {
	ha := BaselineHardeningEvaluator{}.Evaluate(hardeningRaw(t, 0, 0))
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("baseline MIXTE a proposé %d > Defined — plafond violé", ha.ProposedImplLevel)
	}
}

// Les métadonnées portent le bon niveau et le bon flag KM.
func TestDurcissement_Meta(t *testing.T) {
	if PRPS0101Meta.Level != cyfun.LevelImportant || !PRPS0101Meta.KeyMeasure {
		t.Error("PR.PS-01.1 doit être Important + Key Measure")
	}
	if PRPS0103Meta.Level != cyfun.LevelEssential || PRPS0103Meta.KeyMeasure {
		t.Error("PR.PS-01.3 doit être Essential + non-KM")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestDurcissement_CollectErrIsNotAssessed(t *testing.T) {
	ha := PortHardeningEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("collecte échouée: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}
