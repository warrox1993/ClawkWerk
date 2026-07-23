package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func endpointMonitorRaw(t *testing.T, present bool, name string) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(EndpointMonitorEvidence{AgentPresent: present, AgentName: name})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 2 contrôles réutilisent la MÊME sonde EndpointMonitor : présence d'un
// outil => Defined/Pass ; absence => Initial/Fail. Plafond Defined (la réponse/
// analyse opérationnelle reste organisationnelle).
func TestDetectionFam_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		present bool
		wantLvl cyfun.MaturityLevel
		wantSt  assess.Status
	}{
		{"MI0102 présent => Defined", BoundaryDetect0102Evaluator{}, true, cyfun.Defined, assess.StatusPass},
		{"MI0102 absent => Initial", BoundaryDetect0102Evaluator{}, false, cyfun.Initial, assess.StatusFail},
		{"MA0202 présent => Defined", Forensic0202Evaluator{}, true, cyfun.Defined, assess.StatusPass},
		{"MA0202 absent => Initial", Forensic0202Evaluator{}, false, cyfun.Initial, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(endpointMonitorRaw(t, c.present, "EDR-X"))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantSt {
				t.Errorf("statut: got %v want %v", ha.Findings[0].Status, c.wantSt)
			}
		})
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined, même avec un outil présent.
func TestDetectionFam_CapsAtDefined(t *testing.T) {
	for _, e := range []assess.Evaluator{BoundaryDetect0102Evaluator{}, Forensic0202Evaluator{}} {
		ha := e.Evaluate(endpointMonitorRaw(t, true, "EDR-X"))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("%T a proposé %d > Defined — plafond violé", e, ha.ProposedImplLevel)
		}
	}
}

// Les métadonnées portent le bon niveau et le bon flag KM.
func TestDetectionFam_Meta(t *testing.T) {
	if RSMI0102Meta.Level != cyfun.LevelImportant || !RSMI0102Meta.KeyMeasure {
		t.Error("RS.MI-01.2 doit être Important + Key Measure")
	}
	if RSMA0202Meta.Level != cyfun.LevelEssential || RSMA0202Meta.KeyMeasure {
		t.Error("RS.MA-02.2 doit être Essential + non-KM")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestDetectionFam_CollectErrIsNotAssessed(t *testing.T) {
	for _, e := range []assess.Evaluator{BoundaryDetect0102Evaluator{}, Forensic0202Evaluator{}} {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d, attendu NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}

// Une preuve JSON illisible => NotAssessed via errorAssessment.
func TestDetectionFam_BadJSONIsNotAssessed(t *testing.T) {
	raw := assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: []byte("{not-json")}
	ha := BoundaryDetect0102Evaluator{}.Evaluate(raw)
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("JSON illisible: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}
