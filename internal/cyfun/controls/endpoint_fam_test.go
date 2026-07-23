package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

// Contrat Evaluator garanti à la COMPILATION pour les deux évaluateurs.
var (
	_ assess.Evaluator = Edr0302Evaluator{}
	_ assess.Evaluator = Edr0904Evaluator{}
)

// endpointEvaluators regroupe les évaluateurs MIXTES de la famille pour les
// tester d'un seul jeu de cas (présent/absent + plafond).
var endpointEvaluators = []struct {
	name string
	eval assess.Evaluator
}{
	{"DE.CM-03.2", Edr0302Evaluator{}},
	{"DE.CM-09.4", Edr0904Evaluator{}},
}

func TestEndpointFamEvaluators(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name       string
		ev         EndpointMonitorEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"absent", EndpointMonitorEvidence{AgentPresent: false},
			cyfun.Initial, assess.StatusFail},
		{"present", EndpointMonitorEvidence{AgentPresent: true, AgentName: "CSFalconService"},
			cyfun.Defined, assess.StatusPass},
	}
	for _, ev := range endpointEvaluators {
		for _, c := range cases {
			t.Run(ev.name+"/"+c.name, func(t *testing.T) {
				data, _ := json.Marshal(c.ev)
				ha := ev.eval.Evaluate(assess.RawEvidence{Host: host, Data: data})
				if ha.ProposedImplLevel != c.wantLvl {
					t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
				}
				if len(ha.Findings) != 1 || ha.Findings[0].Status != c.wantStatus {
					t.Errorf("statut inattendu: %+v", ha.Findings)
				}
			})
		}
	}
}

// Le scan ne doit JAMAIS dépasser Defined(3) : analyse comportementale/SOC et
// tuning sont des preuves organisationnelles (override tracé), pas déduites d'un hôte.
func TestEndpointFamEvaluators_capAtDefined(t *testing.T) {
	data, _ := json.Marshal(EndpointMonitorEvidence{AgentPresent: true, AgentName: "SentinelAgent"})
	for _, ev := range endpointEvaluators {
		t.Run(ev.name, func(t *testing.T) {
			ha := ev.eval.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
			if ha.ProposedImplLevel > cyfun.Defined {
				t.Fatalf("le scan a proposé %d > Defined(3) — interdit", ha.ProposedImplLevel)
			}
		})
	}
}

// Collecte échouée → NotAssessed + constat en erreur (jamais un score falsifié).
func TestEndpointFamEvaluators_collectError(t *testing.T) {
	for _, ev := range endpointEvaluators {
		t.Run(ev.name, func(t *testing.T) {
			ha := ev.eval.Evaluate(assess.RawEvidence{
				Host: assess.HostRef{ID: "PC-02"}, CollectErr: "ssh: connexion refusée",
			})
			if ha.ProposedImplLevel != cyfun.NotAssessed {
				t.Errorf("niveau = %d, attendu NotAssessed", ha.ProposedImplLevel)
			}
			if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusError {
				t.Errorf("attendu un constat en erreur, obtenu %+v", ha.Findings)
			}
		})
	}
}

// Preuve JSON illisible → NotAssessed (dégradation gracieuse, pas de panique).
func TestEndpointFamEvaluators_badJSON(t *testing.T) {
	for _, ev := range endpointEvaluators {
		t.Run(ev.name, func(t *testing.T) {
			ha := ev.eval.Evaluate(assess.RawEvidence{
				Host: assess.HostRef{ID: "PC-03"}, Data: []byte("pas du json"),
			})
			if ha.ProposedImplLevel != cyfun.NotAssessed {
				t.Errorf("niveau = %d, attendu NotAssessed", ha.ProposedImplLevel)
			}
		})
	}
}

// Métadonnées : IDs/niveaux exacts, non Key Measure.
func TestEndpointFamMeta(t *testing.T) {
	if DECM0302Meta.ID != "DE.CM-03.2" || DECM0302Meta.Level != cyfun.LevelImportant || DECM0302Meta.KeyMeasure {
		t.Errorf("DE.CM-03.2 méta inattendue: %+v", DECM0302Meta)
	}
	if DECM0904Meta.ID != "DE.CM-09.4" || DECM0904Meta.Level != cyfun.LevelEssential || DECM0904Meta.KeyMeasure {
		t.Errorf("DE.CM-09.4 méta inattendue: %+v", DECM0904Meta)
	}
	if DECM0302Meta.Function != cyfun.Detect || DECM0904Meta.Function != cyfun.Detect {
		t.Error("Function attendue DETECT pour les deux contrôles")
	}
}
