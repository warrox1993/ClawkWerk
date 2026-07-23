package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

// Garantit à la COMPILATION que EndpointMonitorEvaluator respecte le contrat.
var _ assess.Evaluator = EndpointMonitorEvaluator{}

func TestEndpointMonitorEvaluator(t *testing.T) {
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
	var e EndpointMonitorEvaluator
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := e.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if len(ha.Findings) != 1 || ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut inattendu: %+v", ha.Findings)
			}
		})
	}
}

// Le scan ne doit JAMAIS dépasser Defined(3) : l'analyse comportementale/SOC
// est une preuve organisationnelle (override tracé), pas déduite d'un hôte.
func TestEndpointMonitorEvaluator_capsAtDefined(t *testing.T) {
	data, _ := json.Marshal(EndpointMonitorEvidence{AgentPresent: true, AgentName: "SentinelAgent"})
	ha := EndpointMonitorEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("le scan a proposé %d > Defined(3) — interdit", ha.ProposedImplLevel)
	}
}

func TestEndpointMonitorEvaluator_CollectError(t *testing.T) {
	ha := EndpointMonitorEvaluator{}.Evaluate(assess.RawEvidence{
		Host: assess.HostRef{ID: "PC-02"}, CollectErr: "ssh: connexion refusée",
	})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("niveau = %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
	if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusError {
		t.Errorf("attendu un constat en erreur, obtenu %+v", ha.Findings)
	}
}

func TestEndpointMonitorNormalizers(t *testing.T) {
	// Windows JSON : agent présent.
	out, err := EndpointMonitorWindowsNormalizer([]byte(`{"agent_present":true,"agent_name":"CSFalconService"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev EndpointMonitorEvidence
	json.Unmarshal(out, &ev)
	if !ev.AgentPresent || ev.AgentName != "CSFalconService" {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}

	// Windows JSON : champ obligatoire absent → erreur.
	if _, err := EndpointMonitorWindowsNormalizer([]byte(`{"agent_name":"x"}`)); err == nil {
		t.Error("attendu une erreur quand agent_present est absent")
	}

	// Linux : deux lignes yes + nom.
	out, err = EndpointMonitorLinuxNormalizer([]byte("yes\nfalcon-sensor\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.AgentPresent || ev.AgentName != "falcon-sensor" {
		t.Fatalf("normalisation Linux (yes) inattendue: %+v", ev)
	}

	// Linux : « no » seul est valide (agent absent).
	out, err = EndpointMonitorLinuxNormalizer([]byte("no\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.AgentPresent {
		t.Fatalf("normalisation Linux (no) inattendue: %+v", ev)
	}
}

func TestEndpointMonitorNormalizer_rejectsEmpty(t *testing.T) {
	if _, err := EndpointMonitorLinuxNormalizer([]byte("   \n")); err == nil {
		t.Error("attendu une erreur sur entrée vide (0 ligne)")
	}
	if _, err := EndpointMonitorWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur JSON invalide")
	}
}

// Métadonnées : DE.CM-03-1 (avec TIRET), non Key Measure.
func TestDECM0301Meta(t *testing.T) {
	if DECM0301Meta.ID != "DE.CM-03-1" {
		t.Errorf("ID = %q, attendu DE.CM-03-1 (avec tiret)", DECM0301Meta.ID)
	}
	if DECM0301Meta.KeyMeasure {
		t.Error("DE.CM-03-1 ne doit PAS être Key Measure")
	}
	if DECM0301Meta.Function != cyfun.Detect {
		t.Errorf("Function = %q, attendu DETECT", DECM0301Meta.Function)
	}
}
