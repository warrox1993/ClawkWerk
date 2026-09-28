package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// TestBackupTested1102Evaluator vérifie la logique de PR.DS-11.2 (test des
// sauvegardes) : pas de solution → Initial ; solution non planifiée →
// Repeatable ; solution planifiée → Defined (présence constatée, test à attester).
func TestBackupTested1102Evaluator(t *testing.T) {
	host := assess.HostRef{ID: "SRV-01", OS: "linux"}
	cases := []struct {
		name       string
		ev         BackupEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"aucune solution", BackupEvidence{}, cyfun.Initial, assess.StatusFail},
		{"solution sans planification", BackupEvidence{SolutionPresent: true}, cyfun.Repeatable, assess.StatusPartial},
		{"solution planifiée", BackupEvidence{SolutionPresent: true, ScheduledJob: true}, cyfun.Defined, assess.StatusPartial},
		// Même avec hors-site, 11.2 se juge sur la planification : toujours Defined (test à attester).
		{"planifiée et hors-site", BackupEvidence{SolutionPresent: true, ScheduledJob: true, OffsiteConfigured: true}, cyfun.Defined, assess.StatusPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := BackupTested1102Evaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if got := ha.Findings[0].Status; got != c.wantStatus {
				t.Errorf("statut: got %q want %q", got, c.wantStatus)
			}
		})
	}
}

// TestBackupOffsite1103Evaluator vérifie PR.DS-11.3 (emplacement distinct) :
// hors-site configuré → Defined/Pass ; sinon NON ÉVALUÉ (aucune sonde ne mesure
// l'emplacement hors-site : la note vient de l'attestation du questionnaire,
// jamais d'une valeur non mesurée — revue du 28/09/2026).
func TestBackupOffsite1103Evaluator(t *testing.T) {
	host := assess.HostRef{ID: "SRV-02", OS: "windows"}
	cases := []struct {
		name       string
		ev         BackupEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"hors-site configuré", BackupEvidence{SolutionPresent: true, ScheduledJob: true, OffsiteConfigured: true}, cyfun.Defined, assess.StatusPass},
		{"pas de hors-site", BackupEvidence{SolutionPresent: true, ScheduledJob: true}, cyfun.NotAssessed, assess.StatusError},
		{"rien", BackupEvidence{}, cyfun.NotAssessed, assess.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := BackupOffsite1103Evaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if got := ha.Findings[0].Status; got != c.wantStatus {
				t.Errorf("statut: got %q want %q", got, c.wantStatus)
			}
		})
	}
}

// TestBackupFam_capsAtDefined : la famille est MIXTE (test de restauration /
// équivalence organisationnels) → aucun évaluateur ne doit dépasser Defined(3),
// même avec la meilleure posture technique possible. Le 4/5 et le 5/5
// s'attestent par preuve documentaire via override tracé.
func TestBackupFam_capsAtDefined(t *testing.T) {
	best := BackupEvidence{SolutionPresent: true, ScheduledJob: true, OffsiteConfigured: true}
	data, _ := json.Marshal(best)
	raw := assess.RawEvidence{Host: assess.HostRef{ID: "SRV-01"}, Data: data}

	for _, ev := range []assess.Evaluator{BackupTested1102Evaluator{}, BackupOffsite1103Evaluator{}} {
		ha := ev.Evaluate(raw)
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Errorf("%T a proposé %d > Defined(3) — interdit pour un contrôle MIXTE", ev, ha.ProposedImplLevel)
		}
	}
}

// TestBackupFam_collectFailure : collecte échouée ou preuve illisible →
// NotAssessed (on ne score pas ce qu'on n'a pas pu constater).
func TestBackupFam_collectFailure(t *testing.T) {
	host := assess.HostRef{ID: "SRV-01"}
	evals := []assess.Evaluator{BackupTested1102Evaluator{}, BackupOffsite1103Evaluator{}}

	for _, ev := range evals {
		// Collecte échouée.
		ha := ev.Evaluate(assess.RawEvidence{Host: host, CollectErr: "timeout SSH"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d want NotAssessed(0)", ev, ha.ProposedImplLevel)
		}
		if ha.Findings[0].Status != assess.StatusError {
			t.Errorf("%T collecte échouée: statut got %q want error", ev, ha.Findings[0].Status)
		}
		// Preuve illisible.
		ha = ev.Evaluate(assess.RawEvidence{Host: host, Data: []byte("pas du json")})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T preuve illisible: got %d want NotAssessed(0)", ev, ha.ProposedImplLevel)
		}
	}
}
