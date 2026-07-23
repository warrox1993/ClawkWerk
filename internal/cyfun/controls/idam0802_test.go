package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestPatchEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "SRV-01", OS: "linux"}
	cases := []struct {
		name     string
		ev       PatchEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"beaucoup en attente", PatchEvidence{PendingSecurityUpdates: 12, DaysSinceLastUpdate: 5}, cyfun.Initial, assess.StatusFail},
		{"parc périmé", PatchEvidence{PendingSecurityUpdates: 0, DaysSinceLastUpdate: 90}, cyfun.Initial, assess.StatusFail},
		{"quelques-uns en attente", PatchEvidence{PendingSecurityUpdates: 3, DaysSinceLastUpdate: 10}, cyfun.Repeatable, assess.StatusPartial},
		{"à jour, sans automatisation", PatchEvidence{PendingSecurityUpdates: 0, DaysSinceLastUpdate: 10, AutoUpdateEnabled: false}, cyfun.Defined, assess.StatusPass},
		{"à jour + auto", PatchEvidence{PendingSecurityUpdates: 0, DaysSinceLastUpdate: 3, AutoUpdateEnabled: true}, cyfun.Managed, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := PatchEvaluator{}.Evaluate(assess.RawEvidence{ControlID: "ID.AM-08.2", Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

func TestPatchEvaluator_UnreadableEvidence(t *testing.T) {
	ha := PatchEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, Data: []byte("{pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("preuve illisible mal gérée: %+v", ha)
	}
}
