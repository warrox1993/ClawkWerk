package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestFirewallEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name     string
		ev       FirewallEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"absent", FirewallEvidence{Present: false}, cyfun.Initial, assess.StatusFail},
		{"présent désactivé", FirewallEvidence{Present: true, Enabled: false}, cyfun.Initial, assess.StatusFail},
		{"actif mais permissif", FirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: false, ProfilesTotal: 3, ProfilesEnabled: 3}, cyfun.Repeatable, assess.StatusPartial},
		{"bloquant, profils partiels", FirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: true, ProfilesTotal: 3, ProfilesEnabled: 2}, cyfun.Defined, assess.StatusPass},
		{"bloquant, tous profils", FirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: true, ProfilesTotal: 3, ProfilesEnabled: 3}, cyfun.Managed, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := FirewallEvaluator{}.Evaluate(assess.RawEvidence{ControlID: "DE.CM-01.1", Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

func TestFirewallEvaluator_CollectError(t *testing.T) {
	ha := FirewallEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, CollectErr: "timeout"})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("erreur de collecte mal gérée: %+v", ha)
	}
}
