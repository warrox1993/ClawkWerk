package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestNetFirewallEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "FW-01", OS: PlatformRouterOS, Role: "firewall"}
	cases := []struct {
		name     string
		ev       NetFirewallEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"pas de pare-feu", NetFirewallEvidence{Present: false}, cyfun.Initial, assess.StatusFail},
		{"aucune règle", NetFirewallEvidence{Present: true, Enabled: false}, cyfun.Initial, assess.StatusFail},
		{"actif sans deny défaut", NetFirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: false, RuleCount: 12}, cyfun.Repeatable, assess.StatusPartial},
		{"deny défaut, peu de règles", NetFirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: true, RuleCount: 3}, cyfun.Defined, assess.StatusPass},
		{"deny défaut, jeu substantiel", NetFirewallEvidence{Present: true, Enabled: true, DefaultInboundDeny: true, RuleCount: 20}, cyfun.Managed, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := NetFirewallEvaluator{}.Evaluate(assess.RawEvidence{ControlID: "PR.IR-01.1", Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

func TestRouterOSNormalizer(t *testing.T) {
	// sortie « terse » simplifiée : 3 règles, dont un drop final sur input.
	raw := []byte(` 0 chain=input action=accept connection-state=established,related
 1 chain=forward action=accept connection-state=established,related
 2 chain=input action=drop`)
	out, err := routerOSFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || !ev.Enabled || !ev.DefaultInboundDeny || ev.RuleCount != 3 {
		t.Fatalf("normalisation RouterOS inattendue: %+v", ev)
	}
}

func TestNetFirewallCoverage_RouterOSRegistered(t *testing.T) {
	found := false
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformRouterOS {
			found = true
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut RouterOS attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur RouterOS doit être enregistré via init()")
	}
}
