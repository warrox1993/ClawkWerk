package controls

import (
	"encoding/json"
	"testing"
)

func TestZynosNormalizer(t *testing.T) {
	// Sortie plausible de `show secure-policy` (format du CLI Reference ZLD) :
	// 3 règles dont une règle entrante WAN→LAN en deny (bloquer par défaut).
	raw := []byte(`secure-policy rule: 1
name: LAN_Outgoing
from: LAN1, to: any
log: no, action: allow, status: yes
secure-policy rule: 2
name: WAN_to_LAN_Default
from: WAN, to: LAN1
log: log, action: deny, status: yes
secure-policy rule: 11
name: WAN_to_Device
from: WAN, to: ZyWALL
log: no, action: allow, status: yes`)
	out, err := zynosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || !ev.Enabled {
		t.Fatalf("attendu présent+actif, obtenu %+v", ev)
	}
	if ev.RuleCount != 3 {
		t.Fatalf("RuleCount: got %d want 3 (%+v)", ev.RuleCount, ev)
	}
	if !ev.DefaultInboundDeny {
		t.Fatalf("deny entrant WAN non détecté: %+v", ev)
	}
}

func TestZynosNormalizer_NoInboundDeny(t *testing.T) {
	// Uniquement des règles allow : pas de politique « bloquer par défaut ».
	raw := []byte(`secure-policy rule: 1
from: LAN1, to: any
action: allow
secure-policy rule: 2
from: WAN, to: LAN1
action: allow`)
	out, err := zynosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if ev.RuleCount != 2 {
		t.Fatalf("RuleCount: got %d want 2", ev.RuleCount)
	}
	if ev.DefaultInboundDeny {
		t.Fatalf("aucun deny entrant ne devait être détecté: %+v", ev)
	}
}

func TestZynosRegistered(t *testing.T) {
	found := false
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformZyNOS {
			found = true
			if a.Vendor != "Zyxel" {
				t.Errorf("vendor: got %q want Zyxel", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut: got %q want %q", a.Status, StatusDocsUnverified)
			}
			if a.Command == "" {
				t.Error("commande de collecte Zyxel vide")
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur Zyxel doit être enregistré via init()")
	}
}
