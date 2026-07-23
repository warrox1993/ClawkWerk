package controls

import (
	"encoding/json"
	"testing"
)

func TestFirewareNormalizer(t *testing.T) {
	// Sortie plausible de `show rule` : un en-tête + un séparateur + 3 politiques.
	// (Format exact des colonnes non validé sur Firebox réel — cf. StatusDocsUnverified.)
	raw := []byte(`Name              Type      Action
----------------  --------  --------
Ping              packet    Allowed
HTTPS-proxy       proxy     Allowed
Outgoing          packet    Allowed`)
	out, err := firewareFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || !ev.Enabled || !ev.DefaultInboundDeny {
		t.Fatalf("posture Fireware inattendue: %+v", ev)
	}
	if ev.RuleCount != 3 {
		t.Fatalf("RuleCount: got %d want 3 (%+v)", ev.RuleCount, ev)
	}
}

func TestFirewareNormalizer_NoRules(t *testing.T) {
	// Que des lignes d'en-tête : aucune politique → pare-feu présent mais inactif.
	raw := []byte("Name  Type  Action\n----  ----  ------")
	out, err := firewareFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if ev.Enabled || ev.RuleCount != 0 {
		t.Fatalf("attendu 0 règle / désactivé, obtenu %+v", ev)
	}
}

func TestFirewareRegistered(t *testing.T) {
	found := false
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformFireware {
			found = true
			if a.Vendor != "WatchGuard" {
				t.Errorf("vendor: got %q want WatchGuard", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut: got %q want %q", a.Status, StatusDocsUnverified)
			}
			if a.Command == "" {
				t.Error("commande de collecte Fireware vide")
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur Fireware doit être enregistré via init()")
	}
}
