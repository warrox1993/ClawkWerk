package controls

import (
	"encoding/json"
	"testing"
)

func TestSonicOSNormalizer(t *testing.T) {
	// Sortie `show access-rules` simplifiée : 3 règles en blocs. La règle 3
	// refuse (action deny) du trafic entrant depuis WAN → deny par défaut détecté.
	raw := []byte(`access-rule ipv4 1
  from LAN to WAN
  action allow
access-rule ipv4 2
  from LAN to DMZ
  action allow
access-rule ipv4 3
  from WAN to LAN
  action deny`)

	out, err := sonicosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || !ev.Enabled || !ev.DefaultInboundDeny || ev.RuleCount != 3 {
		t.Fatalf("normalisation SonicOS inattendue: %+v", ev)
	}
}

func TestSonicOSNormalizer_NoInboundDeny(t *testing.T) {
	// Deux règles sortantes seulement : actif mais aucun deny sur du WAN entrant.
	raw := []byte(`access-rule ipv4 1
  from LAN to WAN
  action allow
access-rule ipv4 2
  from DMZ to WAN
  action allow`)

	out, _ := sonicosFirewallNormalize(raw)
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if ev.RuleCount != 2 || ev.DefaultInboundDeny {
		t.Fatalf("attendu 2 règles sans deny entrant, obtenu: %+v", ev)
	}
}

func TestSonicOSRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformSonicOS {
			found = true
			if a.Vendor != "SonicWall" {
				t.Errorf("vendor attendu SonicWall, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur SonicOS doit être enregistré via init()")
	}
}
