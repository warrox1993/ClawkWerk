package controls

import (
	"encoding/json"
	"testing"
)

func TestPfSenseNormalizer(t *testing.T) {
	// Échantillon représentatif d'une sortie `pfctl -sr` : la ligne `scrub`
	// (normalisation de paquets) doit être ignorée ; on garde 2 block + 3 pass.
	// La règle « block drop in log inet all » est la Default deny rule pfSense.
	raw := []byte(`scrub on em0 all fragment reassemble
block drop in log inet all label "Default deny rule IPv4"
block drop out log inet all label "Default deny rule IPv4"
pass in quick on lo0 all flags any label "pass loopback"
pass in quick inet proto tcp from any to (em0) port = 443 flags S/SA keep state label "anti-lockout"
pass out quick inet all flags S/SA keep state label "let out anything"`)

	out, err := pfsenseFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present {
		t.Errorf("Present: attendu true")
	}
	if !ev.Enabled {
		t.Errorf("Enabled: attendu true (des règles existent)")
	}
	if !ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu true (Default deny rule présente)")
	}
	if ev.RuleCount != 5 {
		t.Errorf("RuleCount: attendu 5 (2 block + 3 pass, scrub ignoré), obtenu %d", ev.RuleCount)
	}
}

// Sans aucune règle block entrante « all », la posture deny par défaut ne doit
// PAS être présumée acquise.
func TestPfSenseNormalizer_NoDefaultDeny(t *testing.T) {
	raw := []byte(`pass in quick inet proto tcp from any to any port = 80 flags S/SA keep state
pass out quick inet all flags S/SA keep state`)

	out, err := pfsenseFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu false (aucune règle block entrante)")
	}
	if ev.RuleCount != 2 {
		t.Errorf("RuleCount: attendu 2, obtenu %d", ev.RuleCount)
	}
}
