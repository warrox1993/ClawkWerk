package controls

import (
	"encoding/json"
	"testing"
)

func TestCiscoIOSNormalizer(t *testing.T) {
	// Échantillon représentatif de `show ip access-lists` : deux ACL, quatre ACE
	// au total. L'ACL étendue « BLOCK-WEB » se termine par un `deny ip any any`
	// EXPLICITE → DefaultInboundDeny doit être true.
	raw := []byte(`Extended IP access list BLOCK-WEB
    10 permit tcp any any eq www
    20 permit tcp any any eq 443
    30 deny ip any any
Standard IP access list 1
    10 permit 10.1.1.0, wildcard bits 0.0.0.255`)

	out, err := ciscoiosFirewallNormalize(raw)
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
		t.Errorf("Enabled: attendu true (des ACE existent)")
	}
	if !ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu true (deny ip any any explicite)")
	}
	if ev.RuleCount != 4 {
		t.Errorf("RuleCount: attendu 4 ACE, obtenu %d", ev.RuleCount)
	}
}

// Une ACL ne comportant QUE des permit : le deny implicite d'IOS n'étant jamais
// affiché, aucun deny explicite → DefaultInboundDeny doit rester false.
func TestCiscoIOSNormalizer_NoExplicitDeny(t *testing.T) {
	raw := []byte(`Extended IP access list PERMIT-ONLY
    10 permit tcp any any eq 22
    20 permit udp any any eq 53`)

	out, err := ciscoiosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu false (aucun deny explicite)")
	}
	if ev.RuleCount != 2 {
		t.Errorf("RuleCount: attendu 2, obtenu %d", ev.RuleCount)
	}
}
