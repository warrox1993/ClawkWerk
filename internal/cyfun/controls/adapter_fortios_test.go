package controls

import (
	"encoding/json"
	"testing"
)

func TestFortiOSNormalizer(t *testing.T) {
	// Échantillon représentatif d'une sortie `show firewall policy` : 2 policies
	// (edit 1 accept, edit 2 deny). Le deny implicite structurel de FortiGate
	// (policy 0) fait que DefaultInboundDeny doit être true dès qu'une policy existe.
	raw := []byte(`config firewall policy
    edit 1
        set name "LAN-to-WAN"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS" "DNS"
    next
    edit 2
        set name "block-suspicious"
        set srcintf "wan1"
        set dstintf "internal"
        set action deny
    next
end`)

	out, err := fortiosFirewallNormalize(raw)
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
		t.Errorf("Enabled: attendu true (des policies existent)")
	}
	if !ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu true (deny implicite policy 0)")
	}
	if ev.RuleCount != 2 {
		t.Errorf("RuleCount: attendu 2 (edit 1 + edit 2), obtenu %d", ev.RuleCount)
	}
}

// Table de policies vide : ni actif, ni deny par défaut présumé.
func TestFortiOSNormalizer_Empty(t *testing.T) {
	raw := []byte(`config firewall policy
end`)

	out, err := fortiosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Enabled {
		t.Errorf("Enabled: attendu false (aucune policy)")
	}
	if ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu false (aucune policy)")
	}
	if ev.RuleCount != 0 {
		t.Errorf("RuleCount: attendu 0, obtenu %d", ev.RuleCount)
	}
}
