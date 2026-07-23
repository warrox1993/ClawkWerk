package controls

import (
	"encoding/json"
	"testing"
)

func TestPanOSNormalizer(t *testing.T) {
	// Échantillon représentatif de `show running security-policy` : deux règles
	// utilisateur suivies des deux règles implicites (intrazone-default allow,
	// interzone-default deny). La DERNIÈRE action est un deny → DefaultInboundDeny
	// doit être true.
	raw := []byte(`"Allow Trust to DMZ; index: 1" {
        from L3-Trust;
        source any;
        to L3-DMZ;
        destination any;
        application/service  any/any/any/any;
        action allow;
        terminal yes;
}
"Block Untrust; index: 2" {
        from L3-Untrust;
        source any;
        to L3-Trust;
        destination any;
        action deny;
        terminal yes;
}
"intrazone-default; index: 3" {
        from any;
        source any;
        action allow;
}
"interzone-default; index: 4" {
        from any;
        source any;
        action deny;
}`)

	out, err := panosFirewallNormalize(raw)
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
		t.Errorf("DefaultInboundDeny: attendu true (interzone-default = deny en dernier)")
	}
	if ev.RuleCount != 4 {
		t.Errorf("RuleCount: attendu 4 règles, obtenu %d", ev.RuleCount)
	}
}

// Cas dégradé : interzone-default a été remplacé par un allow (mauvaise
// pratique). La dernière action n'est plus un deny → posture faible signalée.
func TestPanOSNormalizer_LastActionAllow(t *testing.T) {
	raw := []byte(`"Permit All; index: 1" {
        from any;
        source any;
        action allow;
}
"interzone-default; index: 2" {
        from any;
        source any;
        action allow;
}`)

	out, err := panosFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.DefaultInboundDeny {
		t.Errorf("DefaultInboundDeny: attendu false (dernière action = allow)")
	}
	if ev.RuleCount != 2 {
		t.Errorf("RuleCount: attendu 2, obtenu %d", ev.RuleCount)
	}
}
