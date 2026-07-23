package controls

import (
	"encoding/json"
	"testing"
)

func TestUniFiFirewallNormalize(t *testing.T) {
	// Réponse REST du contrôleur : 2 règles actives, dont un drop sur WAN_IN.
	raw := []byte(`{"data":[
		{"ruleset":"WAN_IN","action":"drop","enabled":true},
		{"ruleset":"LAN_IN","action":"accept","enabled":true},
		{"ruleset":"WAN_IN","action":"accept","enabled":false}
	]}`)
	out, err := unifiFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || !ev.Enabled || !ev.DefaultInboundDeny || ev.RuleCount != 2 {
		t.Fatalf("normalisation UniFi inattendue: %+v", ev)
	}
}

func TestSophosFirewallNormalize(t *testing.T) {
	raw := []byte(`<Response>
		<FirewallRule><Name>r1</Name><Status>Enable</Status>
			<NetworkPolicy><Action>Drop</Action><SourceZones><Zone>WAN</Zone></SourceZones></NetworkPolicy>
		</FirewallRule>
		<FirewallRule><Name>r2</Name><Status>Enable</Status>
			<NetworkPolicy><Action>Accept</Action><SourceZones><Zone>LAN</Zone></SourceZones></NetworkPolicy>
		</FirewallRule>
	</Response>`)
	out, err := sophosxgFirewallNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev NetFirewallEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || ev.RuleCount != 2 || !ev.DefaultInboundDeny {
		t.Fatalf("normalisation Sophos inattendue: %+v", ev)
	}
}
