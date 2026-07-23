package controls

import (
	"encoding/json"
	"testing"
)

func TestRouterOSLoggingNormalize(t *testing.T) {
	// Une action locale + une action distante (syslog) -> forwarding + rétention centrale.
	raw := []byte(` 0 name=memory target=memory
 1 name=remote target=remote remote=10.0.0.5`)
	out, err := routerOSLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation RouterOS inattendue: %+v", ev)
	}
}

func TestNetLoggingCoverage_RouterOSRegistered(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
		if a.Platform == PlatformRouterOS {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur journalisation RouterOS doit être enregistré")
	}
}
