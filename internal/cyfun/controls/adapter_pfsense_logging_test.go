package controls

import (
	"encoding/json"
	"testing"
)

// Renvoi distant configuré (pfSense) : drapeau enableremotelogging + un
// <remoteserver> non vide → Forwarding=true et rétention centralisée (90 j).
func TestPfSenseLoggingNormalizer_Forwarding(t *testing.T) {
	raw := []byte(`<syslog>
    <filterdescriptions>1</filterdescriptions>
    <enableremotelogging></enableremotelogging>
    <remoteserver>10.100.0.5</remoteserver>
    <remoteserver2></remoteserver2>
    <remoteserver3></remoteserver3>
</syslog>`)
	out, err := pfsenseLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled {
		t.Errorf("Enabled: attendu true")
	}
	if !ev.Forwarding {
		t.Errorf("Forwarding: attendu true (serveur syslog distant configuré)")
	}
	if ev.RetentionDays != 90 {
		t.Errorf("RetentionDays: attendu 90 (renvoi centralisé), obtenu %d", ev.RetentionDays)
	}
}

// Aucun renvoi distant (balises <remoteserver> vides, pas de drapeau) →
// Forwarding=false et rétention locale courte (7 j).
func TestPfSenseLoggingNormalizer_NoForwarding(t *testing.T) {
	raw := []byte(`<syslog>
    <filterdescriptions>1</filterdescriptions>
    <remoteserver></remoteserver>
    <remoteserver2></remoteserver2>
    <remoteserver3></remoteserver3>
</syslog>`)
	out, err := pfsenseLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled {
		t.Errorf("Enabled: attendu true (section syslog présente)")
	}
	if ev.Forwarding {
		t.Errorf("Forwarding: attendu false (aucun serveur distant)")
	}
	if ev.RetentionDays != 7 {
		t.Errorf("RetentionDays: attendu 7 (local), obtenu %d", ev.RetentionDays)
	}
}

func TestPfSenseLoggingRegistered(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
		if a.Platform == PlatformPfSense {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur journalisation pfSense doit être enregistré")
	}
}
