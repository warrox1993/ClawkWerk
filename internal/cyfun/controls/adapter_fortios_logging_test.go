package controls

import (
	"encoding/json"
	"testing"
)

// Renvoi distant actif (FortiOS) : status enable + serveur renseigné →
// Forwarding=true et rétention centralisée (90 j).
func TestFortiOSLoggingNormalizer_Forwarding(t *testing.T) {
	raw := []byte(`config log syslogd setting
    set status enable
    set server "10.100.0.5"
    set mode udp
    set port 514
end`)
	out, err := fortiosLoggingNormalize(raw)
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
		t.Errorf("Forwarding: attendu true (syslog distant actif)")
	}
	if ev.RetentionDays != 90 {
		t.Errorf("RetentionDays: attendu 90 (renvoi centralisé), obtenu %d", ev.RetentionDays)
	}
}

// Renvoi désactivé (status disable, pas de serveur) → Forwarding=false et
// rétention locale courte (7 j). Le bloc de config existe → Enabled reste true.
func TestFortiOSLoggingNormalizer_NoForwarding(t *testing.T) {
	raw := []byte(`config log syslogd setting
    set status disable
end`)
	out, err := fortiosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled {
		t.Errorf("Enabled: attendu true (bloc syslogd présent)")
	}
	if ev.Forwarding {
		t.Errorf("Forwarding: attendu false (renvoi désactivé)")
	}
	if ev.RetentionDays != 7 {
		t.Errorf("RetentionDays: attendu 7 (local), obtenu %d", ev.RetentionDays)
	}
}

func TestFortiOSLoggingRegistered(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
		if a.Platform == PlatformFortiOS {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur journalisation FortiOS doit être enregistré")
	}
}
