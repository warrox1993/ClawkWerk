package controls

import (
	"encoding/json"
	"testing"
)

func TestFirewareLoggingNormalize_SyslogServer(t *testing.T) {
	// `show logging` avec un serveur Syslog distant -> forwarding + 90 j.
	raw := []byte(`Logging settings:
  Send log messages to syslog: enabled
  Syslog server: 192.168.10.20 port 514 format Syslog`)
	out, err := firewareLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation Fireware distante inattendue: %+v", ev)
	}
}

func TestFirewareLoggingNormalize_LocalOnly(t *testing.T) {
	// Réglages de log présents mais aucun serveur distant -> local 7 j.
	raw := []byte(`Logging settings:
  Send log messages to syslog: disabled`)
	out, _ := firewareLoggingNormalize(raw)
	var ev LoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.Enabled || ev.Forwarding || ev.RetentionDays != 7 {
		t.Fatalf("attendu actif/local sans forwarding, obtenu: %+v", ev)
	}
}

func TestFirewareLoggingRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
		if a.Platform == PlatformFireware {
			found = true
			if a.Vendor != "WatchGuard" {
				t.Errorf("vendor attendu WatchGuard, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur journalisation Fireware doit être enregistré via init()")
	}
}
