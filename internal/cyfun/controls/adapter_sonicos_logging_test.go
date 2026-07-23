package controls

import (
	"encoding/json"
	"testing"
)

func TestSonicOSLoggingNormalize_RemoteServer(t *testing.T) {
	// Table des serveurs Syslog avec une adresse distante -> forwarding + 90 j.
	raw := []byte(`Syslog Servers:
  1  10.0.0.5  514  Syslog  Local0
Syslog Format: Default`)
	out, err := sonicosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation SonicOS distante inattendue: %+v", ev)
	}
}

func TestSonicOSLoggingNormalize_NoRemote(t *testing.T) {
	// Journalisation Syslog présente mais aucun serveur distant -> local 7 j.
	raw := []byte(`Syslog logging: enabled
No Syslog servers configured`)
	out, _ := sonicosLoggingNormalize(raw)
	var ev LoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.Enabled || ev.Forwarding || ev.RetentionDays != 7 {
		t.Fatalf("attendu actif/local sans forwarding, obtenu: %+v", ev)
	}
}

func TestSonicOSLoggingRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
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
		t.Fatal("l'adaptateur journalisation SonicOS doit être enregistré via init()")
	}
}
