package controls

import (
	"encoding/json"
	"testing"
)

func TestZynosLoggingNormalize_RemoteServer(t *testing.T) {
	// `show logging status syslog` avec un serveur distant actif -> forwarding + 90 j.
	raw := []byte(`Syslog logging: active
Remote server 1: 10.10.0.9  port: 514  facility: local1  active: yes`)
	out, err := zynosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation Zyxel distante inattendue: %+v", ev)
	}
}

func TestZynosLoggingNormalize_NoRemote(t *testing.T) {
	// Journalisation active mais aucun serveur distant -> local 7 j.
	raw := []byte(`Syslog logging: active
Remote server 1: none`)
	out, _ := zynosLoggingNormalize(raw)
	var ev LoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.Enabled || ev.Forwarding || ev.RetentionDays != 7 {
		t.Fatalf("attendu actif/local sans forwarding, obtenu: %+v", ev)
	}
}

func TestZynosLoggingRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetLoggingCoverage() {
		if a.Platform == PlatformZyNOS {
			found = true
			if a.Vendor != "Zyxel" {
				t.Errorf("vendor attendu Zyxel, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur journalisation Zyxel doit être enregistré via init()")
	}
}
