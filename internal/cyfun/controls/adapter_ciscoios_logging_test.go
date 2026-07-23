package controls

import (
	"encoding/json"
	"testing"
)

// Cisco IOS avec un collecteur syslog distant : « Syslog logging: enabled » +
// une ligne « Logging to <ip> » sous « Trap logging ». On attend une
// journalisation active, transférée, donc rétention centralisée (90 j).
func TestCiscoIOSLoggingNormalize_WithRemoteSyslog(t *testing.T) {
	raw := []byte(`Syslog logging: enabled (0 messages dropped, 1 messages rate-limited, 0 flushes)
    Console logging: level debugging, 0 messages logged
    Buffer logging: level debugging, 67 messages logged
    Trap logging: level informational, 71 message lines logged
        Logging to 10.0.0.5 (udp port 514, audit disabled)`)

	out, err := ciscoiosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation Cisco avec syslog distant inattendue: %+v", ev)
	}
}

// Cisco IOS SANS collecteur distant : journalisation locale active mais aucune
// ligne « Logging to ». On attend Enabled=true, Forwarding=false, rétention
// locale courte (7 j).
func TestCiscoIOSLoggingNormalize_NoRemoteSyslog(t *testing.T) {
	raw := []byte(`Syslog logging: enabled (0 messages dropped, 0 flushes)
    Console logging: level debugging, 0 messages logged
    Buffer logging: level debugging, 12 messages logged
    Trap logging: level informational, 0 message lines logged`)

	out, err := ciscoiosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || ev.Forwarding || ev.RetentionDays != 7 {
		t.Fatalf("journalisation Cisco sans syslog distant inattendue: %+v", ev)
	}
}
