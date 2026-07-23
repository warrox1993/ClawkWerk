package controls

import (
	"encoding/json"
	"testing"
)

// PAN-OS avec un profil syslog pointant vers un collecteur distant : la ligne
// « server 10.10.10.10; » identifie l'hôte. On attend une journalisation
// active, transférée, donc rétention centralisée (90 j).
func TestPanOSLoggingNormalize_WithRemoteSyslog(t *testing.T) {
	raw := []byte(`syslog {
  Corp-Syslog {
    server {
      SIEM {
        transport UDP;
        port 514;
        format BSD;
        server 10.10.10.10;
        facility LOG_USER;
      }
    }
  }
}`)

	out, err := panosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || !ev.Forwarding || ev.RetentionDays != 90 {
		t.Fatalf("journalisation PAN-OS avec syslog distant inattendue: %+v", ev)
	}
}

// PAN-OS avec un profil syslog déclaré mais AUCUN hôte distant renseigné (le
// conteneur « server { » reste vide). On attend Enabled=true (profil présent),
// Forwarding=false, rétention locale courte (7 j).
func TestPanOSLoggingNormalize_NoRemoteSyslog(t *testing.T) {
	raw := []byte(`syslog {
  Empty-Profile {
    server {
    }
  }
}`)

	out, err := panosLoggingNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || ev.Forwarding || ev.RetentionDays != 7 {
		t.Fatalf("journalisation PAN-OS sans syslog distant inattendue: %+v", ev)
	}
}
