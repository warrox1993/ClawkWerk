package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestDetLoggingEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name       string
		ev         DetLoggingEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"aucun", DetLoggingEvidence{}, cyfun.Initial, assess.StatusFail},
		{"audit seul", DetLoggingEvidence{SecurityAuditEnabled: true}, cyfun.Repeatable, assess.StatusPartial},
		{"pare-feu seul", DetLoggingEvidence{FirewallLoggingEnabled: true}, cyfun.Repeatable, assess.StatusPartial},
		{"les deux", DetLoggingEvidence{SecurityAuditEnabled: true, FirewallLoggingEnabled: true}, cyfun.Defined, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := DetLoggingEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("status: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
			// Plafond honnête : jamais au-delà de Defined(3), et la rétention/revue
			// doit toujours être rappelée comme preuve organisationnelle.
			if ha.ProposedImplLevel > cyfun.Defined {
				t.Errorf("le scan a proposé %d > Defined(3) — interdit", ha.ProposedImplLevel)
			}
			if !strings.Contains(ha.Findings[0].Message, "rétention/revue à attester") {
				t.Errorf("message n'atteste pas la preuve organisationnelle : %q", ha.Findings[0].Message)
			}
		})
	}
}

func TestDetLoggingNormalizers(t *testing.T) {
	// Windows JSON : les deux activés.
	out, err := DetLoggingWindowsNormalizer([]byte(`{"security_audit_enabled":true,"firewall_logging_enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev DetLoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.SecurityAuditEnabled || !ev.FirewallLoggingEnabled {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : audit oui, journal non.
	out, err = DetLoggingLinuxNormalizer([]byte("yes\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	ev = DetLoggingEvidence{}
	json.Unmarshal(out, &ev)
	if !ev.SecurityAuditEnabled || ev.FirewallLoggingEnabled {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestDetLoggingNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := DetLoggingWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := DetLoggingWindowsNormalizer([]byte(`{"firewall_logging_enabled":true}`)); err == nil {
		t.Error("attendu une erreur quand security_audit_enabled est absent")
	}
	if _, err := DetLoggingLinuxNormalizer([]byte("   ")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
