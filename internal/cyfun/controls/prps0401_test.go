package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestLoggingEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "SRV-01", OS: "linux"}
	cases := []struct {
		name     string
		ev       LoggingEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"désactivée", LoggingEvidence{Enabled: false}, cyfun.Initial, assess.StatusFail},
		{"rétention courte", LoggingEvidence{Enabled: true, RetentionDays: 10}, cyfun.Repeatable, assess.StatusPartial},
		{"active sans centralisation", LoggingEvidence{Enabled: true, RetentionDays: 45, Forwarding: false}, cyfun.Defined, assess.StatusPass},
		{"active centralisée ≥90j", LoggingEvidence{Enabled: true, RetentionDays: 180, Forwarding: true}, cyfun.Managed, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := LoggingEvaluator{}.Evaluate(assess.RawEvidence{ControlID: "PR.PS-04.1", Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

func TestLoggingNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := LoggingWindowsNormalizer([]byte(`{"enabled":true,"retention_days":120,"forwarding":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	json.Unmarshal(out, &ev)
	if !ev.Enabled || ev.RetentionDays != 120 || !ev.Forwarding {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 3 lignes.
	out, err = LoggingLinuxNormalizer([]byte("active\n60\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.Enabled || ev.RetentionDays != 60 || ev.Forwarding {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}
