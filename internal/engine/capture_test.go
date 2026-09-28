package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// Le hook Capture reçoit la sortie BRUTE d'une collecte réussie (avant
// normalisation), et n'est PAS appelé sur un trou de collecte.
func TestEngine_Run_CaptureReceivesRawEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PC1.DE.CM-01.2.json"), []byte(`{"raw":"data"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	captured := map[string]string{}
	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
		Capture: func(controlID, hostID, osName string, raw []byte) {
			captured[controlID+"/"+hostID] = string(raw)
		},
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "PC1", OS: "windows"}}, // DE.CM-01.2 : preuve présente
		{Ref: assess.HostRef{ID: "MAC1", OS: "macos"}},  // aucune commande => pas de capture
	}}
	if _, err := e.Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if got := captured["DE.CM-01.2/PC1"]; got != `{"raw":"data"}` {
		t.Errorf("capture brute attendue pour PC1, obtenu %q", got)
	}
	if _, ok := captured["DE.CM-01.2/MAC1"]; ok {
		t.Error("aucune capture ne doit avoir lieu quand la collecte n'a pas de preuve (OS non supporté)")
	}
}
