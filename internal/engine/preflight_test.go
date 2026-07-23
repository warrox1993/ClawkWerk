package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scan"
	"projetcyber/internal/scope"
)

func TestReadiness(t *testing.T) {
	cases := []struct {
		name   string
		hasCmd bool
		err    error
		raw    assess.RawEvidence
		want   Readiness
	}{
		{"os non supporté", false, nil, assess.RawEvidence{}, ReadyUnsupported},
		{"injoignable (transport)", true, errors.New("dial timeout"), assess.RawEvidence{}, ReadyUnreachable},
		{"droits refusés (sortie)", true, nil, assess.RawEvidence{Data: []byte("Access is denied.")}, ReadyPrivilege},
		{"droits refusés (erreur)", true, nil, assess.RawEvidence{CollectErr: "cat: Permission denied"}, ReadyPrivilege},
		{"preuve absente => injoignable", true, nil, assess.RawEvidence{CollectErr: "preuve absente (x)"}, ReadyUnreachable},
		{"lisible", true, nil, assess.RawEvidence{Data: []byte(`{"ok":true}`)}, ReadyOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := readiness(c.hasCmd, c.err, c.raw); got != c.want {
				t.Errorf("readiness = %q, attendu %q", got, c.want)
			}
		})
	}
}

func TestHostsNeedingProvisioning(t *testing.T) {
	rows := []PreflightRow{
		{Host: "B", Status: ReadyPrivilege},
		{Host: "A", Status: ReadyPrivilege},
		{Host: "A", Status: ReadyPrivilege}, // doublon
		{Host: "C", Status: ReadyOK},        // pas un manque de droits
	}
	got := HostsNeedingProvisioning(rows)
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("dédoublonnage/tri inattendu : %v", got)
	}
}

func TestEngine_Preflight_ClassifiesAccess(t *testing.T) {
	dir := t.TempDir()
	// Preuve lisible pour PC1 ; accès refusé (marqueur Windows) pour WIN7.
	mustWrite(t, filepath.Join(dir, "PC1.DE.CM-01.2.json"), `{"antivirus_enabled":true}`)
	mustWrite(t, filepath.Join(dir, "WIN7.DE.CM-01.2.json"), "Access is denied.")
	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "PC1", OS: "windows"}},
		{Ref: assess.HostRef{ID: "WIN7", OS: "windows"}},
		{Ref: assess.HostRef{ID: "MAC", OS: "macos"}},
	}}
	rows := e.Preflight(context.Background(), sc)

	if got := rowStatus(rows, "PC1", "DE.CM-01.2"); got != ReadyOK {
		t.Errorf("PC1 doit être lisible, obtenu %q", got)
	}
	if got := rowStatus(rows, "WIN7", "DE.CM-01.2"); got != ReadyPrivilege {
		t.Errorf("WIN7 doit être « droits insuffisants », obtenu %q", got)
	}
	if got := rowStatus(rows, "MAC", "DE.CM-01.2"); got != ReadyUnsupported {
		t.Errorf("MAC doit être « OS non supporté », obtenu %q", got)
	}
	// Le preflight ne couvre QUE les contrôles scannables (pas les déclaratifs).
	for _, r := range rows {
		if r.ControlID == "GV.PO-01.1" {
			t.Error("le preflight ne doit pas inclure un contrôle déclaratif")
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rowStatus(rows []PreflightRow, host, ctrl string) Readiness {
	for _, r := range rows {
		if r.Host == host && r.ControlID == ctrl {
			return r.Status
		}
	}
	return ""
}
