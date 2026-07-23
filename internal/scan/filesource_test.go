package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

func sampleHost() scope.ScopedHost {
	return scope.ScopedHost{
		Ref:       assess.HostRef{ID: "PC-01", OS: "windows"},
		Address:   "pc-01.client.lan",
		Transport: scope.WinRM,
	}
}

func TestFileSource_ReadsEvidenceAndJournals(t *testing.T) {
	dir := t.TempDir()
	want := `{"present":true,"enabled":true}`
	if err := os.WriteFile(filepath.Join(dir, "PC-01.DE.CM-01.2.json"), []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(dir)
	j := audit.NewMemoryJournal()
	cmd := ReadOnlyCommand("DE.CM-01.2", "windows", "Get-MpComputerStatus")
	cred := scope.NewCredential("svc-audit-ro", "auditor", []byte("x"))

	ev, err := src.Collect(context.Background(), sampleHost(), cmd, cred, j)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if string(ev.Data) != want {
		t.Errorf("Data = %q, attendu %q", ev.Data, want)
	}
	if ev.CollectErr != "" {
		t.Errorf("CollectErr inattendu : %q", ev.CollectErr)
	}
	// La Source journalise ses actions : connexion + commande (le résultat
	// d'évaluation est journalisé par le moteur, pas ici).
	entries := j.Entries()
	if len(entries) != 2 {
		t.Fatalf("attendu 2 entrées de journal, obtenu %d", len(entries))
	}
	if entries[0].Kind != audit.KindConnection || entries[1].Kind != audit.KindCommand {
		t.Errorf("kinds inattendus : %+v", entries)
	}
}

func TestFileSource_MissingEvidenceIsSoftError(t *testing.T) {
	src := NewFileSource(t.TempDir())
	j := audit.NewMemoryJournal()
	cmd := ReadOnlyCommand("DE.CM-01.2", "windows", "x")

	ev, err := src.Collect(context.Background(), sampleHost(), cmd, nil, j)
	if err != nil {
		t.Fatalf("preuve absente ne doit pas être une erreur fatale : %v", err)
	}
	if ev.CollectErr == "" {
		t.Error("CollectErr attendu pour preuve absente")
	}
}

func TestFileSource_RejectsNonReadOnlyCommand(t *testing.T) {
	src := NewFileSource(t.TempDir())
	j := audit.NewMemoryJournal()
	var mutating CollectCommand // zéro-valeur => readOnly=false
	mutating.ControlID = "DE.CM-01.2"

	if _, err := src.Collect(context.Background(), sampleHost(), mutating, nil, j); err == nil {
		t.Error("une commande non lecture seule doit être refusée")
	}
}

func TestFileSource_RequiresJournal(t *testing.T) {
	src := NewFileSource(t.TempDir())
	cmd := ReadOnlyCommand("DE.CM-01.2", "windows", "x")
	if _, err := src.Collect(context.Background(), sampleHost(), cmd, nil, nil); err == nil {
		t.Error("un journal nil doit être refusé")
	}
}
