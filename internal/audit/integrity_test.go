package audit

import (
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

func filledJournal() *MemoryJournal {
	j := NewMemoryJournal()
	h := assess.HostRef{ID: "SRV01"}
	j.Connection(h, scope.SSH, "auditor")
	j.Command(h, "DE.CM-01.2", "cat /tmp/av.json")
	j.Result(h, "DE.CM-01.2", assess.StatusPass)
	return j
}

func TestJournal_ChainVerifies(t *testing.T) {
	if err := Verify(filledJournal().Entries()); err != nil {
		t.Fatalf("un journal authentique doit se vérifier : %v", err)
	}
}

func TestJournal_DetectsTampering(t *testing.T) {
	entries := filledJournal().Entries()
	entries[1].Detail = "commande falsifiée" // on maquille une commande
	if err := Verify(entries); err == nil {
		t.Fatal("une entrée modifiée doit casser la chaîne")
	}
}

func TestJournal_DetectsReordering(t *testing.T) {
	entries := filledJournal().Entries()
	entries[0], entries[1] = entries[1], entries[0] // on inverse deux entrées
	if err := Verify(entries); err == nil {
		t.Fatal("un réordonnancement doit casser la chaîne")
	}
}

func TestJournal_DetectsDeletion(t *testing.T) {
	entries := filledJournal().Entries()
	entries = append(entries[:1], entries[2:]...) // on supprime l'entrée du milieu
	if err := Verify(entries); err == nil {
		t.Fatal("une suppression doit casser la chaîne")
	}
}
