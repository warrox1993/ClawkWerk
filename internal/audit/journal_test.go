package audit

import (
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

func TestMemoryJournal_RecordsInOrder(t *testing.T) {
	j := NewMemoryJournal()
	h := assess.HostRef{ID: "PC-01"}
	j.Connection(h, scope.WinRM, "auditor")
	j.Command(h, "DE.CM-01.2", "Get-MpComputerStatus")
	j.Result(h, "DE.CM-01.2", assess.StatusPass)

	e := j.Entries()
	if len(e) != 3 {
		t.Fatalf("attendu 3 entrées, obtenu %d", len(e))
	}
	if e[0].Kind != KindConnection || e[1].Kind != KindCommand || e[2].Kind != KindResult {
		t.Errorf("ordre/kinds inattendus : %+v", e)
	}
	if e[1].Control != "DE.CM-01.2" {
		t.Errorf("contrôle non journalisé : %q", e[1].Control)
	}
}

// Entries() doit renvoyer une copie : muter le résultat ne doit pas altérer le
// journal (inaltérabilité).
func TestMemoryJournal_EntriesIsCopy(t *testing.T) {
	j := NewMemoryJournal()
	j.Connection(assess.HostRef{ID: "PC-01"}, scope.SSH, "auditor")
	got := j.Entries()
	got[0].Detail = "falsifié"
	if j.Entries()[0].Detail == "falsifié" {
		t.Error("le journal a été muté via la copie renvoyée")
	}
}
