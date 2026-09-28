package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scope"
	"github.com/warrox1993/clawkwerk/internal/session"
)

// makeSession fabrique une session à un contrôle KM, de maturité paramétrable.
func makeSession(id, client string, doc, impl cyfun.MaturityLevel, exportedAt time.Time) session.AuditSession {
	results := []assess.ControlResult{{
		Meta:     cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, Category: "DE.CM", KeyMeasure: true, Level: "Basic"},
		FinalDoc: doc, FinalImpl: impl,
	}}
	sc := scope.AuditScope{ClientRef: client}
	return session.New(id, sc, results, nil, exportedAt, exportedAt)
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSaveAndHistory_ChronologicalOrder(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	t1 := time.Unix(1_700_000_000, 0)
	t2 := time.Unix(1_700_100_000, 0)
	// Insérées dans le désordre : l'historique doit les retrier par date.
	if err := s.SaveSession(ctx, makeSession("a2", "ACME", cyfun.Defined, cyfun.Managed, t2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx, makeSession("a1", "ACME", cyfun.Defined, cyfun.Initial, t1)); err != nil {
		t.Fatal(err)
	}

	h, err := s.History(ctx, "ACME")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 {
		t.Fatalf("attendu 2 audits, obtenu %d", len(h))
	}
	if h[0].SessionID != "a1" || h[1].SessionID != "a2" {
		t.Errorf("ordre chronologique attendu [a1 a2], obtenu [%s %s]", h[0].SessionID, h[1].SessionID)
	}
	// a1 : moyenne(3,1)=2,0 => non conforme ; a2 : moyenne(3,4)=3,5 => conforme.
	if h[0].Conform {
		t.Error("a1 (2,0) ne doit pas être conforme")
	}
	if !h[1].Conform {
		t.Error("a2 (3,5) doit être conforme")
	}
}

func TestSaveSession_Idempotent(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	ts := time.Unix(1_700_000_000, 0)

	// Deux enregistrements du MÊME SessionID : le second remplace le premier.
	if err := s.SaveSession(ctx, makeSession("x", "ACME", cyfun.Defined, cyfun.Initial, ts)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx, makeSession("x", "ACME", cyfun.Managed, cyfun.Managed, ts)); err != nil {
		t.Fatal(err)
	}
	h, err := s.History(ctx, "ACME")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 1 {
		t.Fatalf("ré-export doit remplacer, pas dupliquer : %d entrées", len(h))
	}
	if h[0].TotalMaturity != 4.0 { // moyenne(4,4)
		t.Errorf("valeur mise à jour attendue 4.0, obtenu %v", h[0].TotalMaturity)
	}
}

func TestProgression(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	// un seul audit => non comparable.
	if err := s.SaveSession(ctx, makeSession("a1", "ACME", cyfun.Defined, cyfun.Initial, time.Unix(1_700_000_000, 0))); err != nil {
		t.Fatal(err)
	}
	if _, comparable, err := s.Progression(ctx, "ACME"); err != nil || comparable {
		t.Fatalf("un seul audit ne doit pas être comparable (comparable=%v err=%v)", comparable, err)
	}

	// deuxième audit meilleur : progression positive.
	if err := s.SaveSession(ctx, makeSession("a2", "ACME", cyfun.Defined, cyfun.Managed, time.Unix(1_700_100_000, 0))); err != nil {
		t.Fatal(err)
	}
	delta, comparable, err := s.Progression(ctx, "ACME")
	if err != nil {
		t.Fatal(err)
	}
	if !comparable {
		t.Fatal("deux audits doivent être comparables")
	}
	// 2,0 -> 3,5 => +1,5
	if delta != 1.5 {
		t.Errorf("progression attendue +1.5, obtenu %v", delta)
	}
}

func TestHistory_IsolatesClients(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.SaveSession(ctx, makeSession("a", "ACME", cyfun.Defined, cyfun.Defined, time.Unix(1_700_000_000, 0))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSession(ctx, makeSession("b", "OTHER", cyfun.Defined, cyfun.Defined, time.Unix(1_700_000_000, 0))); err != nil {
		t.Fatal(err)
	}
	h, err := s.History(ctx, "ACME")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 1 || h[0].ClientRef != "ACME" {
		t.Errorf("l'historique d'un client ne doit pas fuir sur un autre : %+v", h)
	}
}
