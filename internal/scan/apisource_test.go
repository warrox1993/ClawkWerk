package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

func apiHost() scope.ScopedHost {
	return scope.ScopedHost{Ref: assess.HostRef{ID: "FW", OS: "unifi"}, Transport: scope.API}
}

func TestAPISource_Guards(t *testing.T) {
	s := NewAPISource(time.Second, false)
	cred := scope.NewCredential("svc", "u", []byte("p"))
	ro := ReadOnlyCommand("PR.IR-01.1", "unifi", "firewall")

	if _, err := s.Collect(context.Background(), apiHost(), ro, cred, nil); err == nil {
		t.Error("journal nil doit être une erreur")
	}
	if _, err := s.Collect(context.Background(), apiHost(), CollectCommand{ControlID: "X"}, cred, audit.NewMemoryJournal()); err == nil {
		t.Error("commande non lecture seule doit être refusée")
	}
	if _, err := s.Collect(context.Background(), apiHost(), ro, nil, audit.NewMemoryJournal()); err == nil {
		t.Error("credentials nil doit être une erreur")
	}
}

func TestAPISource_NoClientIsSoftError(t *testing.T) {
	s := NewAPISource(time.Second, false) // aucun client enregistré
	ev, err := s.Collect(context.Background(), apiHost(),
		ReadOnlyCommand("PR.IR-01.1", "unifi", "firewall"),
		scope.NewCredential("svc", "u", []byte("p")), audit.NewMemoryJournal())
	if err != nil {
		t.Fatalf("erreur de config inattendue: %v", err)
	}
	if !strings.Contains(ev.CollectErr, "aucun client API") {
		t.Fatalf("trou de collecte attendu (pas de client), obtenu: %q", ev.CollectErr)
	}
}

func TestAPIClients_PlatformIdentifiers(t *testing.T) {
	if NewUniFiClient().Platform() != "unifi" || NewSophosClient().Platform() != "sophosxg" {
		t.Fatal("identifiants de plateforme des clients API incorrects")
	}
}
