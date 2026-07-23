package scan

import (
	"context"
	"testing"
	"time"

	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// Aucun serveur WinRM live n'est disponible dans ce contexte de test : on
// vérifie donc UNIQUEMENT les garde-fous portés par le code (avant toute action
// réseau) et les défauts du constructeur. Aucune connexion réelle n'est tentée.

func TestNewWinRMSource_Defaults(t *testing.T) {
	// timeout <= 0 doit retomber sur la valeur par défaut (15s).
	src := NewWinRMSource(true, 0)
	if src.Timeout != 15*time.Second {
		t.Errorf("timeout par défaut: got %v want 15s", src.Timeout)
	}
	if !src.HTTPS {
		t.Error("HTTPS demandé doit être conservé")
	}
	// Posture sécurisée par défaut : vérification TLS active.
	if src.Insecure {
		t.Error("Insecure doit être false par défaut (vérification TLS active)")
	}
	if src.now == nil {
		t.Error("l'horloge doit être initialisée par le constructeur")
	}

	// Un timeout explicite et positif est conservé tel quel.
	src2 := NewWinRMSource(false, 3*time.Second)
	if src2.Timeout != 3*time.Second {
		t.Errorf("timeout explicite: got %v want 3s", src2.Timeout)
	}
}

func TestWinRMSource_RequiresJournal(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		ReadOnlyCommand("X", "windows", "Get-Item"), scope.NewCredential("s", "u", []byte("p")), nil)
	if err == nil {
		t.Fatal("un journal est requis")
	}
}

func TestWinRMSource_RejectsNonReadOnly(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	// CollectCommand à zéro-valeur : readOnly=false.
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		CollectCommand{ControlID: "X"}, scope.NewCredential("s", "u", []byte("p")), audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("une commande non lecture seule doit être refusée")
	}
}

func TestWinRMSource_RequiresCredentials(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		ReadOnlyCommand("X", "windows", "Get-Item"), nil, audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("des credentials sont requis pour WinRM")
	}
}
