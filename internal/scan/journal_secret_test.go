package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// Le journal d'audit est haché en chaîne (SHA-256) et exporté dans la preuve
// de session : il ne doit JAMAIS porter le secret d'un identifiant. CodeQL
// (go/weak-sensitive-data-hashing) y voyait des « mots de passe » ; ce sont en
// réalité l'identifiant du contrôle et le texte de commandes constantes (par
// exemple la lecture de « PasswordAuthentication » dans sshd_config). Ce test
// fige la garantie réelle : le secret n'entre ni dans le journal, ni dans la
// sérialisation de l'identifiant.
func TestJournal_NeverContainsCredentialSecret(t *testing.T) {
	// Canari tiré au hasard à chaque exécution : aucune valeur fixe qu'un
	// détecteur de secrets prendrait pour un vrai mot de passe dans le dépôt.
	alea := make([]byte, 16)
	if _, err := rand.Read(alea); err != nil {
		t.Fatal(err)
	}
	secret := "canari-" + hex.EncodeToString(alea)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PC-01.PR.AA-03.02.json"), []byte(`{"remote_access_enabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(dir)
	j := audit.NewMemoryJournal()
	cmd := ReadOnlyCommand("PR.AA-03.02", "windows", "reg query PasswordAuthentication")
	cred := scope.NewCredential("svc-audit-ro", "auditor", []byte(secret))

	if _, err := src.Collect(context.Background(), sampleHost(), cmd, cred, j); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	entries := j.Entries()
	if len(entries) == 0 {
		t.Fatal("le journal devrait contenir au moins la connexion et la commande")
	}
	journal, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journal), secret) {
		t.Errorf("le secret de l'identifiant apparaît dans le journal d'audit : %s", journal)
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(credJSON), secret) {
		t.Errorf("le secret apparaît dans la sérialisation de l'identifiant : %s", credJSON)
	}
	if err := audit.Verify(entries); err != nil {
		t.Errorf("chaîne d'intégrité rompue : %v", err)
	}
}
