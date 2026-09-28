package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

func TestBuildSource_File(t *testing.T) {
	src, err := buildSource("file", "./sample/evidence", "", winrmOptions{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*scan.FileSource); !ok {
		t.Fatalf("mode file doit donner une *FileSource, obtenu %T", src)
	}
}

func TestBuildSource_RemoteRequiresKnownHosts(t *testing.T) {
	// Sécurité : pas de connexion SSH sans vérification de clé d'hôte.
	if _, err := buildSource("remote", "", "", winrmOptions{}, time.Second); err == nil {
		t.Fatal("mode remote sans -known-hosts doit échouer")
	}
}

func TestBuildSource_UnknownTransport(t *testing.T) {
	if _, err := buildSource("carrier-pigeon", "", "", winrmOptions{}, time.Second); err == nil {
		t.Fatal("un transport inconnu doit être rejeté")
	}
}

func TestBuildSource_RemoteWithKnownHosts(t *testing.T) {
	// Un fichier known_hosts valide (une entrée) permet de construire la source.
	kh := filepath.Join(t.TempDir(), "known_hosts")
	// Entrée ed25519 syntaxiquement valide (clé d'exemple, non fonctionnelle).
	line := "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINb1eqk2sd6We7q1yB2u5s3p4o5f6g7h8i9j0k1l2m3n\n"
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := buildSource("remote", "", kh, winrmOptions{}, time.Second)
	if err != nil {
		t.Fatalf("known_hosts valide doit permettre la construction : %v", err)
	}
	if _, ok := src.(scan.RemoteSource); !ok {
		t.Fatalf("mode remote doit donner une RemoteSource, obtenu %T", src)
	}
}

func TestLoadCreds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creds.json")
	os.WriteFile(p, []byte(`{"svc":{"username":"svc@acme","secret":"s3cret"}}`), 0o600)
	creds, err := loadCreds(p)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := creds["svc"]
	if !ok || c.Username != "svc@acme" {
		t.Fatalf("credential mal chargé: %+v", creds)
	}
	// Le secret est accessible pour la couche transport mais jamais sérialisé.
	if string(c.Secret()) != "s3cret" {
		t.Errorf("secret non chargé")
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadScope(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	ok := writeFile(t, "scope.json", `{"client":"ACME","hosts":[{"id":"L1","os":"linux","address":"l1","transport":"ssh","cred_ref":"ro"}]}`)
	sc, err := loadScope(ok, now)
	if err != nil || len(sc.Hosts) != 1 {
		t.Fatalf("périmètre valide refusé : %v", err)
	}
	typo := writeFile(t, "scope.json", `{"client":"ACME","hosts":[{"id":"L1","os":"linx","address":"l1","transport":"ssh","cred_ref":"ro"}]}`)
	if _, err := loadScope(typo, now); err == nil {
		t.Error("une plateforme inconnue doit être refusée")
	}
	if _, err := loadScope("", now); err == nil {
		t.Error("-scope vide doit être refusé")
	}
	// L'exemple livré est valide pour la CLI.
	if _, err := loadScope(filepath.Join("..", "..", "sample", "scope.json"), now); err != nil {
		t.Errorf("sample/scope.json refusé : %v", err)
	}
}

func TestResolveCreds(t *testing.T) {
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{{CredRef: "ro-win"}, {CredRef: "ro-lnx"}, {CredRef: "ro-win"}}}

	// Mode file sans -creds : un credential factice par référence.
	creds, err := resolveCreds("file", "", sc)
	if err != nil || len(creds) != 2 || creds["ro-win"] == nil || creds["ro-lnx"] == nil {
		t.Fatalf("mode file : %v, %v", err, creds)
	}
	// Mode remote sans -creds : refus explicite.
	if _, err := resolveCreds("remote", "", sc); err == nil {
		t.Error("mode remote sans -creds doit être refusé")
	}
	// Référence manquante dans le fichier : refus avant toute connexion.
	partial := writeFile(t, "creds.json", `{"ro-win":{"username":"svc","secret":"s"}}`)
	if _, err := resolveCreds("remote", partial, sc); err == nil || !strings.Contains(err.Error(), "ro-lnx") {
		t.Errorf("référence manquante non signalée : %v", err)
	}
	full := writeFile(t, "creds.json", `{"ro-win":{"username":"svc","secret":"s"},"ro-lnx":{"username":"audit","secret":"t"}}`)
	creds, err = resolveCreds("remote", full, sc)
	if err != nil || string(creds["ro-lnx"].Secret()) != "t" {
		t.Fatalf("fichier complet refusé : %v", err)
	}
}

func TestBuildSource_OptionsWinRM(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINb1eqk2sd6We7q1yB2u5s3p4o5f6g7h8i9j0k1l2m3n\n"), 0o600)

	if _, err := buildSource("remote", "", kh, winrmOptions{Auth: "kerberos"}, time.Second); err == nil {
		t.Error("-winrm-auth inconnu doit être refusé")
	}
	if _, err := buildSource("remote", "", kh, winrmOptions{CAFile: filepath.Join(dir, "absent.pem")}, time.Second); err == nil {
		t.Error("-winrm-ca illisible doit être refusé")
	}
	pasPEM := filepath.Join(dir, "pas-pem.pem")
	os.WriteFile(pasPEM, []byte("ceci n'est pas un certificat"), 0o600)
	if _, err := buildSource("remote", "", kh, winrmOptions{CAFile: pasPEM}, time.Second); err == nil {
		t.Error("-winrm-ca sans certificat PEM doit être refusé")
	}

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	src, err := buildSource("remote", "", kh, winrmOptions{Auth: "basic", CAFile: ca}, time.Second)
	if err != nil {
		t.Fatalf("options valides refusées : %v", err)
	}
	w := src.(scan.RemoteSource).WinRM
	if w.Auth != scan.AuthBasic || len(w.CACert) == 0 || w.Insecure {
		t.Fatalf("options WinRM non appliquées : auth=%q ca=%d insecure=%v", w.Auth, len(w.CACert), w.Insecure)
	}
}
