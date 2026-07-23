package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"projetcyber/internal/scan"
)

func TestBuildSource_File(t *testing.T) {
	src, err := buildSource("file", "./sample/evidence", "", false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*scan.FileSource); !ok {
		t.Fatalf("mode file doit donner une *FileSource, obtenu %T", src)
	}
}

func TestBuildSource_RemoteRequiresKnownHosts(t *testing.T) {
	// Sécurité : pas de connexion SSH sans vérification de clé d'hôte.
	if _, err := buildSource("remote", "", "", false, time.Second); err == nil {
		t.Fatal("mode remote sans -known-hosts doit échouer")
	}
}

func TestBuildSource_UnknownTransport(t *testing.T) {
	if _, err := buildSource("carrier-pigeon", "", "", false, time.Second); err == nil {
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
	src, err := buildSource("remote", "", kh, false, time.Second)
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
