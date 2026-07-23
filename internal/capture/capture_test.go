package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := []byte("host 192.168.1.10 mac 00:1A:2B:3C:4D:5E ok")
	out := string(Redact(in))
	if strings.Contains(out, "192.168.1.10") {
		t.Error("IPv4 non masquée")
	}
	if strings.Contains(out, "00:1A:2B:3C:4D:5E") {
		t.Error("MAC non masquée")
	}
	if !strings.Contains(out, "0.0.0.0") || !strings.Contains(out, "00:00:00:00:00:00") {
		t.Errorf("remplacements attendus absents : %q", out)
	}
}

func TestFileSink_WritesRedactedCapture(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Capture("DE.CM-01.2", "PC1", "windows", []byte(`{"ip":"10.0.0.5"}`))

	data, err := os.ReadFile(filepath.Join(dir, "PC1.DE.CM-01.2.windows.raw"))
	if err != nil {
		t.Fatalf("fichier de capture attendu : %v", err)
	}
	if strings.Contains(string(data), "10.0.0.5") {
		t.Error("l'IP aurait dû être masquée dans la capture")
	}
	// Un README d'avertissement RGPD est déposé.
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Error("README d'avertissement attendu")
	}
}

func TestFileSink_SanitizesPathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileSink(dir)
	s.Capture("../evil", "../../host", "linux", []byte("x"))
	// Aucun fichier ne doit s'échapper du répertoire de capture.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "..") {
			t.Errorf("nom de fichier non neutralisé : %s", e.Name())
		}
	}
}
