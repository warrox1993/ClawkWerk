// Package capture enregistre les sorties BRUTES de collecte d'un run d'audit, pour
// bâtir des fixtures « golden » de non-régression pendant les pilotes — sans
// travail manuel. Une redaction best-effort masque les identifiants réseau
// évidents (IPv4, MAC). ATTENTION : la redaction n'est PAS exhaustive (une sortie
// peut contenir des noms d'utilisateurs/machines) ; toute capture doit être RELUE
// avant d'être committée comme fixture (RGPD).
package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reMAC  = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
)

// Redact masque les identifiants réseau évidents (IPv4 → 0.0.0.0, MAC →
// 00:00:00:00:00:00). Best-effort et non exhaustif — voir l'avertissement du paquet.
func Redact(raw []byte) []byte {
	out := reIPv4.ReplaceAll(raw, []byte("0.0.0.0"))
	out = reMAC.ReplaceAll(out, []byte("00:00:00:00:00:00"))
	return out
}

// FileSink écrit chaque sortie brute (redigée) dans un fichier
// `<hostID>.<controlID>.<os>.raw` d'un répertoire. Sûr : ne crée que des fichiers.
type FileSink struct {
	dir string
}

// NewFileSink crée le répertoire de capture (et un README d'avertissement RGPD).
func NewFileSink(dir string) (*FileSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("capture: création du répertoire : %w", err)
	}
	readme := "# Captures brutes de collecte (ClawkWerk)\n\n" +
		"Sorties BRUTES par sonde/hôte, destinées à devenir des fixtures golden.\n" +
		"REDACTION best-effort (IPv4/MAC masquées) — NON exhaustive.\n" +
		"⚠️ RELIRE et anonymiser (noms d'utilisateurs/machines) AVANT tout commit (RGPD).\n"
	// N'échoue pas le run si le README ne peut pas être écrit.
	_ = os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644)
	return &FileSink{dir: dir}, nil
}

// Capture enregistre une sortie brute. Signature compatible engine.CaptureFunc.
func (s *FileSink) Capture(controlID, hostID, osName string, raw []byte) {
	name := fmt.Sprintf("%s.%s.%s.raw", safe(hostID), safe(controlID), safe(osName))
	// Best-effort : une écriture ratée ne doit jamais interrompre l'audit.
	_ = os.WriteFile(filepath.Join(s.dir, name), Redact(raw), 0o644)
}

// safe neutralise les caractères de chemin dans un composant de nom de fichier.
func safe(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" {
		return "unknown"
	}
	return s
}
