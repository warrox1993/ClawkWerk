package controls

import (
	"encoding/json"
	"testing"
	"time"
)

// La sonde patches auto-détecte apt/dnf/zypper/pacman/apk et émet toujours le
// MÊME format 4 lignes ; le normaliseur est donc générique. On vérifie qu'une
// sortie Arch (pacman) et Alpine (apk) se normalisent sans traitement spécial.
func TestPatchLinuxNormalizer_PacmanApk(t *testing.T) {
	now := func() time.Time { return time.Unix(1700100000, 0) }
	n := PatchLinuxNormalizer(now)

	out, err := n([]byte("pacman\n5\n1700000000\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev PatchEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Manager != "pacman" || ev.PendingSecurityUpdates != 5 {
		t.Fatalf("pacman inattendu : %+v", ev)
	}

	out, err = n([]byte("apk\n2\n0\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Manager != "apk" || ev.PendingSecurityUpdates != 2 {
		t.Fatalf("apk inattendu : %+v", ev)
	}
}
