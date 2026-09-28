package engine

import (
	"strings"
	"testing"
)

// privilegeGap ne fait que CONSTATER un accès refusé — jamais d'élévation (règle
// de sécurité absolue). Il doit repérer les marqueurs Windows/Linux, et ne PAS
// déclencher de faux positif sur une sortie normale.
func TestPrivilegeGap(t *testing.T) {
	denied := []string{
		"Access is denied.",
		"cat: /etc/shadow: Permission denied",
		"You must be root to run this",
		"Operation not permitted",
		"Accès refusé",
	}
	for _, d := range denied {
		if privilegeGap([]byte(d)) == "" {
			t.Errorf("accès refusé non détecté : %q", d)
		}
	}
	ok := []string{
		`{"antivirus_enabled":true}`,
		"apt\n3\n1700000000\nyes",
		"",
	}
	for _, o := range ok {
		if privilegeGap([]byte(o)) != "" {
			t.Errorf("faux positif de droits sur une sortie normale : %q", o)
		}
	}
}

// La sonde Windows nomme la ressource refusée (« ACCESS DENIED: <ressource> ») :
// le preflight doit la reprendre pour dire au client QUOI provisionner.
func TestPrivilegeGap_NommeLaRessource(t *testing.T) {
	got := privilegeGap([]byte("ACCESS DENIED: BitLocker (Win32_EncryptableVolume, reserve aux administrateurs)\r\n"))
	if !strings.Contains(got, "(BitLocker (Win32_EncryptableVolume, reserve aux administrateurs))") {
		t.Fatalf("ressource refusée non reprise : %q", got)
	}
	if !strings.HasPrefix(got, gapInsufficientPrivileges) {
		t.Fatalf("préfixe stable attendu : %q", got)
	}
}
